//! `/proc` backend: streams every open fd of every visible process.
//!
//! Design notes:
//! - One pass over `/proc`, one pass over each `fd` directory. No fork/exec,
//!   no materialization of the whole fd table (the Red Hat OOM case).
//! - Every per-fd failure is skipped: processes exit while we scan them.
//! - Scans with many processes split across worker threads (one contiguous,
//!   pid-sorted chunk each); workers call the thread-safe sink directly, so
//!   memory stays flat and every core pulls its weight.
//! - Zero unsafe.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::classify::{classify, stat_link};
use crate::passwd::UserTable;
use crate::types::{Backend, FdEntry, FdKind, FdSink, ProcessInfo, ScanOptions};

/// Cap on the worker count: /proc walking is the workload, more than a few
/// dozen threads buys nothing.
const MAX_WORKERS: usize = 32;

pub struct ProcBackend;

impl ProcBackend {
    pub fn new() -> Self {
        ProcBackend
    }
}

impl Default for ProcBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for ProcBackend {
    fn name(&self) -> &'static str {
        "proc"
    }

    fn scan(&self, opts: &ScanOptions, sink: &FdSink<'_>) -> io::Result<()> {
        let users = if opts.numeric {
            None
        } else {
            Some(UserTable::load())
        };

        // One bulk netlink dump per scan; entries are joined by inode below.
        // Netlink failures degrade silently: /proc data stays correct.
        let socks = if opts.resolve_sockets {
            crate::sockdiag::dump_scope(opts.sock_scope).ok()
        } else {
            None
        };

        let pids = list_pids()?;

        let workers = available_workers();
        if workers <= 1 || pids.len() < opts.parallel_min_pids {
            for &pid in &pids {
                scan_one(pid, opts, socks.as_ref(), users.as_ref(), sink);
            }
            return Ok(());
        }

        self.scan_parallel(&pids, opts, socks.as_ref(), users.as_ref(), sink)
    }
}

fn available_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(MAX_WORKERS)
}

impl ProcBackend {
    /// Parallel scan: pid-sorted contiguous chunks, one worker each. Workers
    /// call the sink directly (it must be thread-safe, see [`FdSink`]); rows
    /// of one process stay ordered, rows of different processes may
    /// interleave. A spawn failure degrades that chunk to an inline scan.
    fn scan_parallel(
        &self,
        pids: &[u32],
        opts: &ScanOptions,
        socks: Option<&crate::sockdiag::SockTable>,
        users: Option<&UserTable>,
        sink: &FdSink<'_>,
    ) -> io::Result<()> {
        let workers = available_workers().min(pids.len()).max(1);
        let chunk_size = pids.len().div_ceil(workers);

        std::thread::scope(|scope| {
            for (i, chunk) in pids.chunks(chunk_size).enumerate() {
                let spawned = std::thread::Builder::new()
                    .name(format!("openfd-scan-{i}"))
                    .spawn_scoped(scope, move || {
                        for &pid in chunk {
                            scan_one(pid, opts, socks, users, sink);
                        }
                    });
                if spawned.is_err() {
                    for &pid in chunk {
                        scan_one(pid, opts, socks, users, sink);
                    }
                }
            }
        });
        Ok(())
    }
}

/// Sorted numeric pid list from /proc; a broken /proc mount is the only
/// hard error.
fn list_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir(Path::new("/proc"))? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

/// Scan one process: cheap pid reject, metadata read, full reject, then the
/// fd loop. Shared by the sequential and the parallel paths.
fn scan_one(
    pid: u32,
    opts: &ScanOptions,
    socks: Option<&crate::sockdiag::SockTable>,
    users: Option<&UserTable>,
    sink: &FdSink<'_>,
) {
    let process_filter = opts.process_filter.as_ref();
    // Cheapest reject first: before /proc/<pid> is read at all.
    if let Some(f) = process_filter
        && !f.accepts_pid(pid)
    {
        return;
    }
    let info = match read_process(pid, users) {
        Some(info) => Arc::new(info),
        None => return,
    };
    if let Some(f) = process_filter
        && !f.accepts(&info)
    {
        return;
    }
    emit_process_fds(pid, &info, opts, socks, sink);
}

fn emit_process_fds(
    pid: u32,
    info: &Arc<ProcessInfo>,
    opts: &ScanOptions,
    socks: Option<&crate::sockdiag::SockTable>,
    sink: &FdSink<'_>,
) {
    let fd_dir: PathBuf = ["/proc", &pid.to_string(), "fd"].iter().collect();
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return, // process gone, or permission denied
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let fd: i32 = match entry.file_name().to_string_lossy().parse() {
            Ok(f) => f,
            Err(_) => continue, // skip non-numeric entries
        };
        let link = entry.path();
        let raw = match fs::read_link(&link) {
            Ok(r) => r.to_string_lossy().into_owned(),
            Err(_) => continue,
        };

        // One stat of the fd link serves classification, inode, size and mode
        // whenever a stat is needed at all (deleted entries and --sizes).
        let cls_deleted_raw = raw.ends_with(" (deleted)") && !raw.starts_with("/memfd:");
        let stat_meta = if cls_deleted_raw || opts.stat_all {
            stat_link(&link)
        } else {
            None
        };
        let cls = classify(&raw, stat_meta.as_ref());

        let mut size = None;
        let mut mode = None;
        if let Some(meta) = &stat_meta {
            size = Some(meta.len());
            mode = Some(meta.mode());
        }

        let sock = match socks {
            Some(table) => match cls.inode {
                Some(ino) if cls.kind == FdKind::Socket => table.get(ino).cloned(),
                _ => None,
            },
            None => None,
        };

        // Fd-level reject: skip the fdinfo read entirely. The probe entry
        // carries everything filters may look at (fd, kind, target, deleted,
        // sock) but not the not-yet-read fdinfo/stat fields.
        if let Some(f) = &opts.fd_filter {
            let probe = FdEntry {
                fd,
                kind: cls.kind,
                target: cls.target.clone(),
                anon_subtype: cls.anon_subtype.clone(),
                deleted: cls.deleted,
                size,
                pos: None,
                flags: None,
                inode: cls.inode,
                mode,
                sock: sock.clone(),
            };
            if !f(&probe) {
                continue;
            }
        }

        let (pos, flags, fdinfo_ino) = if opts.read_fdinfo {
            read_fdinfo(pid, fd)
        } else {
            (None, None, None)
        };

        let fd_entry = FdEntry {
            fd,
            kind: cls.kind,
            target: cls.target,
            anon_subtype: cls.anon_subtype,
            deleted: cls.deleted,
            size,
            pos,
            flags,
            inode: cls.inode.or(fdinfo_ino),
            mode,
            sock,
        };
        sink(info, &fd_entry);
    }
}

/// Read `pos`, `flags` and the file's `ino` (kernels >= 4.x) from
/// `/proc/<pid>/fdinfo/<fd>` in a single pass.
fn read_fdinfo(pid: u32, fd: i32) -> (Option<u64>, Option<u32>, Option<u64>) {
    let mut pos = None;
    let mut flags = None;
    let mut ino = None;
    let path: PathBuf = ["/proc", &pid.to_string(), "fdinfo", &fd.to_string()]
        .iter()
        .collect();
    if let Ok(content) = fs::read_to_string(&path) {
        for line in content.lines() {
            let mut fields = line.splitn(2, ':');
            let key = fields.next().unwrap_or("").trim();
            let value = fields.next().unwrap_or("").trim();
            match key {
                "pos" => pos = value.parse().ok(),
                "flags" => flags = u32::from_str_radix(value, 8).ok(),
                "ino" => ino = value.parse().ok(),
                _ => {}
            }
        }
    }
    (pos, flags, ino)
}

fn read_process(pid: u32, users: Option<&UserTable>) -> Option<ProcessInfo> {
    let base: PathBuf = ["/proc", &pid.to_string()].iter().collect();

    let comm = fs::read_to_string(base.join("comm"))
        .map(|mut s| {
            if s.ends_with('\n') {
                s.pop();
            }
            s
        })
        .unwrap_or_else(|_| "(unknown)".to_string());

    let cmdline0 = fs::read(base.join("cmdline")).ok().and_then(|bytes| {
        bytes
            .split(|b| *b == 0)
            .find(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
    });

    let (ppid, uid) = read_status_fields(&base)?;

    let username = match users {
        Some(t) => t.name(uid).map(str::to_string),
        None => None,
    };

    Some(ProcessInfo {
        pid,
        ppid,
        comm,
        cmdline0,
        uid,
        username,
    })
}

fn read_status_fields(base: &Path) -> Option<(Option<u32>, u32)> {
    let content = fs::read_to_string(base.join("status")).ok()?;
    let mut ppid = None;
    let mut uid = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            // Uid: real effective saved fs
            uid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
            break;
        }
    }
    uid.map(|uid| (ppid, uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fdinfo of the test process' own stdin: pos/flags/ino all parse in one
    /// pass (this used to be two reads of the same file).
    #[test]
    fn fdinfo_single_pass_parses_pos_flags_ino() {
        let (pos, flags, ino) = read_fdinfo(std::process::id(), 0);
        assert!(
            flags.is_some(),
            "fdinfo must expose flags for our own stdin"
        );
        assert!(
            pos.is_some() || ino.is_some(),
            "pos/ino should be present: {pos:?} {ino:?}"
        );
    }
}
