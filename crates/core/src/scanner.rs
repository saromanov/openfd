//! `/proc` backend: streams every open fd of every visible process.
//!
//! Design notes:
//! - One pass over `/proc`, one pass over each `fd` directory. No fork/exec,
//!   no materialization of the whole fd table (the Red Hat OOM case).
//! - Every per-fd failure is skipped: processes exit while we scan them.
//! - Scans with many processes split across worker threads (one contiguous,
//!   pid-sorted chunk each); the writer drains the chunks in pid order via
//!   bounded channels, so output stays a stream with flat memory.
//! - Zero unsafe.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::sync_channel;

use crate::classify::{classify, stat_link};
use crate::passwd::UserTable;
use crate::types::{Backend, FdEntry, FdKind, FdSink, ProcessInfo, ScanOptions};

/// Bound of each worker's channel: keeps memory flat while decoupling the
/// workers from the (usually fast) writer.
const CHANNEL_BOUND: usize = 64;

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

    fn scan(&self, opts: &ScanOptions, sink: &mut FdSink<'_>) -> io::Result<()> {
        let users = if opts.numeric {
            None
        } else {
            Some(Arc::new(UserTable::load()))
        };

        // One bulk netlink dump per scan; entries are joined by inode below.
        // Netlink failures degrade silently: /proc data stays correct.
        let socks = if opts.resolve_sockets {
            crate::sockdiag::dump_scope(opts.sock_scope)
                .ok()
                .map(Arc::new)
        } else {
            None
        };

        let pids = list_pids()?;

        let workers = available_workers();
        if workers <= 1 || pids.len() < opts.parallel_min_pids {
            for &pid in &pids {
                scan_one(pid, opts, socks.as_deref(), users.as_deref(), sink);
            }
            return Ok(());
        }

        // Worker threads need 'static data: Arc everything they read.
        let opts = Arc::new(opts.clone());
        self.scan_parallel(&pids, &opts, socks, users, sink)
    }
}

fn available_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(MAX_WORKERS)
}

impl ProcBackend {
    /// Parallel scan: pid-sorted contiguous chunks, one worker each, writer
    /// drains the channels in pid order. A spawn failure degrades that chunk
    /// to an inline scan at the position it would have had anyway.
    fn scan_parallel(
        &self,
        pids: &[u32],
        opts: &Arc<ScanOptions>,
        socks: Option<Arc<crate::sockdiag::SockTable>>,
        users: Option<Arc<UserTable>>,
        sink: &mut FdSink<'_>,
    ) -> io::Result<()> {
        let workers = available_workers().min(pids.len()).max(1);
        let chunk_size = pids.len().div_ceil(workers);

        let mut chunks = Vec::with_capacity(workers);
        let mut rxs = Vec::with_capacity(workers);
        let mut handles: Vec<Option<std::thread::JoinHandle<()>>> = Vec::with_capacity(workers);
        for (i, chunk) in pids.chunks(chunk_size).enumerate() {
            let chunk_pids: Vec<u32> = chunk.to_vec();
            let chunk_for_list = chunk_pids.clone();
            let (tx, rx) = sync_channel::<(Arc<ProcessInfo>, FdEntry)>(CHANNEL_BOUND);
            let opts = Arc::clone(opts);
            let socks = socks.clone();
            let users = users.clone();
            let handle = std::thread::Builder::new()
                .name(format!("openfd-scan-{i}"))
                .spawn(move || {
                    let mut send = move |info: &Arc<ProcessInfo>, entry: &mut FdEntry| {
                        let _ = tx.send((Arc::clone(info), entry.clone()));
                    };
                    for &pid in &chunk_pids {
                        scan_one(pid, &opts, socks.as_deref(), users.as_deref(), &mut send);
                    }
                });
            match handle {
                Ok(h) => handles.push(Some(h)),
                Err(_) => handles.push(None), // fall back to an inline scan later
            }
            rxs.push(rx);
            chunks.push(chunk_for_list);
        }

        // The writer (this thread) drains the channels in pid order: output
        // stays a bounded-memory stream, not a materialized snapshot.
        for (i, rx) in rxs.into_iter().enumerate() {
            if handles[i].is_none() {
                for &pid in &chunks[i] {
                    scan_one(pid, opts, socks.as_deref(), users.as_deref(), sink);
                }
            } else {
                while let Ok((info, mut entry)) = rx.recv() {
                    sink(&info, &mut entry);
                }
            }
            if let Some(h) = handles[i].take() {
                let _ = h.join();
            }
        }
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
    sink: &mut FdSink<'_>,
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
    sink: &mut FdSink<'_>,
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

        let inode = cls.inode;

        let sock = match socks {
            Some(table) => match cls.inode {
                Some(ino) if cls.kind == FdKind::Socket => table.get(ino).cloned(),
                _ => None,
            },
            None => None,
        };

        let fd_entry = FdEntry {
            fd,
            kind: cls.kind,
            target: cls.target,
            anon_subtype: cls.anon_subtype,
            deleted: cls.deleted,
            size,
            pos: None,
            flags: None,
            inode,
            mode,
            sock,
        };

        // Fd-level reject: skip the fdinfo read entirely.
        if let Some(f) = &opts.fd_filter
            && !f(&fd_entry)
        {
            continue;
        }

        let mut fd_entry = fd_entry;
        let (pos, flags, fdinfo_ino) = if opts.read_fdinfo {
            read_fdinfo(pid, fd)
        } else {
            (None, None, None)
        };
        fd_entry.pos = pos;
        fd_entry.flags = flags;
        if fd_entry.inode.is_none() {
            fd_entry.inode = fdinfo_ino;
        }
        sink(info, &mut fd_entry);
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
