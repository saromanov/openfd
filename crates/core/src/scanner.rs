//! `/proc` backend: streams every open fd of every visible process.
//!
//! Design notes:
//! - One pass over `/proc`, one pass over each `fd` directory. No fork/exec,
//!   no materialization of the whole fd table (the Red Hat OOM case).
//! - Every per-fd failure is skipped: processes exit while we scan them.
//! - Zero unsafe.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::classify::{classify, stat_link};
use crate::passwd::UserTable;
use crate::types::{Backend, FdEntry, FdKind, FdSink, ProcessInfo, ScanOptions};

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
            Some(UserTable::load())
        };

        // One bulk netlink dump per scan; entries are joined by inode below.
        // Netlink failures degrade silently: /proc data stays correct.
        let socks = if opts.resolve_sockets {
            crate::sockdiag::dump_all().ok()
        } else {
            None
        };

        let proc_dir = Path::new("/proc");
        for entry in fs::read_dir(proc_dir)? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let pid: u32 = match entry.file_name().to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue, // not a process directory
            };
            let info = match read_process(pid, users.as_ref()) {
                Some(info) => Arc::new(info),
                None => continue,
            };
            emit_process_fds(pid, &info, opts, socks.as_ref(), sink);
        }
        Ok(())
    }
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

        let cls = classify(&raw);
        let (pos, flags) = read_fdinfo(pid, fd);

        let mut size = None;
        let mut mode = None;
        if (cls.deleted || opts.stat_all)
            && let Some(meta) = stat_link(&link)
        {
            size = Some(meta.len());
            mode = Some(meta.mode());
        }

        let inode = cls.inode.or_else(|| read_fdinfo_inode(pid, fd));

        let sock = match socks {
            Some(table) => match cls.inode {
                Some(ino) if cls.kind == FdKind::Socket => table.get(ino).cloned(),
                _ => None,
            },
            None => None,
        };

        let mut fd_entry = FdEntry {
            fd,
            kind: cls.kind,
            target: cls.target,
            anon_subtype: cls.anon_subtype,
            deleted: cls.deleted,
            size,
            pos,
            flags,
            inode,
            mode,
            sock,
        };
        sink(info, &mut fd_entry);
    }
}

/// Read `pos` and `flags` from `/proc/<pid>/fdinfo/<fd>`.
fn read_fdinfo(pid: u32, fd: i32) -> (Option<u64>, Option<u32>) {
    let mut pos = None;
    let mut flags = None;
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
                _ => {}
            }
        }
    }
    (pos, flags)
}

/// Read the `ino:` field from fdinfo (present for files on kernels >= 4.x).
fn read_fdinfo_inode(pid: u32, fd: i32) -> Option<u64> {
    let path: PathBuf = ["/proc", &pid.to_string(), "fdinfo", &fd.to_string()]
        .iter()
        .collect();
    let content = fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        let mut fields = line.splitn(2, ':');
        if fields.next()?.trim() == "ino" {
            return fields.next()?.trim().parse().ok();
        }
    }
    None
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
