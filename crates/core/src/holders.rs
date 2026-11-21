//! Holder collection for `openfd why`: every way a resource can be held
//! (fd, cwd, root, exe, mmap, file lock, submount) plus the owner resolution
//! and permission accounting that turn a pid into an actionable answer.
//!
//! Read-only by construction: nothing here truncates, signals or restarts.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::locks::{self, LockRecord};
use crate::mounts::path_within;
use crate::owner::{Owner, OwnerKind, parse_cgroup};
use crate::sockdiag;
use crate::target::{Target, TargetKind};
use crate::types::{
    FdEntry, FdKind, FdSink, ProcessInfo, SockAddr, SockInfo, SockProto, SockScope,
};

/// How a resource is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HolderKind {
    Fd,
    Cwd,
    Root,
    Exe,
    Mmap,
    Lock,
    Submount,
}

impl HolderKind {
    pub fn tag(self) -> &'static str {
        match self {
            HolderKind::Fd => "fd",
            HolderKind::Cwd => "cwd",
            HolderKind::Root => "root",
            HolderKind::Exe => "exe",
            HolderKind::Mmap => "mmap",
            HolderKind::Lock => "lock",
            HolderKind::Submount => "submount",
        }
    }

    /// How the reference is shown in the HOW column.
    pub fn describe(self, fd: Option<i32>) -> String {
        match (self, fd) {
            (HolderKind::Fd, Some(fd)) => format!("fd {fd}"),
            (kind, _) => kind.tag().to_string(),
        }
    }
}

/// One reference to the target resource.
#[derive(Debug, Clone)]
pub struct Holder {
    pub pid: u32,
    /// `/proc/<pid>/stat` field 22: distinguishes a reused pid.
    pub start_time: Option<u64>,
    pub comm: String,
    pub uid: u32,
    pub how: HolderKind,
    pub fd: Option<i32>,
    /// Path, socket endpoint or submount path.
    pub target: String,
    pub deleted: bool,
    /// Bytes reclaimable when the file is deleted and still open.
    pub size: Option<u64>,
    pub lock: Option<LockRecord>,
    pub sock: Option<SockInfo>,
    /// File identity of an fd holder, used to join `/proc/locks`.
    pub inode: Option<u64>,
    pub dev: Option<u64>,
    pub owner: Owner,
    /// The process lives in another mount namespace, so its paths are
    /// relative to that namespace.
    pub other_namespace: bool,
    /// Controlling terminal (`/dev/pts/3`), when the process has one.
    pub tty: Option<String>,
}

impl Holder {
    pub fn how_label(&self) -> String {
        match self.how {
            HolderKind::Fd => self.how.describe(self.fd),
            _ => self.how.tag().to_string(),
        }
    }

    /// Grouping key for hints: one hint per owner family, not per fd.
    pub fn owner_key(&self) -> String {
        match self.owner.kind {
            OwnerKind::Unknown => format!("pid {}", self.pid),
            _ => self.owner.label(),
        }
    }
}

/// Result of one `why` collection round.
#[derive(Debug, Default)]
pub struct HolderReport {
    pub holders: Vec<Holder>,
    /// Processes whose `/proc/<pid>` data could not be read (EACCES/EPERM).
    pub denied: u64,
    /// TIME_WAIT sockets on the port, when the target is a port.
    pub time_wait: u64,
}

impl HolderReport {
    /// Distinct pids holding the target. Submounts have no process.
    pub fn process_count(&self) -> usize {
        self.holders
            .iter()
            .filter(|h| h.how != HolderKind::Submount)
            .map(|h| h.pid)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Sum of reclaimable bytes from deleted-but-open files.
    pub fn deleted_bytes(&self) -> u64 {
        self.holders
            .iter()
            .filter(|h| h.deleted)
            .filter_map(|h| h.size)
            .sum()
    }

    pub fn deleted_count(&self) -> usize {
        self.holders.iter().filter(|h| h.deleted).count()
    }
}

/// Knobs for [`collect`].
#[derive(Debug, Clone)]
pub struct CollectOptions {
    /// Resolve `/proc/<pid>/cgroup` to a systemd unit or a container.
    pub owner: bool,
    /// Parse `maps` as well (mount/path/dir modes).
    pub mmap: bool,
    /// Skip username resolution; users are not shown by `why` anyway.
    pub numeric: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        CollectOptions {
            owner: true,
            mmap: true,
            numeric: true,
        }
    }
}

#[derive(Debug, Clone)]
struct ProcMeta {
    comm: String,
    uid: u32,
    start_time: Option<u64>,
    tty_nr: u64,
    owner: Owner,
    other_namespace: bool,
}

/// Collect every holder of `target`.
pub fn collect(target: &Target, opts: &CollectOptions) -> io::Result<HolderReport> {
    let pids = list_pids()?;

    // One metadata read per process: pid, comm, uid, start time, tty,
    // cgroup owner and mount namespace.
    let self_ns = fs::read_link("/proc/self/ns/mnt").ok();
    let mut metas: BTreeMap<u32, ProcMeta> = BTreeMap::new();
    for &pid in &pids {
        if let Some(meta) = read_meta(pid, self_ns.as_deref(), opts.owner) {
            metas.insert(pid, meta);
        }
    }

    let mut report = HolderReport::default();

    if target.kind == TargetKind::Port {
        collect_port(target, opts, &metas, &mut report)?;
        return Ok(report);
    }

    collect_paths(target, opts, &pids, &metas, &mut report)?;
    Ok(report)
}

fn collect_port(
    target: &Target,
    opts: &CollectOptions,
    metas: &BTreeMap<u32, ProcMeta>,
    report: &mut HolderReport,
) -> io::Result<()> {
    let scope = match target.proto {
        Some(SockProto::Tcp) => SockScope::inet_only(true, false),
        Some(SockProto::Udp) => SockScope::inet_only(false, true),
        _ => SockScope::inet_only(true, true),
    };
    let table = sockdiag::dump_scope(scope).unwrap_or_default();
    report.time_wait = target.port.map(|p| table.time_wait_for(p)).unwrap_or(0);

    let found = Mutex::new(Vec::new());
    let scan_opts = crate::types::ScanOptions::new().no_sockets().no_fdinfo();
    let pid_map: HashMap<u32, &ProcMeta> = metas.iter().map(|(p, m)| (*p, m)).collect();
    let sink = |info: &Arc<ProcessInfo>, entry: &FdEntry| {
        let Some(sock) = table.get(entry.inode.unwrap_or(u64::MAX)) else {
            return;
        };
        if !sock_matches(target, sock) {
            return;
        }
        found.lock().unwrap().push(holder_from_fd(
            info,
            entry,
            Some(sock.clone()),
            pid_map.get(&info.pid).copied(),
        ));
    };
    scan(&scan_opts, &sink)?;
    report.holders = found.into_inner().unwrap();
    // Owners are useful even when unresolved: the hint engine falls back to
    // `kill <pid>`, which is honest.
    let _ = opts;
    sort_holders(&mut report.holders);
    Ok(())
}

fn collect_paths(
    target: &Target,
    opts: &CollectOptions,
    pids: &[u32],
    metas: &BTreeMap<u32, ProcMeta>,
    report: &mut HolderReport,
) -> io::Result<()> {
    // Mount mode relies on fdinfo `mnt_id`, and avoids `stat` entirely so a
    // dead NFS/FUSE mount cannot block the scan. Other modes stat fds to
    // compare dev+ino.
    let mount_mode = target.kind == TargetKind::Mount;
    let mut scan_opts = crate::types::ScanOptions::new()
        .no_sockets()
        .parallel_min_pids(1);
    if !mount_mode {
        scan_opts = scan_opts.stat_all();
    }

    let found: Mutex<Vec<Holder>> = Mutex::new(Vec::new());
    let sink = |info: &Arc<ProcessInfo>, entry: &FdEntry| {
        let Some(meta) = metas.get(&info.pid) else {
            return;
        };
        if !fd_matches(target, entry) {
            return;
        }
        found
            .lock()
            .unwrap()
            .push(holder_from_fd(info, entry, entry.sock.clone(), Some(meta)));
    };
    scan(&scan_opts, &sink)?;
    let mut holders = found.into_inner().unwrap();

    // cwd/root/exe, maps and permission accounting share one /proc walk.
    for &pid in pids {
        let Some(meta) = metas.get(&pid) else {
            continue;
        };

        match fs::read_dir(PathBuf::from(format!("/proc/{pid}/fd"))) {
            Ok(_) => {}
            Err(e) if is_denied(&e) => {
                report.denied += 1;
                continue;
            }
            Err(_) => continue,
        }

        for (how, name) in [
            (HolderKind::Cwd, "cwd"),
            (HolderKind::Root, "root"),
            (HolderKind::Exe, "exe"),
        ] {
            let link = PathBuf::from(format!("/proc/{pid}/{name}"));
            match fs::read_link(&link) {
                Ok(path) => {
                    let target_str = path.to_string_lossy().into_owned();
                    if path_matches(target, &target_str) {
                        holders.push(Holder {
                            pid,
                            start_time: meta.start_time,
                            comm: meta.comm.clone(),
                            uid: meta.uid,
                            how,
                            fd: None,
                            target: target_str,
                            deleted: false,
                            size: None,
                            lock: None,
                            sock: None,
                            inode: None,
                            dev: None,
                            owner: meta.owner.clone(),
                            other_namespace: meta.other_namespace,
                            tty: None,
                        });
                    }
                }
                Err(e) if is_denied(&e) => report.denied += 1,
                Err(_) => {}
            }
        }

        if opts.mmap {
            for (path, deleted) in read_maps(pid) {
                if !path_matches(target, &path) {
                    continue;
                }
                holders.push(Holder {
                    pid,
                    start_time: meta.start_time,
                    comm: meta.comm.clone(),
                    uid: meta.uid,
                    how: HolderKind::Mmap,
                    fd: None,
                    target: path,
                    deleted,
                    size: None,
                    lock: None,
                    sock: None,
                    inode: None,
                    dev: None,
                    owner: meta.owner.clone(),
                    other_namespace: meta.other_namespace,
                    tty: None,
                });
            }
        }

        // The controlling terminal is only needed for the cwd hint.
        let tty = if holders
            .iter()
            .any(|h| h.pid == pid && h.how == HolderKind::Cwd)
        {
            read_tty(pid).or_else(|| tty_name(meta.tty_nr))
        } else {
            None
        };
        if let Some(tty) = tty {
            for holder in holders.iter_mut().filter(|h| h.pid == pid) {
                holder.tty = Some(tty.clone());
            }
        }
    }

    attach_locks(target, &mut holders);
    attach_submounts(target, &mut holders);

    // A mount is busy when something on a submount is held; report the
    // submount itself even when no process is visible.
    report.holders = holders;
    sort_holders(&mut report.holders);
    Ok(())
}

fn scan(opts: &crate::types::ScanOptions, sink: &FdSink<'_>) -> io::Result<()> {
    crate::default_backend().scan(opts, sink)
}

fn holder_from_fd(
    info: &ProcessInfo,
    entry: &FdEntry,
    sock: Option<SockInfo>,
    meta: Option<&ProcMeta>,
) -> Holder {
    let owner = meta.map(|m| m.owner.clone()).unwrap_or(Owner {
        kind: OwnerKind::Unknown,
        name: String::new(),
        container_id: None,
        cgroup: String::new(),
    });
    Holder {
        pid: info.pid,
        start_time: meta.and_then(|m| m.start_time),
        comm: info.comm.clone(),
        uid: info.uid,
        how: HolderKind::Fd,
        fd: Some(entry.fd),
        target: entry.target.clone(),
        deleted: entry.deleted,
        size: entry.size,
        lock: None,
        sock,
        inode: entry.inode,
        dev: entry.dev,
        owner,
        other_namespace: meta.map(|m| m.other_namespace).unwrap_or(false),
        tty: None,
    }
}

fn sock_matches(target: &Target, sock: &SockInfo) -> bool {
    if target.proto.is_some_and(|p| sock.proto != p) {
        return false;
    }
    if sock.proto == SockProto::Unix {
        return false;
    }
    let want = target.port.unwrap_or(0);
    match &sock.local {
        SockAddr::Inet { port, .. } => *port == want,
        SockAddr::Unix(_) => false,
    }
}

/// Does an fd entry hold the target?
pub fn fd_matches(target: &Target, entry: &FdEntry) -> bool {
    match target.kind {
        TargetKind::Port => entry.sock.as_ref().is_some_and(|s| sock_matches(target, s)),
        TargetKind::Mount => {
            if let Some(mnt_id) = entry.mnt_id {
                return target.mount_ids.contains(&mnt_id);
            }
            let root = target.path.as_ref().map(|p| p.to_string_lossy());
            root.is_some_and(|root| path_within(&entry.target, &root))
        }
        TargetKind::Dir => {
            let root = target.path.as_ref().map(|p| p.to_string_lossy());
            root.is_some_and(|root| path_within(&entry.target, &root))
        }
        TargetKind::File => {
            if !matches!(
                entry.kind,
                FdKind::File
                    | FdKind::Directory
                    | FdKind::CharDevice
                    | FdKind::BlockDevice
                    | FdKind::Unknown
            ) {
                return false;
            }
            match (target.dev, target.inode, entry.dev, entry.inode) {
                (Some(tdev), Some(tino), Some(edev), Some(eino)) => tdev == edev && tino == eino,
                (Some(tino), _, _, Some(eino)) => tino == eino,
                _ => target
                    .path
                    .as_ref()
                    .is_some_and(|path| path.to_string_lossy() == entry.target),
            }
        }
    }
}

fn path_matches(target: &Target, path: &str) -> bool {
    let Some(root) = target.root_path() else {
        return false;
    };
    let root = root.to_string_lossy();
    match target.kind {
        TargetKind::File => path == root,
        TargetKind::Dir | TargetKind::Mount => path_within(path, &root),
        TargetKind::Port => false,
    }
}

/// Parse `/proc/<pid>/maps`: unique paths, deleted files flagged.
pub fn read_maps(pid: u32) -> Vec<(String, bool)> {
    let Ok(content) = fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        // addr perms offset dev inode pathname
        let Some((_, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let _perms = fields.next();
        let _offset = fields.next();
        let _dev = fields.next();
        let _inode = fields.next();
        let Some(path) = fields.next() else {
            continue;
        };
        if !path.starts_with('/') {
            continue; // [heap], [stack], [vdso], ...
        }
        let (path, deleted) = match path.strip_suffix(" (deleted)") {
            Some(p) => (p, true),
            None => (path, false),
        };
        if seen.insert(path.to_string()) {
            out.push((path.to_string(), deleted));
        }
    }
    out
}

/// Attach `/proc/locks` records to the matching fd holders. `/proc/locks`
/// reports OFD locks with pid `-1`, so a separate fdinfo pass attributes
/// those to the fd that owns them.
fn attach_locks(target: &Target, holders: &mut [Holder]) {
    let proc_locks = locks::read_proc_locks();

    for record in &proc_locks {
        if target.kind != TargetKind::File {
            // Outside file mode the target inode is not known (mount mode
            // deliberately avoids `stat`); fdinfo attribution below still
            // finds OFD locks, and the fd row itself already identifies the
            // holder.
            continue;
        }
        let holder = holders
            .iter_mut()
            .filter(|h| h.how == HolderKind::Fd)
            .filter(|h| record.pid.is_none_or(|pid| pid == h.pid))
            .find(|h| locks::lock_matches(record, h.dev, h.inode));
        if let Some(holder) = holder {
            holder.lock = Some(record.clone());
        }
    }

    // fdinfo `lock:` lines are authoritative for OFD locks (pid -1).
    let fds: Vec<(u32, i32)> = holders
        .iter()
        .filter(|h| h.how == HolderKind::Fd)
        .filter_map(|h| h.fd.map(|fd| (h.pid, fd)))
        .collect();
    for (pid, fd) in fds {
        let Ok(content) = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
            continue;
        };
        let lock = content.lines().find_map(|line| {
            line.trim()
                .strip_prefix("lock:")
                .and_then(locks::parse_lock_line)
        });
        if let Some(lock) = lock
            && let Some(holder) = holders
                .iter_mut()
                .find(|h| h.pid == pid && h.fd == Some(fd) && h.lock.is_none())
        {
            holder.lock = Some(lock);
        }
    }
}

fn attach_submounts(target: &Target, holders: &mut Vec<Holder>) {
    if target.kind != TargetKind::Mount {
        return;
    }
    let Some(mount) = &target.mount else {
        return;
    };
    let Ok(entries) = crate::mounts::self_mountinfo() else {
        return;
    };
    for sub in crate::mounts::submounts(&entries, mount.mount_id) {
        // A submount only blocks `umount` when it is a separate mount;
        // listing it is honest even without a visible holder.
        if holders
            .iter()
            .any(|h| h.how == HolderKind::Submount && h.target == sub.mount_point)
        {
            continue;
        }
        holders.push(Holder {
            pid: 0,
            start_time: None,
            comm: String::new(),
            uid: 0,
            how: HolderKind::Submount,
            fd: None,
            target: sub.mount_point.clone(),
            deleted: false,
            size: None,
            lock: None,
            sock: None,
            inode: None,
            dev: None,
            owner: Owner {
                kind: OwnerKind::Unknown,
                name: String::new(),
                container_id: None,
                cgroup: format!("mount id {}", sub.mount_id),
            },
            other_namespace: false,
            tty: None,
        });
    }
}

fn sort_holders(holders: &mut [Holder]) {
    holders.sort_by(|a, b| {
        a.pid
            .cmp(&b.pid)
            .then_with(|| a.how.cmp(&b.how))
            .then_with(|| a.fd.cmp(&b.fd))
            .then_with(|| a.target.cmp(&b.target))
    });
}

fn is_denied(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

fn list_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

fn read_meta(pid: u32, self_ns: Option<&Path>, resolve_owner: bool) -> Option<ProcMeta> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()?
        .trim()
        .to_string();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|s| s.parse().ok())?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (tty_nr, start_time) = parse_stat_fields(&stat)?;

    let owner = if resolve_owner {
        fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map(|c| parse_cgroup(&c))
            .unwrap_or_else(|_| unknown_owner())
    } else {
        unknown_owner()
    };

    let other_namespace = match (self_ns, fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()) {
        (Some(mine), Some(theirs)) => mine != theirs,
        _ => false,
    };

    Some(ProcMeta {
        comm,
        uid,
        start_time,
        tty_nr,
        owner,
        other_namespace,
    })
}

fn unknown_owner() -> Owner {
    Owner {
        kind: OwnerKind::Unknown,
        name: String::new(),
        container_id: None,
        cgroup: String::new(),
    }
}

/// Parse the tty number and start time out of `/proc/<pid>/stat`. The comm
/// field is parenthesised and may itself contain spaces and parentheses, so
/// parsing starts after the last `)`.
pub fn parse_stat_fields(stat: &str) -> Option<(u64, Option<u64>)> {
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 1..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Field after ')' index 4 is tty_nr (overall field 7), index 19 is
    // starttime (overall field 22).
    let tty_nr = fields.get(4)?.parse().ok()?;
    let start_time = fields.get(19).and_then(|s| s.parse().ok());
    Some((tty_nr, start_time))
}

fn tty_name(tty_nr: u64) -> Option<String> {
    if tty_nr == 0 {
        return None;
    }
    // Linux dev_t for a tty: major in bits 8..; minor in the low byte and
    // high minor bits. Render pts/N for major 136-143, ttyN otherwise.
    let major = (tty_nr >> 8) & 0xfff;
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & !0xff);
    if (136..=143).contains(&major) {
        Some(format!("/dev/pts/{minor}"))
    } else {
        Some(format!("/dev/tty{minor}"))
    }
}

fn read_tty(pid: u32) -> Option<String> {
    let link = fs::read_link(format!("/proc/{pid}/fd/0")).ok()?;
    let path = link.to_string_lossy();
    path.starts_with("/dev/pts/").then(|| path.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields_survive_spaces_and_parens_in_comm() {
        let stat = "42 (a (weird) name) S 1 42 42 34816 42 0 0 0 0 0 0 0 0 0 20 0 1 0 1234567 0";
        let (tty, start) = parse_stat_fields(stat).unwrap();
        assert_eq!(tty, 34816);
        assert_eq!(start, Some(1234567));
    }

    #[test]
    fn malformed_stat_has_no_fields() {
        assert!(parse_stat_fields("42 (x) S").is_none());
        assert!(parse_stat_fields("no parens").is_none());
    }

    #[test]
    fn tty_names_are_rendered() {
        assert_eq!(tty_name(0), None);
        // pts/3: major 136, minor 3 => (136 << 8) | 3
        assert_eq!(tty_name((136 << 8) | 3).as_deref(), Some("/dev/pts/3"));
        assert_eq!(tty_name((4 << 8) | 1).as_deref(), Some("/dev/tty1"));
    }

    #[test]
    fn maps_of_our_own_process_are_visible() {
        let maps = read_maps(std::process::id());
        assert!(!maps.is_empty(), "our own maps must be readable");
        assert!(
            maps.iter().all(|(p, _)| !p.starts_with('[')),
            "pseudo regions are filtered"
        );
        let unique: HashSet<_> = maps.iter().map(|(p, _)| p).collect();
        assert_eq!(unique.len(), maps.len(), "paths are deduplicated");
    }

    #[test]
    fn maps_of_a_missing_pid_is_empty() {
        assert!(read_maps(999_999_999).is_empty());
    }

    #[test]
    fn holder_kind_tags_and_descriptions() {
        assert_eq!(HolderKind::Fd.tag(), "fd");
        assert_eq!(HolderKind::Cwd.describe(None), "cwd");
        assert_eq!(HolderKind::Fd.describe(Some(7)), "fd 7");
        assert_eq!(HolderKind::Mmap.tag(), "mmap");
        assert_eq!(HolderKind::Lock.tag(), "lock");
        assert_eq!(HolderKind::Submount.tag(), "submount");
        assert_eq!(HolderKind::Exe.tag(), "exe");
        assert_eq!(HolderKind::Root.tag(), "root");
    }

    #[test]
    fn report_totals() {
        let mut report = HolderReport::default();
        let holder = |pid, deleted, size| Holder {
            pid,
            start_time: None,
            comm: "x".to_string(),
            uid: 0,
            how: HolderKind::Fd,
            fd: Some(3),
            target: "/x".to_string(),
            deleted,
            size,
            lock: None,
            sock: None,
            inode: None,
            dev: None,
            owner: unknown_owner(),
            other_namespace: false,
            tty: None,
        };
        report.holders.push(holder(1, true, Some(100)));
        report.holders.push(holder(2, true, Some(50)));
        report.holders.push(holder(2, false, None));
        assert_eq!(report.process_count(), 2);
        assert_eq!(report.deleted_bytes(), 150);
        assert_eq!(report.deleted_count(), 2);
        assert_eq!(report.holders[0].owner_key(), "pid 1");
        assert_eq!(report.holders[0].how_label(), "fd 3");
    }

    #[test]
    fn fd_matching_for_files_and_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x");
        fs::write(&file, b"data").unwrap();
        let target = Target::detect_path(&file.to_string_lossy(), false).unwrap();
        let meta = fs::metadata(&file).unwrap();
        use std::os::unix::fs::MetadataExt;
        let entry = FdEntry {
            fd: 3,
            kind: FdKind::File,
            target: file.to_string_lossy().into_owned(),
            anon_subtype: None,
            deleted: false,
            size: Some(4),
            pos: None,
            flags: None,
            inode: Some(meta.ino()),
            mode: None,
            dev: Some(meta.dev()),
            mnt_id: None,
            sock: None,
        };
        assert!(fd_matches(&target, &entry));
        let mut other = entry.clone();
        other.inode = Some(meta.ino() + 1);
        assert!(!fd_matches(&target, &other));

        let dir_target = Target::detect_path(&dir.path().to_string_lossy(), false).unwrap();
        if dir_target.kind == TargetKind::Dir {
            assert!(fd_matches(&dir_target, &entry));
        }
    }

    #[test]
    fn port_target_matching() {
        let target = Target::for_port(8080, Some(SockProto::Tcp));
        let sock = SockInfo {
            proto: SockProto::Tcp,
            family: crate::types::AddrFamily::V4,
            local: SockAddr::Inet {
                addr: "0.0.0.0".parse().unwrap(),
                port: 8080,
            },
            remote: None,
            state: Some("LISTEN"),
        };
        assert!(sock_matches(&target, &sock));
        let mut udp = sock.clone();
        udp.proto = SockProto::Udp;
        assert!(!sock_matches(&target, &udp));
        let mut other_port = sock.clone();
        other_port.local = SockAddr::Inet {
            addr: "0.0.0.0".parse().unwrap(),
            port: 9090,
        };
        assert!(!sock_matches(&target, &other_port));
    }

    #[test]
    fn live_collect_on_our_own_cwd_finds_this_test_process() {
        let cwd = std::env::current_dir().unwrap();
        // The test process must hold its own cwd, whatever it is.
        let target = Target::detect_path(&cwd.to_string_lossy(), false).unwrap();
        let report = collect(
            &target,
            &CollectOptions {
                owner: false,
                mmap: false,
                numeric: true,
            },
        )
        .expect("collection must work");
        assert!(
            report.holders.iter().any(|h| h.pid == std::process::id()),
            "our cwd must be listed: {:?}",
            report.holders
        );
        assert!(
            report
                .holders
                .iter()
                .any(|h| h.pid == std::process::id() && h.how == HolderKind::Cwd),
            "the cwd holder must be tagged"
        );
    }

    #[test]
    fn collect_on_a_missing_proc_is_not_an_error_path() {
        // `collect` only fails when /proc itself is missing; a target with
        // no holders must return an empty report, not an error.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("never-open");
        fs::write(&file, b"x").unwrap();
        let target = Target::detect_path(&file.to_string_lossy(), false).unwrap();
        let report = collect(
            &target,
            &CollectOptions {
                owner: false,
                mmap: false,
                numeric: true,
            },
        )
        .unwrap();
        assert!(
            !report
                .holders
                .iter()
                .any(|h| h.target == file.to_string_lossy()),
            "nobody holds a fresh temp file"
        );
    }
}
