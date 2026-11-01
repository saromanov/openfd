//! Core types shared by every backend.

use std::sync::Arc;

/// Classification of a file descriptor, derived from the `/proc/<pid>/fd/<n>`
/// symlink target and a `stat` of the underlying file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FdKind {
    /// Regular file on a filesystem.
    File,
    /// Directory (mostly `cwd`-like references kept open).
    Directory,
    /// Socket. The `inode` field of [`FdEntry`] carries the socket inode;
    /// inet/unix details are resolved by the netlink backend in later versions.
    Socket,
    /// Pipe (anonymous `pipe:[N]` or a FIFO on disk).
    Pipe,
    /// Character device (`/dev/*`, `/dev/null`, TTYs, ...).
    CharDevice,
    /// Block device.
    BlockDevice,
    /// `memfd:` region.
    Memfd,
    /// Anonymous inode with a kernel-side subtype (`eventfd`, `epoll`, ...).
    AnonInode,
    /// Anything the classifier could not pin down.
    Unknown,
}

impl FdKind {
    /// Short human-readable tag, stable for scripts and the JSON output.
    pub fn tag(self) -> &'static str {
        match self {
            FdKind::File => "file",
            FdKind::Directory => "dir",
            FdKind::Socket => "socket",
            FdKind::Pipe => "pipe",
            FdKind::CharDevice => "chr",
            FdKind::BlockDevice => "blk",
            FdKind::Memfd => "memfd",
            FdKind::AnonInode => "anon_inode",
            FdKind::Unknown => "unknown",
        }
    }
}

/// Everything the scanner knows about one process. Shared by reference so
/// that a flat entry stream does not copy process metadata per fd.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Parent pid, when `/proc/<pid>/status` exposes it.
    pub ppid: Option<u32>,
    /// `/proc/<pid>/comm` (truncated to 15 chars by the kernel).
    pub comm: String,
    /// First element of `/proc/<pid>/cmdline`, when present (None for kernel threads).
    pub cmdline0: Option<String>,
    /// Real uid of the process.
    pub uid: u32,
    /// Username resolved from `/etc/passwd`, or `None` when unknown
    /// (and always `None` in numeric mode).
    pub username: Option<String>,
}

/// One open file descriptor of one process.
#[derive(Debug, Clone)]
pub struct FdEntry {
    pub fd: i32,
    pub kind: FdKind,
    /// `readlink` target with the ` (deleted)` suffix stripped
    /// (when [`FdEntry::deleted`] is set) and `socket:[N]` / `pipe:[N]`
    /// wrappers kept intact for socket/pipe entries.
    pub target: String,
    /// Kernel-side subtype for `anon_inode` entries (`eventfd`, `epoll`, ...).
    pub anon_subtype: Option<String>,
    /// File path ends with ` (deleted)`: the file is unlinked but still open.
    pub deleted: bool,
    /// File size in bytes. For deleted files this is reclaimable disk space.
    pub size: Option<u64>,
    /// File offset from `/proc/<pid>/fdinfo/<n>`.
    pub pos: Option<u64>,
    /// Open flags (octal as reported by the kernel) from fdinfo.
    pub flags: Option<u32>,
    /// Inode: socket/pipe inode parsed from the link target, otherwise
    /// the inode of the underlying file from `stat`.
    pub inode: Option<u64>,
    /// st_mode of the underlying file.
    pub mode: Option<u32>,
}

/// Options that control a scan. Filters stay out of the core: the scanner
/// streams everything and the CLI applies filters, so kernels like `--watch`
/// can diff without re-scanning policy.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Do not resolve uid to username (skips `/etc/passwd` reading).
    pub numeric: bool,
    /// Stat the target of every entry for size/inode/mode.
    /// When false, only deleted entries are stat-ed (needed for `--deleted`).
    pub stat_all: bool,
}

impl ScanOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn numeric(mut self) -> Self {
        self.numeric = true;
        self
    }

    pub fn stat_all(mut self) -> Self {
        self.stat_all = true;
        self
    }
}

/// Callback receiving a resolved process and one of its fds.
pub type FdSink<'a> = dyn FnMut(&Arc<ProcessInfo>, &mut FdEntry) + 'a;

/// Platform backend trait. Linux ships a `/proc` implementation; the trait
/// exists from day one so that a macOS (libproc) backend can be added without
/// touching the CLI.
pub trait Backend {
    fn name(&self) -> &'static str;

    /// Stream every open fd of every visible process into `sink`.
    ///
    /// Individual unreadable processes/fds are skipped: `/proc` changes under
    /// us by design. Only a broken `/proc` mount is an error.
    fn scan(&self, opts: &ScanOptions, sink: &mut FdSink<'_>) -> std::io::Result<()>;
}
