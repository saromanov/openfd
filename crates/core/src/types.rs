//! Core types shared by every backend.

use std::net::IpAddr;
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
    /// Socket details, resolved by the netlink SOCK_DIAG backend when the
    /// entry is a socket and the table was dumped successfully.
    pub sock: Option<SockInfo>,
}

/// Which socket tables the netlink SOCK_DIAG dump should fetch. Derived
/// from the `-i` filter: `-i tcp` does not need UDP or unix tables, so the
/// scan skips those dumps entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockScope {
    /// Dump inet sockets at all.
    pub inet: bool,
    /// Include TCP (implies `inet`).
    pub tcp: bool,
    /// Include UDP (implies `inet`).
    pub udp: bool,
    /// Include unix sockets.
    pub unix: bool,
}

impl SockScope {
    pub fn all() -> Self {
        SockScope {
            inet: true,
            tcp: true,
            udp: true,
            unix: true,
        }
    }

    pub fn none() -> Self {
        SockScope {
            inet: false,
            tcp: false,
            udp: false,
            unix: false,
        }
    }

    /// Inet sockets only, restricted to these protocols (tcp/udp flags).
    pub fn inet_only(tcp: bool, udp: bool) -> Self {
        SockScope {
            inet: tcp || udp,
            tcp,
            udp,
            unix: false,
        }
    }

    /// Unix sockets only.
    pub fn unix_only() -> Self {
        SockScope {
            inet: false,
            tcp: false,
            udp: false,
            unix: true,
        }
    }
}

/// Fd-level filter: true keeps the entry. Runs before the fdinfo read.
pub type FdFilterFn = dyn Fn(&FdEntry) -> bool + Send + Sync;

/// Callback receiving a resolved process and one of its fds.
///
/// Concurrency: the scanner may call the sink from several worker threads
/// (parallel scans), so implementors must be thread-safe — keep shared state
/// behind a `Mutex`/atomics. Rows of one process stay ordered; rows of
/// different processes may interleave.
pub type FdSink<'a> = dyn Fn(&Arc<ProcessInfo>, &FdEntry) + Send + Sync + 'a;

/// Process-level prefilter. The scanner consults it before spending any
/// per-fd work on a process: [`ProcessFilter::accepts_pid`] runs before
/// `/proc/<pid>` is even read, [`ProcessFilter::accepts`] right after
/// reading comm/cmdline/status. A rejected process contributes nothing.
pub trait ProcessFilter: Send + Sync {
    /// Cheap pid-level check, called before any read of `/proc/<pid>`.
    /// Rejection here is the cheapest possible skip.
    fn accepts_pid(&self, _pid: u32) -> bool {
        true
    }

    /// Full check once the process metadata is known.
    fn accepts(&self, info: &ProcessInfo) -> bool;
}

impl<F> ProcessFilter for F
where
    F: Fn(&ProcessInfo) -> bool + Send + Sync,
{
    fn accepts(&self, info: &ProcessInfo) -> bool {
        self(info)
    }
}

/// Options that control a scan. Filters can stay out of the core (the
/// scanner streams everything and the CLI applies them), but optional hooks
/// let the caller push filters *into* the scan so that non-matching
/// processes and fds cost nothing (see [`ProcessFilter`] and
/// [`ScanOptions::fd_filter`]).
#[derive(Clone)]
pub struct ScanOptions {
    /// Do not resolve uid to username (skips `/etc/passwd` reading).
    pub numeric: bool,
    /// Stat the target of every entry for size/inode/mode.
    /// When false, only deleted entries are stat-ed (needed for `--deleted`).
    pub stat_all: bool,
    /// Join socket details (TCP/UDP/unix addresses, states) from netlink
    /// SOCK_DIAG. Costs one bulk netlink dump per scan.
    pub resolve_sockets: bool,
    /// Read `/proc/<pid>/fdinfo/<fd>` for pos/flags/inode. Costs one extra
    /// file read per fd — skip it when the consumer does not need these
    /// fields (human table/terse/watch/top modes). Default: true.
    pub read_fdinfo: bool,
    /// Which netlink SOCK_DIAG tables to dump (default: all). Ignored when
    /// `resolve_sockets` is false.
    pub sock_scope: SockScope,
    /// Minimum process count before the scan switches to worker threads.
    /// Below it, thread startup and channel overhead would cost more than
    /// the scan saves. Default: 32.
    pub(crate) parallel_min_pids: usize,
    /// Reject whole processes before any fd work. None = keep everything.
    pub process_filter: Option<Arc<dyn ProcessFilter>>,
    /// Reject single fds after readlink+classify+socket-join but before the
    /// `/proc/<pid>/fdinfo/<fd>` read. The entry carries fd, kind, target,
    /// deleted and sock; size/pos/flags/mode are not yet populated. None =
    /// keep everything.
    pub fd_filter: Option<Arc<FdFilterFn>>,
}

impl std::fmt::Debug for ScanOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanOptions")
            .field("numeric", &self.numeric)
            .field("stat_all", &self.stat_all)
            .field("resolve_sockets", &self.resolve_sockets)
            .field("read_fdinfo", &self.read_fdinfo)
            .field("sock_scope", &self.sock_scope)
            .field("parallel_min_pids", &self.parallel_min_pids)
            .field("process_filter", &self.process_filter.is_some())
            .field("fd_filter", &self.fd_filter.is_some())
            .finish()
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            numeric: false,
            stat_all: false,
            resolve_sockets: true,
            read_fdinfo: true,
            sock_scope: SockScope::all(),
            parallel_min_pids: 32,
            process_filter: None,
            fd_filter: None,
        }
    }
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

    pub fn no_sockets(mut self) -> Self {
        self.resolve_sockets = false;
        self
    }

    /// Skip `/proc/<pid>/fdinfo` reads: pos/flags/fdinfo-inode become None.
    /// For output modes that never show them (table, terse, summary, tree,
    /// watch, top, wait) this cuts one file read per fd, roughly halving
    /// the scan's CPU cost.
    pub fn no_fdinfo(mut self) -> Self {
        self.read_fdinfo = false;
        self
    }

    /// Restrict the netlink SOCK_DIAG dump to these socket tables.
    pub fn sock_scope(mut self, scope: SockScope) -> Self {
        self.sock_scope = scope;
        self
    }

    /// Lower the process count needed to switch the scan to worker threads
    /// (testing and tuning; the built-in floor of 32 always applies).
    pub fn parallel_min_pids(mut self, n: usize) -> Self {
        self.parallel_min_pids = n;
        self
    }

    /// Reject whole processes before any fd work on them.
    pub fn process_filter(mut self, f: Arc<dyn ProcessFilter>) -> Self {
        self.process_filter = Some(f);
        self
    }

    /// Reject single fds before the fdinfo read (see the field docs for
    /// what the entry contains at that point).
    pub fn fd_filter(mut self, f: Arc<dyn Fn(&FdEntry) -> bool + Send + Sync>) -> Self {
        self.fd_filter = Some(f);
        self
    }
}

/// Address family of a socket endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrFamily {
    V4,
    V6,
    Unix,
}

/// Socket endpoint address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockAddr {
    Inet { addr: IpAddr, port: u16 },
    Unix(String),
}

impl std::fmt::Display for SockAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SockAddr::Inet { addr, port } => write!(f, "{addr}:{port}"),
            SockAddr::Unix(path) => write!(f, "{path}"),
        }
    }
}

/// Transport protocol of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockProto {
    Tcp,
    Udp,
    Unix,
}

impl SockProto {
    pub fn tag(self) -> &'static str {
        match self {
            SockProto::Tcp => "TCP",
            SockProto::Udp => "UDP",
            SockProto::Unix => "UNIX",
        }
    }
}

/// Details of one socket, joined from netlink SOCK_DIAG by inode.
#[derive(Debug, Clone)]
pub struct SockInfo {
    pub proto: SockProto,
    pub family: AddrFamily,
    pub local: SockAddr,
    /// None for unconnected sockets and listening sockets.
    pub remote: Option<SockAddr>,
    /// TCP state name (LISTEN, ESTABLISHED, ...). For UDP this is
    /// "UNCONN" or "ESTABLISHED" by convention.
    pub state: Option<&'static str>,
}

/// Platform backend trait. Linux ships a `/proc` implementation; the trait
/// exists from day one so that a macOS (libproc) backend can be added without
/// touching the CLI.
pub trait Backend {
    fn name(&self) -> &'static str;

    /// Stream every open fd of every visible process into `sink`.
    ///
    /// Individual unreadable processes/fds are skipped: `/proc` changes under
    /// us by design. Only a broken `/proc` mount is an error. The sink must
    /// be thread-safe: parallel scans call it from several workers.
    fn scan(&self, opts: &ScanOptions, sink: &FdSink<'_>) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: Some(1),
            comm: "x".to_string(),
            cmdline0: None,
            uid: 1000,
            username: None,
        }
    }

    #[test]
    fn fd_kind_tags_are_stable() {
        let expected = [
            (FdKind::File, "file"),
            (FdKind::Directory, "dir"),
            (FdKind::Socket, "socket"),
            (FdKind::Pipe, "pipe"),
            (FdKind::CharDevice, "chr"),
            (FdKind::BlockDevice, "blk"),
            (FdKind::Memfd, "memfd"),
            (FdKind::AnonInode, "anon_inode"),
            (FdKind::Unknown, "unknown"),
        ];
        for (kind, tag) in expected {
            assert_eq!(kind.tag(), tag, "tag of {kind:?}");
        }
    }

    #[test]
    fn sock_scope_constructors() {
        assert_eq!(
            SockScope::all(),
            SockScope {
                inet: true,
                tcp: true,
                udp: true,
                unix: true
            }
        );
        assert_eq!(
            SockScope::none(),
            SockScope {
                inet: false,
                tcp: false,
                udp: false,
                unix: false
            }
        );
        assert_eq!(
            SockScope::inet_only(true, false),
            SockScope {
                inet: true,
                tcp: true,
                udp: false,
                unix: false
            }
        );
        assert_eq!(
            SockScope::unix_only(),
            SockScope {
                inet: false,
                tcp: false,
                udp: false,
                unix: true
            }
        );
        assert!(
            !SockScope::inet_only(false, false).inet,
            "no protocol selected means no inet dump"
        );
    }

    #[test]
    fn scan_options_defaults() {
        let opts = ScanOptions::new();
        assert!(!opts.numeric);
        assert!(!opts.stat_all);
        assert!(opts.resolve_sockets);
        assert!(opts.read_fdinfo);
        assert_eq!(opts.sock_scope, SockScope::all());
        assert_eq!(opts.parallel_min_pids, 32);
        assert!(opts.process_filter.is_none());
        assert!(opts.fd_filter.is_none());
        assert_eq!(
            opts.parallel_min_pids,
            ScanOptions::default().parallel_min_pids
        );
    }

    #[test]
    fn scan_options_builders_flip_their_flag() {
        let opts = ScanOptions::new()
            .numeric()
            .stat_all()
            .no_sockets()
            .no_fdinfo()
            .sock_scope(SockScope::unix_only())
            .parallel_min_pids(1);
        assert!(opts.numeric);
        assert!(opts.stat_all);
        assert!(!opts.resolve_sockets);
        assert!(!opts.read_fdinfo);
        assert_eq!(opts.sock_scope, SockScope::unix_only());
        assert_eq!(opts.parallel_min_pids, 1);
    }

    #[test]
    fn scan_options_hooks_and_debug() {
        let opts = ScanOptions::new().process_filter(Arc::new(|i: &ProcessInfo| i.pid == 1));
        let opts = opts.fd_filter(Arc::new(|e: &FdEntry| e.fd > 2));
        let debug = format!("{opts:?}");
        assert!(debug.contains("process_filter: true"), "{debug}");
        assert!(debug.contains("fd_filter: true"), "{debug}");
        assert!(debug.contains("resolve_sockets: true"), "{debug}");
        assert!(opts.process_filter.as_ref().unwrap().accepts(&info(1)));
        assert!(!opts.process_filter.as_ref().unwrap().accepts(&info(2)));
        let entry = FdEntry {
            fd: 3,
            kind: FdKind::File,
            target: "/tmp".to_string(),
            anon_subtype: None,
            deleted: false,
            size: None,
            pos: None,
            flags: None,
            inode: None,
            mode: None,
            sock: None,
        };
        assert!((opts.fd_filter.as_ref().unwrap())(&entry));
    }

    #[test]
    fn default_process_filter_accepts_every_pid() {
        struct All;
        impl ProcessFilter for All {
            fn accepts(&self, _info: &ProcessInfo) -> bool {
                true
            }
        }
        let f = All;
        assert!(f.accepts_pid(1));
        assert!(f.accepts_pid(999_999));
        assert!(f.accepts(&info(5)));
    }

    #[test]
    fn sock_addr_display() {
        let inet = SockAddr::Inet {
            addr: "10.0.0.1".parse().unwrap(),
            port: 8080,
        };
        assert_eq!(inet.to_string(), "10.0.0.1:8080");
        let v6 = SockAddr::Inet {
            addr: "::1".parse().unwrap(),
            port: 443,
        };
        assert_eq!(v6.to_string(), "::1:443");
        assert_eq!(
            SockAddr::Unix("/run/x.sock".to_string()).to_string(),
            "/run/x.sock"
        );
    }

    #[test]
    fn sock_proto_tags() {
        assert_eq!(SockProto::Tcp.tag(), "TCP");
        assert_eq!(SockProto::Udp.tag(), "UDP");
        assert_eq!(SockProto::Unix.tag(), "UNIX");
    }
}
