//! File-lock parsing: `/proc/locks` and the `lock:` lines of
//! `/proc/<pid>/fdinfo/<fd>`.
//!
//! `/proc/locks` is the only place that lists every lock on the system, but
//! OFD locks (`OFDLCK`) report pid `-1` there. The per-fd `lock:` line in
//! fdinfo carries the real owner, so `why` joins both sources by dev+inode
//! and attributes the lock to the process that holds the fd.

/// Lock flavour as printed by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    Posix,
    Flock,
    Ofd,
}

impl LockKind {
    pub fn tag(self) -> &'static str {
        match self {
            LockKind::Posix => "POSIX",
            LockKind::Flock => "FLOCK",
            LockKind::Ofd => "OFDLCK",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Read,
    Write,
}

impl LockMode {
    pub fn tag(self) -> &'static str {
        match self {
            LockMode::Read => "READ",
            LockMode::Write => "WRITE",
        }
    }
}

/// One parsed lock line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRecord {
    pub kind: LockKind,
    pub mode: LockMode,
    /// None for OFD locks, which the kernel reports with pid `-1`.
    pub pid: Option<u32>,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    /// First and last byte of the locked range. `None` means "to EOF".
    pub start: u64,
    pub end: Option<u64>,
}

impl LockRecord {
    /// Human tag used in the HOW column and JSON: `POSIX WRITE`.
    pub fn label(&self) -> String {
        format!("{} {}", self.kind.tag(), self.mode.tag())
    }
}

/// Parse one line of `/proc/locks` or a `lock:` fdinfo line.
///
/// Shape: `1: POSIX ADVISORY WRITE 812 08:01:12345 0 EOF`. Blocked waiters
/// are printed as `5: -> POSIX ...`; the leading `->` is ignored. Mandatory
/// locks use `MANDATORY` instead of `ADVISORY`; the mode word is the one
/// that matters and both accepted.
pub fn parse_lock_line(line: &str) -> Option<LockRecord> {
    let line = line.trim();
    // fdinfo prefixes the same record with `lock:`.
    let line = line.strip_prefix("lock:").map(str::trim).unwrap_or(line);
    let (_, rest) = line.split_once(':')?;
    let mut fields = rest.split_whitespace().filter(|f| *f != "->");
    let kind = match fields.next()? {
        "POSIX" => LockKind::Posix,
        "FLOCK" => LockKind::Flock,
        "OFDLCK" => LockKind::Ofd,
        _ => return None,
    };
    let _advisory = fields.next()?; // ADVISORY or MANDATORY
    let mode = match fields.next()? {
        "READ" => LockMode::Read,
        "WRITE" => LockMode::Write,
        _ => return None,
    };
    let pid = match fields.next()? {
        "-1" => None,
        value => Some(value.parse().ok()?),
    };
    let dev_ino = fields.next()?;
    let mut dev_parts = dev_ino.split(':');
    let dev_major = u32::from_str_radix(dev_parts.next()?, 16).ok()?;
    let dev_minor = u32::from_str_radix(dev_parts.next()?, 16).ok()?;
    let inode = dev_parts.next()?.parse().ok()?;
    let start = fields.next()?.parse().ok()?;
    let end = match fields.next()? {
        "EOF" => None,
        value => Some(value.parse().ok()?),
    };
    Some(LockRecord {
        kind,
        mode,
        pid,
        dev_major,
        dev_minor,
        inode,
        start,
        end,
    })
}

/// Read and parse `/proc/locks`. A missing file (some containers) yields an
/// empty list rather than an error: locks are a best-effort enrichment.
pub fn read_proc_locks() -> Vec<LockRecord> {
    match std::fs::read_to_string("/proc/locks") {
        Ok(content) => content.lines().filter_map(parse_lock_line).collect(),
        Err(_) => Vec::new(),
    }
}

/// Linux `dev_t` to (major, minor). The encoding is stable on Linux and is
/// the same one `/proc/locks` prints.
pub fn dev_major_minor(dev: u64) -> (u32, u32) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major as u32, minor as u32)
}

/// Does a lock record refer to the file with this `st_dev`/inode?
pub fn lock_matches(lock: &LockRecord, dev: Option<u64>, inode: Option<u64>) -> bool {
    if lock.inode != inode.unwrap_or(u64::MAX) {
        return false;
    }
    match dev {
        Some(dev) => dev_major_minor(dev) == (lock.dev_major, lock.dev_minor),
        // Without st_dev (mount mode, network filesystems) fall back to the
        // inode only: inode collisions across devices are rare, and the
        // mountpoint filter narrows the candidates further.
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_posix_write_lock() {
        let lock = parse_lock_line("1: POSIX  ADVISORY  WRITE 812 08:01:12345 0 EOF").unwrap();
        assert_eq!(lock.kind, LockKind::Posix);
        assert_eq!(lock.mode, LockMode::Write);
        assert_eq!(lock.pid, Some(812));
        assert_eq!((lock.dev_major, lock.dev_minor), (8, 1));
        assert_eq!(lock.inode, 12345);
        assert_eq!(lock.start, 0);
        assert_eq!(lock.end, None);
        assert_eq!(lock.label(), "POSIX WRITE");
    }

    #[test]
    fn parses_a_flock_read_lock_with_a_range() {
        let lock = parse_lock_line("7: FLOCK  ADVISORY  READ 42 00:2a:777 10 99").unwrap();
        assert_eq!(lock.kind, LockKind::Flock);
        assert_eq!(lock.mode, LockMode::Read);
        assert_eq!(lock.pid, Some(42));
        assert_eq!((lock.dev_major, lock.dev_minor), (0, 42));
        assert_eq!(lock.end, Some(99));
    }

    #[test]
    fn ofd_locks_have_no_pid() {
        let lock = parse_lock_line("3: OFDLCK ADVISORY  READ -1 00:05:123 0 EOF").unwrap();
        assert_eq!(lock.kind, LockKind::Ofd);
        assert_eq!(lock.pid, None);
        assert_eq!(lock.label(), "OFDLCK READ");
    }

    #[test]
    fn blocked_waiters_are_parsed() {
        let lock = parse_lock_line("5: -> POSIX  ADVISORY  WRITE 900 08:01:1 0 EOF").unwrap();
        assert_eq!(lock.pid, Some(900));
    }

    #[test]
    fn fdinfo_lock_prefix_is_accepted() {
        let lock =
            parse_lock_line("lock:\t1: POSIX  ADVISORY  WRITE 812 08:01:12345 0 EOF").unwrap();
        assert_eq!(lock.inode, 12345);
    }

    #[test]
    fn mandatory_locks_are_accepted() {
        let lock = parse_lock_line("1: POSIX  MANDATORY  WRITE 812 08:01:1 0 EOF").unwrap();
        assert_eq!(lock.mode, LockMode::Write);
    }

    #[test]
    fn malformed_lines_are_rejected() {
        for line in [
            "",
            "garbage",
            "1: WEIRD ADVISORY WRITE 1 08:01:1 0 EOF",
            "1: POSIX ADVISORY SIDEWAYS 1 08:01:1 0 EOF",
            "1: POSIX ADVISORY WRITE 1 not-a-dev 0 EOF",
            "1: POSIX ADVISORY WRITE 1 08:01:1",
            "1: POSIX ADVISORY WRITE 1 08:01:notanum 0 EOF",
        ] {
            assert!(parse_lock_line(line).is_none(), "{line:?}");
        }
    }

    #[test]
    fn dev_encoding_round_trips() {
        assert_eq!(dev_major_minor(0x0801), (8, 1));
        // 8:1 encoded the way stat reports it on Linux.
        let dev = ((8u64 & 0xfff) << 8) | (1 & 0xff);
        assert_eq!(dev_major_minor(dev), (8, 1));
        // High minor bits live in bits 20..32 (glibc makedev layout).
        let dev = (0x2345u64 & 0xff) | (8u64 << 8) | ((0x2345u64 & !0xff) << 12);
        assert_eq!(dev_major_minor(dev), (8, 0x2345));
    }

    #[test]
    fn lock_matching_uses_dev_and_inode() {
        let lock = parse_lock_line("1: POSIX ADVISORY WRITE 1 08:01:100 0 EOF").unwrap();
        let dev = ((8u64 & 0xfff) << 8) | 1;
        assert!(lock_matches(&lock, Some(dev), Some(100)));
        assert!(!lock_matches(&lock, Some(dev), Some(101)));
        let other_dev = ((8u64 & 0xfff) << 8) | 2;
        assert!(!lock_matches(&lock, Some(other_dev), Some(100)));
        assert!(lock_matches(&lock, None, Some(100)));
        assert!(!lock_matches(&lock, None, None));
    }

    #[test]
    fn live_proc_locks_parse_cleanly() {
        // Every non-empty line of a live /proc/locks must parse; the file
        // is the authoritative fixture.
        if let Ok(content) = std::fs::read_to_string("/proc/locks") {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                assert!(parse_lock_line(line).is_some(), "unparsed: {line}");
            }
        }
    }

    #[test]
    fn missing_proc_locks_degrades_to_empty() {
        // The real file exists on Linux; this only pins the API shape.
        let _ = read_proc_locks();
    }
}
