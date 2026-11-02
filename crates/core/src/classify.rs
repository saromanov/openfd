//! Classification of `/proc/<pid>/fd/<n>` link targets.

use crate::types::FdKind;
use std::fs;
use std::os::unix::fs::MetadataExt;

pub(super) struct Classified {
    pub kind: FdKind,
    /// Target with the ` (deleted)` suffix removed.
    pub target: String,
    pub deleted: bool,
    /// `anon_inode` subtype (eventfd, epoll, inotify, ...).
    pub anon_subtype: Option<String>,
    /// Inode parsed from `socket:[N]` / `pipe:[N]`.
    pub inode: Option<u64>,
}

const DELETED_SUFFIX: &str = " (deleted)";
const SOCKET_PREFIX: &str = "socket:[";
const PIPE_PREFIX: &str = "pipe:[";

pub(super) fn classify(raw: &str, meta: Option<&fs::Metadata>) -> Classified {
    if let Some(path) = raw.strip_suffix(DELETED_SUFFIX) {
        // `memfd:name (deleted)` is a memfd, not an unlinked file on disk.
        if raw.starts_with("/memfd:") {
            return Classified {
                kind: FdKind::Memfd,
                target: raw.to_string(),
                deleted: false,
                anon_subtype: None,
                inode: None,
            };
        }
        // One stat serves kind and inode both.
        let (inode, kind) = match meta {
            Some(m) => (Some(m.ino()), kind_from_mode(m.mode())),
            None => (None, FdKind::Unknown),
        };
        return Classified {
            kind,
            target: path.to_string(),
            deleted: true,
            anon_subtype: None,
            inode,
        };
    }

    if let Some(rest) = raw
        .strip_prefix(SOCKET_PREFIX)
        .and_then(|r| r.strip_suffix(']'))
    {
        return Classified {
            kind: FdKind::Socket,
            target: raw.to_string(),
            deleted: false,
            anon_subtype: None,
            inode: rest.parse().ok(),
        };
    }

    if let Some(rest) = raw
        .strip_prefix(PIPE_PREFIX)
        .and_then(|r| r.strip_suffix(']'))
    {
        return Classified {
            kind: FdKind::Pipe,
            target: raw.to_string(),
            deleted: false,
            anon_subtype: None,
            inode: rest.parse().ok(),
        };
    }

    if let Some(sub) = raw.strip_prefix("anon_inode:").map(str::trim) {
        let subtype = sub
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(sub);
        return Classified {
            kind: FdKind::AnonInode,
            target: raw.to_string(),
            deleted: false,
            anon_subtype: Some(subtype.to_string()),
            inode: None,
        };
    }

    if raw.starts_with("/memfd:") {
        return Classified {
            kind: FdKind::Memfd,
            target: raw.to_string(),
            deleted: false,
            anon_subtype: None,
            inode: None,
        };
    }

    // Real path on disk: let stat decide the kind. The caller stats the
    // /proc fd link when it needs size anyway; stat by path is the fallback
    // for scans that skip stat (it still works for files only reachable
    // through the fd).
    let stat = match meta {
        Some(m) => Some((m.ino(), m.mode())),
        None => stat_file(raw).map(|m| (m.ino(), m.mode())),
    };
    match stat {
        Some((ino, mode)) => Classified {
            kind: kind_from_mode(mode),
            target: raw.to_string(),
            deleted: false,
            anon_subtype: None,
            inode: Some(ino),
        },
        None => Classified {
            kind: FdKind::Unknown,
            target: raw.to_string(),
            deleted: false,
            anon_subtype: None,
            inode: None,
        },
    }
}

/// Stat the underlying file of an entry. `path` must be the `/proc/<pid>/fd/<n>`
/// link itself; the kernel resolves it to the target (even for deleted files).
pub(super) fn stat_link(link: &std::path::Path) -> Option<fs::Metadata> {
    fs::metadata(link).ok()
}

fn stat_file(path: &str) -> Option<fs::Metadata> {
    fs::metadata(path).ok()
}

pub(crate) fn kind_from_mode(mode: u32) -> FdKind {
    match mode & S_IFMT {
        0o040000 => FdKind::Directory,
        0o100000 => FdKind::File,
        0o020000 => FdKind::CharDevice,
        0o060000 => FdKind::BlockDevice,
        0o010000 => FdKind::Pipe,
        0o140000 => FdKind::Socket,
        _ => FdKind::Unknown,
    }
}

// File type bitmask (S_IFMT). Kept as constants instead of a libc dependency:
// /proc scanning stays a pure-std affair.
const S_IFMT: u32 = 0o170000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_target_is_parsed() {
        let c = classify("socket:[12345]", None);
        assert_eq!(c.kind, FdKind::Socket);
        assert_eq!(c.inode, Some(12345));
        assert!(!c.deleted);
    }

    #[test]
    fn pipe_target_is_parsed() {
        let c = classify("pipe:[777]", None);
        assert_eq!(c.kind, FdKind::Pipe);
        assert_eq!(c.inode, Some(777));
    }

    #[test]
    fn anon_inode_bracketed() {
        let c = classify("anon_inode:[eventfd]", None);
        assert_eq!(c.kind, FdKind::AnonInode);
        assert_eq!(c.anon_subtype.as_deref(), Some("eventfd"));
    }

    #[test]
    fn anon_inode_unbracketed() {
        let c = classify("anon_inode:inotify", None);
        assert_eq!(c.kind, FdKind::AnonInode);
        assert_eq!(c.anon_subtype.as_deref(), Some("inotify"));
    }

    #[test]
    fn deleted_regular_file() {
        let c = classify("/tmp/foo.log (deleted)", None);
        assert!(c.deleted);
        assert_eq!(c.target, "/tmp/foo.log");
        // No metadata passed: the kind stays honest instead of guessing File.
        assert_eq!(c.kind, FdKind::Unknown);
    }

    #[test]
    fn deleted_memfd_is_not_deleted_file() {
        let c = classify("/memfd:secret (deleted)", None);
        assert!(!c.deleted);
        assert_eq!(c.kind, FdKind::Memfd);
        assert_eq!(c.target, "/memfd:secret (deleted)");
    }

    #[test]
    fn plain_memfd() {
        let c = classify("/memfd:juju", None);
        assert_eq!(c.kind, FdKind::Memfd);
    }

    #[test]
    fn kind_from_mode_table() {
        assert_eq!(kind_from_mode(0o040755), FdKind::Directory);
        assert_eq!(kind_from_mode(0o100644), FdKind::File);
        assert_eq!(kind_from_mode(0o020666), FdKind::CharDevice);
        assert_eq!(kind_from_mode(0o060600), FdKind::BlockDevice);
        assert_eq!(kind_from_mode(0o010600), FdKind::Pipe);
        assert_eq!(kind_from_mode(0o140777), FdKind::Socket);
    }
}
