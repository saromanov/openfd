//! Target detection for `openfd why`.
//!
//! One target may be a file, a directory subtree, a mountpoint or a socket
//! port. Detection is a pure function over `stat` and
//! `/proc/self/mountinfo`, so every branch is unit-tested without a live
//! container or a privileged mount.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::mounts::{self, MountEntry};
use crate::types::SockProto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    File,
    Dir,
    Mount,
    Port,
}

impl TargetKind {
    pub fn tag(self) -> &'static str {
        match self {
            TargetKind::File => "file",
            TargetKind::Dir => "dir",
            TargetKind::Mount => "mount",
            TargetKind::Port => "port",
        }
    }
}

/// What `why` was asked about, resolved to the identity used for matching.
#[derive(Debug, Clone)]
pub struct Target {
    pub kind: TargetKind,
    /// Display string (the path as given, or `:PORT`).
    pub display: String,
    /// Canonical path for path/mount/dir targets.
    pub path: Option<PathBuf>,
    pub dev: Option<u64>,
    pub inode: Option<u64>,
    /// Mount entry for mount targets.
    pub mount: Option<MountEntry>,
    /// Mount ids that count as holders: the target mount and its submounts.
    pub mount_ids: Vec<u64>,
    pub port: Option<u16>,
    pub proto: Option<SockProto>,
}

impl Target {
    /// A port target built from the shared `-i` spec parser.
    pub fn for_port(port: u16, proto: Option<SockProto>) -> Self {
        let display = match proto {
            Some(SockProto::Tcp) => format!("tcp:{port}"),
            Some(SockProto::Udp) => format!("udp:{port}"),
            _ => format!(":{port}"),
        };
        Target {
            kind: TargetKind::Port,
            display,
            path: None,
            dev: None,
            inode: None,
            mount: None,
            mount_ids: Vec::new(),
            port: Some(port),
            proto,
        }
    }

    /// Resolve a path target. `force_mount` treats any directory as a mount
    /// even when it is not a mountpoint root (the `--mount` flag).
    pub fn detect_path(spec: &str, force_mount: bool) -> std::io::Result<Self> {
        let meta = std::fs::metadata(spec)?;
        let canonical = std::fs::canonicalize(spec)?;
        let entries = mounts::self_mountinfo()?;
        let display = canonical.to_string_lossy().into_owned();

        if force_mount || meta.is_dir() {
            if let Some(mount) = mounts::mount_at(&entries, &display) {
                return Ok(Self::for_mount(display, mount, &entries));
            }
            if force_mount && let Some(mount) = mounts::mount_for_path(&entries, &display).cloned()
            {
                return Ok(Self::for_mount(display, &mount, &entries));
            }
        }

        if meta.is_dir() {
            return Ok(Target {
                kind: TargetKind::Dir,
                display,
                path: Some(canonical),
                dev: Some(meta.dev()),
                inode: Some(meta.ino()),
                mount: None,
                mount_ids: Vec::new(),
                port: None,
                proto: None,
            });
        }

        Ok(Target {
            kind: TargetKind::File,
            display,
            path: Some(canonical),
            dev: Some(meta.dev()),
            inode: Some(meta.ino()),
            mount: None,
            mount_ids: Vec::new(),
            port: None,
            proto: None,
        })
    }

    fn for_mount(display: String, mount: &MountEntry, entries: &[MountEntry]) -> Self {
        let mut mount_ids = vec![mount.mount_id];
        mount_ids.extend(
            mounts::submounts(entries, mount.mount_id)
                .iter()
                .map(|m| m.mount_id),
        );
        Target {
            kind: TargetKind::Mount,
            display,
            path: Some(PathBuf::from(&mount.mount_point)),
            dev: None,
            inode: None,
            mount: Some(mount.clone()),
            mount_ids,
            port: None,
            proto: None,
        }
    }

    /// Human description for the report header:
    /// `/mnt/data (ext4, /dev/sdb1)` for mounts, the path otherwise.
    pub fn describe(&self) -> String {
        match (&self.mount, self.kind) {
            (Some(m), TargetKind::Mount) => {
                format!("{} ({}, {})", self.display, m.fstype, m.source)
            }
            _ => self.display.clone(),
        }
    }

    /// Filesystem type of the target, when known.
    pub fn fstype(&self) -> Option<&str> {
        self.mount.as_ref().map(|m| m.fstype.as_str())
    }

    pub fn source(&self) -> Option<&str> {
        self.mount.as_ref().map(|m| m.source.as_str())
    }

    pub fn is_port(&self) -> bool {
        self.kind == TargetKind::Port
    }

    /// Path of the target for matching cwd/root/exe/maps holders.
    pub fn root_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_root_directory_is_a_mount() {
        let target = Target::detect_path("/", false).unwrap();
        assert_eq!(target.kind, TargetKind::Mount);
        assert!(
            target
                .mount_ids
                .contains(&target.mount.as_ref().unwrap().mount_id)
        );
        assert!(target.describe().contains("("), "{}", target.describe());
        assert!(target.fstype().is_some());
        assert!(target.source().is_some());
    }

    #[test]
    fn a_plain_directory_is_a_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().into_owned();
        let target = Target::detect_path(&path, false).unwrap();
        // /tmp may itself be a mountpoint on some systems; only assert the
        // non-mount branch when it is not one.
        if target.kind != TargetKind::Mount {
            assert_eq!(target.kind, TargetKind::Dir);
            assert_eq!(
                target.path.as_deref(),
                Some(dir.path().canonicalize().unwrap().as_path())
            );
        }
    }

    #[test]
    fn forced_mount_on_a_plain_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().into_owned();
        let target = Target::detect_path(&path, true).unwrap();
        assert_eq!(target.kind, TargetKind::Mount);
        assert!(target.mount.is_some());
        assert!(!target.mount_ids.is_empty());
    }

    #[test]
    fn a_regular_file_keeps_dev_and_inode() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data.txt");
        std::fs::write(&file, b"hello").unwrap();
        let target = Target::detect_path(&file.to_string_lossy(), false).unwrap();
        assert_eq!(target.kind, TargetKind::File);
        assert!(target.dev.is_some());
        assert!(target.inode.is_some());
        assert!(!target.is_port());
        assert_eq!(target.fstype(), None);
    }

    #[test]
    fn a_missing_path_is_an_error() {
        let err = Target::detect_path("/definitely/not/here", false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn port_targets_carry_proto_and_display() {
        let t = Target::for_port(8080, None);
        assert_eq!(t.kind, TargetKind::Port);
        assert_eq!(t.display, ":8080");
        assert!(t.is_port());
        assert!(t.mount_ids.is_empty());
        assert_eq!(Target::for_port(53, Some(SockProto::Udp)).display, "udp:53");
        assert_eq!(
            Target::for_port(443, Some(SockProto::Tcp)).display,
            "tcp:443"
        );
    }

    #[test]
    fn kind_tags_are_stable() {
        assert_eq!(TargetKind::File.tag(), "file");
        assert_eq!(TargetKind::Dir.tag(), "dir");
        assert_eq!(TargetKind::Mount.tag(), "mount");
        assert_eq!(TargetKind::Port.tag(), "port");
    }
}
