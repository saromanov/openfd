//! `/proc/self/mountinfo` parsing and mount matching.
//!
//! `why <mountpoint>` needs the mount id, not a `stat`: a `stat` on a dead
//! NFS or FUSE mount blocks in D state. Mount mode matches fds by the
//! `mnt_id` field of `/proc/<pid>/fdinfo/<fd>` and treats submounts as
//! holders, because `umount` fails while anything is mounted underneath.

use std::path::{Component, Path, PathBuf};

/// One line of `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Unique mount id of this mount (field 1).
    pub mount_id: u64,
    /// Mount id of the parent mount (field 2).
    pub parent_id: u64,
    /// `MAJ:MIN` of the mounted filesystem (field 3).
    pub maj_min: String,
    /// Mountpoint with octal escapes decoded (field 5).
    pub mount_point: String,
    /// Filesystem type (field after the `-` separator).
    pub fstype: String,
    /// Mount source, for example `/dev/sdb1` (field after the fstype).
    pub source: String,
}

/// Decode the octal escapes the kernel uses in mountinfo fields
/// (`\040` space, `\011` tab, `\012` newline, `\134` backslash).
pub fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &field[i + 1..i + 4];
            if let Ok(value) = u8::from_str_radix(octal, 8) {
                out.push(value);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a whole mountinfo file.
pub fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in content.lines() {
        if let Some(entry) = parse_mountinfo_line(line) {
            out.push(entry);
        }
    }
    out
}

fn parse_mountinfo_line(line: &str) -> Option<MountEntry> {
    // Fields: id parent maj:min root mountpoint options [optional...] - fstype source superopts
    let (before, after) = line.split_once(" - ")?;
    let mut left = before.split_whitespace();
    let mount_id = left.next()?.parse().ok()?;
    let parent_id = left.next()?.parse().ok()?;
    let maj_min = left.next()?.to_string();
    let _root = left.next()?;
    let mount_point = unescape_mountinfo(left.next()?);

    let mut right = after.split_whitespace();
    let fstype = right.next()?.to_string();
    let source = unescape_mountinfo(right.next()?);

    Some(MountEntry {
        mount_id,
        parent_id,
        maj_min,
        mount_point,
        fstype,
        source,
    })
}

/// Lexically normalize a path: collapse `//`, drop `.`, resolve `..`
/// without touching the filesystem.
fn normalize(path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir => out.push("/"),
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(_) => {}
        }
    }
    if out.as_os_str().is_empty() {
        out.push("/");
    }
    out
}

/// Is `path` inside (or equal to) `root`? Both arguments are normalized
/// lexically, so `/var//log` and `/var/log/` match.
pub fn path_within(path: &str, root: &str) -> bool {
    let path = normalize(path);
    let root = normalize(root);
    path == root || path.starts_with(&root)
}

/// Find the mount that owns a path: the longest mountpoint prefix, with
/// later entries winning on equal mountpoints (stacked mounts).
pub fn mount_for_path<'a>(entries: &'a [MountEntry], path: &str) -> Option<&'a MountEntry> {
    let path = normalize(path);
    entries
        .iter()
        .filter(|m| path_within(&path.to_string_lossy(), &m.mount_point))
        .max_by_key(|m| (normalize(&m.mount_point).as_os_str().len(), m.mount_id))
}

/// Is the path exactly a mountpoint root?
pub fn mount_at<'a>(entries: &'a [MountEntry], path: &str) -> Option<&'a MountEntry> {
    let path = normalize(path);
    entries
        .iter()
        .filter(|m| normalize(&m.mount_point) == path)
        .max_by_key(|m| m.mount_id)
}

/// All mounts nested under `mount_id`, transitively: these block `umount`.
pub fn submounts(entries: &[MountEntry], mount_id: u64) -> Vec<&MountEntry> {
    let mut out: Vec<&MountEntry> = Vec::new();
    let mut parents = vec![mount_id];
    loop {
        let mut added = false;
        for entry in entries {
            if parents.contains(&entry.parent_id)
                && !out.iter().any(|m| m.mount_id == entry.mount_id)
            {
                out.push(entry);
                parents.push(entry.mount_id);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    out
}

/// Filesystem types where a per-fd `stat` can block forever when the
/// server is gone. Mount mode avoids `stat` entirely; this list is used
/// to decide whether a `st_dev` match is trustworthy in the other modes.
const NETWORK_FS: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "afs",
    "9p",
    "fuse.sshfs",
    "fuse.glusterfs",
    "fuse.ceph",
    "ceph",
    "glusterfs",
    "lustre",
    "davfs",
];

pub fn is_network_fs(fstype: &str) -> bool {
    NETWORK_FS.contains(&fstype) || fstype.starts_with("fuse.sshfs")
}

/// Read and parse `/proc/self/mountinfo`.
pub fn self_mountinfo() -> std::io::Result<Vec<MountEntry>> {
    let content = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(parse_mountinfo(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
25 30 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
30 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
31 30 8:2 / /mnt/data rw,relatime shared:2 - ext4 /dev/sdb1 rw
32 31 0:42 / /mnt/data/nfs rw - nfs4 server:/export rw
33 30 0:50 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw
34 30 8:3 / /media/My\\040Disk rw - ext4 /dev/sdc1 rw
";

    #[test]
    fn parses_ids_types_and_sources() {
        let entries = parse_mountinfo(SAMPLE);
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0].mount_id, 25);
        assert_eq!(entries[0].parent_id, 30);
        assert_eq!(entries[0].fstype, "proc");
        assert_eq!(entries[2].fstype, "ext4");
        assert_eq!(entries[2].source, "/dev/sdb1");
    }

    #[test]
    fn decodes_octal_escapes() {
        assert_eq!(unescape_mountinfo("/media/My\\040Disk"), "/media/My Disk");
        assert_eq!(unescape_mountinfo("a\\011b"), "a\tb");
        assert_eq!(unescape_mountinfo("a\\012b"), "a\nb");
        assert_eq!(unescape_mountinfo("a\\134b"), "a\\b");
        // Truncated escape stays literal.
        assert_eq!(unescape_mountinfo("a\\04"), "a\\04");
        assert_eq!(unescape_mountinfo("plain"), "plain");
    }

    #[test]
    fn malformed_lines_are_skipped() {
        assert!(parse_mountinfo("garbage\n\n1 2 3:4 / / x\n").is_empty());
    }

    #[test]
    fn path_within_handles_trailing_slashes_and_dotdot() {
        assert!(path_within("/var/log/syslog", "/var/log"));
        assert!(path_within("/var/log", "/var/log/"));
        assert!(path_within("/var//log/x", "/var/log"));
        assert!(path_within("/var/log/../log/x", "/var/log"));
        assert!(!path_within("/var/logs", "/var/log"));
        assert!(!path_within("/var", "/var/log"));
    }

    #[test]
    fn finds_the_longest_mount_prefix() {
        let entries = parse_mountinfo(SAMPLE);
        let m = mount_for_path(&entries, "/mnt/data/logs/x.log").unwrap();
        assert_eq!(m.mount_id, 31);
        let m = mount_for_path(&entries, "/mnt/data/nfs/file").unwrap();
        assert_eq!(m.mount_id, 32, "submount must win");
        // Every path belongs to the root mount when nothing else matches.
        assert_eq!(mount_for_path(&entries, "/nowhere").unwrap().mount_id, 30);
    }

    #[test]
    fn detects_an_exact_mountpoint() {
        let entries = parse_mountinfo(SAMPLE);
        assert_eq!(mount_at(&entries, "/mnt/data").unwrap().mount_id, 31);
        assert_eq!(mount_at(&entries, "/mnt/data/").unwrap().mount_id, 31);
        assert!(mount_at(&entries, "/mnt").is_none());
    }

    #[test]
    fn submounts_are_transitive() {
        let entries = parse_mountinfo(SAMPLE);
        let subs = submounts(&entries, 30);
        let ids: Vec<u64> = subs.iter().map(|m| m.mount_id).collect();
        assert!(ids.contains(&31));
        assert!(ids.contains(&32), "nested mount must be listed");
        assert!(!ids.contains(&30), "the mount itself is not a submount");
        assert!(submounts(&entries, 32).is_empty());
    }

    #[test]
    fn network_filesystems_are_recognised() {
        assert!(is_network_fs("nfs4"));
        assert!(is_network_fs("fuse.sshfs"));
        assert!(!is_network_fs("ext4"));
        assert!(!is_network_fs("overlay"));
    }

    #[test]
    fn live_mountinfo_contains_the_root() {
        let entries = self_mountinfo().expect("/proc/self/mountinfo must be readable");
        assert!(mount_at(&entries, "/").is_some(), "{entries:?}");
    }
}
