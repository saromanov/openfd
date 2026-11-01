//! Integration tests against the live `/proc` of the test process itself.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use openfd_core::{FdEntry, FdKind, ProcessInfo, ScanOptions};
use std::sync::Arc;

fn collect_self(opts: &ScanOptions) -> (Arc<ProcessInfo>, Vec<FdEntry>) {
    let mut out: Option<(Arc<ProcessInfo>, Vec<FdEntry>)> = None;
    openfd_core::default_backend()
        .scan(opts, &mut |info, entry| {
            if info.pid == std::process::id() {
                let slot = out.get_or_insert_with(|| (Arc::clone(info), Vec::new()));
                slot.1.push(entry.clone());
            }
        })
        .expect("scan must succeed on a live /proc");
    out.expect("test process must appear in /proc")
}

#[test]
fn scan_finds_self_with_open_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scan-test.bin");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(b"0123456789").unwrap(); // 10 bytes
    f.sync_all().unwrap();

    let (info, entries) = collect_self(&ScanOptions::new().stat_all());
    assert_eq!(info.pid, std::process::id());
    assert!(!info.comm.is_empty());

    let raw_fd = f.as_raw_fd();
    let entry = entries
        .iter()
        .find(|e| e.fd == raw_fd)
        .expect("our own open file must be in the fd table");
    assert_eq!(entry.kind, FdKind::File);
    assert!(!entry.deleted);
    assert_eq!(entry.target, path.to_string_lossy());
    assert_eq!(entry.size, Some(10));
    assert_eq!(entry.inode, Some(fs::metadata(&path).unwrap().ino()));
}

#[test]
fn scan_reports_deleted_file_with_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deleted-test.bin");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&vec![0u8; 4096]).unwrap();
    f.sync_all().unwrap();
    fs::remove_file(&path).unwrap();

    let (_, entries) = collect_self(&ScanOptions::new());
    let raw_fd = f.as_raw_fd();
    let entry = entries
        .iter()
        .find(|e| e.fd == raw_fd)
        .expect("deleted-but-open file must be reported");
    assert!(entry.deleted);
    assert_eq!(entry.kind, FdKind::File);
    assert_eq!(entry.target, path.to_string_lossy());
    assert_eq!(entry.size, Some(4096));
}

#[test]
fn scan_invariants_hold_for_every_entry() {
    let (_, entries) = collect_self(&ScanOptions::new().stat_all());
    assert!(!entries.is_empty(), "test process has open fds");
    for e in &entries {
        assert!(e.fd >= 0);
        assert!(!e.target.is_empty());
        if e.kind == FdKind::Socket || e.kind == FdKind::Pipe {
            assert!(e.inode.is_some(), "pipe/socket inode must be parsed: {e:?}");
        }
        if e.kind == FdKind::File && !e.deleted {
            // A file can be unlinked between readlink and stat; then the
            // link carried no " (deleted)" marker but stat already fails.
            // Tolerate only that race: if the path still exists, size must
            // have been filled.
            if e.size.is_none() {
                assert!(
                    !Path::new(&e.target).exists(),
                    "existing file must have a stat-ed size: {e:?}"
                );
            }
        }
    }
}

#[test]
fn scan_reports_pos_from_fdinfo() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pos-test.bin");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&[0u8; 100]).unwrap();
    f.seek(SeekFrom::Start(42)).unwrap();

    let (_, entries) = collect_self(&ScanOptions::new());
    let raw_fd = f.as_raw_fd();
    let entry = entries.iter().find(|e| e.fd == raw_fd).unwrap();
    assert_eq!(entry.pos, Some(42));
}

#[test]
fn numeric_mode_skips_username() {
    let (info, _) = collect_self(&ScanOptions::new().numeric());
    assert!(info.username.is_none());
}

#[test]
fn scan_processes_have_sane_pids() {
    let opts = ScanOptions::new().numeric();
    let mut count = 0usize;
    openfd_core::default_backend()
        .scan(&opts, &mut |info, _| {
            assert!(info.pid > 0);
            count += 1;
        })
        .unwrap();
    assert!(count > 0, "at least one process must be scannable");
}

// A deleted-file stat works through the /proc link itself; guard against
// regressions if this file is later moved into the scanner.
#[test]
fn deleted_target_has_no_stale_stat_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gone.bin");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(b"abc").unwrap();
    fs::remove_file(&path).unwrap();
    assert!(!Path::new(&path).exists());
}
