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

/// All (pid, entry) pairs of the whole scan; used for cross-process
/// invariant checks that must tolerate /proc races.
fn collect_all(opts: &ScanOptions) -> Vec<(u32, FdEntry)> {
    let mut out = Vec::new();
    openfd_core::default_backend()
        .scan(opts, &mut |info, entry| out.push((info.pid, entry.clone())))
        .expect("scan must succeed on a live /proc");
    out
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
    let all = collect_all(&ScanOptions::new().stat_all());
    assert!(!all.is_empty(), "at least one process has open fds");
    for (pid, e) in &all {
        assert!(e.fd >= 0);
        assert!(!e.target.is_empty());
        if e.kind == FdKind::Socket || e.kind == FdKind::Pipe {
            assert!(e.inode.is_some(), "pipe/socket inode must be parsed: {e:?}");
        }
        if e.kind == FdKind::File && !e.deleted && e.size.is_none() {
            // size can be missing only when the owning process exited (or the
            // file was unlinked) between readlink and stat: the /proc fd link
            // is already gone. If both the process and the file are alive,
            // a missing size is a scanner bug. Virtual /proc and /sys targets
            // are exempt: they exist while the owner lives, so the liveness
            // re-check below proves nothing for them (an fd pointing at
            // another process' fdinfo can be closed right after stat).
            let virtual_target = e.target.starts_with("/proc/") || e.target.starts_with("/sys/");
            let proc_alive = Path::new(&format!("/proc/{pid}")).exists();
            let file_alive = Path::new(&e.target).exists();
            assert!(
                virtual_target || !(proc_alive && file_alive),
                "existing file of a live process must have a stat-ed size: {e:?}"
            );
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

#[test]
fn process_filter_skips_whole_processes() {
    // Reject our own pid at the process level: nothing of ours reaches the
    // sink, everything else still does (when visible).
    let me = std::process::id();
    let opts = ScanOptions::new()
        .stat_all()
        .process_filter(Arc::new(move |i: &ProcessInfo| i.pid != me));
    let all = collect_all(&opts);
    assert!(
        all.iter().all(|(pid, _)| *pid != me),
        "own pid must be pre-filtered"
    );
}

#[test]
fn process_filter_accepts_pid_gate() {
    // accepts_pid must run before any read: filtering to a foreign pid that
    // matches nothing is fine and cheap (no panic, no entries).
    let opts = ScanOptions::new().process_filter(Arc::new(|i: &ProcessInfo| i.pid == u32::MAX));
    let all = collect_all(&opts);
    assert!(all.is_empty(), "no process has pid u32::MAX");
}

#[test]
fn fd_filter_gates_fdinfo_and_entries() {
    let opts = ScanOptions::new().fd_filter(Arc::new(|e: &FdEntry| e.fd == 0));
    let (_, entries) = collect_self(&opts);
    assert!(!entries.is_empty(), "fd 0 always exists");
    assert!(entries.iter().all(|e| e.fd == 0));
}

#[test]
fn fd_filter_plus_process_filter_compose() {
    let me = std::process::id();
    let opts = ScanOptions::new()
        .process_filter(Arc::new(move |i: &ProcessInfo| i.pid == me))
        .fd_filter(Arc::new(|e: &FdEntry| e.fd <= 2));
    let (_, entries) = collect_self(&opts);
    assert!(entries.iter().all(|e| e.fd <= 2));
    assert!(entries.len() >= 3, "fds 0,1,2 exist for any process");
}

#[test]
fn parallel_scan_matches_sequential() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("parallel-test.bin");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(b"parallel").unwrap();
    f.sync_all().unwrap();
    let prefix = dir.path().to_string_lossy().into_owned();

    // parallel_min_pids(0) forces the parallel path even on a tiny /proc.
    // Sibling tests spawn and exit while this runs, so only entries under
    // our own tempdir are stable enough to compare.
    let mut stable = |opts: &ScanOptions| {
        let (_, entries) = collect_self(opts);
        let hit = entries.iter().any(|e| e.target == path.to_string_lossy());
        assert!(hit, "scan must find our own open file");
        let mut k: Vec<(i32, String)> = entries
            .iter()
            .filter(|e| e.target.starts_with(&prefix))
            .map(|e| (e.fd, e.target.clone()))
            .collect();
        k.sort();
        k
    };

    let par = stable(&ScanOptions::new().stat_all().parallel_min_pids(0));
    let par_again = stable(&ScanOptions::new().stat_all().parallel_min_pids(0));
    let seq = stable(&ScanOptions::new().stat_all());
    assert_eq!(par, par_again, "two parallel scans agree");
    assert_eq!(par, seq, "parallel == sequential");
}
