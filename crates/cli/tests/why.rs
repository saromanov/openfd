//! `openfd why`: end-to-end tests against helper child processes.
//!
//! Every child is real: the assertions are about what `/proc` says, not
//! about mocks. Children are killed when the guard drops.

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn openfd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openfd"))
        .args(args)
        .output()
        .expect("run openfd")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(script: &str) -> ChildGuard {
    let child = Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn helper");
    wait_for_line(child)
}

/// Wait until the shell has had time to execute the script (the marker is
/// printed by the scripts below, but a small settle is simpler and stable).
fn wait_for_line(child: Child) -> ChildGuard {
    let guard = ChildGuard(child);
    std::thread::sleep(Duration::from_millis(300));
    guard
}

fn eventually(mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn file_holder_is_reported_with_owner_and_hint() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("held.log");
    fs::write(&file, b"x").unwrap();
    let _child = spawn(&format!("exec 3<{}; sleep 30", file.to_string_lossy()));

    let out = openfd(&["why", &file.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("is busy"), "{text}");
    assert!(text.contains("fd 3"), "{text}");
    assert!(text.contains("fix:"), "{text}");
}

#[test]
fn directory_cwd_holder_is_found() {
    let dir = tempfile::tempdir().unwrap();
    let _child = spawn(&format!("cd {}; sleep 30", dir.path().to_string_lossy()));

    let out = openfd(&["why", &dir.path().to_string_lossy()]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(text.contains("cwd"), "{text}");
}

#[test]
fn port_holders_are_listed_and_missing_port_exits_1() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let spec = format!(":{port}");
    let out = openfd(&["why", &spec]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains(&format!(":{port}/tcp")) || text.contains("tcp"),
        "{text}"
    );
    assert!(text.contains("LISTEN"), "{text}");
    drop(listener);

    // A port nobody holds must exit 1.
    assert!(eventually(|| {
        let out = openfd(&["why", &spec]);
        out.status.code() == Some(1)
    }));
}

#[test]
fn missing_target_exits_2_with_a_deleted_hint() {
    let out = openfd(&["why", "/no/such/target"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("openfd -d --path"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn json_output_has_a_holder_row_and_a_summary() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("held.json");
    fs::write(&file, b"x").unwrap();
    let _child = spawn(&format!("exec 3<{}; sleep 30", file.to_string_lossy()));

    let out = openfd(&["why", "--json", &file.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert!(lines.len() >= 2, "{text}");
    let holder: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(holder["type"], "holder");
    assert_eq!(holder["how"], "fd");
    assert!(holder["owner"]["kind"].is_string());
    let summary: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(summary["type"], "summary");
    assert_eq!(summary["target_kind"], "file");
    assert!(summary["processes"].as_u64().unwrap() >= 1);
    assert!(summary["incomplete"]["permission_denied"].is_u64());
}

#[test]
fn quiet_mode_prints_nothing_but_keeps_the_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("quiet");
    fs::write(&file, b"x").unwrap();
    let out = openfd(&["why", "-q", &file.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    assert!(stderr(&out).is_empty(), "{}", stderr(&out));
}

#[test]
fn no_hints_suppresses_the_fix_section() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("held");
    fs::write(&file, b"x").unwrap();
    let _child = spawn(&format!("exec 3<{}; sleep 30", file.to_string_lossy()));
    let out = openfd(&["why", "--no-hints", &file.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!stdout(&out).contains("fix:"), "{}", stdout(&out));
}

#[test]
fn mountpoint_mode_lists_submounts() {
    // /proc always has at least binfmt_misc as a submount.
    let out = openfd(&["why", "--no-hints", "--no-mmap", "/proc"]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(text.contains("submount"), "{text}");
}

#[test]
fn lock_holders_are_shown() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("locked");
    fs::write(&file, b"x").unwrap();
    let script = format!(
        "python3 -c 'import fcntl,time; f=open(\"{}\",\"r+\"); fcntl.lockf(f, fcntl.LOCK_EX); time.sleep(30)'",
        file.to_string_lossy()
    );
    let _child = spawn(&script);

    let found = eventually(|| {
        let out = openfd(&["why", &file.to_string_lossy()]);
        out.status.code() == Some(0) && stdout(&out).contains("[lock: POSIX WRITE]")
    });
    assert!(
        found,
        "a POSIX lock holder must be reported with the lock tag"
    );
}

#[test]
fn mmap_holder_is_found() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("mapped.bin");
    fs::write(&file, vec![0u8; 4096]).unwrap();
    let script = format!(
        "python3 -c 'import mmap,time; f=open(\"{}\",\"rb\"); m=mmap.mmap(f.fileno(),0,prot=mmap.PROT_READ); time.sleep(30)'",
        file.to_string_lossy()
    );
    let _child = spawn(&script);

    let found = eventually(|| {
        let out = openfd(&["why", "--no-hints", &file.to_string_lossy()]);
        stdout(&out).contains("mmap")
    });
    assert!(found, "an mmap holder must be listed");
}

#[test]
fn deleted_file_bytes_are_summed() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gone.log");
    fs::write(&file, vec![0u8; 8192]).unwrap();
    let script = format!(
        "exec 3<{}; rm -f {}; sleep 30",
        file.to_string_lossy(),
        file.to_string_lossy()
    );
    let _child = spawn(&script);

    let found = eventually(|| {
        let out = openfd(&["why", dir.path().to_string_lossy().as_ref()]);
        stdout(&out).contains("deleted file(s)")
    });
    assert!(found, "deleted-but-open bytes must be reported");
    assert!(!Path::new(&file).exists());
}

#[test]
fn a_plain_unheld_file_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("fresh");
    fs::write(&file, b"x").unwrap();
    let out = openfd(&["why", &file.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("nothing holds it"),
        "{}",
        stdout(&out)
    );
}
