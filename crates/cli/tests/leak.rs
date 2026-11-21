//! `openfd leak`: end-to-end tests with a child that really leaks fds.
//!
//! Windows are short (about one second) because the point is the analysis,
//! not the waiting.

use std::process::{Child, Command, Output, Stdio};

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

/// Spawn a python process that opens one file per 20 ms and never closes it.
fn spawn_leaker(path: &std::path::Path) -> ChildGuard {
    let script = format!(
        "import time\nfs=[]\nfor _ in range(100000):\n    fs.append(open(\"{}\",\"a\"))\n    time.sleep(0.02)\n",
        path.to_string_lossy()
    );
    let child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the leaking child");
    std::thread::sleep(std::time::Duration::from_millis(400));
    ChildGuard(child)
}

fn leak_args(pid: u32, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "leak".to_string(),
        "-p".to_string(),
        pid.to_string(),
        "--interval".to_string(),
        "200ms".to_string(),
        "--duration".to_string(),
        "1s".to_string(),
        "--min-samples".to_string(),
        "3".to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

#[test]
fn a_leaking_process_is_diagnosed() {
    let dir = tempfile::tempdir().unwrap();
    let child = spawn_leaker(&dir.path().join("leak"));
    let args = leak_args(child.0.id(), &[]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = openfd(&refs);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}\n{}", stderr(&out));
    assert!(text.contains("leaking"), "{text}");
    assert!(text.contains(&format!("pid {}", child.0.id())), "{text}");
    assert!(text.contains("growth"), "{text}");
    assert!(text.contains("fd/min"), "{text}");
    assert!(text.contains("ETA"), "{text}");
    assert!(text.contains("breakdown"), "{text}");
    assert!(text.contains("verdict"), "{text}");
}

#[test]
fn fail_if_eta_exits_3_and_takes_priority() {
    let dir = tempfile::tempdir().unwrap();
    let child = spawn_leaker(&dir.path().join("leak"));
    let args = leak_args(child.0.id(), &["--fail-if-eta", "30d"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = openfd(&refs);
    assert_eq!(
        out.status.code(),
        Some(3),
        "stdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
}

#[test]
fn a_quiet_process_is_not_a_leak() {
    let child = Command::new("sleep")
        .arg("30")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let guard = ChildGuard(child);
    let args = leak_args(guard.0.id(), &["--min-rate", "1000"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = openfd(&refs);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(stdout(&out).contains("0 leaking"), "{}", stdout(&out));
}

#[test]
fn json_report_has_leak_and_summary_rows() {
    let dir = tempfile::tempdir().unwrap();
    let child = spawn_leaker(&dir.path().join("leak"));
    let args = leak_args(child.0.id(), &["--json"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = openfd(&refs);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout(&out);
    let rows: Vec<serde_json::Value> = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(rows.len() >= 2, "{text}");
    assert_eq!(rows[0]["type"], "leak");
    assert_eq!(rows[0]["pid"], child.0.id());
    assert!(rows[0]["rate_per_min"].as_f64().unwrap() > 0.0);
    assert!(rows[0]["verdict"].is_string());
    let summary = rows.last().unwrap();
    assert_eq!(summary["type"], "summary");
    assert_eq!(summary["leaking"], 1);
    assert!(summary["samples"].as_u64().unwrap() >= 3);
}

#[test]
fn invalid_options_exit_2() {
    for args in [
        vec!["leak", "--interval", "nope"],
        vec!["leak", "--duration", "0s"],
        vec!["leak", "--min-samples", "1"],
        vec!["leak", "--top", "0"],
        vec!["leak", "--min-rate", "-1"],
        vec!["leak", "--fail-if-eta", "soon"],
        vec!["leak", "-p", "oops"],
    ] {
        let out = openfd(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(!stderr(&out).is_empty(), "{args:?}");
    }
}

#[test]
fn command_filter_limits_the_sample() {
    let dir = tempfile::tempdir().unwrap();
    let child = spawn_leaker(&dir.path().join("leak"));
    let mut args = leak_args(child.0.id(), &["-c", "definitely-not-this-command"]);
    // Drop the pid filter: the command filter alone must exclude everything.
    args.drain(1..3);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = openfd(&refs);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(stdout(&out).contains("0 leaking"), "{}", stdout(&out));
}
