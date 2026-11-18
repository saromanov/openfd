//! CLI surface: every output mode, the loop modes and the argument errors.
//! Each case runs the real binary so the parsing and dispatch in `main.rs`
//! is covered end to end.

use std::process::{Command, Output};

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

fn assert_ok(out: &Output) {
    assert!(out.status.success(), "openfd failed: {}", stderr(out));
}

#[test]
fn completions_are_printed_and_exit_zero() {
    let out = openfd(&["--completions", "bash"]);
    assert_ok(&out);
    let text = stdout(&out);
    assert!(text.contains("openfd"), "completion script: {text}");
}

#[test]
fn tree_rejects_machine_formats() {
    for flag in ["-s", "-t", "-j", "--csv"] {
        let out = openfd(&["--tree", flag]);
        assert_eq!(out.status.code(), Some(2), "--tree {flag}");
        assert!(
            stderr(&out).contains("--tree works with the table output only"),
            "stderr: {}",
            stderr(&out)
        );
    }
}

#[test]
fn invalid_filter_specs_are_rejected() {
    let out = openfd(&["-p", "oops"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("invalid pid"), "{}", stderr(&out));

    let out = openfd(&["-f", "oops"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("invalid fd"), "{}", stderr(&out));

    let out = openfd(&["-i", "unix:80"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unix sockets"), "{}", stderr(&out));
}

#[test]
fn invalid_color_is_rejected() {
    let out = openfd(&["--color", "rainbow"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("--color must be auto, always or never"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn table_mode_with_every_filter_runs() {
    let pid = std::process::id().to_string();
    let out = openfd(&[
        "-p", &pid, "-n", "--sizes", "-d", "-u", "root", "-c", "openfd", "--path", "/proc",
        "--dir", "/proc", "--nice", "10",
    ]);
    // Nothing may match (the test process is not root and holds no /proc
    // path), but the run itself must succeed.
    assert_ok(&out);
}

#[test]
fn terse_json_csv_and_summary_modes_run() {
    let pid = std::process::id().to_string();

    let out = openfd(&["-t", "-p", &pid]);
    assert_ok(&out);
    assert_eq!(stdout(&out).trim(), pid, "terse prints only our pid");

    let out = openfd(&["-j", "-p", &pid]);
    assert_ok(&out);
    let first = stdout(&out);
    let first = first.lines().next().expect("json row");
    assert!(
        first.starts_with('{') && first.contains("\"pid\":"),
        "{first}"
    );

    let out = openfd(&["--csv", "-p", &pid]);
    assert_ok(&out);
    assert!(
        stdout(&out).starts_with("COMMAND,PID,USER,FD,TYPE,SIZE,POS,FLAGS,DELETED,TARGET"),
        "{}",
        stdout(&out)
    );

    let out = openfd(&["-s", "-p", &pid]);
    assert_ok(&out);
    assert!(stdout(&out).contains("DEL_BYTES"), "{}", stdout(&out));
}

#[test]
fn tree_mode_prints_our_process() {
    let pid = std::process::id().to_string();
    let out = openfd(&["--tree", "-p", &pid]);
    assert_ok(&out);
    let text = stdout(&out);
    assert!(text.contains(" fds"), "tree header: {text}");
}

#[test]
fn wait_exits_as_soon_as_nothing_matches() {
    let needle = format!("openfd-wait-missing-{}", std::process::id());
    let out = openfd(&["--wait", "--interval", "0.05", "--path", &needle]);
    assert_ok(&out);
    assert!(stdout(&out).is_empty(), "wait prints nothing");
}

#[test]
fn top_reports_the_growth_table() {
    let out = openfd(&[
        "--top",
        "3",
        "--interval",
        "0.1",
        "-p",
        &std::process::id().to_string(),
    ]);
    assert_ok(&out);
    let text = stdout(&out);
    assert!(text.contains("DELTA"), "top header: {text}");
}

#[test]
fn loop_modes_reject_nonpositive_intervals() {
    let out = openfd(&["--wait", "--interval", "0"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--interval must be positive"));

    let out = openfd(&["--top", "1", "--interval", "0"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--interval must be positive"));

    let out = openfd(&["--watch", "--interval", "0"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--interval must be positive"));
}

#[test]
fn top_rejects_a_bad_count() {
    let out = openfd(&["--top", "0"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("--top expects a positive number"),
        "{}",
        stderr(&out)
    );

    let out = openfd(&["--top", "many"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn deleted_files_are_summarised_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("openfd-deleted.bin");
    let file = std::fs::File::create(&path).unwrap();
    std::fs::remove_file(&path).unwrap();

    // Our own test process still holds the unlinked file open.
    let out = openfd(&["-d", "--path", "openfd-deleted.bin"]);
    assert_ok(&out);
    assert!(
        stderr(&out).contains("reclaimable bytes"),
        "stderr: {}",
        stderr(&out)
    );
    drop(file);
}
