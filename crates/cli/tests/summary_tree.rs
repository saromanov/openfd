//! `--tree` process grouping and the extended `-s` smart summary:
//! kind totals and top shared files around one child process holding a file.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Held {
    child: Child,
    _dir: tempfile::TempDir,
    basename: String,
}

impl Drop for Held {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `sleep 30` with stdout and stderr attached to the same temp file,
/// so the file is referenced by two fds.
fn child_holding_file() -> Held {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("held.bin");
    let basename = "held.bin";
    let f1 = std::fs::File::create(&path).unwrap();
    let f2 = f1.try_clone().unwrap();
    let child = Command::new("sleep")
        .arg("30")
        .stdout(Stdio::from(f1))
        .stderr(Stdio::from(f2))
        .spawn()
        .expect("spawn child");
    // Give the kernel a moment to expose /proc/<pid>/fd.
    std::thread::sleep(Duration::from_millis(100));
    Held {
        child,
        _dir: dir,
        basename: basename.to_string(),
    }
}

impl Held {
    fn pid(&self) -> String {
        self.child.id().to_string()
    }
}

fn openfd_stdout(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_openfd"))
        .args(args)
        .output()
        .expect("run openfd");
    assert!(
        out.status.success(),
        "openfd failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn summary_shows_kind_totals_and_top_files() {
    let held = child_holding_file();
    let out = openfd_stdout(&["-s", "-p", &held.pid(), "--sizes"]);
    assert!(
        out.contains("KIND TOTALS: "),
        "kind totals missing: {out:?}"
    );
    assert!(out.contains("file="), "file kind missing: {out:?}");
    assert!(
        out.contains("TOP FILES:") && out.contains(held.basename.as_str()),
        "top files section missing: {out:?}"
    );
}

#[test]
fn tree_groups_fds_under_their_process() {
    let held = child_holding_file();
    let out = openfd_stdout(&["--tree", "-p", &held.pid(), "--sizes"]);
    // Process header line, then indented fd line with the held file.
    let mut saw_header = false;
    let mut saw_indented_fd = false;
    for line in out.lines() {
        if line.contains("sleep") && line.contains("fds") {
            saw_header = true;
        }
        if saw_header && line.starts_with(char::is_whitespace) && line.contains("held.bin") {
            saw_indented_fd = true;
        }
    }
    assert!(saw_header, "process header missing: {out:?}");
    assert!(saw_indented_fd, "indented fd line missing: {out:?}");
}

#[test]
fn tree_rejects_other_output_formats() {
    for bad in [
        ["--tree", "-s"],
        ["--tree", "-t"],
        ["--tree", "-j"],
        ["--tree", "--csv"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_openfd"))
            .args(bad)
            .output()
            .expect("run openfd");
        assert!(
            !out.status.success(),
            "--tree must reject {:?}",
            bad.iter().skip(1).collect::<Vec<_>>()
        );
    }
}

#[test]
fn nice_flag_scans_normally() {
    let held = child_holding_file();
    let out = openfd_stdout(&["--nice", "19", "-p", &held.pid(), "--sizes"]);
    assert!(
        out.contains("sleep"),
        "scan must still work under --nice: {out:?}"
    );
}
