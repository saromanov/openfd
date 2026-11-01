//! Live `--watch` test: opened/closed events around one child process.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn watch_reports_open_and_close_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("watched.bin");
    let basename = "watched.bin";

    let mut watch = Command::new(env!("CARGO_BIN_EXE_openfd"))
        .args(["--watch", "--interval", "0.3", "--path", basename])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start openfd --watch");

    // Let the first snapshot settle, then open and close a file.
    std::thread::sleep(Duration::from_millis(800));
    let mut holder = Command::new("sleep")
        .arg("30")
        .stdout(Stdio::from(std::fs::File::create(&path).unwrap()))
        .spawn()
        .expect("spawn holder");
    std::thread::sleep(Duration::from_millis(1200));
    holder.kill().ok();
    let _ = holder.wait();

    // Give the watcher a tick to notice the close, then stop it.
    std::thread::sleep(Duration::from_millis(1200));
    watch.kill().ok();
    let mut out = String::new();
    if let Some(mut stdout) = watch.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    let _ = watch.wait();

    assert!(
        out.lines()
            .any(|l| l.starts_with('+') && l.contains(basename)),
        "watch must report the opened fd, got: {out:?}"
    );
    assert!(
        out.lines()
            .any(|l| l.starts_with('-') && l.contains(basename)),
        "watch must report the closed fd, got: {out:?}"
    );
}
