//! `openfd-mangen` writes the man page to the requested path.

use std::process::Command;

#[test]
fn mangen_writes_the_page_and_creates_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("nested/man/openfd.1");
    let status = Command::new(env!("CARGO_BIN_EXE_openfd-mangen"))
        .arg(&out)
        .status()
        .expect("run openfd-mangen");
    assert!(status.success(), "mangen must exit 0");

    let text = std::fs::read_to_string(&out).expect("man page written");
    assert!(text.contains(".TH openfd 1"), "roff header: {text}");
    assert_eq!(
        text,
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../man/openfd.1"))
            .expect("committed man page"),
        "mangen output must match the committed page"
    );
}

#[test]
fn mangen_without_a_path_exits_with_usage() {
    let out = Command::new(env!("CARGO_BIN_EXE_openfd-mangen"))
        .output()
        .expect("run openfd-mangen");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("usage: openfd-mangen"),
        "usage message"
    );
}
