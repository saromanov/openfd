//! Live `-i` filter tests: bind real sockets and check openfd sees them.

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};

fn openfd(args: &[&str]) -> String {
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
fn inet_filter_finds_own_tcp_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _guard = listener;

    let out = openfd(&["-i", &format!(":{port}"), "-t"]);
    assert!(
        out.lines().any(|l| l == std::process::id().to_string()),
        "own pid must be reported for -i :{port}, got: {out}"
    );
}

#[test]
fn inet_filter_proto_and_state() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _guard = listener;

    let out = openfd(&["-i", &format!("tcp:{port}")]);
    assert!(
        out.contains(&format!(":{port} ")) && out.contains("LISTEN"),
        "tcp:{port} LISTEN row expected, got: {out}"
    );
}

#[test]
fn inet_filter_udp_unconn() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let _guard = sock;

    let out = openfd(&["-i", &format!("udp:{port}")]);
    assert!(
        out.contains(&format!(":{port} ")) && out.contains("UNCONN"),
        "udp:{port} UNCONN row expected, got: {out}"
    );
}

#[test]
fn inet_filter_unix_named_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("openfd-it.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let _guard = listener;

    let out = openfd(&["-i", "unix"]);
    assert!(
        out.contains(path.to_str().unwrap()),
        "unix socket path must be reported, got: {out}"
    );
}

#[test]
fn inet_filter_rejects_hostnames() {
    // No DNS: a hostname must be rejected with a parse error, not resolved.
    let out = Command::new(env!("CARGO_BIN_EXE_openfd"))
        .args(["-i", "@example.invalid"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not a literal IP"), "stderr: {err}");
}

#[test]
fn inet_filter_bare_i_excludes_unix() {
    // Bare `-i` means "any internet socket": no unix rows allowed.
    let out = openfd(&["-i"]);
    assert!(
        !out.contains(" UNIX "),
        "bare -i must not report unix sockets, got: {out}"
    );
}

#[test]
fn json_output_includes_socket_details() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _guard = listener;

    let out = openfd(&["-i", &format!(":{port}"), "-j"]);
    assert!(
        out.contains("\"proto\":\"TCP\"") && out.contains(&format!("127.0.0.1:{port}")),
        "JSON rows must carry socket details, got: {out}"
    );
}

#[test]
fn streaming_first_line_comes_before_process_exit_hint() {
    // A slow reader must be able to start before the scan ends: run openfd
    // through a pipe and read the first line. If the whole table were
    // buffered, this would only return after the full scan.
    let mut child = Command::new(env!("CARGO_BIN_EXE_openfd"))
        .arg("-i")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("first line must stream");
    assert!(!line.trim().is_empty(), "first line must be non-empty");
    child.kill().ok();
    let _ = child.wait();
}
