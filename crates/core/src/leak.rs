//! FD-leak analysis primitives for `openfd leak`.
//!
//! Pure functions only: limit parsing, robust linear growth fit, ETA to
//! `EMFILE`, fd signatures and verdicts. The sampling loop and formatting
//! live in the CLI, so the whole diagnosis is unit-testable.

use crate::types::{FdEntry, FdKind, SockAddr, SockInfo, SockProto};

/// One point of a per-process fd series: seconds since sampling started and
/// the fd count.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub seconds: f64,
    pub fds: u64,
}

/// Least-squares growth fit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fit {
    /// fd per minute.
    pub rate_per_min: f64,
    /// Coefficient of determination: 1.0 is a perfect line, 0.0 is noise.
    pub r2: f64,
}

/// Fit `fd = a + b * seconds` and return the slope per minute plus R².
/// Returns `None` with fewer than two points or a constant time axis.
pub fn linear_fit(samples: &[Sample]) -> Option<Fit> {
    if samples.len() < 2 {
        return None;
    }
    let n = samples.len() as f64;
    let mean_x = samples.iter().map(|s| s.seconds).sum::<f64>() / n;
    let mean_y = samples.iter().map(|s| s.fds as f64).sum::<f64>() / n;

    let mut sxx = 0.0;
    let mut sxy = 0.0;
    for sample in samples {
        let dx = sample.seconds - mean_x;
        sxx += dx * dx;
        sxy += dx * (sample.fds as f64 - mean_y);
    }
    if sxx <= f64::EPSILON {
        return None;
    }
    let slope = sxy / sxx;

    let mut ss_tot = 0.0;
    let mut ss_res = 0.0;
    let intercept = mean_y - slope * mean_x;
    for sample in samples {
        let predicted = intercept + slope * sample.seconds;
        ss_tot += (sample.fds as f64 - mean_y).powi(2);
        ss_res += (sample.fds as f64 - predicted).powi(2);
    }
    let r2 = if ss_tot <= f64::EPSILON {
        // A perfectly flat series fits perfectly.
        if ss_res <= f64::EPSILON { 1.0 } else { 0.0 }
    } else {
        (1.0 - ss_res / ss_tot).clamp(0.0, 1.0)
    };

    Some(Fit {
        rate_per_min: slope * 60.0,
        r2,
    })
}

/// Seconds until `current + rate * t` reaches `limit`. `None` without a
/// usable limit or with a non-positive rate.
pub fn eta_seconds(current: u64, limit: u64, rate_per_min: f64) -> Option<f64> {
    if rate_per_min <= 0.0 || current >= limit {
        return if current >= limit { Some(0.0) } else { None };
    }
    Some((limit - current) as f64 / (rate_per_min / 60.0))
}

/// Parse the soft `Max open files` value out of `/proc/<pid>/limits`.
///
/// The line looks like `Max open files            1024      1048576  files`;
/// the first number is the soft limit used for the ETA.
pub fn parse_limits(content: &str) -> Option<u64> {
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("Max open files") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        return fields.next().and_then(|soft| soft.parse().ok());
    }
    None
}

/// Read the soft fd limit of `pid`.
pub fn read_limit(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/limits"))
        .ok()
        .and_then(|content| parse_limits(&content))
}

/// Normalize a path for growth grouping: digit runs become `N`, so
/// `/var/log/app-2024-11-21.log` and `/var/log/app-2024-11-22.log` are one
/// signature instead of thousands.
pub fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut in_digits = false;
    for ch in path.chars() {
        if ch.is_ascii_digit() {
            if !in_digits {
                out.push('N');
                in_digits = true;
            }
        } else {
            in_digits = false;
            out.push(ch);
        }
    }
    out
}

fn endpoint(addr: &SockAddr) -> String {
    match addr {
        SockAddr::Inet { addr, port } => format!("{addr}:{port}"),
        SockAddr::Unix(path) => path.clone(),
    }
}

/// Signature that groups fds of one kind together. Peers are grouped by
/// address only (no ephemeral port), so a CLOSE_WAIT pile-up becomes one
/// row instead of thousands.
pub fn fd_signature(entry: &FdEntry) -> String {
    let mut signature = match (&entry.kind, &entry.sock) {
        (FdKind::Socket, Some(sock)) => sock_signature(sock),
        (FdKind::AnonInode, _) => match &entry.anon_subtype {
            Some(sub) => format!("anon_inode:{sub}"),
            None => "anon_inode".to_string(),
        },
        (FdKind::Memfd, _) => format!("memfd:{}", entry.target.trim_start_matches("/memfd:")),
        (FdKind::Pipe, _) => "pipe".to_string(),
        (FdKind::File | FdKind::Directory, _) => normalize_path(&entry.target),
        _ => entry.target.clone(),
    };
    if entry.deleted {
        signature.push_str(" (deleted)");
    }
    signature
}

fn sock_signature(sock: &SockInfo) -> String {
    let proto = match sock.proto {
        SockProto::Tcp => "tcp",
        SockProto::Udp => "udp",
        SockProto::Unix => "unix",
    };
    match sock.proto {
        SockProto::Unix => format!("{proto} {}", endpoint(&sock.local)),
        SockProto::Tcp | SockProto::Udp => match &sock.remote {
            Some(remote) => {
                let peer = match remote {
                    SockAddr::Inet { addr, .. } => addr.to_string(),
                    SockAddr::Unix(path) => path.clone(),
                };
                match sock.state {
                    Some(state) => format!("{proto} -> {peer} {state}"),
                    None => format!("{proto} -> {peer}"),
                }
            }
            None => {
                let local = match &sock.local {
                    SockAddr::Inet { port, .. } => format!("*:{port}"),
                    SockAddr::Unix(path) => path.clone(),
                };
                match sock.state {
                    Some(state) => format!("{proto} {local} {state}"),
                    None => format!("{proto} {local}"),
                }
            }
        },
    }
}

/// Human verdict for a dominant signature.
pub fn verdict(signature: &str) -> &'static str {
    if signature.contains("CLOSE-WAIT") {
        "CLOSE-WAIT accumulation: the application never closes accepted sockets (check response and error paths)"
    } else if signature.contains("TIME-WAIT") {
        "TIME-WAIT accumulation: short-lived outbound connections; check pooling and keep-alive"
    } else if signature.starts_with("tcp") || signature.starts_with("udp") {
        "socket growth: check connection-pool limits and unclosed responses"
    } else if signature.starts_with("anon_inode:eventfd")
        || signature.starts_with("anon_inode:epoll")
    {
        "eventfd/epoll growth: a poller, timer or async-runtime handle is leaked"
    } else if signature.starts_with("anon_inode") {
        "anonymous-inode growth: a kernel handle (eventfd, epoll, inotify) is leaked"
    } else if signature == "pipe" {
        "pipe growth: a pipe end is leaked (often a fork/exec or subprocess path)"
    } else if signature.starts_with("unix ") {
        "unix-socket growth: check local IPC peers"
    } else if signature.contains("(deleted)") {
        "deleted-file growth: files are unlinked while still open"
    } else {
        "file growth: check log rotation and unclosed file handles"
    }
}

/// The signature that grew the most, if any growth is positive.
pub fn dominant(breakdown: &[(String, u64)]) -> Option<&str> {
    breakdown
        .iter()
        .filter(|(_, delta)| *delta > 0)
        .max_by_key(|(_, delta)| *delta)
        .map(|(signature, _)| signature.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AddrFamily, FdKind};

    fn entry(kind: FdKind, target: &str) -> FdEntry {
        FdEntry {
            fd: 3,
            kind,
            target: target.to_string(),
            anon_subtype: None,
            deleted: false,
            size: None,
            pos: None,
            flags: None,
            inode: None,
            mode: None,
            dev: None,
            mnt_id: None,
            sock: None,
        }
    }

    fn sock(
        proto: SockProto,
        local: SockAddr,
        remote: Option<SockAddr>,
        state: Option<&'static str>,
    ) -> SockInfo {
        SockInfo {
            proto,
            family: if proto == SockProto::Unix {
                AddrFamily::Unix
            } else {
                AddrFamily::V4
            },
            local,
            remote,
            state,
        }
    }

    fn inet(addr: &str, port: u16) -> SockAddr {
        SockAddr::Inet {
            addr: addr.parse().unwrap(),
            port,
        }
    }

    #[test]
    fn perfect_growth_fits_with_r2_one() {
        let samples = [
            Sample {
                seconds: 0.0,
                fds: 10,
            },
            Sample {
                seconds: 60.0,
                fds: 20,
            },
            Sample {
                seconds: 120.0,
                fds: 30,
            },
        ];
        let fit = linear_fit(&samples).unwrap();
        assert!((fit.rate_per_min - 10.0).abs() < 1e-9, "{fit:?}");
        assert!((fit.r2 - 1.0).abs() < 1e-9, "{fit:?}");
    }

    #[test]
    fn noisy_series_has_a_lower_r2() {
        let samples = [
            Sample {
                seconds: 0.0,
                fds: 10,
            },
            Sample {
                seconds: 10.0,
                fds: 40,
            },
            Sample {
                seconds: 20.0,
                fds: 12,
            },
            Sample {
                seconds: 30.0,
                fds: 44,
            },
        ];
        let fit = linear_fit(&samples).unwrap();
        assert!(fit.r2 < 0.3, "{fit:?}");
    }

    #[test]
    fn flat_series_is_not_growth() {
        let samples = [
            Sample {
                seconds: 0.0,
                fds: 5,
            },
            Sample {
                seconds: 5.0,
                fds: 5,
            },
        ];
        let fit = linear_fit(&samples).unwrap();
        assert_eq!(fit.rate_per_min, 0.0);
        assert_eq!(fit.r2, 1.0);
        assert!(eta_seconds(5, 100, fit.rate_per_min).is_none());
    }

    #[test]
    fn degenerate_series_has_no_fit() {
        assert!(linear_fit(&[]).is_none());
        assert!(
            linear_fit(&[Sample {
                seconds: 1.0,
                fds: 3
            }])
            .is_none()
        );
        let same_time = [
            Sample {
                seconds: 1.0,
                fds: 3,
            },
            Sample {
                seconds: 1.0,
                fds: 9,
            },
        ];
        assert!(linear_fit(&same_time).is_none());
    }

    #[test]
    fn eta_scales_with_the_rate() {
        assert_eq!(eta_seconds(50, 100, 60.0), Some(50.0));
        assert_eq!(eta_seconds(100, 100, 60.0), Some(0.0));
        assert_eq!(eta_seconds(101, 100, 60.0), Some(0.0));
        assert_eq!(eta_seconds(10, 100, 0.0), None);
        assert_eq!(eta_seconds(10, 100, -5.0), None);
    }

    #[test]
    fn limits_are_parsed_from_proc_format() {
        let content = "\
Limit                     Soft Limit           Hard Limit           Units
Max cpu time              unlimited            unlimited            seconds
Max open files            1024                 1048576              files
Max locked memory         65536                65536                bytes
";
        assert_eq!(parse_limits(content), Some(1024));
        assert_eq!(
            parse_limits("Max open files unlimited unlimited files\n"),
            None
        );
        assert_eq!(parse_limits("nothing here\n"), None);
    }

    #[test]
    fn live_limit_of_our_own_process_is_readable() {
        let limit = read_limit(std::process::id()).expect("our limits must be readable");
        assert!(limit > 0);
    }

    #[test]
    fn paths_are_normalized_by_digit_runs() {
        assert_eq!(
            normalize_path("/var/log/app-2024-11-21.log"),
            "/var/log/app-N-N-N.log"
        );
        assert_eq!(normalize_path("/tmp/a12b34"), "/tmp/aNbN");
        assert_eq!(normalize_path("/plain"), "/plain");
    }

    #[test]
    fn file_signature_groups_rotated_logs() {
        let a = entry(FdKind::File, "/var/log/app-2024-11-21.log");
        let b = entry(FdKind::File, "/var/log/app-2024-11-22.log");
        assert_eq!(fd_signature(&a), fd_signature(&b));
        assert_eq!(fd_signature(&a), "/var/log/app-N-N-N.log");
    }

    #[test]
    fn deleted_files_are_marked_in_the_signature() {
        let mut e = entry(FdKind::File, "/tmp/x");
        e.deleted = true;
        assert_eq!(fd_signature(&e), "/tmp/x (deleted)");
    }

    #[test]
    fn tcp_signatures_group_by_peer_not_port() {
        let mut e = entry(FdKind::Socket, "socket:[1]");
        e.sock = Some(sock(
            SockProto::Tcp,
            inet("10.0.0.1", 40000),
            Some(inet("10.0.0.5", 443)),
            Some("CLOSE-WAIT"),
        ));
        let mut other = e.clone();
        other.sock = Some(sock(
            SockProto::Tcp,
            inet("10.0.0.1", 40001),
            Some(inet("10.0.0.5", 443)),
            Some("CLOSE-WAIT"),
        ));
        assert_eq!(fd_signature(&e), fd_signature(&other));
        assert_eq!(fd_signature(&e), "tcp -> 10.0.0.5 CLOSE-WAIT");
    }

    #[test]
    fn listen_sockets_show_the_local_port() {
        let mut e = entry(FdKind::Socket, "socket:[1]");
        e.sock = Some(sock(
            SockProto::Tcp,
            inet("0.0.0.0", 8080),
            None,
            Some("LISTEN"),
        ));
        assert_eq!(fd_signature(&e), "tcp *:8080 LISTEN");
        let mut udp = entry(FdKind::Socket, "socket:[1]");
        udp.sock = Some(sock(
            SockProto::Udp,
            inet("0.0.0.0", 53),
            None,
            Some("UNCONN"),
        ));
        assert_eq!(fd_signature(&udp), "udp *:53 UNCONN");
    }

    #[test]
    fn unix_and_anonymous_inodes_have_signatures() {
        let mut unix = entry(FdKind::Socket, "socket:[1]");
        unix.sock = Some(sock(
            SockProto::Unix,
            SockAddr::Unix("/run/app.sock".to_string()),
            None,
            None,
        ));
        assert_eq!(fd_signature(&unix), "unix /run/app.sock");

        let mut anon = entry(FdKind::AnonInode, "anon_inode:[eventfd]");
        anon.anon_subtype = Some("eventfd".to_string());
        assert_eq!(fd_signature(&anon), "anon_inode:eventfd");
        let anon = entry(FdKind::AnonInode, "anon_inode");
        assert_eq!(fd_signature(&anon), "anon_inode");

        let pipe = entry(FdKind::Pipe, "pipe:[42]");
        assert_eq!(fd_signature(&pipe), "pipe");
        let memfd = entry(FdKind::Memfd, "/memfd:secret");
        assert_eq!(fd_signature(&memfd), "memfd:secret");
    }

    #[test]
    fn sock_without_remote_or_state() {
        let mut e = entry(FdKind::Socket, "socket:[1]");
        e.sock = Some(sock(SockProto::Tcp, inet("127.0.0.1", 9), None, None));
        assert_eq!(fd_signature(&e), "tcp *:9");
        e.sock = Some(sock(
            SockProto::Tcp,
            inet("127.0.0.1", 9),
            Some(inet("127.0.0.2", 10)),
            None,
        ));
        assert_eq!(fd_signature(&e), "tcp -> 127.0.0.2");
    }

    #[test]
    fn verdicts_name_the_likely_bug() {
        assert!(verdict("tcp -> 10.0.0.5 CLOSE-WAIT").contains("CLOSE-WAIT"));
        assert!(verdict("tcp -> 10.0.0.5 TIME-WAIT").contains("TIME-WAIT"));
        assert!(verdict("tcp *:8080 LISTEN").contains("socket growth"));
        assert!(verdict("udp *:53 UNCONN").contains("socket growth"));
        assert!(verdict("anon_inode:eventfd").contains("eventfd"));
        assert!(verdict("anon_inode:epoll").contains("eventfd"));
        assert!(verdict("anon_inode:inotify").contains("anonymous-inode"));
        assert!(verdict("pipe").contains("pipe growth"));
        assert!(verdict("unix /run/app.sock").contains("unix-socket"));
        assert!(verdict("/tmp/x (deleted)").contains("deleted-file"));
        assert!(verdict("/var/log/app-N.log").contains("file growth"));
    }

    #[test]
    fn dominant_picks_the_largest_positive_delta() {
        let rows = vec![
            ("a".to_string(), 5),
            ("b".to_string(), 20),
            ("c".to_string(), 0),
        ];
        assert_eq!(dominant(&rows), Some("b"));
        assert_eq!(dominant(&[("a".to_string(), 0)]), None);
        assert_eq!(dominant(&[]), None);
    }
}
