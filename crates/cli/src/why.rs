//! `openfd why <TARGET>`: explain who holds a path, directory, mountpoint or
//! port, how it is held, and what to do about it.
//!
//! Strictly read-only: hints are printed, never executed.

use std::io::{self, Write};
use std::process::ExitCode;

use serde::Serialize;

use openfd_core::hints::{Hint, build_hints, format_bytes};
use openfd_core::holders::{CollectOptions, Holder, HolderKind, HolderReport, collect};
use openfd_core::passwd::UserTable;
use openfd_core::target::{Target, TargetKind};
use openfd_core::{LockRecord, SockAddr, SockInfo, SockProto};

use crate::args::WhyArgs;
use crate::filters::InetFilter;

/// Exit codes follow `fuser` and `grep`: 0 found, 1 not found, 2 error.
const EXIT_FOUND: u8 = 0;
const EXIT_NOT_FOUND: u8 = 1;
const EXIT_ERROR: u8 = 2;

pub fn run(args: WhyArgs) -> ExitCode {
    let target = match resolve_target(&args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("openfd: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let opts = CollectOptions {
        owner: !args.no_owner,
        mmap: !args.no_mmap,
        numeric: args.numeric,
    };
    let report = match collect(&target, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("openfd: cannot inspect /proc: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let hints = if args.no_hints {
        Vec::new()
    } else {
        build_hints(&report.holders)
    };

    if !args.quiet {
        let users = if args.numeric {
            None
        } else {
            Some(UserTable::load())
        };
        let mut out = io::stdout().lock();
        let result = if args.json {
            write_json(&mut out, &target, &report, &hints, users.as_ref())
        } else {
            write_table(&mut out, &target, &report, &hints)
        };
        if let Err(e) = result {
            eprintln!("openfd: write failed: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    }

    if report.holders.is_empty() {
        ExitCode::from(EXIT_NOT_FOUND)
    } else {
        ExitCode::from(EXIT_FOUND)
    }
}

/// Port specs are recognised with the same parser as `-i`; everything else
/// is a path.
fn resolve_target(args: &WhyArgs) -> Result<Target, String> {
    let spec = args.target.trim();
    let looks_like_port = spec.starts_with(':')
        || spec.starts_with("tcp:")
        || spec.starts_with("udp:")
        || spec.starts_with('@')
        || spec.starts_with("tcp:@")
        || spec.starts_with("udp:@");
    if looks_like_port {
        let filter = InetFilter::parse(spec)?;
        if filter.is_unix() {
            return Err("why does not take a unix socket spec; pass the socket path".to_string());
        }
        let port = filter
            .port()
            .ok_or_else(|| format!("port target needs a port: {spec}"))?;
        return Ok(Target::for_port(port, filter.proto()));
    }

    Target::detect_path(spec, args.mount).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => format!(
            "{spec}: no such file or directory; a deleted file can still be held - try `openfd -d --path {spec}`"
        ),
        _ => format!("{spec}: {e}"),
    })
}

fn user_name(uid: u32, users: Option<&UserTable>) -> String {
    users
        .and_then(|t| t.name(uid))
        .map(str::to_string)
        .unwrap_or_else(|| uid.to_string())
}

// ---- table ----

fn write_table(
    out: &mut dyn Write,
    target: &Target,
    report: &HolderReport,
    hints: &[Hint],
) -> io::Result<()> {
    let real: Vec<&Holder> = report
        .holders
        .iter()
        .filter(|h| h.how != HolderKind::Submount)
        .collect();
    let submounts: Vec<&Holder> = report
        .holders
        .iter()
        .filter(|h| h.how == HolderKind::Submount)
        .collect();

    if target.kind == TargetKind::Port {
        let proto = match target.proto {
            Some(SockProto::Udp) => "udp",
            _ => "tcp",
        };
        writeln!(out, ":{}/{proto}", target.port.unwrap_or(0))?;
    } else if real.is_empty() && submounts.is_empty() {
        writeln!(out, "{}: nothing holds it", target.describe())?;
    } else {
        writeln!(
            out,
            "{} is busy: {} processes, {} references",
            target.describe(),
            report.process_count(),
            real.len()
        )?;
    }

    if !real.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "{:<24} {:>7} {:<16} {:<8} TARGET",
            "OWNER", "PID", "COMMAND", "HOW"
        )?;
        for holder in &real {
            let mut target_text = holder.target.clone();
            if let Some(sock) = &holder.sock {
                target_text = sock_text(sock);
            }
            if holder.deleted {
                target_text.push_str(" (deleted)");
            }
            if holder.other_namespace {
                target_text.push_str(" (ns)");
            }
            if let Some(lock) = &holder.lock {
                target_text.push_str(&format!(" [lock: {}]", lock.label()));
            }
            writeln!(
                out,
                "{:<24} {:>7} {:<16} {:<8} {}",
                truncate(&holder.owner_key(), 24),
                holder.pid,
                truncate(&holder.comm, 16),
                truncate(&holder.how_label(), 8),
                target_text
            )?;
        }
    }

    for sub in &submounts {
        writeln!(out, "submount {} blocks umount", sub.target)?;
    }

    if !submounts.is_empty() {
        writeln!(
            out,
            "hint: unmount {} first, `umount` fails while anything is mounted under the target",
            submounts
                .iter()
                .map(|s| s.target.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }

    if report.deleted_count() > 0 {
        writeln!(out)?;
        writeln!(
            out,
            "{}: {} held by {} deleted file(s)",
            target.display,
            format_bytes(report.deleted_bytes()),
            report.deleted_count()
        )?;
    }

    if target.kind == TargetKind::Port && report.time_wait > 0 {
        writeln!(
            out,
            "also: {} sockets in TIME-WAIT on :{} (no owning process, expire automatically)",
            report.time_wait,
            target.port.unwrap_or(0)
        )?;
    }

    if report.denied > 0 {
        writeln!(
            out,
            "warning: {} processes could not be inspected (permission denied); run as root for a complete answer",
            report.denied
        )?;
    }

    if !hints.is_empty() {
        writeln!(out)?;
        writeln!(out, "fix:")?;
        let width = hints.iter().map(|h| h.command.len()).max().unwrap_or(0);
        for hint in hints {
            writeln!(out, "  {:<width$}  # {}", hint.command, hint.reason)?;
            if let Some(alt) = &hint.alternative {
                writeln!(out, "  or {alt}")?;
            }
        }
    }
    out.flush()
}

fn sock_text(sock: &SockInfo) -> String {
    let local = match &sock.local {
        SockAddr::Inet { addr, port } => format!("{}:{port}", addr),
        SockAddr::Unix(path) => path.clone(),
    };
    let proto = match sock.proto {
        SockProto::Tcp => "tcp",
        SockProto::Udp => "udp",
        SockProto::Unix => "unix",
    };
    match (&sock.remote, sock.state) {
        (Some(remote), Some(state)) => format!("{proto} {local}->{remote} {state}"),
        (Some(remote), None) => format!("{proto} {local}->{remote}"),
        (None, Some(state)) => format!("{proto} {local} {state}"),
        (None, None) => format!("{proto} {local}"),
    }
}

fn truncate(text: &str, width: usize) -> String {
    text.chars().take(width).collect()
}

// ---- JSON ----

#[derive(Debug, Serialize)]
struct JsonOwner {
    kind: &'static str,
    name: String,
    cgroup: String,
}

#[derive(Debug, Serialize)]
struct JsonLock {
    kind: &'static str,
    mode: &'static str,
    pid: Option<u32>,
    inode: u64,
}

impl From<&LockRecord> for JsonLock {
    fn from(lock: &LockRecord) -> Self {
        JsonLock {
            kind: lock.kind.tag(),
            mode: lock.mode.tag(),
            pid: lock.pid,
            inode: lock.inode,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonSock {
    proto: &'static str,
    local: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct JsonHolder<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_time: Option<u64>,
    comm: &'a str,
    user: String,
    how: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fd: Option<i32>,
    target: &'a str,
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lock: Option<JsonLock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sock: Option<JsonSock>,
    owner: JsonOwner,
    namespace: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tty: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct JsonHint {
    owner: String,
    command: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    alternative: Option<String>,
}

#[derive(Debug, Serialize)]
struct JsonIncomplete {
    permission_denied: u64,
}

#[derive(Debug, Serialize)]
struct JsonSummary<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    target: &'a str,
    target_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fs: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
    holders: usize,
    processes: usize,
    deleted_bytes: u64,
    time_wait: u64,
    hints: Vec<JsonHint>,
    incomplete: JsonIncomplete,
}

fn write_json(
    out: &mut dyn Write,
    target: &Target,
    report: &HolderReport,
    hints: &[Hint],
    users: Option<&UserTable>,
) -> io::Result<()> {
    for holder in &report.holders {
        let row = JsonHolder {
            kind: "holder",
            pid: holder.pid,
            start_time: holder.start_time,
            comm: &holder.comm,
            user: user_name(holder.uid, users),
            how: holder.how.tag(),
            fd: holder.fd,
            target: &holder.target,
            deleted: holder.deleted,
            size: holder.size,
            lock: holder.lock.as_ref().map(JsonLock::from),
            sock: holder.sock.as_ref().map(|s| JsonSock {
                proto: s.proto.tag(),
                local: s.local.to_string(),
                remote: s.remote.as_ref().map(ToString::to_string),
                state: s.state,
            }),
            owner: JsonOwner {
                kind: holder.owner.kind.tag(),
                name: holder.owner.name.clone(),
                cgroup: holder.owner.cgroup.clone(),
            },
            namespace: holder.other_namespace,
            tty: holder.tty.as_deref(),
        };
        serde_json::to_writer(&mut *out, &row)?;
        out.write_all(b"\n")?;
    }

    let summary = JsonSummary {
        kind: "summary",
        target: &target.display,
        target_kind: target.kind.tag(),
        fs: target.fstype(),
        source: target.source(),
        holders: report.holders.len(),
        processes: report.process_count(),
        deleted_bytes: report.deleted_bytes(),
        time_wait: report.time_wait,
        hints: hints
            .iter()
            .map(|h| JsonHint {
                owner: h.owner.clone(),
                command: h.command.clone(),
                reason: h.reason.clone(),
                alternative: h.alternative.clone(),
            })
            .collect(),
        incomplete: JsonIncomplete {
            permission_denied: report.denied,
        },
    };
    serde_json::to_writer(&mut *out, &summary)?;
    out.write_all(b"\n")?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfd_core::owner::{Owner, OwnerKind};

    fn args(target: &str) -> WhyArgs {
        WhyArgs {
            target: target.to_string(),
            mount: false,
            no_hints: false,
            no_owner: false,
            no_mmap: false,
            json: false,
            numeric: false,
            quiet: false,
        }
    }

    #[test]
    fn port_specs_are_parsed_with_the_shared_parser() {
        let target = resolve_target(&args(":8080")).unwrap();
        assert_eq!(target.kind, TargetKind::Port);
        assert_eq!(target.port, Some(8080));
        let target = resolve_target(&args("udp:53")).unwrap();
        assert_eq!(target.proto, Some(SockProto::Udp));
        let target = resolve_target(&args("@127.0.0.1:22")).unwrap();
        assert_eq!(target.port, Some(22));
    }

    #[test]
    fn unix_and_portless_specs_are_rejected() {
        assert!(resolve_target(&args("unix")).is_err());
        assert!(resolve_target(&args("tcp:")).is_err());
    }

    #[test]
    fn a_missing_path_suggests_the_deleted_view() {
        let err = resolve_target(&args("/no/such/file")).unwrap_err();
        assert!(err.contains("openfd -d --path"), "{err}");
    }

    #[test]
    fn socket_text_covers_states_and_endpoints() {
        let sock = SockInfo {
            proto: SockProto::Tcp,
            family: openfd_core::AddrFamily::V4,
            local: SockAddr::Inet {
                addr: "0.0.0.0".parse().unwrap(),
                port: 8080,
            },
            remote: None,
            state: Some("LISTEN"),
        };
        assert_eq!(sock_text(&sock), "tcp 0.0.0.0:8080 LISTEN");
        let mut with_remote = sock.clone();
        with_remote.remote = Some(SockAddr::Inet {
            addr: "10.0.0.5".parse().unwrap(),
            port: 40000,
        });
        assert_eq!(
            sock_text(&with_remote),
            "tcp 0.0.0.0:8080->10.0.0.5:40000 LISTEN"
        );
        let mut no_state = with_remote.clone();
        no_state.state = None;
        assert_eq!(sock_text(&no_state), "tcp 0.0.0.0:8080->10.0.0.5:40000");
        let unix = SockInfo {
            proto: SockProto::Unix,
            family: openfd_core::AddrFamily::Unix,
            local: SockAddr::Unix("/run/x.sock".to_string()),
            remote: None,
            state: None,
        };
        assert_eq!(sock_text(&unix), "unix /run/x.sock");
    }

    #[test]
    fn truncation_keeps_columns_aligned() {
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(truncate("ab", 5), "ab");
    }

    #[test]
    fn user_resolution_falls_back_to_the_uid() {
        assert_eq!(user_name(0, None), "0");
        let table = UserTable::load();
        assert_eq!(user_name(0, Some(&table)), "root");
        assert_eq!(user_name(u32::MAX - 1, Some(&table)), "4294967294");
    }

    fn owner(kind: OwnerKind, name: &str) -> Owner {
        Owner {
            kind,
            name: name.to_string(),
            container_id: None,
            cgroup: format!("/cgroup/{name}"),
        }
    }

    fn holder(
        pid: u32,
        how: HolderKind,
        owner: Owner,
        target: &str,
        sock: Option<SockInfo>,
    ) -> Holder {
        Holder {
            pid,
            start_time: Some(10),
            comm: "app".to_string(),
            uid: 1000,
            how,
            fd: Some(7),
            target: target.to_string(),
            deleted: false,
            size: None,
            lock: None,
            sock,
            inode: Some(10),
            dev: Some(10),
            owner,
            other_namespace: false,
            tty: None,
        }
    }

    fn report(holders: Vec<Holder>) -> HolderReport {
        HolderReport {
            holders,
            denied: 0,
            time_wait: 0,
        }
    }

    #[test]
    fn table_renders_holders_locks_deleted_bytes_and_time_wait() {
        let mut lock =
            openfd_core::parse_lock_line("1: POSIX ADVISORY WRITE 42 08:01:10 0 EOF").unwrap();
        lock.pid = Some(42);
        let mut fd_holder = holder(
            42,
            HolderKind::Fd,
            owner(OwnerKind::SystemdUnit, "nginx.service"),
            "/mnt/data/log",
            None,
        );
        fd_holder.deleted = true;
        fd_holder.size = Some(2 * (1 << 30));
        fd_holder.lock = Some(lock);
        fd_holder.other_namespace = true;
        let mut sock_holder = holder(
            43,
            HolderKind::Fd,
            owner(OwnerKind::Docker, "3f2a9c"),
            "socket:[1]",
            Some(SockInfo {
                proto: SockProto::Tcp,
                family: openfd_core::AddrFamily::V4,
                local: SockAddr::Inet {
                    addr: "0.0.0.0".parse().unwrap(),
                    port: 8080,
                },
                remote: None,
                state: Some("LISTEN"),
            }),
        );
        sock_holder.fd = Some(21);
        let mut r = report(vec![fd_holder, sock_holder]);
        r.denied = 3;
        r.time_wait = 14;
        let hints = vec![Hint {
            owner: "nginx.service".to_string(),
            command: "systemctl reload nginx.service".to_string(),
            reason: "holds deleted fd 7".to_string(),
            alternative: Some(": > /proc/42/fd/7".to_string()),
        }];
        let target = Target::for_port(8080, Some(SockProto::Tcp));
        let mut out = Vec::new();
        write_table(&mut out, &target, &r, &hints).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with(":8080/tcp"), "{text}");
        assert!(text.contains("[lock: POSIX WRITE]"), "{text}");
        assert!(text.contains("(deleted)"), "{text}");
        assert!(text.contains("(ns)"), "{text}");
        assert!(text.contains("tcp 0.0.0.0:8080 LISTEN"), "{text}");
        assert!(text.contains("2.0 GiB held by 1 deleted file(s)"), "{text}");
        assert!(text.contains("14 sockets in TIME-WAIT on :8080"), "{text}");
        assert!(
            text.contains("3 processes could not be inspected"),
            "{text}"
        );
        assert!(text.contains("systemctl reload nginx.service"), "{text}");
        assert!(text.contains("or : > /proc/42/fd/7"), "{text}");
    }

    #[test]
    fn table_marks_submounts_and_empty_targets() {
        let sub = holder(
            0,
            HolderKind::Submount,
            owner(OwnerKind::Unknown, ""),
            "/mnt/data/nfs",
            None,
        );
        let target = Target::for_port(1, None);
        let mut out = Vec::new();
        write_table(&mut out, &target, &report(vec![sub]), &[]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("submount /mnt/data/nfs blocks umount"),
            "{text}"
        );
        assert!(text.contains("hint: unmount"), "{text}");

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("fresh");
        std::fs::write(&file, b"x").unwrap();
        let file_target = Target::detect_path(&file.to_string_lossy(), false).unwrap();
        let mut out = Vec::new();
        let mut empty = report(vec![]);
        empty.denied = 1;
        write_table(&mut out, &file_target, &empty, &[]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("nothing holds it"), "{text}");
        assert!(
            text.contains("1 processes could not be inspected"),
            "{text}"
        );
    }

    #[test]
    fn json_renders_holder_and_summary_objects() {
        let mut h = holder(
            42,
            HolderKind::Fd,
            owner(OwnerKind::SystemdUnit, "nginx.service"),
            "/mnt/data/log",
            Some(SockInfo {
                proto: SockProto::Tcp,
                family: openfd_core::AddrFamily::V4,
                local: SockAddr::Inet {
                    addr: "10.0.0.1".parse().unwrap(),
                    port: 8080,
                },
                remote: Some(SockAddr::Inet {
                    addr: "10.0.0.5".parse().unwrap(),
                    port: 40000,
                }),
                state: Some("ESTABLISHED"),
            }),
        );
        h.lock = openfd_core::parse_lock_line("1: POSIX ADVISORY WRITE 42 08:01:10 0 EOF");
        h.tty = Some("/dev/pts/1".to_string());
        h.deleted = true;
        h.size = Some(128);
        let target = Target::detect_path("/", false).unwrap();
        let hints = vec![Hint {
            owner: "nginx.service".to_string(),
            command: "systemctl restart nginx.service".to_string(),
            reason: "holds".to_string(),
            alternative: None,
        }];
        let mut out = Vec::new();
        write_json(&mut out, &target, &report(vec![h]), &hints, None).unwrap();
        let text = String::from_utf8(out).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["type"], "holder");
        assert_eq!(rows[0]["user"], "1000");
        assert_eq!(rows[0]["lock"]["kind"], "POSIX");
        assert_eq!(rows[0]["sock"]["state"], "ESTABLISHED");
        assert_eq!(rows[0]["sock"]["remote"], "10.0.0.5:40000");
        assert_eq!(rows[0]["owner"]["kind"], "systemd_unit");
        assert_eq!(rows[0]["tty"], "/dev/pts/1");
        assert_eq!(rows[1]["target_kind"], "mount");
        assert_eq!(rows[1]["fs"], target.fstype().unwrap());
        assert_eq!(
            rows[1]["hints"][0]["command"],
            "systemctl restart nginx.service"
        );
        assert!(rows[1]["incomplete"]["permission_denied"].is_u64());
    }

    #[test]
    fn write_errors_are_reported() {
        struct Failing;
        impl Write for Failing {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("boom"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("boom"))
            }
        }
        let target = Target::for_port(22, Some(SockProto::Tcp));
        assert!(write_table(&mut Failing, &target, &report(vec![]), &[]).is_err());
        assert!(write_json(&mut Failing, &target, &report(vec![]), &[], None).is_err());
    }

    #[test]
    fn owner_labels_are_stable() {
        let owner = Owner {
            kind: OwnerKind::Docker,
            name: "3f2a9c".to_string(),
            container_id: Some("3f2a9c".to_string()),
            cgroup: "/docker/3f2a9c".to_string(),
        };
        assert_eq!(owner.label(), "docker:3f2a9c");
    }
}
