//! Output formats for the openfd CLI: table, terse, NDJSON, CSV, summary.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use serde::Serialize;

use openfd_core::{AddrFamily, FdEntry, ProcessInfo, SockAddr, SockInfo, SockProto};

use crate::color::Colors;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Terse,
    Json,
    Csv,
}

/// Socket details sub-object for the JSON format.
#[derive(Debug, Serialize)]
pub struct SockRow {
    proto: &'static str,
    family: &'static str,
    local: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'static str>,
}

fn family_tag(f: &AddrFamily) -> &'static str {
    match f {
        AddrFamily::V4 => "ipv4",
        AddrFamily::V6 => "ipv6",
        AddrFamily::Unix => "unix",
    }
}

fn sock_addr_string(a: &SockAddr) -> String {
    match a {
        SockAddr::Inet { addr, port } => format!("{addr}:{port}"),
        SockAddr::Unix(path) => path.clone(),
    }
}

fn sock_row(sock: &SockInfo) -> SockRow {
    SockRow {
        proto: sock.proto.tag(),
        family: family_tag(&sock.family),
        local: sock_addr_string(&sock.local),
        remote: sock.remote.as_ref().map(sock_addr_string),
        state: sock.state,
    }
}

/// Human-readable socket endpoint string for the table/CSV TARGET column.
fn sock_target_string(sock: &SockInfo) -> String {
    match (&sock.remote, sock.state) {
        (Some(remote), Some(state)) => format!(
            "{}->{} ({})",
            sock_addr_string(&sock.local),
            sock_addr_string(remote),
            state
        ),
        (Some(remote), None) => format!(
            "{}->{}",
            sock_addr_string(&sock.local),
            sock_addr_string(remote)
        ),
        (None, Some(state)) => format!("{} ({})", sock_addr_string(&sock.local), state),
        (None, None) => sock_addr_string(&sock.local),
    }
}

/// One output row, used by the JSON format.
#[derive(Debug, Serialize)]
pub struct Row<'a> {
    pid: u32,
    comm: &'a str,
    user: String,
    fd: i32,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    anon_subtype: Option<&'a str>,
    target: &'a str,
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pos: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inode: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sock: Option<SockRow>,
}

/// TYPE column: transport tag for resolved sockets, fd-kind tag otherwise.
/// The 10-char padding is applied before coloring so columns stay aligned.
fn display_kind(entry: &FdEntry, colors: &Colors) -> String {
    match &entry.sock {
        Some(sock) => match sock.proto {
            SockProto::Tcp => colors.tcp(&format!("{:<10}", "TCP")),
            SockProto::Udp => colors.udp(&format!("{:<10}", "UDP")),
            SockProto::Unix => colors.unix(&format!("{:<10}", "UNIX")),
        },
        None => format!("{:<10}", entry.kind.tag()),
    }
}

/// TARGET column: socket endpoints for resolved sockets, path otherwise.
/// Deleted files are shown in red (human output only).
fn display_target(entry: &FdEntry, colors: &Colors) -> String {
    let text = if let Some(sock) = &entry.sock {
        sock_target_string(sock)
    } else if entry.deleted {
        format!("{} (deleted)", entry.target)
    } else {
        entry.target.clone()
    };
    if entry.deleted {
        colors.deleted(&text)
    } else {
        text
    }
}

fn user_of(info: &ProcessInfo) -> String {
    match &info.username {
        Some(name) => name.clone(),
        None => info.uid.to_string(),
    }
}

fn row<'a>(info: &'a ProcessInfo, entry: &'a FdEntry) -> Row<'a> {
    Row {
        pid: info.pid,
        comm: &info.comm,
        user: user_of(info),
        fd: entry.fd,
        kind: entry.kind.tag(),
        anon_subtype: entry.anon_subtype.as_deref(),
        target: &entry.target,
        deleted: entry.deleted,
        size: entry.size,
        pos: entry.pos,
        flags: entry.flags.map(|f| format!("{f:#o}")),
        inode: entry.inode,
        sock: entry.sock.as_ref().map(sock_row),
    }
}

#[derive(Debug, Default)]
struct SummaryLine {
    comm: String,
    user: String,
    count: u64,
    deleted_files: u64,
    deleted_bytes: u64,
}

pub struct Printer {
    format: Format,
    summary_mode: bool,
    sizes: bool,
    colors: Colors,
    csv: Option<csv::Writer<Box<dyn io::Write + Send>>>,
    pids: BTreeSet<u32>,
    summary: BTreeMap<u32, SummaryLine>,
    /// (count, bytes) of deleted files, aggregated across the scan
    deleted_total: (u64, u64),
}

impl Printer {
    pub fn new(
        format: Format,
        summary_mode: bool,
        sizes: bool,
        colors: Colors,
        stdout: Box<dyn io::Write + Send>,
    ) -> Self {
        let csv = match format {
            Format::Csv => {
                let mut w = csv::Writer::from_writer(stdout);
                let _ = w.write_record([
                    "COMMAND", "PID", "USER", "FD", "TYPE", "SIZE", "POS", "FLAGS", "DELETED",
                    "TARGET",
                ]);
                Some(w)
            }
            _ => None,
        };
        Printer {
            format,
            summary_mode,
            sizes,
            colors,
            csv,
            pids: BTreeSet::new(),
            summary: BTreeMap::new(),
            deleted_total: (0, 0),
        }
    }

    pub fn write_row(&mut self, info: &ProcessInfo, entry: &FdEntry) {
        match self.format {
            Format::Terse => {
                self.pids.insert(info.pid);
            }
            Format::Json => {
                let r = row(info, entry);
                if let Ok(line) = serde_json::to_string(&r) {
                    let mut out = io::stdout().lock();
                    let _ = writeln!(out, "{line}");
                }
            }
            Format::Csv => {
                let plain = Colors::new(false);
                if let Some(w) = &mut self.csv {
                    let _ = w.write_record([
                        info.comm.as_str(),
                        &info.pid.to_string(),
                        &user_of(info),
                        &entry.fd.to_string(),
                        &display_kind(entry, &plain),
                        &entry.size.map(|s| s.to_string()).unwrap_or_default(),
                        &entry.pos.map(|p| p.to_string()).unwrap_or_default(),
                        &entry.flags.map(|f| format!("{f:#o}")).unwrap_or_default(),
                        &entry.deleted.to_string(),
                        &display_target(entry, &plain),
                    ]);
                }
            }
            Format::Table => {
                if !self.summary_mode {
                    self.write_table_row(info, entry);
                }
            }
        }

        if let Some(s) = self.summary.get_mut(&info.pid) {
            s.count += 1;
            if entry.deleted {
                s.deleted_files += 1;
                s.deleted_bytes += entry.size.unwrap_or(0);
            }
        } else {
            let s = SummaryLine {
                comm: info.comm.clone(),
                user: user_of(info),
                count: 1,
                deleted_files: u64::from(entry.deleted),
                deleted_bytes: if entry.deleted {
                    entry.size.unwrap_or(0)
                } else {
                    0
                },
            };
            self.summary.insert(info.pid, s);
        }

        if entry.deleted {
            self.deleted_total.0 += 1;
            self.deleted_total.1 += entry.size.unwrap_or(0);
        }
    }

    fn write_table_row(&self, info: &ProcessInfo, entry: &FdEntry) {
        let mut out = io::stdout().lock();
        let target = display_target(entry, &self.colors);
        let kind = display_kind(entry, &self.colors);
        if self.sizes {
            let size = entry
                .size
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            let _ = writeln!(
                out,
                "{comm:<19} {pid:>7} {user:<12} {fd:>6} {kind:<10} {size:>10}  {target}",
                comm = info.comm,
                pid = info.pid,
                user = user_of(info),
                fd = entry.fd,
            );
        } else {
            let _ = writeln!(
                out,
                "{comm:<19} {pid:>7} {user:<12} {fd:>6} {kind:<10} {target}",
                comm = info.comm,
                pid = info.pid,
                user = user_of(info),
                fd = entry.fd,
            );
        }
    }

    pub fn finish(&mut self) {
        if self.summary_mode {
            self.print_summary();
            return;
        }
        match self.format {
            Format::Terse => {
                let mut out = io::stdout().lock();
                for pid in &self.pids {
                    let _ = writeln!(out, "{pid}");
                }
            }
            Format::Csv => {
                if let Some(w) = self.csv.as_mut() {
                    let _ = w.flush();
                }
            }
            Format::Table => {
                if self.deleted_total.0 > 0 {
                    let mut out = io::stderr().lock();
                    let (count, bytes) = self.deleted_total;
                    let _ = writeln!(
                        out,
                        "openfd: {count} deleted file(s) hold {bytes} reclaimable bytes"
                    );
                }
            }
            Format::Json => {}
        }
    }

    fn print_summary(&self) {
        let mut out = io::stdout().lock();
        let _ = writeln!(
            out,
            "{:<7} {:<12} {:<19} {:>6} {:>9} {:>12}",
            "PID", "USER", "COMMAND", "FDS", "DELETED", "DEL_BYTES"
        );
        for (pid, s) in &self.summary {
            let _ = writeln!(
                out,
                "{pid:<7} {user:<12} {comm:<19} {count:>6} {df:>9} {db:>12}",
                user = s.user,
                comm = s.comm,
                count = s.count,
                df = s.deleted_files,
                db = s.deleted_bytes,
            );
        }
    }
}
