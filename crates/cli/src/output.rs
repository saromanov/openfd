//! Output formats for the openfd CLI: table, terse, NDJSON, CSV, summary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
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

/// One process in `--tree` mode: metadata plus its buffered fd rows.
struct TreeProc {
    comm: String,
    user: String,
    ppid: Option<u32>,
    rows: Vec<FdEntry>,
}

pub struct Printer {
    format: Format,
    summary_mode: bool,
    tree_mode: bool,
    sizes: bool,
    colors: Colors,
    /// Mutable output state behind a mutex. Critical sections stay short:
    /// row formatting (the fat part) runs on the lock-free immutable config
    /// above, so parallel workers only queue for the buffered write.
    state: std::sync::Mutex<PrinterState>,
}

struct PrinterState {
    csv: Option<csv::Writer<Box<dyn io::Write + Send>>>,
    /// Buffered stdout for the line modes (table, json, terse finish):
    /// one buffer instead of a write syscall per row.
    line_out: Option<std::io::BufWriter<Box<dyn io::Write + Send>>>,
    pids: BTreeSet<u32>,
    summary: BTreeMap<u32, SummaryLine>,
    tree: BTreeMap<u32, TreeProc>,
    /// fd count per kind tag (summary mode only)
    kind_totals: BTreeMap<&'static str, u64>,
    /// fd count per regular-file target, top-N at the end (summary mode only)
    file_targets: std::collections::HashMap<String, u64>,
    /// (count, bytes) of deleted files, aggregated across the scan
    deleted_total: (u64, u64),
}

impl Printer {
    pub fn new(
        format: Format,
        summary_mode: bool,
        tree_mode: bool,
        sizes: bool,
        colors: Colors,
        stdout: Box<dyn io::Write + Send>,
    ) -> Self {
        let (csv, line_out) = match format {
            Format::Csv => {
                let mut w = csv::Writer::from_writer(stdout);
                let _ = w.write_record([
                    "COMMAND", "PID", "USER", "FD", "TYPE", "SIZE", "POS", "FLAGS", "DELETED",
                    "TARGET",
                ]);
                (Some(w), None)
            }
            _ => (
                None,
                Some(std::io::BufWriter::with_capacity(256 * 1024, stdout)),
            ),
        };
        Printer {
            format,
            summary_mode,
            tree_mode,
            sizes,
            colors,
            state: std::sync::Mutex::new(PrinterState {
                csv,
                line_out,
                pids: BTreeSet::new(),
                summary: BTreeMap::new(),
                tree: BTreeMap::new(),
                kind_totals: BTreeMap::new(),
                file_targets: std::collections::HashMap::new(),
                deleted_total: (0, 0),
            }),
        }
    }

    pub fn write_row(&self, info: &ProcessInfo, entry: &FdEntry) {
        match self.format {
            Format::Terse => {
                // One lock acquisition per distinct pid, not per row: a worker
                // scans a pid-sorted chunk, so repeats are consecutive.
                thread_local! {
                    static LAST: std::cell::Cell<(Option<std::thread::ThreadId>, u32)> =
                        const { std::cell::Cell::new((None, u32::MAX)) };
                }
                let tid = std::thread::current().id();
                if LAST.with(|c| c.get()) == (Some(tid), info.pid) {
                    return;
                }
                LAST.with(|c| c.set((Some(tid), info.pid)));
                self.state.lock().unwrap().pids.insert(info.pid);
            }
            Format::Json => {
                let line = serde_json::to_string(&row(info, entry)).ok();
                let mut st = self.state.lock().unwrap();
                if let (Some(line), Some(out)) = (line, st.line_out.as_mut()) {
                    let _ = writeln!(out, "{line}");
                }
                self.aggregate(&mut st, info, entry);
            }
            Format::Csv => {
                let plain = Colors::new(false);
                let user = user_of(info);
                let kind = display_kind(entry, &plain);
                let target = display_target(entry, &plain);
                let pid_s = info.pid.to_string();
                let fd_s = entry.fd.to_string();
                let size_s = entry.size.map(|s| s.to_string()).unwrap_or_default();
                let pos_s = entry.pos.map(|p| p.to_string()).unwrap_or_default();
                let flags_s = entry.flags.map(|f| format!("{f:#o}")).unwrap_or_default();
                let del_s = entry.deleted.to_string();
                let record = [
                    info.comm.as_str(),
                    &pid_s,
                    &user,
                    &fd_s,
                    &kind,
                    &size_s,
                    &pos_s,
                    &flags_s,
                    &del_s,
                    &target,
                ];
                let mut st = self.state.lock().unwrap();
                if let Some(w) = st.csv.as_mut() {
                    let _ = w.write_record(record);
                }
                self.aggregate(&mut st, info, entry);
            }
            Format::Table => {
                if self.tree_mode {
                    let mut st = self.state.lock().unwrap();
                    match st.tree.get_mut(&info.pid) {
                        Some(p) => p.rows.push(entry.clone()),
                        None => {
                            st.tree.insert(
                                info.pid,
                                TreeProc {
                                    comm: info.comm.clone(),
                                    user: user_of(info),
                                    ppid: info.ppid,
                                    rows: vec![entry.clone()],
                                },
                            );
                        }
                    }
                    self.aggregate(&mut st, info, entry);
                } else if self.summary_mode {
                    let mut st = self.state.lock().unwrap();
                    self.aggregate(&mut st, info, entry);
                } else {
                    // Format first (lock-free), then one short locked write.
                    let sizes = self.sizes;
                    let target = display_target(entry, &self.colors);
                    let kind = display_kind(entry, &self.colors);
                    let size = entry
                        .size
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let mut st = self.state.lock().unwrap();
                    if let Some(out) = st.line_out.as_mut() {
                        if sizes {
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
                    self.aggregate(&mut st, info, entry);
                }
            }
        }
    }

    /// Summary/tree/deleted aggregation; caller holds the state lock.
    fn aggregate(&self, st: &mut PrinterState, info: &ProcessInfo, entry: &FdEntry) {
        if self.summary_mode {
            *st.kind_totals.entry(entry.kind.tag()).or_insert(0) += 1;
            if entry.kind == openfd_core::FdKind::File {
                *st.file_targets.entry(entry.target.clone()).or_insert(0) += 1;
            }
        }

        if let Some(s) = st.summary.get_mut(&info.pid) {
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
            st.summary.insert(info.pid, s);
        }

        if entry.deleted {
            st.deleted_total.0 += 1;
            st.deleted_total.1 += entry.size.unwrap_or(0);
        }
    }

    pub fn finish(&self) {
        let mut st = self.state.lock().unwrap();
        if self.tree_mode || self.summary_mode {
            let text = if self.tree_mode {
                self.tree_text(&st)
            } else {
                self.summary_text(&st)
            };
            if let Some(out) = st.line_out.as_mut() {
                let _ = out.write_all(text.as_bytes());
            }
        } else {
            match self.format {
                Format::Terse => {
                    let pids: Vec<u32> = st.pids.iter().copied().collect();
                    if let Some(out) = st.line_out.as_mut() {
                        for pid in &pids {
                            let _ = writeln!(out, "{pid}");
                        }
                    }
                }
                Format::Csv => {
                    if let Some(w) = st.csv.as_mut() {
                        let _ = w.flush();
                    }
                }
                Format::Table => {
                    if st.deleted_total.0 > 0 {
                        let mut out = io::stderr().lock();
                        let (count, bytes) = st.deleted_total;
                        let _ = writeln!(
                            out,
                            "openfd: {count} deleted file(s) hold {bytes} reclaimable bytes"
                        );
                    }
                }
                Format::Json => {}
            }
        }
        if let Some(out) = st.line_out.as_mut() {
            let _ = out.flush();
        }
    }

    /// Summary report as text; written to the output at the end of the scan.
    fn summary_text(&self, st: &PrinterState) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{:<7} {:<12} {:<19} {:>6} {:>9} {:>12}",
            "PID", "USER", "COMMAND", "FDS", "DELETED", "DEL_BYTES"
        );
        for (pid, s) in &st.summary {
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

        if !st.kind_totals.is_empty() {
            let mut kinds: Vec<(&'static str, u64)> =
                st.kind_totals.iter().map(|(k, n)| (*k, *n)).collect();
            kinds.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            let parts = kinds
                .iter()
                .map(|(tag, n)| format!("{tag}={n}"))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(out, "KIND TOTALS: {parts}");
        }

        let mut files: Vec<(&String, &u64)> =
            st.file_targets.iter().filter(|(_, n)| **n > 1).collect();
        files.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        files.truncate(10);
        if !files.is_empty() {
            let parts = files
                .iter()
                .map(|(path, n)| format!("{n}x {path}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "TOP FILES: {parts}");
        }
        out
    }

    /// Render buffered rows as a process tree: parents above children,
    /// fd rows indented under their process. Orphans (parent not visible)
    /// and pid 1 sit at the top level; cycles are broken defensively.
    fn tree_text(&self, st: &PrinterState) -> String {
        let mut out = String::new();
        let mut children: std::collections::HashMap<u32, Vec<u32>> =
            std::collections::HashMap::new();
        for (pid, proc) in &st.tree {
            let parent = match proc.ppid {
                Some(ppid) if st.tree.contains_key(&ppid) && ppid != *pid => ppid,
                _ => 0,
            };
            children.entry(parent).or_default().push(*pid);
        }
        let mut visited = std::collections::BTreeSet::new();
        let mut roots = children.get(&0).cloned().unwrap_or_default();
        roots.sort_unstable();
        for pid in roots {
            self.tree_node(&mut out, st, pid, &children, &mut visited, 0);
        }
        // Defensive: any process not reachable from the roots (a cycle among
        // parents) is printed at the top level too.
        for &pid in st.tree.keys() {
            if !visited.contains(&pid) {
                self.tree_node(&mut out, st, pid, &children, &mut visited, 0);
            }
        }
        out
    }

    fn tree_node(
        &self,
        out: &mut String,
        st: &PrinterState,
        pid: u32,
        children: &std::collections::HashMap<u32, Vec<u32>>,
        visited: &mut std::collections::BTreeSet<u32>,
        depth: usize,
    ) {
        if !visited.insert(pid) {
            return;
        }
        let proc = match st.tree.get(&pid) {
            Some(p) => p,
            None => return,
        };
        let indent = "  ".repeat(depth);
        let _ = writeln!(
            out,
            "{indent}{comm:<19} {pid:>7} {user:<12} {count:>5} fds",
            comm = proc.comm,
            user = proc.user,
            count = proc.rows.len(),
        );
        for entry in &proc.rows {
            let target = display_target(entry, &self.colors);
            let kind = display_kind(entry, &self.colors);
            let _ = writeln!(out, "{indent}  {fd:>4} {kind:<10} {target}", fd = entry.fd);
        }
        if let Some(kids) = children.get(&pid) {
            for &kid in kids {
                self.tree_node(out, st, kid, children, visited, depth + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfd_core::{FdKind, ProcessInfo};
    use std::sync::{Arc, Mutex};

    /// Test sink: the printer owns a `Box<dyn Write>`, which cannot be read
    /// back, so hand it a shared buffer instead of stdout.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl SharedBuf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn printer(
        format: Format,
        summary_mode: bool,
        tree_mode: bool,
        sizes: bool,
        enabled: bool,
    ) -> (Printer, SharedBuf) {
        let buf = SharedBuf::default();
        let p = Printer::new(
            format,
            summary_mode,
            tree_mode,
            sizes,
            Colors::new(enabled),
            Box::new(buf.clone()),
        );
        (p, buf)
    }

    fn info(pid: u32, username: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: None,
            comm: "demo".to_string(),
            cmdline0: None,
            uid: 1000,
            username: username.map(str::to_string),
        }
    }

    fn entry(fd: i32, kind: FdKind, target: &str) -> FdEntry {
        FdEntry {
            fd,
            kind,
            target: target.to_string(),
            anon_subtype: None,
            deleted: false,
            size: None,
            pos: None,
            flags: None,
            inode: None,
            mode: None,
            sock: None,
        }
    }

    fn sock(
        proto: SockProto,
        family: AddrFamily,
        local: SockAddr,
        remote: Option<SockAddr>,
        state: Option<&'static str>,
    ) -> SockInfo {
        SockInfo {
            proto,
            family,
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
    fn table_rows_show_kind_target_and_sizes() {
        let (p, buf) = printer(Format::Table, false, false, true, false);
        let i = info(7, Some("alice"));
        let mut file = entry(3, FdKind::File, "/var/log/syslog");
        file.size = Some(4096);
        p.write_row(&i, &file);

        let mut gone = entry(4, FdKind::File, "/tmp/gone");
        gone.deleted = true;
        gone.size = Some(512);
        p.write_row(&i, &gone);
        p.finish();

        let text = buf.text();
        assert!(text.contains("alice"), "table shows the username: {text}");
        assert!(
            text.contains("4096"),
            "table shows the size with --sizes: {text}"
        );
        assert!(text.contains("/var/log/syslog"), "{text}");
        assert!(
            text.contains("/tmp/gone (deleted)"),
            "deleted files are tagged: {text}"
        );
        assert!(text.contains("file"), "kind tag is printed: {text}");
    }

    #[test]
    fn table_without_sizes_has_no_size_column() {
        let (p, buf) = printer(Format::Table, false, false, false, false);
        p.write_row(&info(1, None), &entry(0, FdKind::Pipe, "pipe:[42]"));
        p.finish();
        let text = buf.text();
        assert!(text.contains("pipe:[42]"), "{text}");
        assert!(
            text.contains("1000"),
            "uid shown when the name is unknown: {text}"
        );
        assert!(text.contains("pipe"), "kind tag: {text}");
    }

    #[test]
    fn table_colors_deleted_and_socket_kinds() {
        let (p, buf) = printer(Format::Table, false, false, false, true);
        let mut gone = entry(3, FdKind::File, "/tmp/x");
        gone.deleted = true;
        p.write_row(&info(1, Some("bob")), &gone);

        for (proto, local) in [
            (SockProto::Tcp, inet("127.0.0.1", 80)),
            (SockProto::Udp, inet("127.0.0.1", 53)),
            (SockProto::Unix, SockAddr::Unix("/run/a.sock".to_string())),
        ] {
            let mut e = entry(4, FdKind::Socket, "socket:[7]");
            let family = match proto {
                SockProto::Unix => AddrFamily::Unix,
                _ => AddrFamily::V4,
            };
            e.sock = Some(sock(proto, family, local, None, None));
            p.write_row(&info(1, Some("bob")), &e);
        }
        p.finish();

        let text = buf.text();
        assert!(text.contains("\x1b[31m/tmp/x (deleted)\x1b[0m"), "{text}");
        assert!(text.contains("\x1b[36mTCP"), "tcp is cyan: {text}");
        assert!(text.contains("\x1b[35mUDP"), "udp is magenta: {text}");
        assert!(text.contains("\x1b[33mUNIX"), "unix is yellow: {text}");
        assert!(text.contains("127.0.0.1:80"), "{text}");
        assert!(text.contains("/run/a.sock"), "{text}");
    }

    #[test]
    fn sock_target_string_covers_all_endpoint_shapes() {
        let local = inet("10.0.0.1", 1234);
        let remote = inet("10.0.0.2", 443);

        let both = sock(
            SockProto::Tcp,
            AddrFamily::V4,
            local.clone(),
            Some(remote.clone()),
            Some("ESTABLISHED"),
        );
        assert_eq!(
            sock_target_string(&both),
            "10.0.0.1:1234->10.0.0.2:443 (ESTABLISHED)"
        );

        let remote_only_state = sock(
            SockProto::Tcp,
            AddrFamily::V4,
            local.clone(),
            Some(remote),
            None,
        );
        assert_eq!(
            sock_target_string(&remote_only_state),
            "10.0.0.1:1234->10.0.0.2:443"
        );

        let local_only = sock(
            SockProto::Tcp,
            AddrFamily::V4,
            local.clone(),
            None,
            Some("LISTEN"),
        );
        assert_eq!(sock_target_string(&local_only), "10.0.0.1:1234 (LISTEN)");

        let bare = sock(SockProto::Udp, AddrFamily::V4, local, None, None);
        assert_eq!(sock_target_string(&bare), "10.0.0.1:1234");
    }

    #[test]
    fn json_rows_carry_optional_fields() {
        let (p, buf) = printer(Format::Json, false, false, false, false);
        let i = info(7, Some("alice"));

        let mut full = entry(3, FdKind::File, "/data/x.bin");
        full.size = Some(10);
        full.pos = Some(20);
        full.flags = Some(0o1_000_002);
        full.inode = Some(33);
        p.write_row(&i, &full);

        let ipv6 = sock(
            SockProto::Tcp,
            AddrFamily::V6,
            inet("::1", 8080),
            Some(inet("::2", 443)),
            Some("ESTABLISHED"),
        );
        let mut sock_entry = entry(4, FdKind::Socket, "socket:[9]");
        sock_entry.sock = Some(ipv6);
        p.write_row(&i, &sock_entry);

        let unix = sock(
            SockProto::Unix,
            AddrFamily::Unix,
            SockAddr::Unix("@anon".to_string()),
            None,
            None,
        );
        let mut unix_entry = entry(5, FdKind::Socket, "socket:[10]");
        unix_entry.anon_subtype = Some("eventfd".to_string());
        unix_entry.sock = Some(unix);
        p.write_row(&i, &unix_entry);
        p.finish();

        let lines: Vec<serde_json::Value> = buf
            .text()
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line is JSON"))
            .collect();
        assert_eq!(lines.len(), 3);

        assert_eq!(lines[0]["kind"], "file");
        assert_eq!(lines[0]["size"], 10);
        assert_eq!(lines[0]["pos"], 20);
        assert_eq!(lines[0]["flags"], "0o1000002");
        assert_eq!(lines[0]["inode"], 33);
        assert!(lines[0].get("sock").is_none(), "no socket object for files");

        assert_eq!(lines[1]["sock"]["family"], "ipv6");
        assert_eq!(lines[1]["sock"]["proto"], "TCP");
        assert_eq!(lines[1]["sock"]["local"], "::1:8080");
        assert_eq!(lines[1]["sock"]["state"], "ESTABLISHED");

        assert_eq!(lines[2]["anon_subtype"], "eventfd");
        assert_eq!(lines[2]["sock"]["family"], "unix");
        assert_eq!(lines[2]["sock"]["local"], "@anon");
        assert!(
            lines[2]["sock"].get("remote").is_none(),
            "absent remote is skipped"
        );
        assert!(lines[2]["sock"].get("state").is_none());
    }

    #[test]
    fn json_ipv4_socket_family() {
        let (p, buf) = printer(Format::Json, false, false, false, false);
        let mut e = entry(3, FdKind::Socket, "socket:[1]");
        e.sock = Some(sock(
            SockProto::Udp,
            AddrFamily::V4,
            inet("127.0.0.1", 53),
            None,
            Some("UNCONN"),
        ));
        p.write_row(&info(1, Some("u")), &e);
        p.finish();

        let v: serde_json::Value = serde_json::from_str(buf.text().trim()).unwrap();
        assert_eq!(v["sock"]["family"], "ipv4");
        assert_eq!(v["sock"]["proto"], "UDP");
        assert_eq!(v["sock"]["state"], "UNCONN");
    }

    #[test]
    fn csv_header_and_row() {
        let (p, buf) = printer(Format::Csv, false, false, false, false);
        let mut e = entry(3, FdKind::File, "/tmp/csv");
        e.size = Some(7);
        e.pos = Some(1);
        e.flags = Some(0o1_000_000);
        e.deleted = true;
        p.write_row(&info(42, None), &e);
        p.finish();

        let text = buf.text();
        let mut lines = text.lines();
        assert_eq!(
            lines.next().unwrap(),
            "COMMAND,PID,USER,FD,TYPE,SIZE,POS,FLAGS,DELETED,TARGET"
        );
        let row = lines.next().unwrap();
        // CSV keeps the padded TYPE column of the table format.
        assert_eq!(
            row.trim_end(),
            "demo,42,1000,3,file      ,7,1,0o1000000,true,/tmp/csv (deleted)".trim_end()
        );
    }

    #[test]
    fn terse_prints_each_pid_once() {
        let (p, buf) = printer(Format::Terse, false, false, false, false);
        let a = info(11, Some("a"));
        let b = info(22, None);
        let e = entry(3, FdKind::File, "/tmp/x");
        p.write_row(&a, &e);
        p.write_row(&a, &e); // same pid: suppressed by the thread-local cache
        p.write_row(&b, &e);
        p.write_row(&a, &e); // different pid since: printed again, deduped by the set
        p.finish();

        assert_eq!(buf.text(), "11\n22\n");
    }

    #[test]
    fn summary_reports_counts_kinds_and_shared_files() {
        let (p, buf) = printer(Format::Table, true, false, false, false);
        let i = info(5, Some("carol"));

        let mut deleted = entry(3, FdKind::File, "/tmp/old");
        deleted.deleted = true;
        deleted.size = Some(100);
        p.write_row(&i, &deleted);
        p.write_row(&i, &entry(4, FdKind::File, "/tmp/shared"));
        p.write_row(&i, &entry(5, FdKind::File, "/tmp/shared"));
        p.write_row(&i, &entry(6, FdKind::Pipe, "pipe:[1]"));
        p.finish();

        let text = buf.text();
        assert!(text.contains("DEL_BYTES"), "header: {text}");
        assert!(
            text.lines()
                .any(|l| l.contains("carol") && l.contains(" 4 ") && l.contains("100")),
            "summary line with fds/deleted bytes: {text}"
        );
        assert!(text.contains("KIND TOTALS:"), "{text}");
        assert!(
            text.contains("2x /tmp/shared"),
            "files shared by two fds are listed: {text}"
        );
        assert!(text.contains("file="), "kind totals: {text}");
        assert!(text.contains("pipe="), "{text}");
    }

    #[test]
    fn summary_without_kinds_or_shared_files_is_short() {
        let (p, buf) = printer(Format::Table, true, false, false, false);
        p.finish();
        let text = buf.text();
        assert!(text.contains("DEL_BYTES"), "{text}");
        assert!(!text.contains("KIND TOTALS:"), "{text}");
        assert!(!text.contains("TOP FILES:"), "{text}");
    }

    #[test]
    fn tree_nests_children_orphans_and_cycles() {
        let (p, buf) = printer(Format::Table, false, true, false, false);

        let mut root = info(1, Some("root"));
        root.comm = "init".to_string();
        p.write_row(&root, &entry(3, FdKind::File, "/sbin/init"));

        let mut child = info(10, Some("root"));
        child.comm = "child".to_string();
        child.ppid = Some(1);
        p.write_row(&child, &entry(4, FdKind::File, "/tmp/child"));

        let mut grandchild = info(11, Some("root"));
        grandchild.comm = "grand".to_string();
        grandchild.ppid = Some(10);
        p.write_row(&grandchild, &entry(5, FdKind::Pipe, "pipe:[2]"));

        // Orphan: parent is not in the tree.
        let mut orphan = info(20, Some("root"));
        orphan.comm = "orphan".to_string();
        orphan.ppid = Some(999);
        p.write_row(&orphan, &entry(6, FdKind::File, "/tmp/orphan"));

        // Cycle: each pid claims the other as parent, plus a self-parent.
        let mut cyc_a = info(30, Some("root"));
        cyc_a.comm = "cyc-a".to_string();
        cyc_a.ppid = Some(31);
        p.write_row(&cyc_a, &entry(7, FdKind::File, "/tmp/a"));

        let mut cyc_b = info(31, Some("root"));
        cyc_b.comm = "cyc-b".to_string();
        cyc_b.ppid = Some(30);
        p.write_row(&cyc_b, &entry(8, FdKind::File, "/tmp/b"));

        let mut self_parent = info(40, Some("root"));
        self_parent.comm = "selfy".to_string();
        self_parent.ppid = Some(40);
        p.write_row(&self_parent, &entry(9, FdKind::File, "/tmp/self"));
        p.finish();

        let text = buf.text();
        let line_of = |needle: &str| {
            text.lines()
                .find(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} missing in: {text}"))
                .to_string()
        };
        assert!(line_of("init").starts_with("init"), "roots are flush left");
        assert!(
            line_of("child").starts_with("  child"),
            "children are indented once: {text}"
        );
        assert!(
            line_of("grand").starts_with("    grand"),
            "grandchildren are indented twice: {text}"
        );
        assert!(line_of("orphan").starts_with("orphan"));
        assert!(line_of("selfy").starts_with("selfy"));
        // Both cycle members are printed exactly once (header line only).
        assert_eq!(text.matches("cyc-a").count(), 1);
        assert_eq!(text.matches("cyc-b").count(), 1);
        assert!(text.contains("pipe:[2]"), "fd rows under a process: {text}");
    }
}
