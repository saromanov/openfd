//! Argument parsing and filters for the openfd CLI.

use std::collections::HashSet;
use std::net::IpAddr;

use openfd_core::{FdEntry, ProcessInfo, SockAddr, SockInfo, SockProto};

/// Parsed `-i` filter: lsof-style `[proto][:port][@addr]`, restricted to
/// literal IPs (no DNS - openfd performs no network access).
#[derive(Debug, Default, Clone)]
pub struct InetFilter {
    proto: Option<SockProto>,
    port: Option<u16>,
    addr: Option<IpAddr>,
    unix: bool,
}

impl InetFilter {
    /// `""` = any internet socket (like bare lsof `-i`).
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut f = InetFilter::default();
        if spec.is_empty() {
            return Ok(f);
        }
        let mut rest = spec;
        if let Some(r) = rest.strip_prefix("tcp") {
            f.proto = Some(SockProto::Tcp);
            rest = r;
        } else if let Some(r) = rest.strip_prefix("udp") {
            f.proto = Some(SockProto::Udp);
            rest = r;
        } else if let Some(r) = rest.strip_prefix("unix") {
            f.unix = true;
            rest = r;
        }
        if f.unix {
            if rest.starts_with(':') || rest.starts_with('@') {
                return Err("unix sockets accept only `unix` (no port/addr)".to_string());
            }
            if !rest.is_empty() {
                return Err(format!("unsupported -i suffix: {rest}"));
            }
            return Ok(f);
        }
        if rest.is_empty() {
            return Ok(f);
        }
        // optional @addr then optional :port (lsof order), but also accept
        // :port without addr ("tcp:443")
        if let Some(r) = rest.strip_prefix('@') {
            let (host, tail) = match r.split_once(':') {
                Some((h, t)) => (h, Some(t)),
                None => (r, None),
            };
            if host.is_empty() {
                return Err("empty address after '@'".to_string());
            }
            f.addr = Some(
                host.parse()
                    .map_err(|_| format!("not a literal IP: {host}"))?,
            );
            rest = tail.unwrap_or("");
        }
        if let Some(port_str) = rest.strip_prefix(':') {
            f.port = Some(
                port_str
                    .parse()
                    .map_err(|_| format!("invalid port: {port_str}"))?,
            );
            rest = "";
        }
        if !rest.is_empty() {
            return Err(format!("unsupported -i syntax: {spec}"));
        }
        Ok(f)
    }

    fn matches_sock(&self, sock: &SockInfo) -> bool {
        if self.unix {
            return sock.proto == SockProto::Unix;
        }
        if sock.proto == SockProto::Unix {
            return false;
        }
        if let Some(p) = self.proto
            && sock.proto != p
        {
            return false;
        }
        if let Some(want_port) = self.port {
            let port_hit = match &sock.local {
                SockAddr::Inet { port, .. } => *port == want_port,
                _ => false,
            } || sock.remote.as_ref().is_some_and(|r| match r {
                SockAddr::Inet { port, .. } => *port == want_port,
                _ => false,
            });
            if !port_hit {
                return false;
            }
        }
        if let Some(want_addr) = self.addr {
            let addr_hit = match &sock.local {
                SockAddr::Inet { addr, .. } => *addr == want_addr,
                _ => false,
            } || sock.remote.as_ref().is_some_and(|r| match r {
                SockAddr::Inet { addr, .. } => *addr == want_addr,
                _ => false,
            });
            if !addr_hit {
                return false;
            }
        }
        true
    }
}

/// Subset of the lsof 80/20 flag surface, AND-composed between groups,
/// OR-composed inside one group (like lsof).
#[derive(Debug, Default, Clone)]
pub struct Filters {
    pids: HashSet<u32>,
    users: HashSet<String>,
    commands: Vec<String>,
    paths: Vec<String>,
    fds: HashSet<i32>,
    only_deleted: bool,
    inet: Option<InetFilter>,
}

impl Filters {
    pub fn matches(&self, info: &ProcessInfo, entry: &FdEntry) -> bool {
        if self.only_deleted && !entry.deleted {
            return false;
        }
        if !self.pids.is_empty() && !self.pids.contains(&info.pid) {
            return false;
        }
        if !self.fds.is_empty() && !self.fds.contains(&entry.fd) {
            return false;
        }
        if !self.users.is_empty() {
            let uid_str = info.uid.to_string();
            let hit = self.users.iter().any(|want| match &info.username {
                Some(name) => name.eq_ignore_ascii_case(want) || want.as_str() == uid_str,
                None => want.as_str() == uid_str,
            });
            if !hit {
                return false;
            }
        }
        if !self.commands.is_empty() && !self.commands.iter().any(|c| command_matches(c, info)) {
            return false;
        }
        if !self.paths.is_empty() && !self.paths.iter().any(|p| entry.target.contains(p)) {
            return false;
        }
        if let Some(inet) = &self.inet {
            match &entry.sock {
                Some(sock) if inet.matches_sock(sock) => {}
                _ => return false,
            }
        }
        true
    }

    pub fn set_pids(&mut self, spec: &str) -> Result<(), String> {
        for part in spec.split(',') {
            let pid: u32 = part
                .trim()
                .parse()
                .map_err(|_| format!("invalid pid: {part}"))?;
            self.pids.insert(pid);
        }
        Ok(())
    }

    pub fn set_fds(&mut self, spec: &str) -> Result<(), String> {
        for part in spec.split(',') {
            let fd: i32 = part
                .trim()
                .parse()
                .map_err(|_| format!("invalid fd: {part}"))?;
            self.fds.insert(fd);
        }
        Ok(())
    }

    pub fn set_users(&mut self, spec: &str) {
        for part in spec.split(',') {
            let u = part.trim();
            if !u.is_empty() {
                self.users.insert(u.to_string());
            }
        }
    }

    pub fn set_commands(&mut self, spec: &str) {
        for part in spec.split(',') {
            let c = part.trim();
            if !c.is_empty() {
                self.commands.push(c.to_string());
            }
        }
    }

    pub fn set_paths(&mut self, spec: &str) {
        for part in spec.split(',') {
            let p = part.trim();
            if !p.is_empty() {
                self.paths.push(p.to_string());
            }
        }
    }

    pub fn set_deleted(&mut self) {
        self.only_deleted = true;
    }

    pub fn set_inet(&mut self, spec: &str) -> Result<(), String> {
        self.inet = Some(InetFilter::parse(spec)?);
        Ok(())
    }
}

/// `-c` semantics: case-insensitive match against comm and, when available,
/// the basename of the first cmdline element.
fn command_matches(want: &str, info: &ProcessInfo) -> bool {
    if info.comm.eq_ignore_ascii_case(want) {
        return true;
    }
    if let Some(cmd0) = &info.cmdline0 {
        let base = cmd0.rsplit('/').next().unwrap_or(cmd0);
        if base.eq_ignore_ascii_case(want) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfd_core::FdKind;

    fn info(pid: u32, uid: u32, comm: &str, cmdline0: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: None,
            comm: comm.to_string(),
            cmdline0: cmdline0.map(str::to_string),
            uid,
            username: Some(format!("user{uid}")),
        }
    }

    fn entry(fd: i32, target: &str, deleted: bool) -> FdEntry {
        FdEntry {
            fd,
            kind: FdKind::File,
            target: target.to_string(),
            anon_subtype: None,
            deleted,
            size: Some(10),
            pos: None,
            flags: None,
            inode: None,
            mode: None,
            sock: None,
        }
    }

    #[test]
    fn empty_filters_match_everything() {
        let f = Filters::default();
        assert!(f.matches(&info(1, 0, "init", None), &entry(3, "/tmp/x", false)));
    }

    #[test]
    fn pid_filter() {
        let mut f = Filters::default();
        f.set_pids("1,42").unwrap();
        assert!(f.matches(&info(42, 0, "x", None), &entry(0, "/tmp", false)));
        assert!(!f.matches(&info(43, 0, "x", None), &entry(0, "/tmp", false)));
    }

    #[test]
    fn pid_filter_rejects_garbage() {
        let mut f = Filters::default();
        assert!(f.set_pids("1,oops").is_err());
    }

    #[test]
    fn deleted_filter() {
        let mut f = Filters::default();
        f.set_deleted();
        assert!(f.matches(&info(1, 0, "x", None), &entry(3, "/tmp/x", true)));
        assert!(!f.matches(&info(1, 0, "x", None), &entry(3, "/tmp/x", false)));
    }

    #[test]
    fn user_filter_by_name_and_uid() {
        let mut f = Filters::default();
        f.set_users("user7,1000");
        let mut i = info(1, 7, "x", None);
        assert!(f.matches(&i, &entry(0, "/tmp", false)));
        i.uid = 1000;
        i.username = None;
        assert!(
            f.matches(&i, &entry(0, "/tmp", false)),
            "uid fallback when name is None"
        );
    }

    #[test]
    fn command_filter_matches_comm_and_basename() {
        let mut f = Filters::default();
        f.set_commands("nginx");
        assert!(f.matches(&info(1, 0, "nginx", None), &entry(0, "/tmp", false)));
        assert!(f.matches(
            &info(1, 0, "nginx: worker", Some("/usr/sbin/nginx")),
            &entry(0, "/tmp", false)
        ));
        assert!(!f.matches(&info(1, 0, "postgres", None), &entry(0, "/tmp", false)));
    }

    #[test]
    fn path_filter_and_groups() {
        let mut f = Filters::default();
        f.set_paths("/var/log");
        let _ = f.set_fds("2");
        assert!(f.matches(&info(1, 0, "x", None), &entry(2, "/var/log/syslog", false)));
        assert!(!f.matches(&info(1, 0, "x", None), &entry(2, "/etc/hosts", false)));
        assert!(!f.matches(&info(1, 0, "x", None), &entry(1, "/var/log/syslog", false)));
    }
}
