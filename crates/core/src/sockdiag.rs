//! netlink SOCK_DIAG backend: one bulk dump for every inet socket
//! (TCP/UDP, IPv4/IPv6) and one for every unix socket, joined to fd entries
//! by socket inode.
//!
//! Unprivileged: the kernel returns only sockets visible to the calling user.
//! Failure to open the netlink socket degrades gracefully (no socket details),
//! because /proc-only output is still correct.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::types::{AddrFamily, SockAddr, SockInfo, SockProto};

// ---- netlink message constants (include/uapi/linux/netlink.h et al) ----

const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300; // ROOT | MATCH

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_UNIX: u8 = 1;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// inet_diag state values (include/net/tcp_states.h)
const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_TIME_WAIT: u8 = 6;
const TCP_CLOSE: u8 = 7;
const TCP_CLOSE_WAIT: u8 = 8;
const TCP_LAST_ACK: u8 = 9;
const TCP_LISTEN: u8 = 10;
const TCP_CLOSING: u8 = 11;
const TCP_NEW_SYN_RECV: u8 = 12;

// unix_diag attributes (include/uapi/linux/unix_diag.h: NAME is index 0)
const UNIX_DIAG_NAME: u16 = 0;

// unix_diag_req.udiag_show flags
const UDIAG_SHOW_NAME: u32 = 0x00000001;

fn state_name(state: u8) -> Option<&'static str> {
    Some(match state {
        TCP_ESTABLISHED => "ESTABLISHED",
        TCP_SYN_SENT => "SYN-SENT",
        TCP_SYN_RECV => "SYN-RECV",
        TCP_FIN_WAIT1 => "FIN-WAIT-1",
        TCP_FIN_WAIT2 => "FIN-WAIT-2",
        TCP_TIME_WAIT => "TIME-WAIT",
        TCP_CLOSE => "CLOSE",
        TCP_CLOSE_WAIT => "CLOSE-WAIT",
        TCP_LAST_ACK => "LAST-ACK",
        TCP_LISTEN => "LISTEN",
        TCP_CLOSING => "CLOSING",
        TCP_NEW_SYN_RECV => "NEW-SYN-RECV",
        _ => return None,
    })
}

// ---- message building ----

/// nlmsghdr + payload, NLA-aligned.
fn nlmsg(msg_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let len = (16 + payload.len()) as u32;
    let mut out = Vec::with_capacity(len as usize);
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&msg_type.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // seq
    out.extend_from_slice(&0u32.to_ne_bytes()); // pid
    out.extend_from_slice(payload);
    out
}

/// inet_diag_sockid: sport(2) dport(2) src(16) dst(16) if(4) cookie(8) = 48.
const INET_DIAG_SOCKID_LEN: usize = 48;

/// inet_diag_req_v2 payload: 4 + 4 (states) + 48 = 56 bytes.
fn inet_diag_req_v2(family: u8, protocol: u8) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + INET_DIAG_SOCKID_LEN);
    p.push(family);
    p.push(protocol);
    p.push(0); // idiag_ext
    p.push(0); // pad
    p.extend_from_slice(&0xFFFFu32.to_ne_bytes()); // idiag_states: all
    // inet_diag_sockid (48 bytes of zeroes)
    p.resize(8 + INET_DIAG_SOCKID_LEN, 0);
    p
}

/// unix_diag_req payload (24 bytes).
fn unix_diag_req() -> Vec<u8> {
    let mut p = vec![AF_UNIX, 0];
    p.extend_from_slice(&0u16.to_ne_bytes()); // pad
    p.extend_from_slice(&0xFFFFu32.to_ne_bytes()); // udiag_states: all
    p.extend_from_slice(&0u32.to_ne_bytes()); // udiag_ino
    p.extend_from_slice(&UDIAG_SHOW_NAME.to_ne_bytes()); // udiag_show
    p.extend_from_slice(&0u32.to_ne_bytes()); // cookie[2]
    p.extend_from_slice(&0u32.to_ne_bytes());
    p
}

// ---- message parsing ----

struct NlMsg<'a> {
    payload: &'a [u8],
}

fn iter_nlmsgs(buf: &[u8]) -> (Vec<NlMsg<'_>>, bool) {
    // (messages, done)
    let mut msgs = Vec::new();
    let mut done = false;
    let mut off = 0usize;
    while off + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if len < 16 || off + len > buf.len() {
            break;
        }
        let msg_type = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        match msg_type {
            NLMSG_DONE => {
                done = true;
                break;
            }
            NLMSG_ERROR => {
                // error from kernel: stop, report as error by empty result
                let err = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap_or([0; 4]));
                if err != 0 {
                    done = true;
                    break;
                }
            }
            SOCK_DIAG_BY_FAMILY => {
                msgs.push(NlMsg {
                    payload: &buf[off + 16..off + len],
                });
            }
            _ => {}
        }
        off += len;
    }
    (msgs, done)
}

/// Fixed part of inet_diag_msg (72 bytes): family/state/timer/retrans (4),
/// inet_diag_sockid (48), expires/rqueue/wqueue/uid/inode (20).
struct InetHdr {
    family: u8,
    state: u8,
    sport: u16,
    dport: u16,
    inode: u64,
}

fn parse_inet_hdr(payload: &[u8]) -> Option<InetHdr> {
    if payload.len() < 72 {
        return None;
    }
    let id = &payload[4..4 + INET_DIAG_SOCKID_LEN];
    Some(InetHdr {
        family: payload[0],
        state: payload[1],
        sport: u16::from_be_bytes(id[0..2].try_into().unwrap()),
        dport: u16::from_be_bytes(id[2..4].try_into().unwrap()),
        inode: u32::from_ne_bytes(payload[68..72].try_into().unwrap()) as u64,
    })
}

fn parse_inet_addr(bytes: &[u8], family: u8) -> Option<IpAddr> {
    match family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        AF_INET6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_unix_diag(payload: &[u8]) -> Option<(u64, Option<String>)> {
    // unix_diag_msg: family(1) type(1) state(1) pad(1) ino(4) cookie(8)
    if payload.len() < 16 {
        return None;
    }
    let ino = u32::from_ne_bytes(payload[4..8].try_into().unwrap()) as u64;
    let mut name = None;
    let mut off = 16usize;
    while off + 4 <= payload.len() {
        let alen = u16::from_ne_bytes(payload[off..off + 2].try_into().unwrap()) as usize;
        let atype = u16::from_ne_bytes(payload[off + 2..off + 4].try_into().unwrap());
        if alen < 4 || off + alen > payload.len() {
            break;
        }
        if atype & 0x7fff == UNIX_DIAG_NAME {
            let raw = &payload[off + 4..off + alen];
            let end = raw.iter().rposition(|b| *b != 0).map_or(0, |pos| pos + 1);
            let trimmed = &raw[..end];
            // Abstract sockets start with NUL: render as @name (ss convention).
            let s = if !trimmed.is_empty() && trimmed[0] == 0 {
                format!("@{}", String::from_utf8_lossy(&trimmed[1..]))
            } else {
                String::from_utf8_lossy(trimmed).into_owned()
            };
            name = Some(s);
        }
        off += align4(alen);
    }
    Some((ino, name))
}

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

// ---- public dump API ----

/// Result of a socket-diagnosis round: tables keyed by socket inode.
#[derive(Debug, Default)]
pub struct SockTable {
    pub tcp: HashMap<u64, SockInfo>,
    pub udp: HashMap<u64, SockInfo>,
    pub unix: HashMap<u64, SockInfo>,
}

impl SockTable {
    pub fn len(&self) -> usize {
        self.tcp.len() + self.udp.len() + self.unix.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, inode: u64) -> Option<&SockInfo> {
        self.tcp
            .get(&inode)
            .or_else(|| self.udp.get(&inode))
            .or_else(|| self.unix.get(&inode))
    }
}

/// Dump every visible socket via netlink. Errors are reported to the caller,
/// which decides whether to degrade (no socket details) or fail.
pub fn dump_all() -> std::io::Result<SockTable> {
    let mut table = SockTable::default();
    dump_inet(IPPROTO_TCP, &mut table.tcp)?;
    dump_inet(IPPROTO_UDP, &mut table.udp)?;
    dump_unix(&mut table.unix)?;
    Ok(table)
}

fn open_diag_socket() -> std::io::Result<netlink_sys::Socket> {
    use netlink_sys::{Protocol, Socket, SocketAddr};
    let mut sock = Socket::new(Protocol::SockDiag)?;
    let _ = sock.bind_auto()?;
    sock.connect(&SocketAddr::new(0, 0))?;
    Ok(sock)
}

fn roundtrip(
    sock: &netlink_sys::Socket,
    request: Vec<u8>,
    mut sink: impl FnMut(&[u8]) -> bool,
) -> std::io::Result<()> {
    // NLM_F_* flags live in the nlmsghdr; sendmsg flags stay 0.
    sock.send(&request, 0)?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = sock.recv(&mut buf, 0)?;
        if n == 0 {
            return Ok(());
        }
        let (msgs, done) = iter_nlmsgs(&buf[..n]);
        for msg in msgs {
            if !sink(msg.payload) {
                return Ok(());
            }
        }
        if done {
            return Ok(());
        }
    }
}

fn dump_inet(protocol: u8, out: &mut HashMap<u64, SockInfo>) -> std::io::Result<()> {
    let sock = open_diag_socket()?;
    for family in [AF_INET, AF_INET6] {
        let req = nlmsg(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_REQUEST | NLM_F_DUMP,
            &inet_diag_req_v2(family, protocol),
        );
        roundtrip(&sock, req, |payload| {
            // TIME_WAIT sockets arrive as compact 72-byte bodies without inode;
            // they have no owning fd and are skipped.
            // TIME_WAIT and friends still carry the full 72-byte struct;
            // only truly truncated messages are rejected.
            if payload.len() < 72 {
                return true;
            }
            let hdr = match parse_inet_hdr(payload) {
                Some(h) => h,
                None => return true,
            };
            let InetHdr {
                family: msg_family,
                state,
                sport,
                dport,
                inode,
            } = hdr;
            if inode == 0 || (msg_family != AF_INET && msg_family != AF_INET6) {
                return true;
            }
            let id = &payload[4..4 + INET_DIAG_SOCKID_LEN];
            let info = SockInfo {
                proto: if protocol == IPPROTO_TCP {
                    SockProto::Tcp
                } else {
                    SockProto::Udp
                },
                family: if msg_family == AF_INET6 {
                    AddrFamily::V6
                } else {
                    AddrFamily::V4
                },
                local: match parse_inet_addr(&id[4..20], msg_family) {
                    Some(addr) => SockAddr::Inet { addr, port: sport },
                    None => return true,
                },
                remote: if dport == 0 {
                    None
                } else {
                    parse_inet_addr(&id[20..36], msg_family)
                        .map(|addr| SockAddr::Inet { addr, port: dport })
                },
                state: match protocol {
                    IPPROTO_TCP => state_name(state),
                    _ => {
                        if dport == 0 {
                            Some("UNCONN")
                        } else {
                            Some("ESTABLISHED")
                        }
                    }
                },
            };
            out.insert(inode, info);
            true
        })?;
    }
    Ok(())
}

fn dump_unix(out: &mut HashMap<u64, SockInfo>) -> std::io::Result<()> {
    let sock = open_diag_socket()?;
    let req = nlmsg(
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        &unix_diag_req(),
    );
    roundtrip(&sock, req, |payload| {
        if let Some((ino, name)) = parse_unix_diag(payload)
            && ino != 0
        {
            let state_byte = payload[2];
            out.insert(
                ino,
                SockInfo {
                    proto: SockProto::Unix,
                    family: AddrFamily::Unix,
                    local: SockAddr::Unix(name.unwrap_or_else(|| "(anonymous)".into())),
                    remote: None,
                    state: state_name(state_byte),
                },
            );
        }
        true
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlmsg_header_layout() {
        let m = nlmsg(0x14, 0x301, &[1, 2, 3]);
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()), 19); // 16 + 3
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), 0x14);
        assert_eq!(u16::from_ne_bytes(m[6..8].try_into().unwrap()), 0x301);
        assert_eq!(&m[16..], &[1, 2, 3]);
    }

    #[test]
    fn inet_req_size() {
        assert_eq!(inet_diag_req_v2(AF_INET, IPPROTO_TCP).len(), 56);
        assert_eq!(unix_diag_req().len(), 24);
    }

    #[test]
    fn state_names_cover_all_tcp_states() {
        for s in 1..=12u8 {
            assert!(state_name(s).is_some(), "state {s} unnamed");
        }
        assert!(state_name(0).is_none());
    }

    #[test]
    fn parse_unix_diag_with_name() {
        let mut payload = vec![AF_UNIX, 1, TCP_LISTEN, 0];
        payload.extend_from_slice(&42u32.to_ne_bytes()); // ino
        payload.extend_from_slice(&0u32.to_ne_bytes()); // cookie
        payload.extend_from_slice(&0u32.to_ne_bytes());
        // attr: name
        let name = b"/run/test.sock\0";
        let mut attr = ((4 + name.len()) as u16).to_ne_bytes().to_vec();
        attr.extend_from_slice(&UNIX_DIAG_NAME.to_ne_bytes());
        attr.extend_from_slice(name);
        payload.extend_from_slice(&attr);

        let (ino, name) = parse_unix_diag(&payload).unwrap();
        assert_eq!(ino, 42);
        assert_eq!(name.as_deref(), Some("/run/test.sock"));
    }

    #[test]
    fn parse_unix_diag_abstract() {
        let mut payload = vec![AF_UNIX, 1, TCP_ESTABLISHED, 0];
        payload.extend_from_slice(&7u32.to_ne_bytes());
        payload.extend_from_slice(&0u32.to_ne_bytes());
        payload.extend_from_slice(&0u32.to_ne_bytes());
        let raw = b"\0abstract-sock";
        let mut attr = ((4 + raw.len()) as u16).to_ne_bytes().to_vec();
        attr.extend_from_slice(&UNIX_DIAG_NAME.to_ne_bytes());
        attr.extend_from_slice(raw);
        payload.extend_from_slice(&attr);

        let (_, name) = parse_unix_diag(&payload).unwrap();
        assert_eq!(name.as_deref(), Some("@abstract-sock"));
    }

    #[test]
    fn truncated_inet_diag_is_rejected() {
        assert!(parse_inet_hdr(&[0u8; 40]).is_none());
    }

    #[test]
    fn inet_hdr_fields() {
        let mut payload = vec![AF_INET, TCP_LISTEN, 0, 0];
        // sockid: sport(2) dport(2) src(16) dst(16) if(4) cookie(8) = 48
        payload.extend_from_slice(&0x1F90u16.to_be_bytes()); // sport 8080
        payload.extend_from_slice(&0u16.to_be_bytes()); // dport 0
        payload.extend_from_slice(&[127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(&[0u8; 8]);
        payload.extend_from_slice(&[0u8; 16]); // expires/rqueue/wqueue/uid
        payload.extend_from_slice(&12345u32.to_ne_bytes()); // inode
        assert_eq!(payload.len(), 72);

        let h = parse_inet_hdr(&payload).unwrap();
        assert_eq!(h.family, AF_INET);
        assert_eq!(h.state, TCP_LISTEN);
        assert_eq!(h.sport, 8080);
        assert_eq!(h.dport, 0);
        assert_eq!(h.inode, 12345);
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn dump_all_sees_own_tcp_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let table = dump_all().expect("netlink sockdiag must work on Linux");

        let hit = table.tcp.values().find(|s| match (&s.local, s.state) {
            (SockAddr::Inet { addr, port: p }, Some("LISTEN")) => {
                *addr == IpAddr::from([127, 0, 0, 1]) && *p == port
            }
            _ => false,
        });
        assert!(
            hit.is_some(),
            "own LISTEN socket {port} must appear in inet_diag dump"
        );
    }

    #[test]
    fn dump_all_sees_unix_listener() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("diag.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let _ = listener;
        let table = dump_all().unwrap();
        let hit = table
            .unix
            .values()
            .any(|s| s.local == SockAddr::Unix(path.to_string_lossy().into_owned()));
        assert!(hit, "bound unix socket path must appear in unix_diag dump");
    }
}
