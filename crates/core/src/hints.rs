//! Hint engine for `openfd why`.
//!
//! Hints are text only: `why` never executes anything. Every hint carries a
//! reason, the rules are ordered, the first match per holder wins, and
//! hints are grouped per owner so a unit holding fifty fds produces one
//! suggestion, not fifty.

use crate::holders::{Holder, HolderKind};
use crate::owner::OwnerKind;

/// One safe, copy-pasteable suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    /// Owner label the hint belongs to (`nginx.service`, `pid 4410`, ...).
    pub owner: String,
    pub command: String,
    pub reason: String,
    /// Optional alternative that does not restart the process.
    pub alternative: Option<String>,
}

/// Build the hint list for a report. Deterministic order: the first holder
/// that produces a hint per owner wins.
pub fn build_hints(holders: &[Holder]) -> Vec<Hint> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for holder in holders {
        // A submount is a kernel object, not a process: it has no pid that
        // could be restarted or killed.
        if holder.how == HolderKind::Submount {
            continue;
        }
        let Some(hint) = hint_for(holder) else {
            continue;
        };
        let key = (hint.owner.clone(), hint.command.clone());
        if seen.insert(key) {
            out.push(hint);
        }
    }
    out
}

fn hint_for(holder: &Holder) -> Option<Hint> {
    let owner = holder.owner_key();
    match holder.owner.kind {
        OwnerKind::SystemdUnit => {
            if holder.deleted && holder.fd.is_some() {
                let size = holder
                    .size
                    .map(format_bytes)
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default();
                return Some(Hint {
                    owner,
                    command: format!("systemctl reload {}", holder.owner.name),
                    reason: format!(
                        "{} holds deleted fd {}{size}",
                        holder.comm,
                        holder.fd.unwrap_or_default()
                    ),
                    alternative: holder
                        .fd
                        .map(|fd| format!(": > /proc/{}/fd/{fd}", holder.pid)),
                });
            }
            Some(Hint {
                owner,
                command: format!("systemctl restart {}", holder.owner.name),
                reason: format!("{} ({}) holds the target", holder.comm, holder.how_label()),
                alternative: None,
            })
        }
        OwnerKind::UserService => Some(Hint {
            owner,
            command: format!("systemctl --user restart {}", holder.owner.name),
            reason: format!("{} holds the target", holder.comm),
            alternative: None,
        }),
        OwnerKind::Docker => Some(Hint {
            owner: owner.clone(),
            command: format!("docker restart {}", holder.owner.name),
            reason: format!("container {owner} holds the target"),
            alternative: None,
        }),
        OwnerKind::Podman => Some(Hint {
            owner: owner.clone(),
            command: format!("podman restart {}", holder.owner.name),
            reason: format!("container {owner} holds the target"),
            alternative: None,
        }),
        OwnerKind::Containerd => Some(Hint {
            owner: owner.clone(),
            command: format!("crictl stop {}", holder.owner.name),
            reason: format!("containerd container {owner} holds the target"),
            alternative: None,
        }),
        OwnerKind::K8sPod => Some(Hint {
            owner: owner.clone(),
            command: format!("kubectl delete pod {}", holder.owner.name),
            reason: format!("{owner} holds the target (delete or restart the workload)"),
            alternative: None,
        }),
        OwnerKind::UserSession | OwnerKind::Unknown => {
            if holder.how == HolderKind::Cwd && holder.tty.is_some() {
                let tty = holder.tty.as_deref().unwrap_or("tty");
                return Some(Hint {
                    owner: owner.clone(),
                    command: format!("cd out of {}", holder.target),
                    reason: format!(
                        "pid {} ({}, {}) has its cwd inside {}",
                        holder.pid, holder.comm, tty, holder.target
                    ),
                    alternative: None,
                });
            }
            if holder.deleted && holder.fd.is_some() {
                return Some(Hint {
                    owner,
                    command: format!(
                        ": > /proc/{}/fd/{}",
                        holder.pid,
                        holder.fd.unwrap_or_default()
                    ),
                    reason: format!(
                        "truncate in place: frees {} without a restart",
                        holder
                            .size
                            .map(format_bytes)
                            .unwrap_or_else(|| "space".to_string())
                    ),
                    alternative: None,
                });
            }
            Some(Hint {
                owner,
                command: format!("kill {}", holder.pid),
                reason: format!(
                    "last resort: pid {} ({}) holds the target via {}",
                    holder.pid,
                    holder.comm,
                    holder.how_label()
                ),
                alternative: None,
            })
        }
    }
}

/// `1.9 GiB`-style formatting for the truncate hint.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("B", 1),
    ];
    for (unit, size) in UNITS {
        if bytes >= size {
            let value = bytes as f64 / size as f64;
            return if size == 1 {
                format!("{bytes} B")
            } else {
                format!("{value:.1} {unit}")
            };
        }
    }
    "0 B".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holders::{Holder, HolderKind};
    use crate::owner::{Owner, OwnerKind};

    fn owner(kind: OwnerKind, name: &str) -> Owner {
        Owner {
            kind,
            name: name.to_string(),
            container_id: None,
            cgroup: String::new(),
        }
    }

    fn holder(owner: Owner, how: HolderKind) -> Holder {
        Holder {
            pid: 812,
            start_time: Some(1),
            comm: "app".to_string(),
            uid: 0,
            how,
            fd: Some(7),
            target: "/mnt/data/log".to_string(),
            deleted: false,
            size: None,
            lock: None,
            sock: None,
            inode: Some(1),
            dev: Some(1),
            owner,
            other_namespace: false,
            tty: None,
        }
    }

    #[test]
    fn systemd_unit_gets_a_restart_hint() {
        let hints = build_hints(&[holder(
            owner(OwnerKind::SystemdUnit, "nginx.service"),
            HolderKind::Fd,
        )]);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].command, "systemctl restart nginx.service");
        assert!(hints[0].reason.contains("holds the target"));
    }

    #[test]
    fn deleted_log_prefers_reload_with_truncate_alternative() {
        let mut h = holder(
            owner(OwnerKind::SystemdUnit, "postgresql.service"),
            HolderKind::Fd,
        );
        h.deleted = true;
        h.size = Some(2 * (1 << 30));
        let hints = build_hints(&[h]);
        assert_eq!(hints[0].command, "systemctl reload postgresql.service");
        assert!(hints[0].reason.contains("deleted fd 7"));
        assert!(hints[0].reason.contains("2.0 GiB"));
        assert_eq!(hints[0].alternative.as_deref(), Some(": > /proc/812/fd/7"));
    }

    #[test]
    fn user_service_uses_the_user_manager() {
        let hints = build_hints(&[holder(
            owner(OwnerKind::UserService, "dbus.service"),
            HolderKind::Fd,
        )]);
        assert_eq!(hints[0].command, "systemctl --user restart dbus.service");
    }

    #[test]
    fn containers_get_restart_hints() {
        let hints = build_hints(&[holder(owner(OwnerKind::Docker, "3f2a9c"), HolderKind::Fd)]);
        assert_eq!(hints[0].command, "docker restart 3f2a9c");
        let hints = build_hints(&[holder(owner(OwnerKind::Podman, "aa11bb"), HolderKind::Fd)]);
        assert_eq!(hints[0].command, "podman restart aa11bb");
        let hints = build_hints(&[holder(
            owner(OwnerKind::Containerd, "bb22cc"),
            HolderKind::Fd,
        )]);
        assert_eq!(hints[0].command, "crictl stop bb22cc");
    }

    #[test]
    fn k8s_hint_is_generic_and_makes_no_api_call() {
        let hints = build_hints(&[holder(owner(OwnerKind::K8sPod, "1f2e3d4c"), HolderKind::Fd)]);
        assert_eq!(hints[0].command, "kubectl delete pod 1f2e3d4c");
        assert!(hints[0].reason.contains("delete or restart"));
    }

    #[test]
    fn interactive_shell_cwd_gets_a_cd_hint() {
        let mut h = holder(
            owner(OwnerKind::UserSession, "user@1000/session-3"),
            HolderKind::Cwd,
        );
        h.fd = None;
        h.tty = Some("/dev/pts/3".to_string());
        let hints = build_hints(&[h]);
        assert_eq!(hints[0].command, "cd out of /mnt/data/log");
        assert!(hints[0].reason.contains("/dev/pts/3"));
    }

    #[test]
    fn deleted_file_without_owner_gets_truncate_first() {
        let mut h = holder(owner(OwnerKind::Unknown, ""), HolderKind::Fd);
        h.deleted = true;
        h.size = Some(1024);
        let hints = build_hints(&[h]);
        assert_eq!(hints[0].command, ": > /proc/812/fd/7");
        assert!(hints[0].reason.contains("1.0 KiB"));
    }

    #[test]
    fn fallback_is_kill_with_a_last_resort_note() {
        let hints = build_hints(&[holder(owner(OwnerKind::Unknown, ""), HolderKind::Fd)]);
        assert_eq!(hints[0].command, "kill 812");
        assert!(hints[0].reason.contains("last resort"));
        assert_eq!(hints[0].owner, "pid 812");
    }

    #[test]
    fn hints_are_grouped_per_owner() {
        let mut a = holder(
            owner(OwnerKind::SystemdUnit, "nginx.service"),
            HolderKind::Fd,
        );
        let mut b = a.clone();
        b.fd = Some(8);
        b.pid = 813;
        a.deleted = false;
        let hints = build_hints(&[a, b]);
        assert_eq!(hints.len(), 1, "one hint per owner, not per fd");
    }

    #[test]
    fn byte_formatting() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(3 * (1 << 30)), "3.0 GiB");
    }
}
