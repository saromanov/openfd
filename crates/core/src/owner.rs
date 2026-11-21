//! Owner resolution: map a process to the systemd unit, user session,
//! container or Kubernetes pod it belongs to, using `/proc/<pid>/cgroup`
//! only.
//!
//! The parser is a pure function so the whole matrix (cgroup v1 and v2,
//! Docker cgroupfs and systemd drivers, Podman, containerd, k8s, user
//! sessions) is unit-tested with fixtures and never needs a live container
//! runtime. No sockets, no network.

/// Kind of owner a cgroup path resolves to. The tag is part of the JSON
/// output and stays stable for scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerKind {
    SystemdUnit,
    UserSession,
    UserService,
    Docker,
    Podman,
    Containerd,
    K8sPod,
    Unknown,
}

impl OwnerKind {
    pub fn tag(self) -> &'static str {
        match self {
            OwnerKind::SystemdUnit => "systemd_unit",
            OwnerKind::UserSession => "user_session",
            OwnerKind::UserService => "user_service",
            OwnerKind::Docker => "docker",
            OwnerKind::Podman => "podman",
            OwnerKind::Containerd => "containerd",
            OwnerKind::K8sPod => "k8s_pod",
            OwnerKind::Unknown => "unknown",
        }
    }
}

/// Resolved owner of one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub kind: OwnerKind,
    /// Unit name, session name, pod uid or 12-char container id.
    pub name: String,
    /// Container id when the owner is a container or a pod.
    pub container_id: Option<String>,
    /// Raw cgroup path, always kept so `--json` can show the source.
    pub cgroup: String,
}

impl Owner {
    /// A short label for the OWNER column and hint grouping.
    pub fn label(&self) -> String {
        match self.kind {
            OwnerKind::SystemdUnit | OwnerKind::UserService => self.name.clone(),
            OwnerKind::UserSession => self.name.clone(),
            OwnerKind::Docker => format!("docker:{}", self.name),
            OwnerKind::Podman => format!("podman:{}", self.name),
            OwnerKind::Containerd => format!("containerd:{}", self.name),
            OwnerKind::K8sPod => match (self.name.is_empty(), &self.container_id) {
                (true, Some(id)) => format!("k8s pod (container {id})"),
                (true, None) => "k8s pod".to_string(),
                (false, Some(id)) => format!("k8s pod {} (container {id})", self.name),
                (false, None) => format!("k8s pod {}", self.name),
            },
            OwnerKind::Unknown => "unknown".to_string(),
        }
    }

    fn unknown(cgroup: &str) -> Self {
        Owner {
            kind: OwnerKind::Unknown,
            name: String::new(),
            container_id: None,
            cgroup: cgroup.to_string(),
        }
    }
}

/// Parse `/proc/<pid>/cgroup` into the process owner.
///
/// cgroup v2 writes one `0::<path>` line; cgroup v1 writes one line per
/// controller. For v1 the `name=systemd` line wins (that is the hierarchy
/// systemd, Docker and Podman agree on for scopes), then the `cpu` line,
/// then the first line.
pub fn parse_cgroup(content: &str) -> Owner {
    let path = cgroup_path(content);
    classify_path(&path).unwrap_or_else(|| Owner::unknown(&path))
}

/// Extract the most useful cgroup path from a cgroup file.
fn cgroup_path(content: &str) -> String {
    let mut systemd = None;
    let mut cpu = None;
    let mut first = None;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: hierarchy-ID:controller-list:cgroup-path. The path may
        // itself contain colons, so split only twice.
        let mut parts = line.splitn(3, ':');
        let (Some(_hierarchy), Some(controllers), Some(path)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let path = path.trim();
        if controllers.is_empty() {
            // cgroup v2: 0::/path
            return path.to_string();
        }
        if first.is_none() {
            first = Some(path.to_string());
        }
        if controllers.split(',').any(|c| c == "name=systemd") {
            systemd = Some(path.to_string());
        } else if cpu.is_none() && controllers.split(',').any(|c| c == "cpu") {
            cpu = Some(path.to_string());
        }
    }
    systemd.or(cpu).or(first).unwrap_or_default()
}

/// First hex run of at least 12 characters: container ids are 64 hex chars,
/// and systemd scopes carry the full id in their name (`docker-<id>.scope`).
fn long_id(path: &str) -> Option<String> {
    path.split(|c: char| !c.is_ascii_hexdigit())
        .filter(|s| s.len() >= 12)
        .map(|s| s[..12].to_string())
        .next()
}

/// Container id of the innermost cgroup component. The runtime marker is
/// preferred (`cri-containerd-<id>`, `docker-<id>`), otherwise the whole
/// component is used (k8s cgroupfs layout ends with the bare id).
fn container_id(path: &str) -> Option<String> {
    let last = path.rsplit('/').next().unwrap_or(path);
    for marker in [
        "cri-containerd-",
        "containerd-",
        "cri-o-",
        "docker-",
        "libpod-",
    ] {
        if let Some(rest) = last.split(marker).nth(1) {
            return long_id(rest);
        }
    }
    long_id(last)
}

/// `pod<uid with underscores>`: k8s writes the uid with underscores in
/// place of dashes.
fn k8s_pod_uid(path: &str) -> Option<String> {
    // `rsplit_once` skips the `kubepods` wrapper and finds the `pod<uid>`
    // component, which is the innermost one.
    let (_, rest) = path.rsplit_once("pod")?;
    let raw: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if raw.len() >= 32 {
        Some(raw.replace('_', "-"))
    } else {
        None
    }
}

fn classify_path(path: &str) -> Option<Owner> {
    if path.is_empty() || path == "/" {
        return Some(Owner::unknown(path));
    }

    // Kubernetes takes precedence: its cgroups also contain a container id.
    if path.contains("kubepods") {
        let id = container_id(path);
        let name = k8s_pod_uid(path).unwrap_or_default();
        return Some(Owner {
            kind: OwnerKind::K8sPod,
            name,
            container_id: id,
            cgroup: path.to_string(),
        });
    }

    for (marker, kind) in [
        ("docker", OwnerKind::Docker),
        ("libpod", OwnerKind::Podman),
        ("cri-containerd", OwnerKind::Containerd),
    ] {
        if path.contains(marker)
            && let Some(id) = container_id(path)
        {
            return Some(Owner {
                kind,
                name: id.clone(),
                container_id: Some(id),
                cgroup: path.to_string(),
            });
        }
    }

    // User session: /user.slice/user-1000.slice/session-3.scope
    if let Some(rest) = path
        .split("user.slice")
        .nth(1)
        .and_then(|r| r.split_once("session-"))
    {
        let n = rest
            .1
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>();
        let uid: String = path
            .split("user-")
            .nth(1)
            .map(|r| r.chars().take_while(|c| c.is_ascii_digit()).collect())
            .unwrap_or_default();
        if !n.is_empty() {
            let name = if uid.is_empty() {
                format!("session-{n}")
            } else {
                format!("user@{uid}/session-{n}")
            };
            return Some(Owner {
                kind: OwnerKind::UserSession,
                name,
                container_id: None,
                cgroup: path.to_string(),
            });
        }
    }

    // User service: .../user@1000.service/app.slice/foo.service
    if path.contains("user.slice")
        && let Some(unit) = path
            .split('/')
            .rev()
            .find(|part| part.ends_with(".service"))
    {
        return Some(Owner {
            kind: OwnerKind::UserService,
            name: unit.to_string(),
            container_id: None,
            cgroup: path.to_string(),
        });
    }

    if path.contains("system.slice")
        && let Some(unit) = path
            .split('/')
            .rev()
            .find(|part| part.ends_with(".service"))
    {
        return Some(Owner {
            kind: OwnerKind::SystemdUnit,
            name: unit.to_string(),
            container_id: None,
            cgroup: path.to_string(),
        });
    }

    Some(Owner::unknown(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind_and_name(content: &str) -> (OwnerKind, String) {
        let o = parse_cgroup(content);
        (o.kind, o.name)
    }

    #[test]
    fn cgroup_v2_systemd_service() {
        let (kind, name) = kind_and_name("0::/system.slice/nginx.service\n");
        assert_eq!(kind, OwnerKind::SystemdUnit);
        assert_eq!(name, "nginx.service");
    }

    #[test]
    fn cgroup_v1_prefers_the_systemd_hierarchy() {
        let content = "\
12:cpu,cpuacct:/docker/3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c
1:name=systemd:/system.slice/sshd.service
";
        let (kind, name) = kind_and_name(content);
        assert_eq!(kind, OwnerKind::SystemdUnit);
        assert_eq!(name, "sshd.service");
    }

    #[test]
    fn cgroup_v1_falls_back_to_cpu_then_first() {
        let content = "\
4:memory:/system.slice/cron.service
2:cpu:/user.slice/user-1000.slice/session-2.scope
";
        let (kind, name) = kind_and_name(content);
        assert_eq!(kind, OwnerKind::UserSession);
        assert_eq!(name, "user@1000/session-2");

        let (kind, name) = kind_and_name("4:memory:/system.slice/cron.service\n");
        assert_eq!(kind, OwnerKind::SystemdUnit);
        assert_eq!(name, "cron.service");
    }

    #[test]
    fn docker_systemd_scope_and_cgroupfs_driver() {
        for content in [
            "0::/system.slice/docker-3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c.scope\n",
            "0::/docker/3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c\n",
        ] {
            let o = parse_cgroup(content);
            assert_eq!(o.kind, OwnerKind::Docker, "{content}");
            assert_eq!(o.name, "3f2a9c1e8b7d");
            assert_eq!(o.container_id.as_deref(), Some("3f2a9c1e8b7d"));
        }
    }

    #[test]
    fn podman_scope() {
        let o = parse_cgroup(
            "0::/machine.slice/libpod-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b.scope\n",
        );
        assert_eq!(o.kind, OwnerKind::Podman);
        assert_eq!(o.name, "1a2b3c4d5e6f");
    }

    #[test]
    fn containerd_scope() {
        let o = parse_cgroup(
            "0::/system.slice/containerd.service/cri-containerd-aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66.scope\n",
        );
        assert_eq!(o.kind, OwnerKind::Containerd);
        assert_eq!(o.container_id.as_deref(), Some("aa11bb22cc33"));
    }

    #[test]
    fn k8s_pod_with_container_id() {
        let o = parse_cgroup(
            "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1f2e3d4c_5b6a_7c8d_9e0f_1a2b3c4d5e6f.slice/cri-containerd-aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66.scope\n",
        );
        assert_eq!(o.kind, OwnerKind::K8sPod);
        assert_eq!(o.name, "1f2e3d4c-5b6a-7c8d-9e0f-1a2b3c4d5e6f");
        assert_eq!(o.container_id.as_deref(), Some("aa11bb22cc33"));
        assert!(o.label().contains("k8s pod"));
        assert!(o.label().contains("aa11bb22cc33"));
    }

    #[test]
    fn k8s_pod_without_uid_still_resolves() {
        let o = parse_cgroup("0::/kubepods/pod1234/abcdef0123456789\n");
        assert_eq!(o.kind, OwnerKind::K8sPod);
        assert_eq!(o.name, "");
        assert_eq!(o.label(), "k8s pod (container abcdef012345)");
    }

    #[test]
    fn user_service_under_user_slice() {
        let o = parse_cgroup(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service\n",
        );
        assert_eq!(o.kind, OwnerKind::UserService);
        assert_eq!(o.name, "dbus.service");
        assert_eq!(o.label(), "dbus.service");
    }

    #[test]
    fn root_session_has_no_uid_prefix() {
        let o = parse_cgroup("0::/user.slice/user-0.slice/session-1.scope\n");
        assert_eq!(o.kind, OwnerKind::UserSession);
        assert_eq!(o.name, "user@0/session-1");
    }

    #[test]
    fn unknown_and_empty_paths() {
        assert_eq!(parse_cgroup("0::/\n").kind, OwnerKind::Unknown);
        assert_eq!(parse_cgroup("").kind, OwnerKind::Unknown);
        assert_eq!(parse_cgroup("garbage\n").kind, OwnerKind::Unknown);
        let o = parse_cgroup("0::/custom.slice/foo\n");
        assert_eq!(o.kind, OwnerKind::Unknown);
        assert_eq!(o.cgroup, "/custom.slice/foo");
        assert_eq!(o.label(), "unknown");
    }

    #[test]
    fn owner_kind_tags_are_stable() {
        let all = [
            (OwnerKind::SystemdUnit, "systemd_unit"),
            (OwnerKind::UserSession, "user_session"),
            (OwnerKind::UserService, "user_service"),
            (OwnerKind::Docker, "docker"),
            (OwnerKind::Podman, "podman"),
            (OwnerKind::Containerd, "containerd"),
            (OwnerKind::K8sPod, "k8s_pod"),
            (OwnerKind::Unknown, "unknown"),
        ];
        for (kind, tag) in all {
            assert_eq!(kind.tag(), tag);
        }
    }

    #[test]
    fn labels_of_container_kinds() {
        let o = parse_cgroup(
            "0::/docker/3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c\n",
        );
        assert_eq!(o.label(), "docker:3f2a9c1e8b7d");
        let o = parse_cgroup(
            "0::/machine.slice/libpod-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b.scope\n",
        );
        assert_eq!(o.label(), "podman:1a2b3c4d5e6f");
        let o = parse_cgroup(
            "0::/system.slice/containerd.service/cri-containerd-aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66.scope\n",
        );
        assert_eq!(o.label(), "containerd:aa11bb22cc33");
    }
}
