# Roadmap

openfd is intentionally scoped: it replaces the 20% of lsof that solves 80% of
the work. Anything that would bloat the binary or slow the scan needs a strong
argument.

## Next

- **crates.io publish** — `cargo install openfd` as the first-class install path.
- **Container awareness** — pid → cgroup v2 → container id (containerd/Docker/podman)
  → container name in the output. In the k8s world lsof showing a bare pid is
  half an answer; nobody else answers "whose container is this fd in?".
- **deb/rpm packages** — via `cargo-deb`/`cargo-rpm` after launch, so apt/dnf
  users get updates without a package-manager fight.

## Later

- **macOS backend** — the `Backend` trait split exists from day one for this;
  a libproc-based backend lands behind a `macos` status. Parity with the /proc
  backend is not promised.
- **More lsof surface** — flag by flag, driven by real demand: open an issue
  with the exact lsof invocation you miss.
- **man pages in distro packages** — deb/rpm carry `man/openfd.1` automatically.

## Non-goals

- Byte-for-byte lsof output compatibility: openfd output is designed to be
  read by humans first and parsed second (JSON/CSV cover the machine case).
- Network access of any kind beyond the local netlink socket.
- Replacing full observability suites: openfd is a one-question tool —
  "who holds this file/port?" — answered instantly.
