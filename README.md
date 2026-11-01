# openfd

**lsof that answers instantly** — a fast, streaming file-descriptor scanner for Linux.

`lsof` on busy systems takes minutes, burns a full CPU core and can exhaust memory
([Red Hat knowledge base](https://access.redhat.com/solutions/7002308)). `openfd` reads
`/proc` directly, streams the result as it scans, and answers in milliseconds —
with output a human can actually read.

```console
$ openfd -p 85816
zsh                     85816 sergey            0 chr        /dev/null
zsh                     85816 sergey            1 socket     socket:[29235180]
zsh                     85816 sergey            2 socket     socket:[29235182]

$ openfd -d | head -4
chrome                 15198 sergey            5 file       /home/sergey/.config/google-chrome/BrowserMetrics/BrowserMetrics-6ADED192-3B5E.pma (deleted)
chrome                 15290 sergey           31 file       /tmp/.com.google.Chrome.Auk2yT (deleted)
chrome                 15453 sergey           23 file       /tmp/.com.google.Chrome.N8rqrE (deleted)
chrome                 15462 sergey           31 file       /tmp/.com.google.Chrome.M05bqc (deleted)
openfd: 168 deleted file(s) hold 342770063 reclaimable bytes
```

## Why

- **Streaming by construction.** The first line prints while the scan is still
  running; a full snapshot is never materialized. The lsof OOM case
  (hundreds of thousands of fds) is closed architecturally, not by tuning.
- **Zero unsafe, zero network.** Pure `std` in the core: `readlink`, `fdinfo`,
  `stat`. Static binary, no runtime dependencies.
- **Reclaimable bytes.** `--deleted` is not just a list — it sums the disk
  space held by unlinked-but-open files (the "why didn't the disk free up
  after I deleted the log" case).

## Install

From source (Rust 1.85+):

```sh
git clone https://github.com/saromanov/openfd
cd openfd
cargo install --path crates/cli
```

Prebuilt binaries: see [Releases](https://github.com/saromanov/openfd/releases).

## Usage

```
openfd [OPTIONS]

  -p, --pid <PIDS>        comma-separated pids (-p in lsof)
  -c, --command <NAMES>   comma-separated command names (comm + cmdline basename)
  -u, --user <USERS>      comma-separated users (names or uids)
  -f, --fd <FDS>          comma-separated fd numbers
      --path <SUBSTR>     match target paths by substring
  -d, --deleted           only unlinked-but-open files (reclaimable bytes)
  -t, --terse             print pids only
  -s, --summary           per-process summary instead of one line per fd
  -n, --numeric           skip username resolution (faster)
      --sizes             stat every fd and show sizes
  -j, --json              NDJSON output (streaming, one object per line)
      --csv               CSV output
```

Groups of the same kind are OR-composed (like lsof), different groups AND-composed:

```sh
openfd -c chrome,code          # fds of chrome or code
openfd -u postgres -d          # deleted files held by postgres
openfd --path /var/log -t      # pids touching /var/log
```

## Honest scope (MVP)

This MVP covers the common 20% of the lsof surface. **Not yet implemented**
(and tracked on the roadmap): `-i` socket filtering via netlink `inet_diag`
(in progress), `--watch` with live diff, `--top` fd-leak detector, `--wait`,
`+D` recursive directory filter, TCP state details, container awareness
(cgroup → container id). If a flag is missing, `openfd` exits with an error —
scripts should keep lsof until the flag they need lands.

## Architecture

- [`openfd-core`](crates/core) — the library: `/proc` scanner, fd classification,
  user lookup, and the `Backend` trait (platform abstraction, day-one separation
  so a macOS libproc backend can land without CLI changes).
- [`openfd`](crates/cli) — the binary: clap-based filters, streaming table /
  NDJSON / CSV printers, per-process summary.

Core contains no unsafe code and performs no network access.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
