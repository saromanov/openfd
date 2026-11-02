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
- **Fast.** On a desktop with ~300 processes / ~100k fds, a full terse scan
  takes ~0.3 s wall clock; the same `lsof -t -n` takes ~21 s on the same box
  (hyperfine tables land with the first release).
- **Zero unsafe, zero network.** Pure `std` in the core plus one netlink
  library: `readlink`, `fdinfo`, `stat`, netlink SOCK_DIAG. No DNS, no
  downloads, static binary, no runtime dependencies.
- **Reclaimable bytes.** `--deleted` is not just a list — it sums the disk
  space held by unlinked-but-open files (the "why didn't the disk free up
  after I deleted the log" case).
- **Sockets without shell glue.** TCP/UDP/unix endpoints and TCP states come
  from one bulk netlink SOCK_DIAG dump per scan, joined to fds by inode —
  no `ss`/`lsof`/`awk` pipelines.

## Install

Homebrew (Linux):

```sh
brew install saromanov/tap/openfd
```

From source (Rust 1.85+):

```sh
git clone https://github.com/saromanov/openfd
cd openfd
cargo install --path crates/cli
```

Prebuilt binaries: see [Releases](https://github.com/saromanov/openfd/releases).

Man page: [`man/openfd.1`](man/openfd.1) — install with
`install -Dm644 man/openfd.1 /usr/local/share/man/man1/openfd.1`.

## Usage

```
openfd [OPTIONS]

  -p, --pid <PIDS>        comma-separated pids (-p in lsof)
  -c, --command <NAMES>   comma-separated command names (comm + cmdline basename)
  -u, --user <USERS>      comma-separated users (names or uids)
  -f, --fd <FDS>          comma-separated fd numbers
      --path <SUBSTR>     match target paths by substring
      --dir <DIR>         only fds under DIR (lsof +D)
  -i, --inet [SPEC]       socket filter: bare -i, tcp, udp, unix, :443,
                          tcp:443, @127.0.0.1:8080 (literal IPs, no DNS)
  -d, --deleted           only unlinked-but-open files (reclaimable bytes)
  -t, --terse             print pids only
  -s, --summary           per-process summary + kind totals + top shared files
      --tree              group output as a process tree (table format only)
  -n, --numeric           skip username resolution (faster)
      --sizes             stat every fd and show sizes
      --top [N]           fd-leak detector: growth between two scans
      --watch             live mode: + for opened fds, - for closed ones
      --wait              block until no entry matches the filters
      --interval <SEC>    poll interval for --watch/--top/--wait (default 1)
      --nice <N>          run at this nice value (0-19) to stay polite on busy systems
  -j, --json              NDJSON output (streaming, one object per line)
      --csv               CSV output
      --color <WHEN>      auto (default) | always | never
      --completions <SHELL>  print completion script (bash/zsh/fish/powershell)
```

Groups of the same kind are OR-composed (like lsof), different groups AND-composed:

```sh
openfd -c chrome,code          # fds of chrome or code
openfd -u postgres -d          # deleted files held by postgres
openfd --path /var/log -t      # pids touching /var/log
openfd -i :443                 # who holds port 443
openfd -i tcp                  # all TCP sockets with addresses and states
openfd --watch -c python       # live fd churn of python processes
openfd --top 5 --interval 2    # fastest fd growers over 2 s
openfd --wait --path app.lock  # exit when nothing holds app.lock anymore
openfd --nice 19               # full scan without crowding out other work
openfd -s                      # 10 000 lines become ~50 per-process rows
openfd --tree -c nginx         # fds grouped under each nginx worker
```

Long scans from cron or monitoring benefit from `--nice 19`: the scan keeps
its wall-clock speed but yields the CPU whenever anything else wants it.

## Honest scope (MVP)

This MVP covers the common 20% of the lsof surface. **Not yet implemented**
(and tracked on the roadmap): `+L`/`+M` style offsets-in-memory views, NFS/FS
details, container awareness (cgroup v2 →
container id), and macOS support (Linux-only for now). If a flag is missing,
`openfd` exits with an error — scripts should keep lsof until the flag they
need lands.

## Architecture

- [`openfd-core`](crates/core) — the library: `/proc` scanner, fd classification,
  user lookup, and the `Backend` trait (platform abstraction, day-one separation
  so a macOS libproc backend can land without CLI changes).
- [`openfd`](crates/cli) — the binary: clap-based filters, streaming table /
  NDJSON / CSV printers, per-process summary with kind totals and top shared
  files, `--tree` process grouping.

Core contains no unsafe code and performs no network access.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
