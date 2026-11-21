# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com) and the project adheres
to [Semantic Versioning](https://semver.org).

## [Unreleased]

### Added

- `openfd why <path|dir|mountpoint|:port>`: explains who holds a resource,
  how (`fd`, `cwd`, `root`, `exe`, `mmap`, lock, submount), which systemd
  unit, user session, container or pod owns each pid (cgroup v1/v2), how many
  deleted-but-open bytes are held, and what to do. Hints are printed, never
  executed. `--json` emits one holder object per line plus a summary
  (`docs/json.md`); exit codes follow `fuser`/`grep` (0/1/2) and `-q` only
  sets the code.
- Core: `owner::parse_cgroup`, `mounts::parse_mountinfo`,
  `locks::parse_lock_line`, `target` detection, holder collection and the
  hint rule table, all covered by unit tests.
- `FdEntry::dev` and `FdEntry::mnt_id`: file identity and mount id for
  mount-mode matching without `stat`.
- `SockTable::time_wait`: TIME_WAIT sockets per local port.

### Changed

- The CLI accepts subcommands (`why`) while every existing flag keeps
  working at the top level.
- Mount mode matches fds by `mnt_id` and never `stat`s fds, so a dead
  network filesystem cannot block the scan.

## [0.2.1] - 2026-11-18

### Fixed

- `-i @ADDR:PORT` (for example `-i @127.0.0.1:8080`), the form documented
  in the README and `--help`, was rejected with "unsupported -i syntax".
  The address branch swallowed the colon, so the port parser never ran.

### Changed

- `netlink-sys` 0.9: the SOCK_DIAG socket now uses the `protocols` constants
  and a `bytes::BufMut` receive buffer.
- `clap_mangen` 0.3 for the man-page generator.
- Line coverage raised to 95% (was 79%); CI uploads it to Codecov and the
  README shows the badge.

## [0.2.0] - 2026-11-04

### Added

- `--tree`: process-tree grouping of fds (table format only).
- `-s` summary now prints kind totals and the top shared files.
- `--nice N`: run the scan at a low scheduling priority.
- `man/openfd.1`, committed and kept fresh by a test; shipped in release
  archives (`openfd-mangen`).
- Parallel scan: the sorted pid list splits into contiguous chunks, one
  worker thread per core (up to 32); the sink is called directly from the
  workers, so memory stays flat. Rows of one process stay ordered; rows of
  different processes may interleave. Below 32 processes the scan stays
  single-threaded.
- Filter pushdown into the scan: `-p`/`-c`/`-u` reject whole processes
  before their fd directory is opened; `-i`/`--path`/`+D`/`-f`/`--deleted`
  reject entries before the fdinfo read. Filtered scans drop from
  full-scan cost to near-instant (15 ms at 100k fds).
- `ScanOptions::sock_scope`: the netlink SOCK_DIAG dump is restricted to
  the tables the `-i` filter needs (`-i tcp` skips UDP and unix dumps).

### Changed

- `/proc/<pid>/fdinfo/<fd>` is read in a single pass (was two reads per fd).
- One `stat` per fd serves kind, inode, size and mode (was up to three for
  deleted entries).
- Human output modes (table, terse, summary, tree, watch, top, wait) skip the
  fdinfo read entirely: full scans are ~60% faster; JSON and CSV keep
  pos/flags/inode.
- Benchmarks re-run on Ubuntu 26.04 with lsof 4.99.4 and lsfd 2.41.3
  (`bench/run.sh` targets `ubuntu:26.04`; the harness records competitor
  versions and supports a multi-process load shape, `bench/run.sh 100000 100`).
- `FdSink` is now `Fn(&ProcessInfo, &FdEntry) + Send + Sync` (was
  `FnMut(..., &mut FdEntry)`): parallel scans call the sink from several
  worker threads, so shared state moves behind a `Mutex`/atomics.
- Table and JSON output are buffered (256 KiB) instead of one write
  syscall per row.

## [0.1.0] - 2026-11-01

### Added

- `/proc` backend: streaming scan of every visible process, fd classification
  (file, dir, socket, pipe, chr/blk, memfd, anon_inode), username resolution.
- Netlink `SOCK_DIAG` join: TCP/UDP (v4+v6) and unix sockets with local/remote
  addresses and TCP states, resolved by inode.
- Filters: `-p/-c/-u/-f/--path/--dir(+D)/-i [PROTO][:PORT][@ADDR]/-d`.
- Output: human table with colors, terse pid list, NDJSON (`-j`), CSV.
- Killer features: `--deleted` with reclaimable bytes, `--watch` live diff,
  `--top` fd-leak detector, `--wait`.
- `--sizes`, `-n`, `--interval`, `--color auto|always|never` (NO_COLOR aware),
  `--completions bash|zsh|fish|powershell`.
- CI (test, fmt, clippy), cross-compiled static musl release binaries with
  sha256, Dependabot.
