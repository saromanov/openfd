# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com) and the project adheres
to [Semantic Versioning](https://semver.org).

## [Unreleased]

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
