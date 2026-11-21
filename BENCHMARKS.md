# Benchmarks

openfd against `lsof` (4.99.4) and `lsfd` (util-linux 2.41.3) on the same
system, same minute, sequential runs of each binary.

## Methodology

- Container: `ubuntu:26.04` (Docker), lsof 4.99.4 and lsfd 2.41.3 installed
  from the distribution archives, openfd as the static musl release build.
- Load: file descriptors held open on empty files in `/dev/shm`, started
  before the measurements, in two shapes:
  - **single**: one process holding all 10 000 / 100 000 fds;
  - **spread**: the same total split over 10 / 100 loader processes
    (1 000 fds each) — the realistic shape for a busy desktop, and the one
    that exercises openfd's parallel scan.
- Timing: [hyperfine](https://github.com/sharkdp/hyperfine), wall clock,
  warmup 2, min-runs 5 (full scan) / 10 (filtered by a loader pid).
  Memory column is hyperfine's peak resident set.
- Reproduce: `bench/run.sh 10000` (single), `bench/run.sh 10000 10` and
  `bench/run.sh 100000 100` (spread); see `bench/bench.sh` for the harness.
  The harness prints the exact lsof/lsfd revisions it measured.
- Two extra scenarios cover tools with a narrower scope than a full fd
  scan: sockets (`openfd -i` vs `lsof -i` vs `ss -tuanp`) and reverse
  lookup by path (`openfd --path <file>` vs `lsof <file>` vs
  `fuser -v <file>`). `ss` only lists sockets and `fuser` answers "who
  holds this file", so neither is comparable with an fd scan of one
  process.

## CI

`.github/workflows/bench.yml` runs the same container harness on every
pull request with `LOAD=10000 MULTI_PROCS=10`: lsof, lsfd, ss and fuser
come from the ubuntu:26.04 packages, openfd is the static musl build of
the PR. The latest openfd release (`openfd-x86_64-linux` from GitHub
Releases) joins every scenario as the baseline, so the job shows both the
speedup over the competitors and the change since the released version.
Results are posted to the job summary and uploaded as the
`bench-results` artifact. GitHub-hosted runners share CPU, so treat the
numbers as a trend, not a gate: compare the openfd/lsof ratio between
runs rather than absolute times.

## Results

Ubuntu 26.04 container on a 12-core desktop. `full` = scan of every visible
process; `filtered` = the same scan restricted to one loader pid
(`-p <pid>`).

### 10 000 fds, one process

| scenario | tool | wall time | peak RSS |
|---|---|---:|---:|
| full | openfd | **77 ms** | 3.2 MiB |
| full | lsof -nw | 205 ms (2.7x) | 7.5 MiB |
| full | lsfd -n | 279 ms (3.6x) | 16.6 MiB |

### 100 000 fds, one process

| scenario | tool | wall time | peak RSS |
|---|---|---:|---:|
| full | openfd | **713 ms** | 3.2 MiB |
| full | lsof -nw | 2 045 ms (2.9x) | 41.8 MiB |
| full | lsfd -n | 2 835 ms (4.0x) | 140.0 MiB |

A single-process load is bounded by that process: openfd walks one
process' fds on one worker thread, like everyone else. Spread the same
fds over many processes and the parallel scan pays off:

### 10 000 fds across 10 processes (1 000 each)

| scenario | tool | wall time | peak RSS |
|---|---|---:|---:|
| full | openfd | **78 ms** | 3.2 MiB |
| full | lsof -nw | 218 ms (2.8x) | 7.4 MiB |
| full | lsfd -n | 274 ms (3.5x) | 17.4 MiB |

### 100 000 fds across 100 processes (1 000 each)

| scenario | tool | wall time | peak RSS |
|---|---|---:|---:|
| full | openfd | **475 ms** | 3.4 MiB |
| full | lsof -nw | 1 975 ms (4.2x) | 42.4 MiB |
| full | lsfd -n | 2 921 ms (6.2x) | 151.6 MiB |
| filtered | openfd | **15 ms** | 3.2 MiB |
| filtered | lsof -nw -p | 33 ms (2.2x) | 4.0 MiB |
| filtered | lsfd -n -p | 31 ms (2.0x) | 3.9 MiB |

Notes:

- lsof 4.99.4 is much faster than the 4.97-era build measured on the
  previous ubuntu:24.04 setup (810 → 205 ms at 10k single), so the ratios
  above are tighter than they used to be — and still 2.7–6.2x with
  2–45x less memory.
- Filtered scans are near-instant because the filters are pushed into the
  scan: non-matching processes never get their fd directory opened, and
  the socket dump is restricted to the protocol the `-i` filter asks for.
- Streaming keeps memory flat: RSS does not grow with the fd count
  (3.2–3.4 MiB at 100 000 fds), which is the point of not materializing
  a snapshot.

## CPU usage

A scan splits over worker threads (one per core, up to 32): total wall
time shrinks roughly with the core count for multi-process loads. Under
parallelism the total CPU is somewhat higher than a single-threaded scan
(kernel-side contention on the same dentries/tasks), which is the price
of answering in a quarter of the time. `--nice 19` keeps a scan polite on
a busy system:

```sh
openfd --nice 19 -n          # same speed, yields the CPU to everything else
```

## Effect of the syscall optimizations (v0.1.0 → now)

Measured on the previous ubuntu:24.04 setup (openfd-only numbers, so they
stay comparable across setups). The first cut read `/proc/<pid>/fdinfo/<fd>`
twice per fd (pos/flags, then inode) and statted deleted targets three times.
The single-pass fdinfo read, the stat dedup and skipping fdinfo in human
output modes cut the cost:

| scenario | before | after | delta |
|---|---:|---:|---|
| 10k, full scan | 287 ms | 106 ms | −63% |
| 10k, filtered by pid | 301 ms | 100 ms | −67% |
| 100k, full scan | 2 376 ms | 960 ms | −60% |
| 100k, filtered by pid | 2 556 ms | 934 ms | −63% |

Note: the "before" runs predate the single-pass fdinfo read; the "after"
runs are the numbers that fed the 24.04 tables. openfd's own delta, not
competitor variance, drives the speedup.
