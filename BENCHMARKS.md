# Benchmarks

openfd against `lsof` (4.99.4) and `lsfd` (util-linux 2.41.3) on the same system,
same minute, sequential runs of each binary.

## Methodology

- Container: `ubuntu:26.04` (Docker), lsof 4.99.4 and lsfd 2.41.3 installed
  from the distribution archives, openfd as the static musl release build.
- Load: one process holding **10 000** / **100 000** file descriptors
  (empty files in `/dev/shm`), started before the measurements.
- Timing: [hyperfine](https://github.com/sharkdp/hyperfine), wall clock,
  warmup 2, min-runs 5 (full scan) / 10 (filtered by the load pid).
  Memory column is hyperfine's peak resident set.
- Reproduce: `bench/run.sh 10000` and `bench/run.sh 100000` (see
  `bench/bench.sh` for the full harness).

## Results

Host: Ubuntu 26.04 (container) on a 12-core desktop. `full` = scan of every
visible process (a container with ~15 processes plus the load process);
`filtered` = same scan restricted to the load process (`-p <pid>`).

### 10 000 fds

| scenario | tool | wall time | peak RSS |
|---|---|---:|---:|
| full | openfd | **89 ms** | 3.4 MiB |
| full | lsof -nw | 204 ms (2.3x) | 7.4 MiB |
| full | lsfd -n | 281 ms (3.2x) | 16.2 MiB |
| filtered | openfd | **95 ms** | 3.2 MiB |
| filtered | lsof -nw -p | 204 ms (2.1x) | 7.4 MiB |
| filtered | lsfd -n -p | 287 ms (3.0x) | 15.9 MiB |

### 100 000 fds

| scenario | tool | wall time | peak RSS |
|---|---|---:|---:|
| full | openfd | **847 ms** | 3.1 MiB |
| full | lsof -nw | 1 925 ms (2.3x) | 40.1 MiB |
| full | lsfd -n | 2 679 ms (3.2x) | 136.9 MiB |
| filtered | openfd | **870 ms** | 3.4 MiB |
| filtered | lsof -nw -p | 1 964 ms (2.3x) | 40.1 MiB |
| filtered | lsfd -n -p | 2 758 ms (3.2x) | 136.7 MiB |

Note: lsof 4.99.4 is much faster than the 4.97-era build in the previous
run (810 → 204 ms at 10k, 2 790 → 1 925 ms at 100k), so the ratios above
are tighter — and still 2.1–3.2x in openfd's favor with 4.6x less memory.

### Effect of the syscall optimizations (v0.1.0 → now)

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

## CPU usage

A scan is single-threaded and CPU-bound: while it runs it takes one core
(~100% of one core, not of the machine). The optimizations above shrink the
total CPU spent (2.4 s → 1.0 s at 100k fds), and `--nice 19` keeps a scan
from crowding out other work on a busy system:

```sh
openfd --nice 19 -n          # same speed, yields the CPU to everything else
```

Streaming keeps memory flat: RSS does not grow with the fd count (3.0 MiB at
100k fds), which is the point of not materializing a snapshot.
