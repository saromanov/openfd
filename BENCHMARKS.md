# Benchmarks

openfd against `lsof` (5.0) and `lsfd` (util-linux 2.39) on the same system,
same minute, sequential runs of each binary.

## Methodology

- Container: `ubuntu:24.04` (Docker), lsof and lsfd installed from the
  distribution archives, openfd as the static musl release build.
- Load: one process holding **10 000** / **100 000** file descriptors
  (empty files in `/dev/shm`), started before the measurements.
- Timing: [hyperfine](https://github.com/sharkdp/hyperfine), wall clock,
  warmup 2, min-runs 5 (full scan) / 10 (filtered by the load pid).
  Memory column is hyperfine's peak resident set.
- Reproduce: `bench/run.sh 10000` and `bench/run.sh 100000` (see
  `bench/bench.sh` for the full harness).

## Results

Host: Ubuntu 24.04, 12-core desktop. `full` = scan of every visible process
(a container with ~15 processes plus the load process); `filtered` = same
scan restricted to the load process (`-p <pid>`).

### 10 000 fds

| scenario | tool | wall time | peak RSS |
|---|---|---:|---:|
| full | openfd | **106 ms** | 3.2 MiB |
| full | lsof -nw | 810 ms (7.6x) | 6.8 MiB |
| full | lsfd -n | 281 ms (2.6x) | 13.3 MiB |
| filtered | openfd | **100 ms** | 3.1 MiB |
| filtered | lsof -nw -p | 835 ms (8.3x) | 6.8 MiB |
| filtered | lsfd -n -p | 273 ms (2.7x) | 13.1 MiB |

### 100 000 fds

| scenario | tool | wall time | peak RSS |
|---|---|---:|---:|
| full | openfd | **960 ms** | 3.0 MiB |
| full | lsof -nw | 2 790 ms (2.9x) | 39.7 MiB |
| full | lsfd -n | 3 023 ms (3.2x) | 112.1 MiB |
| filtered | openfd | **934 ms** | 3.1 MiB |
| filtered | lsof -nw -p | 2 834 ms (3.0x) | 39.6 MiB |
| filtered | lsfd -n -p | 2 772 ms (3.0x) | 112.0 MiB |

### Effect of the syscall optimizations (v0.1.0 → now)

The first cut read `/proc/<pid>/fdinfo/<fd>` twice per fd (pos/flags, then
inode) and statted deleted targets three times. The single-pass fdinfo read,
the stat dedup and skipping fdinfo in human output modes cut the cost:

| scenario | before | after | delta |
|---|---:|---:|---|
| 10k, full scan | 287 ms | 106 ms | −63% |
| 10k, filtered by pid | 301 ms | 100 ms | −67% |
| 100k, full scan | 2 376 ms | 960 ms | −60% |
| 100k, filtered by pid | 2 556 ms | 934 ms | −63% |

Note: lsof/lsfd numbers were measured with the optimized openfd and shifted
with system noise (lsof 1 010 → 810 ms at 10k); openfd's relative speedup
comes from its own delta, not from their variance.

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
