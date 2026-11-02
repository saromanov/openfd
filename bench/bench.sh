#!/usr/bin/env bash
# Benchmark harness, runs INSIDE the benchmark container (see bench/run.sh).
#
# Creates a load process holding LOAD file descriptors (files in /dev/shm),
# then measures openfd against lsof and lsfd with hyperfine:
#   1. full system scan
#   2. filtered by the load process pid
# and records peak RSS of each full scan with /usr/bin/time -v.
#
# Required mounts: /openfd (the openfd binary), /bench (this directory).
set -euo pipefail

LOAD="${LOAD:-10000}"
BENCH_DIR=/bench
DATA=/dev/shm/fdbench
OUT=/bench/results
mkdir -p "$OUT" "$DATA"

echo "== container: $(. /etc/os-release && echo "$PRETTY_NAME") =="

apt-get update -qq
apt-get install -y -qq lsof util-linux util-linux-extra time python3 >/dev/null

echo "== load process: $LOAD fds =="
LOAD_PID_FILE=/tmp/fdbench.pid
python3 - "$LOAD" "$LOAD_PID_FILE" <<'PY' &
import os, signal, sys
load = int(sys.argv[1])
files = []
for i in range(load):
    files.append(open(f"/dev/shm/fdbench/f{i}", "w"))
with open(sys.argv[2], "w") as pf:
    pf.write(str(os.getpid()))
print(f"load ready: {load} fds", flush=True)
signal.pause()
PY
for _ in $(seq 100); do
    [ -s "$LOAD_PID_FILE" ] && break
    sleep 0.1
done
LOAD_PID=$(cat "$LOAD_PID_FILE")
[ -n "$LOAD_PID" ] || { echo "load process did not start" >&2; exit 1; }
sleep 0.5
echo "load pid: $LOAD_PID"

cleanup() { kill "$LOAD_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "== sanity: fd counts of the load process =="
echo "openfd: $(/openfd -n -p "$LOAD_PID" | wc -l)"
echo "lsof:   $(lsof -nw -p "$LOAD_PID" | tail -n +2 | wc -l)"
echo "lsfd:   $(lsfd -n -p "$LOAD_PID" | tail -n +2 | wc -l)"

HYPERFINE=/hyperfine
[ -x "$HYPERFINE" ] || { echo "/hyperfine must be mounted (host-built hyperfine)" >&2; exit 1; }

echo "== hyperfine: full system scan =="
"$HYPERFINE" --style basic --warmup 2 --min-runs 5 \
    --export-json "$OUT/full.json" \
    "/openfd -n" \
    "lsof -nw" \
    "lsfd -n" 2>&1 | tee "$OUT/full.txt"

echo "== hyperfine: filtered by load pid =="
"$HYPERFINE" --style basic --warmup 2 --min-runs 10 \
    --export-json "$OUT/filtered.json" \
    "/openfd -n -p $LOAD_PID" \
    "lsof -nw -p $LOAD_PID" \
    "lsfd -n -p $LOAD_PID" 2>&1 | tee "$OUT/filtered.txt"

echo "== peak RSS (full scan, /usr/bin/time -v) =="
for tool in "/openfd -n" "lsof -nw" "lsfd -n"; do
    rss=$(/usr/bin/time -v $tool 2>&1 >/dev/null | grep "Maximum resident" | grep -o '[0-9]*')
    echo "$tool -> $rss KB"
done | tee "$OUT/rss.txt"

echo "== done, results in $OUT =="
