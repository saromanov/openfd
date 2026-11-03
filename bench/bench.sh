#!/usr/bin/env bash
# Benchmark harness, runs INSIDE the benchmark container (see bench/run.sh).
#
# Creates load process(es) holding LOAD file descriptors (files in
# /dev/shm), spread across MULTI_PROCS processes when set, then measures
# openfd against lsof and lsfd with hyperfine:
#   1. full system scan
#   2. filtered by one load process pid
# and records peak RSS of each full scan with /usr/bin/time -v.
#
# Required mounts: /openfd (the openfd binary), /bench (this directory).
set -euo pipefail

LOAD="${LOAD:-10000}"
MULTI="${MULTI_PROCS:-1}"
BENCH_DIR=/bench
DATA=/dev/shm/fdbench
OUT=/bench/results
mkdir -p "$OUT" "$DATA"
rm -rf "$DATA"/*

echo "== container: $(. /etc/os-release && echo "$PRETTY_NAME") =="

apt-get update -qq
apt-get install -y -qq lsof util-linux util-linux-extra time python3 >/dev/null

echo "lsof revision: $(lsof -v 2>&1 | sed -n 's/^[[:space:]]*revision:[[:space:]]*//p')"
echo "lsfd: $(lsfd --version 2>&1 | tail -n1)"

HYPERFINE=/hyperfine
[ -x "$HYPERFINE" ] || { echo "/hyperfine must be mounted (host-built hyperfine)" >&2; exit 1; }

# One loader process: opens its share of fds, writes its pid file, waits.
load_one() {
python3 - "$1" "$2" "$3" <<'PY'
import os, resource, signal, sys
share = int(sys.argv[1])
tag = sys.argv[2]
pidfile = sys.argv[3]
hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
files = []
for i in range(share):
    files.append(open(f"/dev/shm/fdbench/f{tag}_{i}", "w"))
with open(pidfile, "w") as pf:
    pf.write(f"{os.getpid()}\n")
print(f"loader {tag} ready: {share} fds", flush=True)
signal.pause()
PY
}

if [ "$MULTI" -le 1 ]; then
    echo "== load process: $LOAD fds =="
    LOAD_PID_FILE=/tmp/fdbench.pid
    load_one "$LOAD" "single" "$LOAD_PID_FILE" &
    for _ in $(seq 100); do
        [ -s "$LOAD_PID_FILE" ] && break
        sleep 0.1
    done
    LOAD_PIDS=$(cat "$LOAD_PID_FILE")
else
    echo "== load processes: $MULTI x $((LOAD / MULTI)) fds =="
    LOAD_PIDS=""
    for i in $(seq "$MULTI"); do
        PID_FILE="/tmp/fdbench.$i.pid"
        load_one "$((LOAD / MULTI))" "$i" "$PID_FILE" &
    done
    for _ in $(seq 300); do
        n=$(find /tmp -maxdepth 1 -name 'fdbench.*.pid' | wc -l)
        if [ "$n" -ge "$MULTI" ]; then break; fi
        sleep 0.1
    done
    LOAD_PIDS=$(cat /tmp/fdbench.*.pid | tr '\n' ' ')
fi
sleep 0.5
echo "load pids: $LOAD_PIDS"

FIRST_PID=$(echo "$LOAD_PIDS" | awk '{print $1}')
cleanup() {
    for p in $LOAD_PIDS; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "== sanity: fd counts (first loader pid / whole scan) =="
echo "openfd: $(/openfd -n -p "$FIRST_PID" | wc -l)"
echo "lsof:   $(lsof -nw -p "$FIRST_PID" | tail -n +2 | wc -l)"
echo "lsfd:   $(lsfd -n -p "$FIRST_PID" | tail -n +2 | wc -l)"
echo "openfd full-scan rows: $(/openfd -n | wc -l)"

echo "== hyperfine: full system scan =="
"$HYPERFINE" --style basic --warmup 2 --min-runs 5 \
    --export-json "$OUT/full.json" \
    "/openfd -n" \
    "lsof -nw" \
    "lsfd -n" 2>&1 | tee "$OUT/full.txt"

echo "== hyperfine: filtered by loader pid =="
"$HYPERFINE" --style basic --warmup 2 --min-runs 10 \
    --export-json "$OUT/filtered.json" \
    "/openfd -n -p $FIRST_PID" \
    "lsof -nw -p $FIRST_PID" \
    "lsfd -n -p $FIRST_PID" 2>&1 | tee "$OUT/filtered.txt"

echo "== peak RSS (full scan, /usr/bin/time -v) =="
for tool in "/openfd -n" "lsof -nw" "lsfd -n"; do
    rss=$(/usr/bin/time -v $tool 2>&1 >/dev/null | grep "Maximum resident" | grep -o '[0-9]*')
    echo "$tool -> $rss KB"
done | tee "$OUT/rss.txt"

echo "== done, results in $OUT =="
