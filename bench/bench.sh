#!/usr/bin/env bash
# Benchmark harness, runs INSIDE the benchmark container (see bench/run.sh).
#
# Creates load process(es) holding LOAD file descriptors (files in
# /dev/shm), spread across MULTI_PROCS processes when set, then measures
# openfd against lsof and lsfd with hyperfine:
#   1. full system scan
#   2. filtered by one load process pid
#   3. socket listing (openfd -i vs lsof -i vs ss -tuanp)
#   4. reverse lookup by path (openfd --path vs lsof <file> vs fuser -v)
# When /openfd-release is mounted (the latest openfd release binary), it
# joins every scenario as the baseline.
# and records peak RSS of each full scan with /usr/bin/time -v.
#
# Scenarios 3 and 4 are inherently narrower than a full fd scan: ss only
# lists sockets, and fuser answers "who holds this file", not "what does
# this process hold". Do not compare them against openfd -p.
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
apt-get install -y -qq lsof util-linux util-linux-extra iproute2 psmisc time python3 >/dev/null

echo "lsof revision: $(lsof -v 2>&1 | sed -n 's/^[[:space:]]*revision:[[:space:]]*//p')"
echo "lsfd: $(lsfd --version 2>&1 | tail -n1)"
echo "ss: $(ss -V 2>&1 | head -n1)"
echo "fuser: $(fuser -V 2>&1 | head -n1)"

HYPERFINE=/hyperfine
[ -x "$HYPERFINE" ] || { echo "/hyperfine must be mounted (host-built hyperfine)" >&2; exit 1; }

# Optional baseline: the latest openfd release, mounted as /openfd-release.
RELEASE=/openfd-release
if [ -x "$RELEASE" ]; then
    echo "openfd release: $("$RELEASE" --version 2>&1 | head -n1)"
else
    RELEASE=""
    echo "openfd release: not mounted, skipping the baseline"
fi

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
# A file held by a loader, for the reverse-lookup scenario.
set -- "$DATA"/*
TARGET="$1"
cleanup() {
    for p in $LOAD_PIDS; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "== sanity: fd counts (first loader pid / whole scan) =="
echo "openfd: $(/openfd -n -p "$FIRST_PID" | wc -l)"
echo "lsof:   $(lsof -nw -p "$FIRST_PID" | tail -n +2 | wc -l)"
echo "lsfd:   $(lsfd -n -p "$FIRST_PID" | tail -n +2 | wc -l)"
echo "openfd full-scan rows: $(/openfd -n | wc -l)"
if [ -n "$RELEASE" ]; then
    echo "openfd release full-scan rows: $("$RELEASE" -n | wc -l)"
fi
echo "ss socket rows: $(ss -tuanp | tail -n +2 | wc -l)"
echo "fuser hits on $TARGET: $(fuser -v "$TARGET" 2>&1 | wc -l)"

# The PR build comes first so hyperfine prints every other tool relative
# to it; the release baseline goes second.
full_cmds=("/openfd -n")
filtered_cmds=("/openfd -n -p $FIRST_PID")
socket_cmds=("/openfd -n -i")
path_cmds=("/openfd -n --path $TARGET")
rss_tools=("/openfd -n")
if [ -n "$RELEASE" ]; then
    full_cmds+=("$RELEASE -n")
    filtered_cmds+=("$RELEASE -n -p $FIRST_PID")
    socket_cmds+=("$RELEASE -n -i")
    path_cmds+=("$RELEASE -n --path $TARGET")
    rss_tools+=("$RELEASE -n")
fi
full_cmds+=("lsof -nw" "lsfd -n")
filtered_cmds+=("lsof -nw -p $FIRST_PID" "lsfd -n -p $FIRST_PID")
socket_cmds+=("lsof -nw -i" "ss -tuanp")
path_cmds+=("lsof -nw $TARGET" "fuser -v $TARGET")
rss_tools+=("lsof -nw" "lsfd -n" "ss -tuanp" "fuser -v $TARGET")

echo "== hyperfine: full system scan =="
"$HYPERFINE" --style basic --warmup 2 --min-runs 5 \
    --export-json "$OUT/full.json" \
    "${full_cmds[@]}" 2>&1 | tee "$OUT/full.txt"

echo "== hyperfine: filtered by loader pid =="
"$HYPERFINE" --style basic --warmup 2 --min-runs 10 \
    --export-json "$OUT/filtered.json" \
    "${filtered_cmds[@]}" 2>&1 | tee "$OUT/filtered.txt"

echo "== hyperfine: sockets (-i) =="
"$HYPERFINE" --style basic --warmup 2 --min-runs 10 --ignore-failure \
    --export-json "$OUT/sockets.json" \
    "${socket_cmds[@]}" 2>&1 | tee "$OUT/sockets.txt"

echo "== hyperfine: reverse lookup by path =="
"$HYPERFINE" --style basic --warmup 2 --min-runs 10 --ignore-failure \
    --export-json "$OUT/path.json" \
    "${path_cmds[@]}" 2>&1 | tee "$OUT/path.txt"

echo "== peak RSS (/usr/bin/time -v) =="
for tool in "${rss_tools[@]}"; do
    rss=$(/usr/bin/time -v $tool 2>&1 >/dev/null | grep "Maximum resident" | grep -o '[0-9]*')
    echo "$tool -> $rss KB"
done | tee "$OUT/rss.txt"

echo "== done, results in $OUT =="
