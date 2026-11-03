#!/usr/bin/env bash
# Host-side driver: run bench/bench.sh inside an ubuntu:26.04 container.
#
#   bench/run.sh [LOAD] [PROCS]
#
# LOAD = total fds held by the load (default 10000); PROCS = number of
# loader processes sharing the fds (default 1; 100 gives a realistic
# multi-process desktop shape and exercises the parallel scan).
#
# Results land in bench/results/ (JSON, hyperfine text, RSS).
set -euo pipefail
cd "$(dirname "$0")/.."

LOAD="${1:-10000}"
PROCS="${2:-1}"

# Prefer the static musl binary (immune to glibc mismatches).
BIN=target/x86_64-unknown-linux-musl/release/openfd
if [ ! -x "$BIN" ]; then
    BIN=target/release/openfd
fi
[ -x "$BIN" ] || { echo "build openfd first: cargo build --release -p openfd" >&2; exit 1; }

HYPERFINE=$(command -v hyperfine)
[ -n "$HYPERFINE" ] || { echo "hyperfine not on PATH: cargo install hyperfine" >&2; exit 1; }

mkdir -p bench/results
rm -f bench/results/*.json bench/results/*.txt

docker run --rm \
    -e LOAD="$LOAD" \
    -e MULTI_PROCS="$PROCS" \
    -v "$PWD/bench:/bench" \
    -v "$PWD/$BIN:/openfd:ro" \
    -v "$HYPERFINE:/hyperfine:ro" \
    ubuntu:26.04 \
    bash /bench/bench.sh
