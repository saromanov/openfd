#!/usr/bin/env python3
"""Render bench/results/*.json (hyperfine) and rss.txt as a markdown summary.

Used by the CI benchmark job to post the numbers into the job summary.
Supports both hyperfine JSON layouts: the current one nests per-metric
statistics under ``summary``, the legacy one keeps mean/stddev/min/max at
the top level.
"""

import json
import pathlib
import re

RESULTS = pathlib.Path(__file__).resolve().parent / "results"


def millis(seconds):
    return f"{seconds * 1000:.1f}"


def wall_and_memory(run):
    summary = run.get("summary")
    if summary:
        return summary["time_wall_clock"], summary.get("memory_peak_resident")
    return run, None


def hyperfine_table(scenario, path):
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    lines = [
        f"#### {scenario}",
        "",
        "| command | mean, ms | ± σ | min | max | peak RSS, MiB |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for run in data["results"]:
        wall, memory = wall_and_memory(run)
        memory_mib = f"{memory['mean'] / 2**20:.1f}" if memory else "—"
        lines.append(
            f"| `{run['command']}` | {millis(wall['mean'])} | "
            f"{millis(wall['stddev'])} | {millis(wall['min'])} | "
            f"{millis(wall['max'])} | {memory_mib} |"
        )
    lines.append("")
    return lines


def rss_table(path):
    if not path.exists():
        return []
    lines = [
        "#### Peak RSS (/usr/bin/time -v)",
        "",
        "| command | peak RSS, MiB |",
        "|---|---:|",
    ]
    for line in path.read_text().splitlines():
        match = re.match(r"^(.*?) -> (\d+) KB$", line)
        if match:
            mib = int(match.group(2)) / 1024
            lines.append(f"| `{match.group(1)}` | {mib:.1f} |")
    lines.append("")
    return lines


def main():
    lines = ["### openfd benchmarks", ""]
    for scenario in ("full", "filtered", "sockets", "path"):
        lines += hyperfine_table(scenario, RESULTS / f"{scenario}.json")
    lines += rss_table(RESULTS / "rss.txt")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
