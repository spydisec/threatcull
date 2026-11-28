# SPDX-License-Identifier: AGPL-3.0-only
"""Run scripts/bench.py in Docker containers over a matrix of sizes and limits.

Usage:
    uv run python scripts/bench_matrix.py --out results.jsonl [--image IMAGE]
        [--sizes 150000,300000] [--sources 4] [--overlap 0.3] [--duplicates 0.05]
        [--memory 512m,1g,2g,4g] [--cpus 1] [--timeout-minutes 60]
        [--resume] [--dry-run]
    uv run python scripts/bench_matrix.py --summary results.jsonl

Each combination runs in its own container with a CPU and memory limit (swap
disabled) and a fresh named volume mounted at /data, so the benchmark's files
land on real disk. The script appends one JSON line per run to ``--out`` as soon
as the run finishes. ``--summary`` prints a GitHub Markdown table from such a file.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_IMAGE = "ghcr.io/spydisec/threatcull:latest"
DEFAULT_SIZES = "150000,300000,1000000,1600000,3200000"
DEFAULT_MEMORY = "512m,1g,2g,4g"
BENCH_PATH = Path(__file__).resolve().parent / "bench.py"
FINISHED = {"ok", "oom", "timeout"}
OOM_EXIT = 137
LISTS_SUBDIR = "lists"
GENERATE_TIMEOUT = 30 * 60

_UNITS = {"": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


@dataclass(frozen=True)
class Combo:
    """One benchmark run: list size and container limits."""

    lines: int
    sources: int
    overlap: float
    duplicates: float
    memory: str
    cpus: str
    image: str

    def key(self) -> tuple[Any, ...]:
        return (
            self.lines,
            self.sources,
            self.overlap,
            self.duplicates,
            self.memory,
            self.cpus,
            self.image,
        )


@dataclass(frozen=True)
class RunResult:
    """What a runner returns for one command."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[list[str], float | None], RunResult]


def memory_bytes(text: str) -> int:
    """Convert a docker memory limit such as ``512m`` or ``2g`` to bytes."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([bkmg]?)b?", text.strip().lower())
    if match is None:
        raise ValueError(f"bad memory limit: {text!r}")
    return int(float(match.group(1)) * _UNITS[match.group(2)])


def build_matrix(
    sizes: Iterable[int],
    memories: Iterable[str],
    cpus: Iterable[str],
    *,
    sources: int,
    overlap: float,
    duplicates: float,
    image: str,
) -> list[Combo]:
    """Order runs smallest size first, then largest memory first, then CPUs as given."""
    cpu_list = list(cpus)
    mem_list = sorted(memories, key=memory_bytes, reverse=True)
    return [
        Combo(lines, sources, overlap, duplicates, memory, cpu, image)
        for lines in sorted(sizes)
        for memory in mem_list
        for cpu in cpu_list
    ]


def lists_volume_name(combo: Combo) -> str:
    """One volume of generated lists per list shape, shared by every limit."""
    shape = f"{combo.lines}-{combo.sources}-{combo.overlap}-{combo.duplicates}"
    return "threatcull-bench-lists-" + re.sub(r"[^0-9a-z-]", "-", shape)


def list_args(combo: Combo) -> list[str]:
    return [
        "--lines",
        str(combo.lines),
        "--sources",
        str(combo.sources),
        "--overlap",
        str(combo.overlap),
        "--duplicates",
        str(combo.duplicates),
        "--kind",
        "domain",
    ]


def docker_generate_args(combo: Combo, name: str, bench: Path = BENCH_PATH) -> list[str]:
    """Write the lists into their volume with no memory limit.

    Generating holds every distinct entry in memory, so under a small limit the
    generator itself would be killed before ThreatCull runs. The volume is mounted
    at ``/data``, the one path the image's user can write to.
    """
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--entrypoint",
        "python",
        "-v",
        f"{bench}:/bench.py:ro",
        "-v",
        f"{lists_volume_name(combo)}:/data",
        combo.image,
        "/bench.py",
        "--generate-only",
        "--lists-dir",
        f"/data/{LISTS_SUBDIR}",
        *list_args(combo),
    ]


def docker_run_args(
    combo: Combo, name: str, volume: str, bench: Path = BENCH_PATH, *, lists: str | None = None
) -> list[str]:
    """The exact ``docker run`` argument list for one combination.

    ``lists`` names a volume written by ``docker_generate_args``; it is mounted
    read-only and the benchmark reuses the lists in it.
    """
    reuse = ["-v", f"{lists}:/lists:ro"] if lists else []
    reuse_flag = ["--lists-dir", f"/lists/{LISTS_SUBDIR}"] if lists else []
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--cpus",
        combo.cpus,
        "--memory",
        combo.memory,
        "--memory-swap",
        combo.memory,
        "--entrypoint",
        "python",
        "-v",
        f"{bench}:/bench.py:ro",
        "-v",
        f"{volume}:/data",
        *reuse,
        combo.image,
        "/bench.py",
        "--json",
        *reuse_flag,
        *list_args(combo),
    ]


def subprocess_runner(args: list[str], timeout: float | None) -> RunResult:
    """Run a command without a shell. Raises ``subprocess.TimeoutExpired`` on timeout."""
    done = subprocess.run(  # noqa: S603
        args, capture_output=True, text=True, timeout=timeout, check=False
    )
    return RunResult(done.returncode, done.stdout, done.stderr)


def _tail(text: str, limit: int = 500) -> str:
    return text[-limit:]


def ensure_lists(combo: Combo, runner: Runner, ready: set[str]) -> str | None:
    """Generate this combination's lists once; return their volume, or None on failure."""
    volume = lists_volume_name(combo)
    if volume in ready:
        return volume
    name = f"threatcull-bench-gen-{uuid.uuid4().hex[:10]}"
    if runner(["docker", "volume", "create", volume], 60).returncode != 0:
        return None
    if runner(docker_generate_args(combo, name), GENERATE_TIMEOUT).returncode != 0:
        return None
    ready.add(volume)
    return volume


def run_combo(
    combo: Combo, timeout_minutes: float, runner: Runner, *, lists: str | None = None
) -> dict[str, Any]:
    """Run one combination and return its result record."""
    suffix = uuid.uuid4().hex[:10]
    name = f"threatcull-bench-{suffix}"
    volume = f"threatcull-bench-{suffix}"
    record: dict[str, Any] = {
        "lines": combo.lines,
        "sources": combo.sources,
        "overlap": combo.overlap,
        "duplicates": combo.duplicates,
        "memory": combo.memory,
        "cpus": combo.cpus,
        "image": combo.image,
        "status": "failed",
        "wall_seconds": 0.0,
        "report": None,
        "error": None,
    }
    started = time.monotonic()
    try:
        created = runner(["docker", "volume", "create", volume], 60)
        if created.returncode != 0:
            record["error"] = _tail(created.stderr)
            return record
        try:
            result = runner(docker_run_args(combo, name, volume, lists=lists), timeout_minutes * 60)
        except subprocess.TimeoutExpired:
            runner(["docker", "kill", name], 60)
            record["status"] = "timeout"
            return record
        _classify(record, result)
    finally:
        record["wall_seconds"] = round(time.monotonic() - started, 1)
        runner(["docker", "volume", "rm", "-f", volume], 60)
    return record


def _classify(record: dict[str, Any], result: RunResult) -> None:
    report: Any = None
    try:
        report = json.loads(result.stdout)
    except ValueError:
        report = None
    if result.returncode == 0 and isinstance(report, dict):
        record["status"] = "ok"
        record["report"] = report
    elif result.returncode == OOM_EXIT and not isinstance(report, dict):
        record["status"] = "oom"
    else:
        record["status"] = "failed"
        record["error"] = _tail(result.stderr)
        if isinstance(report, dict):
            record["report"] = report


def read_results(path: Path) -> list[dict[str, Any]]:
    """Read a JSON Lines results file; a missing file is empty."""
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def finished_keys(rows: Iterable[dict[str, Any]]) -> set[tuple[Any, ...]]:
    return {
        (
            r["lines"],
            r["sources"],
            r["overlap"],
            r["duplicates"],
            r["memory"],
            r["cpus"],
            r["image"],
        )
        for r in rows
        if r.get("status") in FINISHED
    }


def _count(value: Any) -> str:
    return "-" if value is None else f"{int(value):,}"


def _seconds(value: Any) -> str:
    return "-" if value is None else f"{float(value):,.0f} s"


def _megabytes(value: Any) -> str:
    return "-" if value is None else f"{float(value):,.0f} MB"


def _step_seconds(report: dict[str, Any] | None, step: str) -> Any:
    if not report:
        return None
    return (report.get("steps") or {}).get(step, {}).get("seconds")


def render_summary(rows: list[dict[str, Any]]) -> str:
    """A GitHub Markdown table, one row per run."""

    def sort_key(row: dict[str, Any]) -> tuple[int, int]:
        report = row.get("report") or {}
        return (int(report.get("indicators") or 0), memory_bytes(row["memory"]))

    header = [
        "Indicators",
        "Sightings",
        "Memory limit",
        "CPUs",
        "First Fetch",
        "Unchanged Fetch",
        "Compile",
        "Second Compile",
        "Database",
        "Output",
        "Container peak memory",
        "Status",
    ]
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for row in sorted(rows, key=sort_key):
        report = row.get("report")
        cells = [
            _count(report.get("indicators")) if report else "-",
            _count(report.get("sightings")) if report else "-",
            str(row["memory"]),
            str(row["cpus"]),
            _seconds(_step_seconds(report, "first Fetch")),
            _seconds(_step_seconds(report, "unchanged Fetch")),
            _seconds(_step_seconds(report, "Compile")),
            _seconds(_step_seconds(report, "second Compile")),
            _megabytes(report.get("database_mb_after_compile") if report else None),
            _megabytes(report.get("output_mb") if report else None),
            _megabytes(report.get("cgroup_memory_peak_mb") if report else None),
            str(row["status"]),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def run_matrix(
    combos: list[Combo],
    out: Path,
    *,
    timeout_minutes: float,
    resume: bool,
    dry_run: bool,
    runner: Runner = subprocess_runner,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr),
    emit: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    """Run (or print) every combination in order and append each result to ``out``."""
    if dry_run:
        for combo in combos:
            args = docker_run_args(combo, "<name>", "<volume>")
            emit(" ".join(shlex.quote(arg) for arg in args))
        return []
    skip = finished_keys(read_results(out)) if resume else set()
    results: list[dict[str, Any]] = []
    ready: set[str] = set()
    try:
        _run_all(combos, out, skip, ready, results, timeout_minutes, runner, log)
    finally:
        for volume in sorted(ready):
            runner(["docker", "volume", "rm", "-f", volume], 60)
    return results


def _run_all(  # noqa: PLR0917 - one loop split out so its volumes are always removed
    combos: list[Combo],
    out: Path,
    skip: set[tuple[Any, ...]],
    ready: set[str],
    results: list[dict[str, Any]],
    timeout_minutes: float,
    runner: Runner,
    log: Callable[[str], None],
) -> None:
    for combo in combos:
        label = (
            f"{combo.lines:,} lines x {combo.sources} Sources, "
            f"memory {combo.memory}, cpus {combo.cpus}"
        )
        if combo.key() in skip:
            log(f"skip (already finished): {label}")
            continue
        lists = ensure_lists(combo, runner, ready)
        if lists is None:
            log(f"could not generate the lists, generating inside the limit: {label}")
        log(f"start: {label}")
        record = run_combo(combo, timeout_minutes, runner, lists=lists)
        with out.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
            handle.flush()
        log(f"{record['status']} after {record['wall_seconds']:,.0f} s: {label}")
        results.append(record)


def _csv(text: str) -> list[str]:
    return [part.strip() for part in text.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--sizes", default=DEFAULT_SIZES, help="lines per Source, comma-separated")
    parser.add_argument("--sources", type=int, default=4)
    parser.add_argument("--overlap", type=float, default=0.3)
    parser.add_argument("--duplicates", type=float, default=0.05)
    parser.add_argument("--memory", default=DEFAULT_MEMORY, help="docker memory limits")
    parser.add_argument("--cpus", default="1", help="docker CPU limits, comma-separated")
    parser.add_argument("--timeout-minutes", type=float, default=60)
    parser.add_argument("--out", type=Path, help="JSON Lines file to append results to")
    parser.add_argument("--resume", action="store_true", help="skip finished combinations")
    parser.add_argument("--dry-run", action="store_true", help="print docker commands only")
    parser.add_argument("--summary", type=Path, help="print a Markdown table from a results file")
    return parser


def main(argv: list[str] | None = None, runner: Runner = subprocess_runner) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.summary is not None:
        print(render_summary(read_results(args.summary)))
        return 0
    if args.out is None:
        parser.error("--out is required")
    combos = build_matrix(
        [int(size) for size in _csv(args.sizes)],
        _csv(args.memory),
        _csv(args.cpus),
        sources=args.sources,
        overlap=args.overlap,
        duplicates=args.duplicates,
        image=args.image,
    )
    run_matrix(
        combos,
        args.out,
        timeout_minutes=args.timeout_minutes,
        resume=args.resume,
        dry_run=args.dry_run,
        runner=runner,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
