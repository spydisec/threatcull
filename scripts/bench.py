# SPDX-License-Identifier: AGPL-3.0-only
"""Benchmark ThreatCull's Fetch and Compile on a synthetic list.

Usage:
    uv run python scripts/bench.py [--lines N] [--duplicates FRACTION]
                                   [--kind domain|ip] [--format plain|hosts]
                                   [--sources N] [--overlap FRACTION]
                                   [--lists-dir DIR [--generate-only]]
                                   [--keep] [--json]

The script writes a deterministic list (fixed seed) to a temporary directory,
creates a fresh data directory next to it with that list as the only enabled
Source (a ``file://`` custom Source), and then measures four steps with the
real code, in-process through the library API:

1. the first Fetch (download, parse, validate, apply);
2. a second Fetch of the unchanged list;
3. a Compile;
4. a second Compile right after the first.

``--sources N`` (1 to 50, default 1) writes N lists of ``--lines`` lines, each its
own custom Source (``custom-bench``, or ``custom-bench-1`` to ``custom-bench-N``
for several) and its own family, so they count as independent. ``--overlap F``
(0 to below 1, default 0) is the share of each later list taken from the entries
of the first; the rest are new. The first Fetch downloads all Sources in one call.
The report adds the Indicator and Sighting counts, the per-stage seconds of both
Compiles and, when the cgroup files are readable, the memory and CPU limits.

Each step runs in a fresh child process (multiprocessing, spawn), so one step's
memory high-water mark never carries over to the next. The child reports its own
peak resident set size: VmHWM from /proc on Linux (``ru_maxrss`` would carry the
parent's peak across exec), ``getrusage`` elsewhere. The numbers are comparable
between hosts of any size: a single-board computer, a small VM or a large server.

The table goes to stdout; ``--json`` prints one JSON object instead, for
comparing runs. ``--keep`` keeps the temporary directory and prints its path.
The exit status is non-zero when a step fails.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import multiprocessing
import os
import platform
import random
import resource
import shutil
import sqlite3
import string
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Literal

from threatcull.catalog_update import active_catalog
from threatcull.clock import utcnow
from threatcull.compiling import compile_outputs
from threatcull.datadir import ensure_data_dir
from threatcull.fetcher import HttpFetcher
from threatcull.fetching import fetch_all
from threatcull.outputs.files import output_path
from threatcull.store.db import connect
from threatcull.store.outputs import OutputSpec, create_output, ensure_default_outputs, get_output
from threatcull.store.runs import last_run
from threatcull.store.sources import add_custom_source, list_sources, set_enabled, sync_catalog

DB_NAME = "threatcull.db"  # the name cli.py and the web app use
SEED = 61
LISTS_META = "lists.json"
SOURCE_ID = "custom-bench"
OUTPUT_NAME = "bench"
TLDS = ("com", "net", "org", "info", "io", "xyz", "top", "shop", "online", "site", "biz")
SUBDOMAIN_SHARE = 0.3  # share of domains with a subdomain label
SUBDOMAINS = ("www", "mail", "cdn", "login", "secure", "api", "update", "portal")
COMMENT_LINES = 5
MB = 1024 * 1024
MAX_SOURCES = 50

Kind = Literal["domain", "ip"]
Format = Literal["plain", "hosts"]
StepName = Literal["fetch", "compile"]
CGROUP_ROOT = Path("/sys/fs/cgroup")
UNLIMITED_BYTES = 1024**4  # a v1 limit above 1 TB means no limit


@dataclass(frozen=True, slots=True)
class StepResult:
    """One measured step, as reported by its child process."""

    ok: bool
    seconds: float
    peak_rss_mb: float
    detail: str
    stages: dict[str, float] | None = None  # a Compile's seconds per stage


# ---- the synthetic list ------------------------------------------------------------


def _random_domain(rng: random.Random) -> str:
    label = "".join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(5, 14)))
    domain = f"{label}.{rng.choice(TLDS)}"
    if rng.random() < SUBDOMAIN_SHARE:
        domain = f"{rng.choice(SUBDOMAINS)}.{domain}"
    return domain


def _random_public_ip(rng: random.Random) -> str:
    """A public IPv4 address (``is_global``), so every line validates."""
    while True:
        address = ipaddress.IPv4Address(rng.getrandbits(32))
        if address.is_global and not address.is_multicast:
            return str(address)


def _lines(
    lines: int,
    duplicates: float,
    kind: Kind,
    rng: random.Random,
    *,
    pool: list[str] | None = None,
    overlap: float = 0.0,
) -> Iterator[str]:
    """``lines`` entries, of which about ``duplicates`` repeat an earlier one.

    With ``pool`` (the first list's distinct entries), ``round(lines * overlap)`` of
    the lines come from it and the rest are new.
    """
    make = _random_domain if kind == "domain" else _random_public_ip
    seen: list[str] = []
    shared = round(lines * overlap) if pool else 0
    if shared and pool:
        picked = rng.sample(pool, shared) if shared <= len(pool) else rng.choices(pool, k=shared)
        yield from picked
    for _ in range(lines - shared):
        if seen and rng.random() < duplicates:
            yield rng.choice(seen)
        else:
            value = make(rng)
            seen.append(value)
            yield value


def write_list(
    path: Path,
    lines: int,
    duplicates: float,
    kind: Kind,
    fmt: Format,
    *,
    index: int = 0,
    pool: list[str] | None = None,
    overlap: float = 0.0,
) -> list[str]:
    """Write list number ``index`` (0 is the first); return its distinct entries in order.

    The generator is seeded from SEED plus ``index``, so every list is reproducible.
    """
    rng = random.Random(SEED + index)  # noqa: S311 - reproducible test data, not a secret
    unique: dict[str, None] = {}
    with path.open("w", encoding="utf-8") as handle:
        for i in range(COMMENT_LINES):
            handle.write(f"# ThreatCull benchmark list, comment line {i + 1}\n")
        for value in _lines(lines, duplicates, kind, rng, pool=pool, overlap=overlap):
            unique[value] = None
            handle.write(f"0.0.0.0 {value}\n" if fmt == "hosts" else f"{value}\n")
    return list(unique)


def source_id(number: int, sources: int) -> str:
    """The Source id of list ``number`` (1-based): ``custom-bench`` when there is one."""
    return SOURCE_ID if sources == 1 else f"{SOURCE_ID}-{number}"


# ---- the data directory --------------------------------------------------------------


def prepare_data_dir(data_dir: Path, list_paths: list[Path], kind: Kind, fmt: Format) -> None:
    """A fresh data directory whose only enabled Sources are the benchmark lists.

    Mirrors ``threatcull init`` plus ``sources add-custom`` / ``enable`` /
    ``disable`` in cli.py, without printing the default Outputs' Feed Tokens.
    """
    ensure_data_dir(data_dir)
    conn = connect(data_dir / DB_NAME)
    try:
        sync_catalog(conn, active_catalog(data_dir).catalog.entries)
        ensure_default_outputs(conn)
        for source in list_sources(conn, enabled_only=True):
            set_enabled(conn, source.id, False)
        for number, list_path in enumerate(list_paths, start=1):
            sid = source_id(number, len(list_paths))
            # add_custom_source sets the family to the id, so each Source is independent.
            add_custom_source(
                conn,
                source_id=sid,
                name=f"Benchmark list {number}" if len(list_paths) > 1 else "Benchmark list",
                url=list_path.as_uri(),
                fmt=fmt,
                kind=kind,
                category="malicious",
            )
            set_enabled(conn, sid, True)
        # One Source means every entry is in the low tier: an Output that takes it,
        # so the Compile writes every unique entry for both kinds.
        create_output(
            conn, OutputSpec(OUTPUT_NAME, kind, frozenset({"malicious"}), "low", None, "plain")
        )
    finally:
        conn.close()


# ---- the measured steps (each in its own child process) ------------------------------


def _peak_rss_mb() -> float:
    """This process's peak resident set size in MB.

    On Linux, VmHWM in /proc/self/status: ru_maxrss survives exec, so a spawned
    child would report its parent's peak (the parent that generated the list).
    Elsewhere ru_maxrss, which is bytes on macOS and kilobytes on Linux.
    """
    status = Path("/proc/self/status")
    if status.exists():
        for line in status.read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) / 1024
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / MB if sys.platform == "darwin" else peak / 1024


def _run_step(step: StepName, data_dir: str, pipe: Connection) -> None:
    """Child process: run one step against ``data_dir`` and send a StepResult back."""
    started = time.perf_counter()
    stages: dict[str, float] | None = None
    try:
        conn = connect(Path(data_dir) / DB_NAME)
        try:
            if step == "fetch":
                outcomes = fetch_all(conn, HttpFetcher(spool=True), now=utcnow())
                ok = all(o.status != "failed" for o in outcomes)
                if len(outcomes) == 1:
                    (outcome,) = outcomes
                    detail = outcome.error or (
                        f"{outcome.status}: {outcome.parsed} parsed, {outcome.valid} valid, "
                        f"{outcome.invalid} invalid"
                    )
                else:
                    failed = [o.error or o.status for o in outcomes if o.status == "failed"]
                    label = "/".join(sorted({o.status for o in outcomes}))
                    detail = "; ".join(failed) or (
                        f"{label}: {sum(o.parsed for o in outcomes)} parsed, "
                        f"{sum(o.valid for o in outcomes)} valid, "
                        f"{sum(o.invalid for o in outcomes)} invalid"
                    )
            else:
                report = compile_outputs(conn, Path(data_dir) / "outputs", now=utcnow(), force=True)
                ok = report.status == "ok"
                detail = (
                    f"{report.status}: {report.counts.get(OUTPUT_NAME, 0)} entries in {OUTPUT_NAME}"
                )
                run = last_run(conn, "compile")
                stages = {k: round(v, 3) for k, v in run.timings.items()} if run else {}
        finally:
            conn.close()
    except Exception as exc:  # report any failure as a failed step, not a traceback
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    pipe.send(StepResult(ok, time.perf_counter() - started, _peak_rss_mb(), detail, stages))
    pipe.close()


def measure(step: StepName, data_dir: Path) -> StepResult:
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    child = context.Process(target=_run_step, args=(step, str(data_dir), send))
    child.start()
    send.close()
    try:
        result: StepResult = receive.recv()
    except EOFError:
        result = StepResult(False, 0.0, 0.0, f"child process exited with code {child.exitcode}")
    child.join()
    return result


# ---- report --------------------------------------------------------------------------


def _size_mb(path: Path) -> float:
    return path.stat().st_size / MB if path.exists() else 0.0


def _database_mb(data_dir: Path) -> float:
    """The database plus its write-ahead log, which holds recent writes until a checkpoint."""
    db = data_dir / DB_NAME
    return sum(_size_mb(db.with_name(db.name + suffix)) for suffix in ("", "-wal"))


def _output_mb(data_dir: Path) -> float:
    conn = connect(data_dir / DB_NAME)
    try:
        spec = get_output(conn, OUTPUT_NAME)
    finally:
        conn.close()
    return _size_mb(output_path(data_dir / "outputs", spec))


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def memory_limit_mb(root: Path = CGROUP_ROOT) -> float | None:
    """The cgroup memory limit in MB; ``None`` when unlimited or unreadable."""
    text = _read(root / "memory.max")  # cgroup v2
    if text is None:
        text = _read(root / "memory" / "memory.limit_in_bytes")  # cgroup v1
    if text is None or not text.isdigit():  # "max" means unlimited
        return None
    value = int(text)
    return None if value > UNLIMITED_BYTES else round(value / MB, 1)


def cpu_limit(root: Path = CGROUP_ROOT) -> float | None:
    """CPUs the cgroup allows, as a float; ``None`` when unlimited or unreadable."""
    text = _read(root / "cpu.max")
    if text is None:
        return None
    quota, _, period = text.partition(" ")
    if not quota.isdigit() or not period.isdigit() or int(period) == 0:  # "max 100000"
        return None
    return round(int(quota) / int(period), 2)


def cgroup_memory_peak_mb(root: Path = CGROUP_ROOT) -> float | None:
    """The cgroup's memory high-water mark in MB (``memory.peak``), or ``None``."""
    text = _read(root / "memory.peak")
    return round(int(text) / MB, 1) if text is not None and text.isdigit() else None


def _count(data_dir: Path, table: Literal["indicators", "sightings"]) -> int:
    conn = connect(data_dir / DB_NAME)
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # noqa: S608 - fixed names
        return int(row[0])
    finally:
        conn.close()


def environment() -> dict[str, Any]:
    return {
        "platform": f"{platform.system()} {platform.machine()}",
        "cpus": os.cpu_count(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "memory_limit_mb": memory_limit_mb(),
        "cpu_limit": cpu_limit(),
    }


def print_table(report: dict[str, Any]) -> None:
    env, data, steps = report["environment"], report["list"], report["steps"]
    print(
        f"ThreatCull benchmark  {env['platform']}, {env['cpus']} CPUs, "
        f"Python {env['python']}, SQLite {env['sqlite']}"
    )
    sources = data.get("sources", 1)
    shape = f"{sources} lists of " if sources > 1 else ""
    print(
        f"List: {shape}{data['lines']:,} lines ({data['kind']}, {data['format']}), "
        f"{data['unique']:,} unique, {data['size_mb']:.1f} MB"
    )
    if sources > 1:
        print(f"Sources: {sources}, overlap {data['overlap']:.0%} with the first list")
    limits = []
    if env.get("memory_limit_mb") is not None:
        limits.append(f"memory limit {env['memory_limit_mb']:,.0f} MB")
    if env.get("cpu_limit") is not None:
        limits.append(f"CPU limit {env['cpu_limit']}")
    if limits:
        print("Container: " + ", ".join(limits))
    print()
    print(f"{'Step':<18}{'Time':>10}{'Lines/s':>12}{'Peak RSS':>12}  Result")
    for name, step in steps.items():
        rate = f"{step['lines_per_second']:,.0f}" if step.get("lines_per_second") else "-"
        print(
            f"{name:<18}{step['seconds']:>9.1f}s{rate:>12}{step['peak_rss_mb']:>9.0f} MB  "
            f"{step['detail']}"
        )
        for stage, seconds in (step.get("stages") or {}).items():
            print(f"  {stage:<16}{seconds:>9.3f}s")
    print()
    print(
        f"Database: {report['database_mb_after_fetch']:.1f} MB after the first Fetch, "
        f"{report['database_mb_after_compile']:.1f} MB after the Compile"
    )
    print(f"Output file: {report['output_mb']:.1f} MB")
    print(f"Indicators: {report['indicators']:,}, Sightings: {report['sightings']:,}")
    peak = report.get("cgroup_memory_peak_mb")
    if peak is not None:
        print(f"Container memory peak: {peak:,.0f} MB")


# ---- main ----------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0] if __doc__ else None)
    parser.add_argument("--lines", type=int, default=1_000_000, help="entries in the list")
    parser.add_argument(
        "--duplicates", type=float, default=0.4, help="share of lines that repeat an earlier one"
    )
    parser.add_argument("--kind", choices=("domain", "ip"), default="domain")
    parser.add_argument("--format", dest="fmt", choices=("plain", "hosts"), default="plain")
    parser.add_argument("--sources", type=int, default=1, help="number of Sources, 1 to 50")
    parser.add_argument(
        "--overlap",
        type=float,
        default=0.0,
        help="share of each later list taken from the first list's entries",
    )
    parser.add_argument(
        "--lists-dir",
        type=Path,
        help="keep the lists here and reuse them when their parameters match",
    )
    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="write the lists to --lists-dir and stop, without measuring",
    )
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory")
    parser.add_argument("--json", action="store_true", help="print one JSON object")
    args = parser.parse_args(argv)
    if args.lines < 1:
        parser.error("--lines must be at least 1")
    if not 0 <= args.duplicates < 1:
        parser.error("--duplicates must be at least 0 and below 1")
    if not 1 <= args.sources <= MAX_SOURCES:
        parser.error(f"--sources must be between 1 and {MAX_SOURCES}")
    if not 0 <= args.overlap < 1:
        parser.error("--overlap must be at least 0 and below 1")
    if args.generate_only and args.lists_dir is None:
        parser.error("--generate-only needs --lists-dir")
    return args


def _list_params(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "lines": args.lines,
        "duplicates": args.duplicates,
        "kind": args.kind,
        "format": args.fmt,
        "sources": args.sources,
        "overlap": args.overlap,
        "seed": SEED,
    }


def _list_paths(directory: Path, args: argparse.Namespace) -> list[Path]:
    suffix = "txt" if args.fmt == "plain" else "hosts"
    return [directory / f"list-{n}.{suffix}" for n in range(1, args.sources + 1)]


def generate_lists(directory: Path, args: argparse.Namespace) -> tuple[list[Path], int]:
    """Write the lists and a ``lists.json`` with their parameters and distinct count.

    Generating holds every distinct entry in memory, so a run under a memory limit
    reuses lists written outside the limit.
    """
    directory.mkdir(parents=True, exist_ok=True)
    list_paths = _list_paths(directory, args)
    distinct: list[list[str]] = []
    for index, list_path in enumerate(list_paths):
        distinct.append(
            write_list(
                list_path,
                args.lines,
                args.duplicates,
                args.kind,
                args.fmt,
                index=index,
                pool=distinct[0] if index else None,
                overlap=args.overlap if index else 0.0,
            )
        )
    unique = len({value for entries in distinct for value in entries})
    meta = {"params": _list_params(args), "unique": unique}
    (directory / LISTS_META).write_text(json.dumps(meta), encoding="utf-8")
    return list_paths, unique


def load_lists(directory: Path, args: argparse.Namespace) -> tuple[list[Path], int] | None:
    """The lists already in ``directory``, when they were written with these parameters."""
    try:
        meta = json.loads((directory / LISTS_META).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    list_paths = _list_paths(directory, args)
    if meta.get("params") != _list_params(args) or not all(p.exists() for p in list_paths):
        return None
    return list_paths, int(meta["unique"])


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    work = Path(tempfile.mkdtemp(prefix="threatcull-bench-"))
    try:
        data_dir = work / "data"
        lists_dir = args.lists_dir or work
        loaded = load_lists(lists_dir, args) if args.lists_dir else None
        list_paths, unique = loaded or generate_lists(lists_dir, args)
        if args.generate_only:
            print(f"Wrote {len(list_paths)} lists to {lists_dir}", file=sys.stderr)
            return 0
        prepare_data_dir(data_dir, list_paths, args.kind, args.fmt)

        first = measure("fetch", data_dir)
        db_after_fetch = _database_mb(data_dir)
        indicators = _count(data_dir, "indicators") if first.ok else 0
        sightings = _count(data_dir, "sightings") if first.ok else 0
        skipped = StepResult(False, 0, 0, "skipped")
        again = measure("fetch", data_dir) if first.ok else skipped
        compiled = measure("compile", data_dir) if first.ok else skipped
        compiled_again = measure("compile", data_dir) if first.ok else skipped

        steps = {
            "first Fetch": first,
            "unchanged Fetch": again,
            "Compile": compiled,
            "second Compile": compiled_again,
        }
        report: dict[str, Any] = {
            "environment": environment(),
            "list": {
                "lines": args.lines,
                "duplicates": args.duplicates,
                "kind": args.kind,
                "format": args.fmt,
                "unique": unique,
                "size_mb": round(sum(_size_mb(path) for path in list_paths), 2),
                "sources": args.sources,
                "overlap": args.overlap,
            },
            "steps": {
                name: {k: v for k, v in asdict(step).items() if k != "stages" or v is not None}
                for name, step in steps.items()
            },
            "indicators": indicators,
            "sightings": sightings,
            "database_mb_after_fetch": round(db_after_fetch, 2),
            "database_mb_after_compile": round(_database_mb(data_dir), 2),
            "output_mb": round(_output_mb(data_dir), 2) if compiled.ok else 0.0,
            "cgroup_memory_peak_mb": cgroup_memory_peak_mb(),
        }
        if first.ok and first.seconds:
            rate = round(args.lines * args.sources / first.seconds)
            report["steps"]["first Fetch"]["lines_per_second"] = rate
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print_table(report)
        if args.keep:
            print(f"Kept {work}", file=sys.stderr)
        return 0 if all(step.ok for step in steps.values()) else 1
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
