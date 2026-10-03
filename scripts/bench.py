# SPDX-License-Identifier: AGPL-3.0-only
"""Benchmark ThreatCull's Fetch and Compile on a synthetic list.

Usage:
    uv run python scripts/bench.py [--lines N] [--duplicates FRACTION]
                                   [--kind domain|ip] [--format plain|hosts]
                                   [--keep] [--json]

The script writes a deterministic list (fixed seed) to a temporary directory,
creates a fresh data directory next to it with that list as the only enabled
Source (a ``file://`` custom Source), and then measures three steps with the
real code, in-process through the library API:

1. the first Fetch (download, parse, validate, apply);
2. a second Fetch of the unchanged list;
3. a Compile.

Each step runs in a fresh child process (multiprocessing, spawn), so one step's
memory high-water mark never carries over to the next. The child reports its own
peak resident set size with ``getrusage(RUSAGE_SELF)``: kilobytes on Linux,
bytes on macOS (converted here). The numbers are comparable between hosts of
any size: a single-board computer, a small VM or a large server.

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
from threatcull.store.sources import add_custom_source, list_sources, set_enabled, sync_catalog

DB_NAME = "threatcull.db"  # the name cli.py and the web app use
SEED = 61
SOURCE_ID = "custom-bench"
OUTPUT_NAME = "bench"
TLDS = ("com", "net", "org", "info", "io", "xyz", "top", "shop", "online", "site", "biz")
SUBDOMAIN_SHARE = 0.3  # share of domains with a subdomain label
SUBDOMAINS = ("www", "mail", "cdn", "login", "secure", "api", "update", "portal")
COMMENT_LINES = 5
MB = 1024 * 1024

Kind = Literal["domain", "ip"]
Format = Literal["plain", "hosts"]
StepName = Literal["fetch", "compile"]


@dataclass(frozen=True, slots=True)
class StepResult:
    """One measured step, as reported by its child process."""

    ok: bool
    seconds: float
    peak_rss_mb: float
    detail: str


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


def _lines(lines: int, duplicates: float, kind: Kind) -> Iterator[str]:
    """``lines`` entries, of which about ``duplicates`` repeat an earlier one."""
    rng = random.Random(SEED)  # noqa: S311 - reproducible test data, not a secret
    make = _random_domain if kind == "domain" else _random_public_ip
    seen: list[str] = []
    for _ in range(lines):
        if seen and rng.random() < duplicates:
            yield rng.choice(seen)
        else:
            value = make(rng)
            seen.append(value)
            yield value


def write_list(path: Path, lines: int, duplicates: float, kind: Kind, fmt: Format) -> int:
    """Write the list; return how many distinct entries it holds."""
    unique: set[str] = set()
    with path.open("w", encoding="utf-8") as handle:
        for i in range(COMMENT_LINES):
            handle.write(f"# ThreatCull benchmark list, comment line {i + 1}\n")
        for value in _lines(lines, duplicates, kind):
            unique.add(value)
            handle.write(f"0.0.0.0 {value}\n" if fmt == "hosts" else f"{value}\n")
    return len(unique)


# ---- the data directory --------------------------------------------------------------


def prepare_data_dir(data_dir: Path, list_path: Path, kind: Kind, fmt: Format) -> None:
    """A fresh data directory whose only enabled Source is the benchmark list.

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
        add_custom_source(
            conn,
            source_id=SOURCE_ID,
            name="Benchmark list",
            url=list_path.as_uri(),
            fmt=fmt,
            kind=kind,
            category="malicious",
        )
        set_enabled(conn, SOURCE_ID, True)
        # One Source means every entry is in the low tier: an Output that takes it,
        # so the Compile writes every unique entry for both kinds.
        create_output(
            conn, OutputSpec(OUTPUT_NAME, kind, frozenset({"malicious"}), "low", None, "plain")
        )
    finally:
        conn.close()


# ---- the measured steps (each in its own child process) ------------------------------


def _peak_rss_mb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # ru_maxrss is bytes on macOS and kilobytes on Linux.
    return peak / MB if sys.platform == "darwin" else peak / 1024


def _run_step(step: StepName, data_dir: str, pipe: Connection) -> None:
    """Child process: run one step against ``data_dir`` and send a StepResult back."""
    started = time.perf_counter()
    try:
        conn = connect(Path(data_dir) / DB_NAME)
        try:
            if step == "fetch":
                outcomes = fetch_all(conn, HttpFetcher(spool=True), now=utcnow())
                (outcome,) = outcomes
                ok = outcome.status != "failed"
                detail = outcome.error or (
                    f"{outcome.status}: {outcome.parsed} parsed, {outcome.valid} valid, "
                    f"{outcome.invalid} invalid"
                )
            else:
                report = compile_outputs(conn, Path(data_dir) / "outputs", now=utcnow(), force=True)
                ok = report.status == "ok"
                detail = (
                    f"{report.status}: {report.counts.get(OUTPUT_NAME, 0)} entries in {OUTPUT_NAME}"
                )
        finally:
            conn.close()
    except Exception as exc:  # report any failure as a failed step, not a traceback
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    pipe.send(StepResult(ok, time.perf_counter() - started, _peak_rss_mb(), detail))
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


def environment() -> dict[str, Any]:
    return {
        "platform": f"{platform.system()} {platform.machine()}",
        "cpus": os.cpu_count(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
    }


def print_table(report: dict[str, Any]) -> None:
    env, data, steps = report["environment"], report["list"], report["steps"]
    print(
        f"ThreatCull benchmark  {env['platform']}, {env['cpus']} CPUs, "
        f"Python {env['python']}, SQLite {env['sqlite']}"
    )
    print(
        f"List: {data['lines']:,} lines ({data['kind']}, {data['format']}), "
        f"{data['unique']:,} unique, {data['size_mb']:.1f} MB"
    )
    print()
    print(f"{'Step':<18}{'Time':>10}{'Lines/s':>12}{'Peak RSS':>12}  Result")
    for name, step in steps.items():
        rate = f"{step['lines_per_second']:,.0f}" if step.get("lines_per_second") else "-"
        print(
            f"{name:<18}{step['seconds']:>9.1f}s{rate:>12}{step['peak_rss_mb']:>9.0f} MB  "
            f"{step['detail']}"
        )
    print()
    print(
        f"Database: {report['database_mb_after_fetch']:.1f} MB after the first Fetch, "
        f"{report['database_mb_after_compile']:.1f} MB after the Compile"
    )
    print(f"Output file: {report['output_mb']:.1f} MB")


# ---- main ----------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0] if __doc__ else None)
    parser.add_argument("--lines", type=int, default=1_000_000, help="entries in the list")
    parser.add_argument(
        "--duplicates", type=float, default=0.4, help="share of lines that repeat an earlier one"
    )
    parser.add_argument("--kind", choices=("domain", "ip"), default="domain")
    parser.add_argument("--format", dest="fmt", choices=("plain", "hosts"), default="plain")
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory")
    parser.add_argument("--json", action="store_true", help="print one JSON object")
    args = parser.parse_args(argv)
    if args.lines < 1:
        parser.error("--lines must be at least 1")
    if not 0 <= args.duplicates < 1:
        parser.error("--duplicates must be at least 0 and below 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    work = Path(tempfile.mkdtemp(prefix="threatcull-bench-"))
    try:
        list_path = work / f"list.{'txt' if args.fmt == 'plain' else 'hosts'}"
        data_dir = work / "data"
        unique = write_list(list_path, args.lines, args.duplicates, args.kind, args.fmt)
        prepare_data_dir(data_dir, list_path, args.kind, args.fmt)

        first = measure("fetch", data_dir)
        db_after_fetch = _database_mb(data_dir)
        again = measure("fetch", data_dir) if first.ok else StepResult(False, 0, 0, "skipped")
        compiled = measure("compile", data_dir) if first.ok else StepResult(False, 0, 0, "skipped")

        steps = {"first Fetch": first, "unchanged Fetch": again, "Compile": compiled}
        report: dict[str, Any] = {
            "environment": environment(),
            "list": {
                "lines": args.lines,
                "duplicates": args.duplicates,
                "kind": args.kind,
                "format": args.fmt,
                "unique": unique,
                "size_mb": round(_size_mb(list_path), 2),
            },
            "steps": {name: asdict(step) for name, step in steps.items()},
            "database_mb_after_fetch": round(db_after_fetch, 2),
            "database_mb_after_compile": round(_database_mb(data_dir), 2),
            "output_mb": round(_output_mb(data_dir), 2) if compiled.ok else 0.0,
        }
        if first.ok and first.seconds:
            report["steps"]["first Fetch"]["lines_per_second"] = round(args.lines / first.seconds)
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
