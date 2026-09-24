# SPDX-License-Identifier: AGPL-3.0-only
"""Command-line interface: `threatcull --help`."""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import get_args

from threatcull.catalog import BusinessUse, Category, load_catalog
from threatcull.clock import utcnow
from threatcull.compiling import compile_outputs
from threatcull.fetcher import HttpFetcher
from threatcull.fetching import fetch_all
from threatcull.indicators import SourceKind
from threatcull.lookup import lookup
from threatcull.parsers import SourceFormat
from threatcull.store.allowlist import add_entry, operator_entries, remove_entry
from threatcull.store.db import connect
from threatcull.store.errors import NotFoundError, PolicyError
from threatcull.store.outputs import ensure_default_outputs, list_outputs, rotate_token
from threatcull.store.sources import (
    add_custom_source,
    list_sources,
    set_business_mode,
    set_enabled,
    sync_catalog,
)

DB_NAME = "threatcull.db"
EXIT_OK, EXIT_ERROR, EXIT_BLOCKED = 0, 1, 2
Handler = Callable[[sqlite3.Connection, argparse.Namespace], int]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatcull", description="Self-hosted threat-feed compiler."
    )
    parser.add_argument(
        "--data-dir", type=Path, default=Path(os.environ.get("THREATCULL_DATA_DIR", "data"))
    )
    parser.add_argument(
        "--catalog", type=Path, default=None, help="Catalog YAML to use instead of the shipped one"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create the database, sync the Catalog, create default Outputs")

    sources = sub.add_parser("sources", help="List, enable, disable or add Sources")
    src = sources.add_subparsers(dest="action", required=True)
    src_list = src.add_parser("list")
    src_list.add_argument("--enabled", action="store_true")
    enable = src.add_parser("enable")
    enable.add_argument("source_id")
    enable.add_argument("--acknowledge-restricted", action="store_true")
    src.add_parser("disable").add_argument("source_id")
    custom = src.add_parser("add-custom")
    custom.add_argument("--id", dest="source_id", required=True)
    custom.add_argument("--name", required=True)
    custom.add_argument("--url", required=True)
    custom.add_argument("--format", dest="fmt", required=True, choices=get_args(SourceFormat))
    custom.add_argument("--kind", required=True, choices=get_args(SourceKind))
    custom.add_argument("--category", required=True, choices=get_args(Category))
    custom.add_argument("--csv-column", type=int, default=0)
    custom.add_argument("--json-key", dest="json_keys", action="append", default=[])
    custom.add_argument(
        "--business-use", choices=[b.value for b in BusinessUse], default=BusinessUse.UNKNOWN.value
    )

    sub.add_parser("business-mode", help="Turn Business Mode on or off").add_argument(
        "state", choices=["on", "off"]
    )

    allow = sub.add_parser("allow", help="Manage the operator Allowlist")
    allow_sub = allow.add_subparsers(dest="action", required=True)
    allow_add = allow_sub.add_parser("add")
    allow_add.add_argument("value")
    allow_add.add_argument("--note", default="")
    allow_sub.add_parser("remove").add_argument("value")
    allow_sub.add_parser("list")

    sub.add_parser("fetch", help="Fetch enabled Sources").add_argument("source_ids", nargs="*")
    sub.add_parser("compile", help="Compile Outputs").add_argument("--force", action="store_true")
    sub.add_parser("run", help="Fetch every enabled Source, then Compile").add_argument(
        "--force", action="store_true"
    )
    sub.add_parser("lookup", help="Explain one IP, CIDR or domain").add_argument("value")

    outputs = sub.add_parser("outputs", help="List Outputs or rotate a Feed Token")
    out_sub = outputs.add_subparsers(dest="action", required=True)
    out_sub.add_parser("list")
    out_sub.add_parser("rotate-token").add_argument("name")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.data_dir.mkdir(parents=True, exist_ok=True)
    conn = connect(args.data_dir / DB_NAME)
    try:
        sync_catalog(conn, load_catalog(args.catalog))
        for name, token in ensure_default_outputs(conn).items():
            _print_token(name, token)
        handler = _HANDLERS[(args.command, getattr(args, "action", None))]
        return handler(conn, args)
    except (PolicyError, NotFoundError, ValueError) as exc:  # CatalogError, ValidationError too
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        conn.close()


def _print_token(name: str, token: str) -> None:
    print(f"Feed Token for Output '{name}' (shown once, store it safely): {token}")


def _init(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    print(f"ThreatCull ready in {args.data_dir}")
    return EXIT_OK


def _sources_list(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    for s in list_sources(conn, enabled_only=args.enabled):
        state = "on " if s.enabled else "off"
        health = s.last_error or (
            f"ok {s.last_success_at}" if s.last_success_at else "never fetched"
        )
        note = f" ({s.disabled_reason})" if s.disabled_reason else ""
        print(
            f"{state}  {s.id:<30} {s.role:<9} {s.licence_class:<13} "
            f"business={s.business_use:<9} {health}{note}"
        )
    return EXIT_OK


def _sources_enable(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    source = set_enabled(
        conn, args.source_id, True, acknowledge_restricted=args.acknowledge_restricted
    )
    print(f"enabled {source.id}")
    return EXIT_OK


def _sources_disable(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    print(f"disabled {set_enabled(conn, args.source_id, False).id}")
    return EXIT_OK


def _sources_add_custom(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    source = add_custom_source(
        conn,
        source_id=args.source_id,
        name=args.name,
        url=args.url,
        fmt=args.fmt,
        kind=args.kind,
        category=args.category,
        csv_column=args.csv_column,
        json_keys=tuple(args.json_keys),
        business_use=BusinessUse(args.business_use),
    )
    print(f"added {source.id} (disabled; enable it with `threatcull sources enable {source.id}`)")
    return EXIT_OK


def _business_mode(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    disabled = set_business_mode(conn, args.state == "on")
    print(f"Business Mode {args.state}")
    for source_id in disabled:
        print(f"disabled {source_id}: not cleared for business use")
    return EXIT_OK


def _allow_add(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    entry = add_entry(conn, args.value, args.note, now=utcnow())
    print(f"allowlisted {entry.value}")
    return EXIT_OK


def _allow_remove(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    remove_entry(conn, args.value)
    print(f"removed {args.value.strip()}")
    return EXIT_OK


def _allow_list(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    for entry in operator_entries(conn):
        print(f"{entry.value}  {entry.note}")
    return EXIT_OK


def _fetch(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    for outcome in fetch_all(conn, HttpFetcher(), now=utcnow(), source_ids=args.source_ids or None):
        if outcome.status == "failed":
            print(f"FAIL {outcome.source_id}: {outcome.error}")
        elif outcome.status == "not_modified":
            print(f"same {outcome.source_id}")
        else:
            print(
                f"ok   {outcome.source_id}: {outcome.valid} valid, {outcome.invalid} invalid, "
                f"+{outcome.added} -{outcome.removed}"
            )
    return EXIT_OK


def _compile(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    report = compile_outputs(conn, args.data_dir / "outputs", now=utcnow(), force=args.force)
    for name, count in report.counts.items():
        print(f"{name}: {count}")
    print(f"allowlisted: {report.allowlisted}")
    for reason in report.reasons:
        print(f"guard: {reason}")
    if report.status == "blocked":
        print("Compile blocked: previous Outputs kept. Re-run with --force to publish anyway.")
        return EXIT_BLOCKED
    return EXIT_OK


def _run(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    args.source_ids = []
    _fetch(conn, args)
    return _compile(conn, args)


def _lookup(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    result = lookup(conn, args.value, now=utcnow())
    if result is None:
        print(f"error: {args.value.strip()!r} is not a public IP, CIDR or domain", file=sys.stderr)
        return EXIT_ERROR
    print(f"{result.value} ({result.kind}): score {result.score} ({result.tier or 'not listed'})")
    for s in result.sightings:
        state = "current" if s.current else "no longer listed"
        print(
            f"  {s.source_name}: {state}, first {s.first_seen}, last {s.last_seen}"
            f"{'' if s.enabled else ' [Source disabled]'}"
        )
    if result.allowlisted_by:
        print(f"  allowlisted by {result.allowlisted_by.value}: {result.allowlisted_by.note}")
    # Qualifying by kind/Tier/category doesn't guarantee publication: an Output with a
    # max_entries cap may still cut this Indicator during Compile, so show the cap.
    caps = {spec.name: spec.max_entries for spec in list_outputs(conn)}
    labels = [
        f"{name} (cap {caps[name]})" if caps.get(name) else name for name in result.eligible_outputs
    ]
    print(f"  Outputs: {', '.join(labels) or 'none'}")
    return EXIT_OK


def _outputs_list(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    for spec in list_outputs(conn):
        cap = spec.max_entries or "no cap"
        print(
            f"{spec.name:<20} {spec.kind:<7} {spec.format:<8} min={spec.min_tier:<7} "
            f"cap={cap}  last={spec.last_count if spec.last_count is not None else '-'}"
        )
    return EXIT_OK


def _outputs_rotate(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    _print_token(args.name, rotate_token(conn, args.name))
    return EXIT_OK


_HANDLERS: dict[tuple[str, str | None], Handler] = {
    ("init", None): _init,
    ("sources", "list"): _sources_list,
    ("sources", "enable"): _sources_enable,
    ("sources", "disable"): _sources_disable,
    ("sources", "add-custom"): _sources_add_custom,
    ("business-mode", None): _business_mode,
    ("allow", "add"): _allow_add,
    ("allow", "remove"): _allow_remove,
    ("allow", "list"): _allow_list,
    ("fetch", None): _fetch,
    ("compile", None): _compile,
    ("run", None): _run,
    ("lookup", None): _lookup,
    ("outputs", "list"): _outputs_list,
    ("outputs", "rotate-token"): _outputs_rotate,
}
