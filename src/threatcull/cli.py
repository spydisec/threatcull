# SPDX-License-Identifier: AGPL-3.0-only
"""Command-line interface: `threatcull --help`."""

from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import get_args
from zoneinfo import ZoneInfoNotFoundError

import uvicorn
import yaml

from threatcull.catalog import Category, SourceRole, load_catalog
from threatcull.catalog_update import (
    DEFAULT_CATALOG_URL,
    MAX_CATALOG_BYTES,
    active_catalog,
    apply_update,
    download_catalog,
)
from threatcull.clock import TZ_ENV_VAR, display_zone, utcnow
from threatcull.compiling import compile_outputs, is_frozen
from threatcull.datadir import DataDirError, ensure_data_dir
from threatcull.fetcher import FetchError, HttpFetcher
from threatcull.fetching import fetch_all
from threatcull.home_detect import detect_candidates, public_ip_candidate, public_ip_fetcher
from threatcull.indicators import SourceKind
from threatcull.listfile import ListLine, parse_list_file, report_lines
from threatcull.lookup import lookup, output_labels
from threatcull.parsers import SourceFormat
from threatcull.store.allowlist import add_entry, import_entries, operator_entries, remove_entry
from threatcull.store.api_tokens import create_api_token, list_api_tokens, revoke_api_token
from threatcull.store.config import MAX_CONFIG_BYTES, apply_config, dump_config, parse_config
from threatcull.store.db import connect
from threatcull.store.errors import NotFoundError, PolicyError
from threatcull.store.outputs import ensure_default_outputs, list_outputs, rotate_token
from threatcull.store.runs import fail_interrupted_runs
from threatcull.store.settings import load_settings
from threatcull.store.sources import (
    add_custom_source,
    list_sources,
    new_custom_id,
    set_enabled,
    sync_catalog,
)
from threatcull.store.users import count_users, create_user, list_users, set_password
from threatcull.web.app import create_app
from threatcull.web.routes.feeds import install_feed_token_redaction
from threatcull.web.security import parse_trusted_proxies

DB_NAME = "threatcull.db"
EXIT_OK, EXIT_ERROR, EXIT_BLOCKED = 0, 1, 2
MINE_HELP = "your own network: never published, and flagged when a Source lists it"
ADMIN_ENV_VAR = "THREATCULL_ADMIN_PASSWORD"
ADMIN_FILE_ENV_VAR = "THREATCULL_ADMIN_PASSWORD_FILE"  # a Docker secret; wins over the above
Handler = Callable[[sqlite3.Connection, argparse.Namespace], int]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatcull", description="Self-hosted threat-feed compiler."
    )
    parser.add_argument(
        "--data-dir", type=Path, default=Path(os.environ.get("THREATCULL_DATA_DIR", "data"))
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=None,
        help="Catalog YAML to use instead of the active one (see `catalog show`)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create the database, sync the Catalog, create default Outputs")

    _add_sources_parser(sub)

    allow = sub.add_parser("allow", help="Manage the operator Allowlist")
    allow_sub = allow.add_subparsers(dest="action", required=True)
    allow_add = allow_sub.add_parser("add")
    allow_add.add_argument("value")
    allow_add.add_argument("--note", default="")
    allow_add.add_argument(
        "--mine",
        action="store_true",
        help=MINE_HELP,
    )
    allow_sub.add_parser("remove").add_argument("value")
    allow_sub.add_parser("list")
    allow_import = allow_sub.add_parser(
        "import", help="Add every value from a txt or csv file (value[,note] per line)"
    )
    allow_import.add_argument("file", type=Path)
    allow_import.add_argument(
        "--mine",
        action="store_true",
        help=MINE_HELP,
    )
    detect = allow_sub.add_parser(
        "detect", help="Suggest your own addresses from this host's interfaces, gateway and DNS"
    )
    detect.add_argument(
        "--public-ip",
        action="store_true",
        help="Also ask api.ipify.org for this network's public IP (contacts the internet)",
    )
    detect.add_argument("--apply", action="store_true", help="Add every candidate as --mine")

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

    _add_user_parser(sub)

    _add_serve_parser(sub)
    _add_api_token_parser(sub)
    _add_config_parser(sub)
    _add_catalog_parser(sub)
    return parser


def _add_user_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    user = sub.add_parser("user", help="Manage web UI users")
    user_sub = user.add_subparsers(dest="action", required=True)
    user_create = user_sub.add_parser("create", help="Create a web UI user")
    user_create.add_argument("username")
    user_create.add_argument(
        "--password-stdin", action="store_true", help="Read the password from one line of stdin"
    )
    user_pw = user_sub.add_parser(
        "set-password", help="Change a user's password (ends their web sessions)"
    )
    user_pw.add_argument("username")
    user_pw.add_argument(
        "--password-stdin", action="store_true", help="Read the password from one line of stdin"
    )
    user_sub.add_parser("list", help="List web UI users")


def _add_serve_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    serve = sub.add_parser("serve", help="Run the web UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=6969)
    serve.add_argument(
        "--secure-cookies",
        action="store_true",
        help="Set the session cookie's Secure flag (only when served over HTTPS)",
    )
    serve.add_argument(
        "--trusted-proxy",
        dest="trusted_proxies",
        action="append",
        default=[],
        type=_trusted_proxy,
        metavar="IP_OR_CIDR",
        help="Reverse proxy whose X-Forwarded-For is believed (repeatable; default: none)",
    )


def _add_config_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    config = sub.add_parser(
        "config", help="Export or import the configuration as YAML (no passwords or tokens)"
    )
    config_sub = config.add_subparsers(dest="action", required=True)
    export = config_sub.add_parser("export", help="Write the configuration as YAML")
    export.add_argument("-o", "--output", type=Path, help="file to write (default: stdout)")
    config_sub.add_parser(
        "import", help="Merge a YAML configuration file into this install (never deletes)"
    ).add_argument("file", help="the YAML file, or - to read it from stdin")


def _add_sources_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    sources = sub.add_parser("sources", help="List, enable, disable or add Sources")
    src = sources.add_subparsers(dest="action", required=True)
    src_list = src.add_parser("list")
    src_list.add_argument("--enabled", action="store_true")
    enable = src.add_parser("enable")
    enable.add_argument("source_id")
    src.add_parser("disable").add_argument("source_id")
    custom = src.add_parser("add-custom")
    custom.add_argument("--name", required=True)
    custom.add_argument("--url", required=True)
    custom.add_argument("--kind", required=True, choices=get_args(SourceKind))
    custom.add_argument(
        "--allowlist",
        action="store_true",
        help="feed the Allowlist instead of the blocklists (its values never appear in Outputs)",
    )
    custom.add_argument(
        "--id", dest="source_id", help="custom-<name>; made from --name when left out"
    )
    custom.add_argument("--format", dest="fmt", default="plain", choices=get_args(SourceFormat))
    custom.add_argument(
        "--category",
        default="malicious",
        choices=get_args(Category),
        help="blocklists only (default: malicious)",
    )
    custom.add_argument("--csv-column", type=int, default=0)
    custom.add_argument("--json-key", dest="json_keys", action="append", default=[])


def _add_catalog_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    catalog = sub.add_parser("catalog", help="Show or update the Catalog of Sources")
    catalog_sub = catalog.add_subparsers(dest="action", required=True)
    catalog_sub.add_parser("show", help="Show the Catalog revision in use")
    update = catalog_sub.add_parser(
        "update", help="Apply a newer Catalog (new Sources arrive disabled)"
    )
    where = update.add_mutually_exclusive_group()
    where.add_argument("--file", type=Path, help="a Catalog YAML file (for offline installs)")
    where.add_argument(
        "--url", default=DEFAULT_CATALOG_URL, help="where to download it (https only)"
    )


def _add_api_token_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    api_token = sub.add_parser("api-token", help="Manage API tokens for scripts")
    token_sub = api_token.add_subparsers(dest="action", required=True)
    token_create = token_sub.add_parser("create", help="Create an API token (shown once)")
    token_create.add_argument("name")
    token_create.add_argument("--user", required=True, help="Web UI user the token acts as")
    token_sub.add_parser("list", help="List API tokens (never the tokens themselves)")
    token_sub.add_parser("revoke", help="Revoke an API token").add_argument("name")


def _trusted_proxy(value: str) -> str:
    try:
        parse_trusted_proxies([value])
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ensure_data_dir(args.data_dir)
    except DataDirError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    conn = connect(args.data_dir / DB_NAME)
    try:
        entries = (
            load_catalog(args.catalog)
            if args.catalog
            else active_catalog(args.data_dir).catalog.entries
        )
        sync_catalog(conn, entries)
        created = ensure_default_outputs(conn)
        if args.command == "serve":
            # serve's output ends up in journald / container logs: no tokens there.
            if created:
                print(
                    "Default Outputs created; rotate their tokens on the Outputs page "
                    "or with `threatcull outputs rotate-token`"
                )
        else:
            for name, token in created.items():
                _print_token(name, token)
        handler = _HANDLERS[(args.command, getattr(args, "action", None))]
        return handler(conn, args)
    except (
        PolicyError,
        NotFoundError,
        ValueError,
        OSError,
        yaml.YAMLError,
        FetchError,
    ) as exc:
        # ValueError covers CatalogError and pydantic's ValidationError; OSError covers a
        # missing/unreadable --catalog file; yaml.YAMLError covers malformed Catalog YAML.
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
    settings, now = load_settings(conn), utcnow()
    for s in list_sources(conn, enabled_only=args.enabled):
        state = "on " if s.enabled else "off"
        health = s.last_error or (
            f"ok {s.last_success_at}" if s.last_success_at else "never fetched"
        )
        if s.last_changed_at:
            health += f" · changed {s.last_changed_at[:10]}"
        if is_frozen(s, now=now, settings=settings):
            health += " FROZEN"
        note = f" ({s.disabled_reason})" if s.disabled_reason else ""
        print(f"{state}  {s.id:<30} {s.role:<9} {s.kind:<6} {s.category:<14} {health}{note}")
    return EXIT_OK


def _sources_enable(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    source = set_enabled(conn, args.source_id, True)
    print(f"enabled {source.id}")
    return EXIT_OK


def _sources_disable(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    print(f"disabled {set_enabled(conn, args.source_id, False).id}")
    return EXIT_OK


def _sources_add_custom(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    role: SourceRole = "allowlist" if args.allowlist else "blocklist"
    source = add_custom_source(
        conn,
        source_id=args.source_id or new_custom_id(conn, args.name),
        name=args.name,
        url=args.url,
        fmt=args.fmt,
        kind=args.kind,
        category=args.category if role == "blocklist" else "infrastructure",
        csv_column=args.csv_column,
        json_keys=tuple(args.json_keys),
        role=role,
    )
    print(f"added {source.id} (disabled; enable it with `threatcull sources enable {source.id}`)")
    return EXIT_OK


def _allow_add(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    entry = add_entry(conn, args.value, args.note, mine=args.mine, now=utcnow())
    print(f"allowlisted {entry.value}{' (my network)' if entry.mine else ''}")
    return EXIT_OK


def _allow_remove(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    remove_entry(conn, args.value)
    print(f"removed {args.value.strip()}")
    return EXIT_OK


def _allow_list(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    for entry in operator_entries(conn):
        print(f"{entry.value}  {'mine  ' if entry.mine else ''}{entry.note}")
    return EXIT_OK


def _read_list_file(path: Path) -> list[ListLine]:
    try:
        return parse_list_file(path.read_bytes())
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror}") from exc


def _allow_import(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    report = import_entries(conn, _read_list_file(args.file), mine=args.mine, now=utcnow())
    print("\n".join(report_lines(report)))
    return EXIT_OK


def _allow_detect(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    existing = operator_entries(conn)
    candidates = detect_candidates(existing=existing)
    if args.public_ip:
        public, candidate = public_ip_candidate(
            public_ip_fetcher(), existing=existing, found=candidates
        )
        if public is None:
            print("could not learn the public IP from api.ipify.org", file=sys.stderr)
        elif candidate is not None:
            candidates.append(candidate)
    if not candidates:
        print("no new candidates: your public addresses are already on the Allowlist")
    for candidate in candidates:
        if args.apply:
            add_entry(conn, candidate.value, candidate.reason, mine=True, now=utcnow())
            print(f"added {candidate.value}  {candidate.reason}")
        else:
            print(f"{candidate.value}  {candidate.reason}")
    return EXIT_OK


def _fetch(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    failed = False
    fetcher = HttpFetcher(spool=True)  # large lists go to a temporary file, not RAM
    for outcome in fetch_all(conn, fetcher, now=utcnow(), source_ids=args.source_ids or None):
        if outcome.status == "failed":
            failed = True
            print(f"FAIL {outcome.source_id}: {outcome.error}", file=sys.stderr)
        elif outcome.status == "not_modified":
            print(f"same {outcome.source_id}")
        else:
            print(
                f"ok   {outcome.source_id}: {outcome.valid} valid, {outcome.invalid} invalid, "
                f"+{outcome.added} -{outcome.removed}"
            )
    return EXIT_ERROR if failed else EXIT_OK


def _compile(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    report = compile_outputs(conn, args.data_dir / "outputs", now=utcnow(), force=args.force)
    for name, count in report.counts.items():
        print(f"{name}: {count}")
    print(f"allowlisted: {report.allowlisted}")
    for value, sources in report.home_hits:
        print(f"WARNING: your network is listed by {sources}: {value}", file=sys.stderr)
    if report.home_hit_count > len(report.home_hits):
        more = report.home_hit_count - len(report.home_hits)
        print(f"WARNING: your network is listed {more} more times", file=sys.stderr)
    for reason in report.reasons:
        print(f"guard: {reason}")
    for name in report.rebaselined:
        print(f"guard: {name} baseline reset (a Source that fed it was disabled)")
    if report.status == "blocked":
        print("Compile blocked: previous Outputs kept. Re-run with --force to publish anyway.")
        return EXIT_BLOCKED
    return EXIT_OK


def _run(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    args.source_ids = []
    fetch_code = _fetch(conn, args)
    # Compile even after failed Fetches: their Sources keep their previous Sightings.
    compile_code = _compile(conn, args)
    return compile_code if compile_code != EXIT_OK else fetch_code


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
    labels = output_labels(conn, result.eligible_outputs)
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


def _read_new_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    password = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != password:
        raise ValueError("passwords do not match")
    return password


def _user_create(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    create_user(conn, args.username, _read_new_password(args.password_stdin), now=utcnow())
    print(f"created user {args.username}")
    return EXIT_OK


def _user_set_password(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    # Sessions carry a fingerprint of the password hash, so every web session
    # of this user stops working on its next request.
    set_password(conn, args.username, _read_new_password(args.password_stdin))
    print(f"password changed for {args.username}; their web sessions are signed out")
    return EXIT_OK


def _user_list(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    users = list_users(conn)
    if not users:
        print("no web UI users yet (create one with `threatcull user create <name>`)")
    for username, created_at in users:
        print(f"{username:<24} created={created_at}")
    return EXIT_OK


def _serve(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    try:
        display_zone()
    except (ZoneInfoNotFoundError, ValueError):
        print(
            f"error: {TZ_ENV_VAR}={os.environ[TZ_ENV_VAR]} is not a timezone name. "
            "Use an IANA name such as Australia/Melbourne, or leave it unset for UTC.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    if count_users(conn) == 0:
        source, password = ADMIN_ENV_VAR, os.environ.get(ADMIN_ENV_VAR)
        if password_file := os.environ.get(ADMIN_FILE_ENV_VAR):
            try:
                source, password = (
                    ADMIN_FILE_ENV_VAR,
                    Path(password_file).read_text(encoding="utf-8").splitlines()[0],
                )
            except (OSError, IndexError):
                print(
                    f"error: {ADMIN_FILE_ENV_VAR} names {password_file}, "
                    "which is missing, unreadable or empty",
                    file=sys.stderr,
                )
                return EXIT_ERROR
        if not password:
            print(
                "error: no web UI users yet. Create one with `threatcull user create <name>` "
                f"(or set {ADMIN_FILE_ENV_VAR} or {ADMIN_ENV_VAR} to create 'admin' "
                "on first start).",
                file=sys.stderr,
            )
            return EXIT_ERROR
        create_user(conn, "admin", password, now=utcnow())
        print(f"created user admin from {source}")
    # No run survives a restart: close any the last process left "running".
    fail_interrupted_runs(conn, now=utcnow())
    install_feed_token_redaction()  # Feed Tokens must never land in the access log
    app = create_app(
        args.data_dir, secure_cookies=args.secure_cookies, trusted_proxies=args.trusted_proxies
    )
    # proxy_headers=False: uvicorn would otherwise rewrite the client address
    # from X-Forwarded-For for peers it trusts (loopback by default), bypassing
    # client_ip() and the explicit --trusted-proxy opt-in.
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", proxy_headers=False)
    return EXIT_OK


def _config_export(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    text = dump_config(conn, now=utcnow())
    if args.output is None:
        sys.stdout.write(text)
        return EXIT_OK
    # 0600 from the first byte: the file describes the operator's network.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    args.output.chmod(0o600)  # an existing file keeps its old mode through O_CREAT
    print(f"wrote {args.output}", file=sys.stderr)
    return EXIT_OK


def _config_import(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    # Read one byte past the limit: enough for parse_config to refuse a larger file.
    if args.file == "-":
        data = sys.stdin.buffer.read(MAX_CONFIG_BYTES + 1)
    else:
        with Path(args.file).open("rb") as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
    result = apply_config(conn, parse_config(data), now=utcnow())
    for line in [*result.applied, *result.skipped]:
        print(line)
    for name, token in result.new_feed_tokens.items():
        print(f"new Feed Token for {name} (shown once): {token}")
    if not result.applied and not result.skipped:
        print("nothing to change: this install already matches the file")
    return EXIT_OK


def _catalog_show(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    if args.catalog:
        print(f"using {args.catalog} (--catalog)")
        return EXIT_OK
    active = active_catalog(args.data_dir)
    where = "shipped with ThreatCull" if active.origin == "shipped" else "saved by an update"
    count = len(active.catalog.entries)
    print(f"Catalog revision {active.catalog.revision}, {where}, {count} Sources")
    return EXIT_OK


def _catalog_update(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    if args.file is not None:
        with args.file.open("rb") as handle:
            data = handle.read(MAX_CATALOG_BYTES + 1)
        text = data.decode("utf-8-sig")
    else:
        text = download_catalog(args.url)
    report = apply_update(conn, args.data_dir, text)
    print(report.summary())
    for label, ids in (("new", report.added), ("updated", report.changed)):
        for source_id in ids:
            print(f"  {label}: {source_id}")
    for source_id in report.removed:
        print(f"  removed: {source_id} (disabled if it was enabled)")
    if report.added:
        print("Enable new Sources with `threatcull sources enable <id>`.")
    return EXIT_OK


def _api_token_create(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    token = create_api_token(conn, args.name, args.user, now=utcnow())
    print(f"API token '{args.name}' for user {args.user} (shown once, store it safely): {token}")
    return EXIT_OK


def _api_token_list(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    for info in list_api_tokens(conn):
        print(
            f"{info.name:<24} user={info.username:<16} created={info.created_at}  "
            f"last used={info.last_used_at or 'never'}"
        )
    return EXIT_OK


def _api_token_revoke(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    revoke_api_token(conn, args.name)
    print(f"revoked API token {args.name}")
    return EXIT_OK


_HANDLERS: dict[tuple[str, str | None], Handler] = {
    ("init", None): _init,
    ("sources", "list"): _sources_list,
    ("sources", "enable"): _sources_enable,
    ("sources", "disable"): _sources_disable,
    ("sources", "add-custom"): _sources_add_custom,
    ("allow", "add"): _allow_add,
    ("allow", "remove"): _allow_remove,
    ("allow", "list"): _allow_list,
    ("allow", "import"): _allow_import,
    ("allow", "detect"): _allow_detect,
    ("fetch", None): _fetch,
    ("compile", None): _compile,
    ("run", None): _run,
    ("lookup", None): _lookup,
    ("outputs", "list"): _outputs_list,
    ("outputs", "rotate-token"): _outputs_rotate,
    ("user", "create"): _user_create,
    ("user", "set-password"): _user_set_password,
    ("user", "list"): _user_list,
    ("serve", None): _serve,
    ("api-token", "create"): _api_token_create,
    ("catalog", "show"): _catalog_show,
    ("catalog", "update"): _catalog_update,
    ("config", "export"): _config_export,
    ("config", "import"): _config_import,
    ("api-token", "list"): _api_token_list,
    ("api-token", "revoke"): _api_token_revoke,
}
