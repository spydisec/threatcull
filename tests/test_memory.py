# SPDX-License-Identifier: AGPL-3.0-only
"""Memory budgets: Fetch and Compile must not hold every Indicator in Python at once."""

import sqlite3
import tracemalloc
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from tests.factories import make_entry
from threatcull.compiling import compile_outputs
from threatcull.fetcher import HttpFetcher
from threatcull.fetching import fetch_source
from threatcull.indicators import Indicator
from threatcull.store.outputs import OutputSpec, create_output
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import get_source, sync_catalog

MIB = 1024 * 1024
COMPILE_BUDGET = 28 * MIB  # about 1/5 of the 140 MiB peak before Compile streamed
FETCH_BUDGET = 8 * MIB  # about 1/5 of the 40 MiB peak before Fetch streamed
LINES = 200_000


def _ip(i: int) -> str:
    return f"45.{i >> 16}.{(i >> 8) & 255}.{i & 255}"


def _peak(action: Callable[[], object]) -> int:
    tracemalloc.start()
    try:
        action()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_compile_peak_stays_bounded(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="a", url="https://a.example/1", default_enabled=True),
            make_entry(id="b", url="https://b.example/1", default_enabled=True),
            make_entry(id="c", url="https://c.example/1", kind="domain", default_enabled=True),
        ],
    )
    ips = [Indicator(_ip(i), "ip") for i in range(100_000)]
    record_fetch_success(conn, "a", ips, now=now, etag=None, last_modified=None)
    record_fetch_success(conn, "b", ips[::4], now=now, etag=None, last_modified=None)
    domains = (Indicator(f"host{i}.bad.example", "domain") for i in range(100_000))
    record_fetch_success(conn, "c", domains, now=now, etag=None, last_modified=None)
    del ips
    create_output(conn, OutputSpec("ips", "ip", frozenset({"malicious"}), "low", None, "plain"))
    create_output(
        conn, OutputSpec("domains", "domain", frozenset({"malicious"}), "low", None, "hosts")
    )

    peak = _peak(lambda: compile_outputs(conn, tmp_path, now=now))

    assert (tmp_path / "ips.txt").stat().st_size > 0
    assert peak < COMPILE_BUDGET, f"Compile peak {peak / MIB:.1f} MiB"


def test_fetch_peak_stays_bounded(conn: sqlite3.Connection, now: datetime, tmp_path: Path) -> None:
    listing = tmp_path / "big.txt"
    listing.write_text("".join(f"{_ip(i)}\n" for i in range(LINES)), encoding="utf-8")
    sync_catalog(conn, [make_entry(id="big", url=listing.as_uri(), default_enabled=True)])
    source = get_source(conn, "big")
    outcome = None

    def fetch() -> None:
        nonlocal outcome
        outcome = fetch_source(conn, source, HttpFetcher(), now=now)

    peak = _peak(fetch) - listing.stat().st_size

    assert outcome is not None
    assert (outcome.status, outcome.valid) == ("ok", LINES)
    assert peak < FETCH_BUDGET, f"Fetch peak {peak / MIB:.1f} MiB beyond the file's text"
