# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime, timedelta

import pytest

from tests.factories import make_entry
from threatcull.clock import ts
from threatcull.indicators import Indicator
from threatcull.store.sightings import (
    apply_fetched,
    prune,
    record_fetch_failure,
    record_fetch_success,
    record_not_modified,
    stage_fetched,
)
from threatcull.store.sources import get_source, sync_catalog

A = Indicator("1.2.3.4", "ip")
B = Indicator("5.6.7.8", "ip")
C = Indicator("9.9.9.0/24", "cidr")


@pytest.fixture(autouse=True)
def _source(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [make_entry(id="src", default_enabled=True)])


def _current(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT i.value FROM sightings s JOIN indicators i ON i.id = s.indicator_id "
        "WHERE s.source_id = 'src' AND s.current = 1"
    )
    return {r[0] for r in rows}


def test_first_fetch_adds_everything(conn: sqlite3.Connection, now: datetime) -> None:
    result = record_fetch_success(conn, "src", {A, B}, now=now, etag='"1"', last_modified=None)
    assert result == (2, 0)
    assert _current(conn) == {"1.2.3.4", "5.6.7.8"}
    source = get_source(conn, "src")
    assert (source.etag, source.last_success_at, source.last_error) == ('"1"', ts(now), None)


def test_later_fetch_marks_missing_indicators_not_current(
    conn: sqlite3.Connection, now: datetime
) -> None:
    record_fetch_success(conn, "src", {A, B}, now=now, etag=None, last_modified=None)
    later = now + timedelta(hours=1)
    result1 = record_fetch_success(conn, "src", {B, C}, now=later, etag=None, last_modified=None)
    assert result1 == (1, 1)
    assert _current(conn) == {"5.6.7.8", "9.9.9.0/24"}
    result2 = record_fetch_success(conn, "src", {A, B, C}, now=later, etag=None, last_modified=None)
    assert result2 == (1, 0)


def test_first_seen_is_kept_and_last_seen_moves(conn: sqlite3.Connection, now: datetime) -> None:
    record_fetch_success(conn, "src", {A}, now=now, etag=None, last_modified=None)
    later = now + timedelta(days=1)
    record_fetch_success(conn, "src", {A}, now=later, etag=None, last_modified=None)
    first, last = conn.execute("SELECT first_seen, last_seen FROM sightings").fetchone()
    assert (first, last) == (ts(now), ts(later))


def test_not_modified_refreshes_last_seen(conn: sqlite3.Connection, now: datetime) -> None:
    record_fetch_success(conn, "src", {A}, now=now, etag=None, last_modified=None)
    later = now + timedelta(hours=2)
    record_not_modified(conn, "src", now=later)
    assert conn.execute("SELECT last_seen FROM sightings").fetchone()[0] == ts(later)
    assert get_source(conn, "src").last_success_at == ts(later)


def test_failure_keeps_sightings_and_records_error(conn: sqlite3.Connection, now: datetime) -> None:
    record_fetch_success(conn, "src", {A}, now=now, etag=None, last_modified=None)
    record_fetch_failure(conn, "src", "HTTP 500", now=now + timedelta(hours=1))
    source = get_source(conn, "src")
    assert (source.last_error, source.last_success_at) == ("HTTP 500", ts(now))
    assert source.last_attempt_at == ts(now + timedelta(hours=1))
    assert _current(conn) == {"1.2.3.4"}


def test_prune_removes_old_sightings_and_orphan_indicators(
    conn: sqlite3.Connection, now: datetime
) -> None:
    old = now - timedelta(days=40)
    record_fetch_success(conn, "src", {A}, now=old, etag=None, last_modified=None)
    record_fetch_success(conn, "src", {B}, now=now, etag=None, last_modified=None)
    assert prune(conn, now=now, retention_days=30) == 1
    assert {r[0] for r in conn.execute("SELECT value FROM indicators")} == {"5.6.7.8"}


def test_staging_counts_distinct_and_leaves_sightings_alone(
    conn: sqlite3.Connection, now: datetime
) -> None:
    record_fetch_success(conn, "src", {A}, now=now, etag=None, last_modified=None)
    assert stage_fetched(conn, (ind for ind in (B, B, C))) == 2
    assert _current(conn) == {"1.2.3.4"}
    later = now + timedelta(hours=1)
    assert apply_fetched(conn, "src", now=later, etag=None, last_modified=None) == (2, 1)
    assert _current(conn) == {"5.6.7.8", "9.9.9.0/24"}


def test_record_fetch_success_accepts_any_iterable(conn: sqlite3.Connection, now: datetime) -> None:
    result = record_fetch_success(
        conn, "src", iter([A, A, B]), now=now, etag=None, last_modified=None
    )
    assert result == (2, 0)
