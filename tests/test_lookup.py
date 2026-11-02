# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime

from tests.factories import make_entry
from threatcull.indicators import Indicator
from threatcull.lookup import lookup
from threatcull.store.allowlist import add_entry
from threatcull.store.outputs import ensure_default_outputs
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import sync_catalog


def _setup(conn: sqlite3.Connection, now: datetime) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="a", url="https://a.example/1", default_enabled=True, name="Source A"),
            make_entry(id="b", url="https://b.example/1", default_enabled=True, name="Source B"),
            make_entry(id="c", url="https://c.example/1", default_enabled=True, name="Source C"),
        ],
    )
    ensure_default_outputs(conn)
    for source_id in ("a", "b", "c"):
        record_fetch_success(
            conn, source_id, {Indicator("45.9.20.1", "ip")}, now=now, etag=None, last_modified=None
        )


def test_lookup_explains_sources_score_and_outputs(conn: sqlite3.Connection, now: datetime) -> None:
    _setup(conn, now)
    result = lookup(conn, " 45.9.20.1 ", now=now)
    assert result is not None
    assert [s.source_name for s in result.sightings] == ["Source A", "Source B", "Source C"]
    assert (result.score, result.tier, result.allowlisted_by) == (3, "high", None)
    assert result.eligible_outputs == ("ip-high", "ip-medium")


def test_lookup_reports_the_allowlist_reason(conn: sqlite3.Connection, now: datetime) -> None:
    _setup(conn, now)
    add_entry(conn, "45.9.20.0/24", "our partner", now=now)
    result = lookup(conn, "45.9.20.1", now=now)
    assert result is not None
    assert result.allowlisted_by is not None
    assert result.allowlisted_by.note == "our partner"
    assert result.eligible_outputs == ()


def test_unseen_indicator_has_no_score(conn: sqlite3.Connection, now: datetime) -> None:
    _setup(conn, now)
    result = lookup(conn, "example.com", now=now)
    assert result is not None
    assert (result.kind, result.score, result.tier, result.sightings) == ("domain", 0, None, ())


def test_invalid_or_private_values_return_none(conn: sqlite3.Connection, now: datetime) -> None:
    assert lookup(conn, "192.168.1.10", now=now) is None
    assert lookup(conn, "not a thing", now=now) is None


def test_lookup_reports_an_allowlisted_subdomain(conn: sqlite3.Connection, now: datetime) -> None:
    _setup(conn, now)
    record_fetch_success(
        conn, "a", {Indicator("example.com", "domain")}, now=now, etag=None, last_modified=None
    )
    add_entry(conn, "login.example.com", "staff sign-in", now=now)
    result = lookup(conn, "example.com", now=now)
    assert result is not None
    assert result.allowlisted_by is not None
    assert result.allowlisted_by.value == "login.example.com"
    assert result.eligible_outputs == ()
