# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime, timedelta

import pytest

from tests.factories import make_entry
from threatcull.fetcher import FetchError, FetchResult
from threatcull.fetching import fetch_all, fetch_source
from threatcull.store.errors import PolicyError
from threatcull.store.runs import recent_runs
from threatcull.store.sources import get_source, sync_catalog

URL = "https://example.com/list.txt"


class FakeFetcher:
    def __init__(self, results: dict[str, FetchResult | Exception]) -> None:
        self.results = results
        self.calls: list[tuple[str, str | None]] = []

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        self.calls.append((url, etag))
        result = self.results[url]
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture(autouse=True)
def _source(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [make_entry(id="src", url=URL, default_enabled=True)])


def _current_count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM sightings WHERE current = 1").fetchone()[0])


def test_ok_fetch_counts_parsed_valid_and_invalid(conn: sqlite3.Connection, now: datetime) -> None:
    fetcher = FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n1.2.3.4\n10.0.0.1\njunk\n", '"e"')})
    outcome = fetch_source(conn, get_source(conn, "src"), fetcher, now=now)
    assert (outcome.status, outcome.parsed, outcome.valid, outcome.invalid, outcome.added) == (
        "ok",
        4,
        1,
        2,
        1,
    )
    assert get_source(conn, "src").etag == '"e"'
    assert recent_runs(conn)[0].status == "ok"


def test_html_error_page_with_200_keeps_previous_sightings(
    conn: sqlite3.Connection, now: datetime
) -> None:
    fetch_source(
        conn, get_source(conn, "src"), FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n")}), now=now
    )
    html = "<!DOCTYPE html><html><body>Rate limited</body></html>\n"
    outcome = fetch_source(
        conn,
        get_source(conn, "src"),
        FakeFetcher({URL: FetchResult("ok", html)}),
        now=now + timedelta(hours=1),
    )
    assert outcome.status == "failed"
    assert outcome.error is not None
    assert "no valid indicators" in outcome.error
    assert _current_count(conn) == 1


def test_empty_body_keeps_previous_sightings(conn: sqlite3.Connection, now: datetime) -> None:
    fetch_source(
        conn, get_source(conn, "src"), FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n")}), now=now
    )
    outcome = fetch_source(
        conn, get_source(conn, "src"), FakeFetcher({URL: FetchResult("ok", "")}), now=now
    )
    assert outcome.status == "failed"
    assert _current_count(conn) == 1


def test_fetch_error_is_recorded(conn: sqlite3.Connection, now: datetime) -> None:
    outcome = fetch_source(
        conn, get_source(conn, "src"), FakeFetcher({URL: FetchError("HTTP 500")}), now=now
    )
    assert (outcome.status, outcome.error) == ("failed", "HTTP 500")
    assert get_source(conn, "src").last_error == "HTTP 500"
    assert recent_runs(conn)[0].status == "failed"


def test_not_modified_passes_etag(conn: sqlite3.Connection, now: datetime) -> None:
    fetch_source(
        conn,
        get_source(conn, "src"),
        FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n", '"e"')}),
        now=now,
    )
    fetcher = FakeFetcher({URL: FetchResult("not_modified")})
    assert fetch_source(conn, get_source(conn, "src"), fetcher, now=now).status == "not_modified"
    assert fetcher.calls == [(URL, '"e"')]


def test_parse_error_is_a_failed_fetch(conn: sqlite3.Connection, now: datetime) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="src", url=URL, default_enabled=True),
            make_entry(
                id="js",
                url="https://example.com/j",
                format="json",
                json_keys=("a",),
                default_enabled=True,
            ),
        ],
    )
    fetcher = FakeFetcher({"https://example.com/j": FetchResult("ok", "not json")})
    assert fetch_source(conn, get_source(conn, "js"), fetcher, now=now).status == "failed"


def test_fetch_all_only_touches_enabled_sources(conn: sqlite3.Connection, now: datetime) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="src", url=URL, default_enabled=True),
            make_entry(id="off", url="https://example.com/off"),
        ],
    )
    fetcher = FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n")})
    assert [o.source_id for o in fetch_all(conn, fetcher, now=now)] == ["src"]


def test_fetch_all_rejects_disabled_explicit_ids(conn: sqlite3.Connection, now: datetime) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="src", url=URL, default_enabled=True),
            make_entry(id="off", url="https://example.com/off"),
        ],
    )
    with pytest.raises(PolicyError, match="disabled"):
        fetch_all(conn, FakeFetcher({}), now=now, source_ids=["off"])
