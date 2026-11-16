# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.factories import make_entry
from threatcull.fetcher import FetchError, FetchResult, HttpFetcher
from threatcull.fetching import FetchOutcome, content_digest, fetch_all, fetch_source
from threatcull.store.errors import PolicyError
from threatcull.store.runs import recent_runs
from threatcull.store.sources import get_source, set_enabled, sync_catalog

URL = "https://example.com/list.txt"


class FakeFetcher:
    def __init__(self, results: dict[str, FetchResult | BaseException]) -> None:
        self.results = results
        self.calls: list[tuple[str, str | None]] = []

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        self.calls.append((url, etag))
        result = self.results[url]
        if isinstance(result, BaseException):
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
    assert "HTML page" in outcome.error
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


def _three_sources(conn: sqlite3.Connection, middle: dict[str, object]) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="a-src", url="https://example.com/a", default_enabled=True),
            make_entry(
                id="b-src", **{"url": "https://example.com/b", "default_enabled": True, **middle}
            ),
            make_entry(id="c-src", url="https://example.com/c", default_enabled=True),
        ],
    )
    set_enabled(conn, "src", False)


def _assert_isolated(conn: sqlite3.Connection, outcomes: list[FetchOutcome], error: str) -> None:
    assert [(o.source_id, o.status) for o in outcomes] == [
        ("a-src", "ok"),
        ("b-src", "failed"),
        ("c-src", "ok"),
    ]
    assert outcomes[1].error is not None
    assert error in outcomes[1].error
    assert error in (get_source(conn, "b-src").last_error or "")
    statuses = [row[0] for row in conn.execute("SELECT status FROM runs ORDER BY id")]
    assert statuses == ["ok", "failed", "ok"]


def test_unexpected_exception_fails_only_that_source(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _three_sources(conn, {})
    fetcher = FakeFetcher(
        {
            "https://example.com/a": FetchResult("ok", "1.2.3.4\n"),
            "https://example.com/b": RuntimeError("boom"),
            "https://example.com/c": FetchResult("ok", "5.6.7.8\n"),
        }
    )
    _assert_isolated(conn, fetch_all(conn, fetcher, now=now), "RuntimeError: boom")


def test_csv_error_fails_only_that_source(conn: sqlite3.Connection, now: datetime) -> None:
    _three_sources(conn, {"format": "csv"})
    fetcher = FakeFetcher(
        {
            "https://example.com/a": FetchResult("ok", "1.2.3.4\n"),
            "https://example.com/b": FetchResult("ok", '"' + "x" * (200 * 1024) + '"\n'),
            "https://example.com/c": FetchResult("ok", "5.6.7.8\n"),
        }
    )
    _assert_isolated(conn, fetch_all(conn, fetcher, now=now), "CSV")


def test_local_directory_fails_only_that_source(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    for name, body in (("a", "1.2.3.4\n"), ("c", "5.6.7.8\n")):
        (tmp_path / f"{name}.txt").write_text(body, encoding="utf-8")
    sync_catalog(
        conn,
        [
            make_entry(id="a-src", url=(tmp_path / "a.txt").as_uri(), default_enabled=True),
            make_entry(id="b-src", url=tmp_path.as_uri(), default_enabled=True),
            make_entry(id="c-src", url=(tmp_path / "c.txt").as_uri(), default_enabled=True),
        ],
    )
    set_enabled(conn, "src", False)
    outcomes = fetch_all(conn, HttpFetcher(), now=now)
    _assert_isolated(conn, outcomes, "cannot read")


def test_keyboard_interrupt_is_not_swallowed(conn: sqlite3.Connection, now: datetime) -> None:
    fetcher = FakeFetcher({URL: KeyboardInterrupt()})
    with pytest.raises(KeyboardInterrupt):
        fetch_source(conn, get_source(conn, "src"), fetcher, now=now)


DOM_URL = "https://example.com/domains.txt"
CHALLENGE = """<!DOCTYPE html>
<html lang="en">
<head><title>Just a moment...</title></head>
<body>
    raw.githubusercontent.com
</body>
</html>
"""


def _fetch_domains(
    conn: sqlite3.Connection, now: datetime, text: str, content_type: str | None = None
) -> FetchOutcome:
    sync_catalog(
        conn,
        [
            make_entry(id="src", url=URL, default_enabled=True),
            make_entry(id="dom", url=DOM_URL, kind="domain", default_enabled=True),
        ],
    )
    result = FetchResult("ok", text, content_type=content_type)
    return fetch_source(conn, get_source(conn, "dom"), FakeFetcher({DOM_URL: result}), now=now)


def _dom_values(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT i.value FROM sightings s JOIN indicators i ON i.id = s.indicator_id "
        "WHERE s.source_id = 'dom' AND s.current = 1"
    )
    return {row[0] for row in rows}


@pytest.mark.parametrize(
    ("text", "content_type"),
    [
        (CHALLENGE, None),
        ("\n  " + CHALLENGE, "text/plain"),
        ("fresh.example.org\n", "text/html; charset=UTF-8"),
    ],
)
def test_html_page_never_replaces_a_domain_list(
    conn: sqlite3.Connection, now: datetime, text: str, content_type: str | None
) -> None:
    assert _fetch_domains(conn, now, "evil.example.com\nbad.example.net\n").status == "ok"
    outcome = _fetch_domains(conn, now + timedelta(hours=1), text, content_type)
    assert outcome.status == "failed"
    assert outcome.error == "looks like an HTML page, not a list"
    assert _dom_values(conn) == {"evil.example.com", "bad.example.net"}


def test_list_starting_with_a_comment_is_not_html(conn: sqlite3.Connection, now: datetime) -> None:
    text = "# <b>Blocklist</b> generated hourly\nevil.example.com\n"
    assert _fetch_domains(conn, now, text, "text/plain; charset=utf-8").status == "ok"
    assert _dom_values(conn) == {"evil.example.com"}


def _ips(count: int) -> str:
    return "".join(f"45.9.{i >> 8}.{i & 255}\n" for i in range(count))


def test_collapse_to_under_a_tenth_keeps_previous_sightings(
    conn: sqlite3.Connection, now: datetime
) -> None:
    fetch_source(
        conn, get_source(conn, "src"), FakeFetcher({URL: FetchResult("ok", _ips(1500))}), now=now
    )
    outcome = fetch_source(
        conn,
        get_source(conn, "src"),
        FakeFetcher({URL: FetchResult("ok", _ips(149))}),
        now=now + timedelta(hours=1),
    )
    assert outcome.status == "failed"
    assert outcome.error is not None
    assert "149" in outcome.error
    assert "1500" in outcome.error
    assert _current_count(conn) == 1500


def test_normal_shrink_is_applied(conn: sqlite3.Connection, now: datetime) -> None:
    fetch_source(
        conn, get_source(conn, "src"), FakeFetcher({URL: FetchResult("ok", _ips(1500))}), now=now
    )
    outcome = fetch_source(
        conn,
        get_source(conn, "src"),
        FakeFetcher({URL: FetchResult("ok", _ips(1200))}),
        now=now + timedelta(hours=1),
    )
    assert (outcome.status, outcome.removed) == ("ok", 300)
    assert _current_count(conn) == 1200


def test_small_list_may_shrink_freely(conn: sqlite3.Connection, now: datetime) -> None:
    fetch_source(
        conn, get_source(conn, "src"), FakeFetcher({URL: FetchResult("ok", _ips(999))}), now=now
    )
    outcome = fetch_source(
        conn, get_source(conn, "src"), FakeFetcher({URL: FetchResult("ok", _ips(1))}), now=now
    )
    assert outcome.status == "ok"


def test_error_while_applying_is_a_failed_fetch(
    conn: sqlite3.Connection, now: datetime, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object, **__: object) -> tuple[int, int]:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr("threatcull.fetching.apply_fetched", broken)
    fetcher = FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n")})
    outcome = fetch_source(conn, get_source(conn, "src"), fetcher, now=now)
    assert (outcome.status, outcome.error) == ("failed", "OperationalError: disk I/O error")
    assert recent_runs(conn)[0].status == "failed"


def _run_statuses(conn: sqlite3.Connection) -> list[str]:
    return [run.status for run in recent_runs(conn)]


def _fetch_body(conn: sqlite3.Connection, body: str, now: datetime) -> FetchOutcome:
    fetcher = FakeFetcher({URL: FetchResult("ok", body)})
    return fetch_source(conn, get_source(conn, "src"), fetcher, now=now)


def test_unchanged_content_skips_parsing(conn: sqlite3.Connection, now: datetime) -> None:
    body = "1.2.3.4\n5.6.7.8\n"
    _fetch_body(conn, body, now)
    later = now + timedelta(hours=1)
    modified = "Sat, 03 Oct 2026 06:00:00 GMT"
    fetcher = FakeFetcher({URL: FetchResult("ok", body, '"new"', modified)})
    outcome = fetch_source(conn, get_source(conn, "src"), fetcher, now=later)
    assert outcome.status == "not_modified"
    assert _run_statuses(conn)[0] == "not_modified"
    assert _current_count(conn) == 2
    source = get_source(conn, "src")
    assert (source.etag, source.last_modified) == ('"new"', modified)
    assert source.last_success_at is not None
    assert source.last_success_at.startswith("2026-09-24T13")
    seen = {row[0] for row in conn.execute("SELECT last_seen FROM sightings")}
    assert all(stamp.startswith("2026-09-24T13") for stamp in seen)


def test_changed_content_is_parsed(conn: sqlite3.Connection, now: datetime) -> None:
    _fetch_body(conn, "1.2.3.4\n", now)
    outcome = _fetch_body(conn, "1.2.3.4\n5.6.7.8\n", now)
    assert (outcome.status, outcome.added) == ("ok", 1)


def test_same_content_reparses_when_sightings_changed_since(
    conn: sqlite3.Connection, now: datetime
) -> None:
    body = "1.2.3.4\n5.6.7.8\n"
    _fetch_body(conn, body, now)
    # e.g. pruned while the Source was disabled: the stored hash no longer describes them
    conn.execute(
        "DELETE FROM sightings WHERE indicator_id = (SELECT MIN(indicator_id) FROM sightings)"
    )
    outcome = _fetch_body(conn, body, now)
    assert (outcome.status, outcome.added) == ("ok", 1)
    assert _current_count(conn) == 2


def test_failed_fetch_keeps_the_hash_of_the_applied_list(
    conn: sqlite3.Connection, now: datetime
) -> None:
    body = "1.2.3.4\n"
    _fetch_body(conn, body, now)
    _fetch_body(conn, "", now)
    outcome = _fetch_body(conn, body, now)
    assert outcome.status == "not_modified"


def test_content_digest_covers_how_the_list_is_parsed(conn: sqlite3.Connection) -> None:
    source = get_source(conn, "src")
    body = FetchResult("ok", "1.2.3.4\n")
    more = FetchResult("ok", "1.2.3.4\n5.6.7.8\n")
    assert content_digest(source, body) == content_digest(source, body)
    assert content_digest(source, body) != content_digest(source, more)
    assert content_digest(source, body) != content_digest(replace(source, format="hosts"), body)
    assert content_digest(source, body) != content_digest(replace(source, url=URL + "?v=2"), body)


def test_spooled_and_in_memory_downloads_hash_the_same(
    conn: sqlite3.Connection, tmp_path: Path
) -> None:
    # A list fetched before spooling (text) and after (body + sha256) is one list.
    listing = tmp_path / "list.txt"
    listing.write_text("1.2.3.4\n5.6.7.8\n")
    spooled = HttpFetcher(spool=True)(listing.as_uri(), etag=None, last_modified=None)
    try:
        source = get_source(conn, "src")
        assert content_digest(source, spooled) == content_digest(
            source, FetchResult("ok", "1.2.3.4\n5.6.7.8\n")
        )
    finally:
        spooled.close()


def test_validators_are_dropped_when_sightings_changed_since(
    conn: sqlite3.Connection, now: datetime
) -> None:
    # e.g. disabled past the retention period: prune deleted its Sightings, and a 304
    # answering the stored ETag would leave the re-enabled Source empty for good.
    first = FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n", '"e"')})
    fetch_source(conn, get_source(conn, "src"), first, now=now)
    conn.execute("DELETE FROM sightings")
    fetcher = FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n", '"e"')})
    outcome = fetch_source(conn, get_source(conn, "src"), fetcher, now=now)
    assert fetcher.calls == [(URL, None)]
    assert (outcome.status, outcome.added) == ("ok", 1)


def test_validators_are_sent_while_sightings_are_unchanged(
    conn: sqlite3.Connection, now: datetime
) -> None:
    fetch_source(
        conn,
        get_source(conn, "src"),
        FakeFetcher({URL: FetchResult("ok", "1.2.3.4\n", '"e"')}),
        now=now,
    )
    fetcher = FakeFetcher({URL: FetchResult("not_modified")})
    fetch_source(conn, get_source(conn, "src"), fetcher, now=now)
    assert fetcher.calls == [(URL, '"e"')]


def _file_source(conn: sqlite3.Connection, path: Path, fmt: str = "plain") -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="src", url=URL, default_enabled=True),
            make_entry(id="file", url=path.as_uri(), format=fmt, default_enabled=True),
        ],
    )


def test_a_spooled_download_is_parsed_line_by_line(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    listing = tmp_path / "big.txt"
    # Over the in-memory limit, so the body really goes to a temporary file.
    lines = [f"45.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}" for i in range(1, 700_001)]
    listing.write_text("# header\r\n" + "\r\n".join(lines) + "\r\n")
    _file_source(conn, listing)
    fetcher = HttpFetcher(spool=True)
    outcome = fetch_source(conn, get_source(conn, "file"), fetcher, now=now)
    assert (outcome.status, outcome.parsed, outcome.valid) == ("ok", 700_000, 700_000)
    again = fetch_source(conn, get_source(conn, "file"), fetcher, now=now)
    assert again.status == "not_modified"  # unchanged: hashed while copying, not parsed


def test_a_spooled_html_page_is_rejected(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    page = tmp_path / "page.txt"
    page.write_text("<!DOCTYPE html><html><body>Rate limited</body></html>\n")
    _file_source(conn, page)
    outcome = fetch_source(conn, get_source(conn, "file"), HttpFetcher(spool=True), now=now)
    assert outcome.status == "failed"
    assert outcome.error is not None
    assert "HTML page" in outcome.error


def test_a_spooled_csv_source_parses(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    table = tmp_path / "list.csv"
    table.write_text("# ip,note\n1.2.3.4,a\n5.6.7.8,b\n")
    _file_source(conn, table, "csv")
    outcome = fetch_source(conn, get_source(conn, "file"), HttpFetcher(spool=True), now=now)
    assert (outcome.status, outcome.valid) == ("ok", 2)


def test_the_spooled_body_is_closed_after_the_fetch(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    listing = tmp_path / "list.txt"
    listing.write_text("1.2.3.4\n")
    _file_source(conn, listing)
    seen: list[FetchResult] = []
    spool = HttpFetcher(spool=True)

    def recording(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        result = spool(url, etag=etag, last_modified=last_modified)
        seen.append(result)
        return result

    fetch_source(conn, get_source(conn, "file"), recording, now=now)
    assert seen[0].body is not None
    assert seen[0].body.closed


@pytest.mark.parametrize("spool", [True, False])
def test_html_after_lots_of_whitespace_is_still_rejected(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path, spool: bool
) -> None:
    page = tmp_path / "page.txt"
    page.write_text("\ufeff" + " \n" * 10_000 + "<html><body>\n1.2.3.4\n</body></html>\n")
    _file_source(conn, page)
    outcome = fetch_source(conn, get_source(conn, "file"), HttpFetcher(spool=spool), now=now)
    assert outcome.status == "failed"
    assert outcome.error is not None
    assert "HTML page" in outcome.error


def test_a_fetch_records_how_long_each_stage_took(conn: sqlite3.Connection, now: datetime) -> None:
    _fetch_body(conn, "1.2.3.4\n5.6.7.8\n", now)
    run = recent_runs(conn)[0]
    assert list(run.timings) == ["download", "parse", "apply"]
    assert all(seconds >= 0 for seconds in run.timings.values())
    _fetch_body(conn, "1.2.3.4\n5.6.7.8\n", now)  # unchanged: only the download
    assert list(recent_runs(conn)[0].timings) == ["download"]
