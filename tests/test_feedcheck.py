# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import io

from threatcull.feedcheck import Feed, probe_feed
from threatcull.fetcher import Fetcher, FetchError, FetchResult

FEED = Feed("https://feeds.example/list.txt", "plain", "ip")


def _fetch(text: str, content_type: str | None = "text/plain") -> Fetcher:
    def fetch(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        return FetchResult("ok", text, content_type=content_type)

    return fetch


def test_probe_counts_and_hashes_the_entry_set() -> None:
    probe = probe_feed(FEED, _fetch("45.9.20.1\n45.9.20.2\nnot-an-ip\n192.168.1.1\n"))
    assert (probe.valid, probe.rejected, probe.error, probe.html) == (2, 2, None, False)
    assert len(probe.set_sha256) == 64


def test_order_duplicates_and_comment_headers_do_not_change_the_hash() -> None:
    first = probe_feed(FEED, _fetch("# Generated: 2026-10-01\n45.9.20.1\n45.9.20.2\n"))
    second = probe_feed(FEED, _fetch("# Generated: 2026-10-11\n45.9.20.2\n45.9.20.1\n45.9.20.1\n"))
    assert first.set_sha256 == second.set_sha256


def test_a_different_entry_set_changes_the_hash() -> None:
    first = probe_feed(FEED, _fetch("45.9.20.1\n"))
    second = probe_feed(FEED, _fetch("45.9.20.2\n"))
    assert first.set_sha256 != second.set_sha256


def test_an_html_page_is_flagged_not_parsed() -> None:
    page = probe_feed(FEED, _fetch("<!doctype html><p>Not found</p>", "text/plain"))
    assert (page.html, page.valid, page.set_sha256) == (True, 0, "")
    typed = probe_feed(FEED, _fetch("45.9.20.1\n", "text/html; charset=utf-8"))
    assert typed.html is True


def test_a_download_error_is_reported() -> None:
    def down(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        raise FetchError("ConnectError")

    assert probe_feed(FEED, down).error == "ConnectError"


def test_an_html_page_in_a_json_or_csv_feed_is_flagged() -> None:
    json_page = probe_feed(
        Feed("https://f.example/x.json", "json", "ip", json_keys=("a",)),
        _fetch("<html>challenge</html>", "text/html"),
    )
    assert (json_page.html, json_page.parse_error, json_page.problem) == (
        True,
        None,
        ("html", "HTML page, not a list"),
    )
    csv_page = probe_feed(
        Feed("https://f.example/x.csv", "csv", "domain"),
        _fetch("\n  <!DOCTYPE html><title>Just a moment...</title>\nevil.example\n", "text/html"),
    )
    assert csv_page.html is True
    assert csv_page.valid == 0


def test_a_csv_or_json_feed_served_as_text_html_but_not_markup_is_parsed() -> None:
    probe = probe_feed(
        Feed("https://f.example/x.csv", "csv", "ip"), _fetch("45.9.20.1\n", "text/html")
    )
    assert (probe.html, probe.valid) == (False, 1)


def test_a_parse_error_is_reported_apart_from_a_download_error() -> None:
    probe = probe_feed(
        Feed("https://f.example/x.json", "json", "ip", json_keys=("a",)), _fetch("{broken")
    )
    assert probe.error is None
    assert probe.parse_error is not None
    assert probe.parse_error.startswith("invalid JSON")
    assert probe.problem == ("parse", probe.parse_error)


def test_problem_names_why_a_probe_is_unusable() -> None:
    assert probe_feed(FEED, _fetch("45.9.20.1\n")).problem is None
    assert probe_feed(FEED, _fetch("not-an-ip\n")).problem == (
        "empty",
        "0 valid entries (1 lines rejected)",
    )

    def down(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        raise FetchError("HTTP 410 from x")

    assert probe_feed(FEED, down).problem == ("download", "HTTP 410 from x")


def test_a_spooled_download_is_parsed_and_closed() -> None:
    body = io.BytesIO(b"45.9.20.1\n45.9.20.2\n")

    def spooled(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        return FetchResult("ok", "", content_type="text/plain", body=body, sha256="x")

    probe = probe_feed(FEED, spooled)
    assert (probe.valid, probe.problem) == (2, None)
    assert body.closed
