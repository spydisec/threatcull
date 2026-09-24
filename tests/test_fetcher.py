# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path

import httpx
import pytest

from tests.fixture_server import FixtureServer
from threatcull.fetcher import FetchError, FetchResult, HttpFetcher


def _fetcher(**kwargs: object) -> HttpFetcher:
    return HttpFetcher(retry_delays=(0.0, 0.0), sleep=lambda _: None, **kwargs)  # type: ignore[arg-type]


def test_ok_response_returns_text_and_validators(fixture_server: FixtureServer) -> None:
    fixture_server.add("/list", (200, b"1.2.3.4\n", {"ETag": '"v1"', "Last-Modified": "Wed"}))
    result = _fetcher()(fixture_server.url("/list"), etag=None, last_modified=None)
    assert result == FetchResult("ok", "1.2.3.4\n", '"v1"', "Wed")


def test_conditional_headers_and_not_modified(fixture_server: FixtureServer) -> None:
    fixture_server.add("/list", (304, b"", {}))
    result = _fetcher()(fixture_server.url("/list"), etag='"v1"', last_modified="Wed")
    assert result.status == "not_modified"
    headers = fixture_server.routes["/list"].request_headers[0]
    assert headers["If-None-Match"] == '"v1"'
    assert headers["If-Modified-Since"] == "Wed"
    assert headers["User-Agent"].startswith("ThreatCull/")


def test_retries_transient_errors_then_succeeds(fixture_server: FixtureServer) -> None:
    fixture_server.add("/flaky", (503, b"", {}), (200, b"ok\n", {}))
    assert _fetcher()(fixture_server.url("/flaky"), etag=None, last_modified=None).text == "ok\n"
    assert fixture_server.routes["/flaky"].calls == 2


def test_gives_up_after_retries(fixture_server: FixtureServer) -> None:
    fixture_server.add("/down", (500, b"", {}))
    with pytest.raises(FetchError, match="HTTP 500"):
        _fetcher()(fixture_server.url("/down"), etag=None, last_modified=None)
    assert fixture_server.routes["/down"].calls == 3


def test_client_errors_are_not_retried(fixture_server: FixtureServer) -> None:
    with pytest.raises(FetchError, match="HTTP 404"):
        _fetcher()(fixture_server.url("/missing"), etag=None, last_modified=None)


def test_redirect_loop_is_a_fetch_error_and_not_retried(fixture_server: FixtureServer) -> None:
    url = fixture_server.url("/loop")
    fixture_server.add("/loop", (302, b"", {"Location": url}))
    max_redirects = 3
    client = httpx.Client(follow_redirects=True, max_redirects=max_redirects)
    with pytest.raises(FetchError, match="TooManyRedirects"):
        _fetcher(client=client)(url, etag=None, last_modified=None)
    assert fixture_server.routes["/loop"].calls == max_redirects + 1


def test_size_cap(fixture_server: FixtureServer) -> None:
    fixture_server.add("/big", (200, b"x" * 2048, {}))
    with pytest.raises(FetchError, match="exceeds"):
        _fetcher(max_bytes=1024)(fixture_server.url("/big"), etag=None, last_modified=None)


def test_connection_refused_is_a_fetch_error() -> None:
    with pytest.raises(FetchError):
        _fetcher()("http://127.0.0.1:9/nothing", etag=None, last_modified=None)


def test_reads_local_files(tmp_path: Path) -> None:
    path = tmp_path / "list.txt"
    path.write_text("5.6.7.8\n", encoding="utf-8")
    result = _fetcher()(path.as_uri(), etag=None, last_modified=None)
    assert (result.status, result.text) == ("ok", "5.6.7.8\n")


def test_missing_or_oversized_local_files(tmp_path: Path) -> None:
    with pytest.raises(FetchError, match="cannot read"):
        _fetcher()((tmp_path / "nope.txt").as_uri(), etag=None, last_modified=None)
    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * 2048)
    with pytest.raises(FetchError, match="exceeds"):
        _fetcher(max_bytes=1024)(big.as_uri(), etag=None, last_modified=None)


def test_local_file_url_with_a_host_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FetchError, match="host"):
        _fetcher()("file://feeds/x.txt", etag=None, last_modified=None)


def test_local_file_url_with_localhost_host_is_read(tmp_path: Path) -> None:
    path = tmp_path / "list.txt"
    path.write_text("5.6.7.8\n", encoding="utf-8")
    result = _fetcher()(f"file://localhost{path}", etag=None, last_modified=None)
    assert result.text == "5.6.7.8\n"


def test_local_directory_is_a_fetch_error(tmp_path: Path) -> None:
    with pytest.raises(FetchError, match="cannot read"):
        _fetcher()(tmp_path.as_uri(), etag=None, last_modified=None)


def test_unreadable_local_file_is_a_fetch_error(tmp_path: Path) -> None:
    path = tmp_path / "secret.txt"
    path.write_text("5.6.7.8\n", encoding="utf-8")
    path.chmod(0)
    try:
        if os.access(path, os.R_OK):
            pytest.skip("running with privileges that ignore file modes")
        with pytest.raises(FetchError, match="cannot read"):
            _fetcher()(path.as_uri(), etag=None, last_modified=None)
    finally:
        path.chmod(0o600)


def test_endless_local_file_is_capped() -> None:
    with pytest.raises(FetchError, match="exceeds"):
        _fetcher(max_bytes=1024)("file:///dev/zero", etag=None, last_modified=None)


def test_content_type_is_passed_through(fixture_server: FixtureServer) -> None:
    fixture_server.add(
        "/page", (200, b"<html></html>", {"Content-Type": "text/html; charset=utf-8"})
    )
    result = _fetcher()(fixture_server.url("/page"), etag=None, last_modified=None)
    assert result.content_type == "text/html; charset=utf-8"
