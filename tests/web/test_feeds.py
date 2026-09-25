# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /o/{name}``: serving Outputs to devices via Feed Tokens."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import BinaryIO

import pytest
from fastapi.testclient import TestClient

from threatcull.clock import utcnow
from threatcull.outputs.files import output_path
from threatcull.store import outputs as store_outputs
from threatcull.store.outputs import OutputSpec, create_output, record_published
from threatcull.web.deps import open_db
from threatcull.web.routes import feeds

PLAIN_SPEC = OutputSpec("ip-high", "ip", frozenset({"malicious"}), "high", None, "plain")
JSON_SPEC = OutputSpec("ip-json", "ip", frozenset({"malicious"}), "high", None, "json")
CSV_SPEC = OutputSpec("ip-csv", "ip", frozenset({"malicious"}), "high", None, "csv")
HOSTS_SPEC = OutputSpec("dom-hosts", "domain", frozenset({"malicious"}), "high", None, "hosts")


def _seed(tmp_path: Path, spec: OutputSpec, body: str) -> str:
    """Create ``spec``, write and "publish" its file; return its Feed Token."""
    conn = open_db(tmp_path)
    try:
        token = create_output(conn, spec)
        out_dir = tmp_path / "outputs"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = output_path(out_dir, spec)
        path.write_text(body, encoding="utf-8")
        record_published(conn, spec.name, body.count("\n"), now=utcnow())
    finally:
        conn.close()
    return token


def _create_unpublished(tmp_path: Path, spec: OutputSpec) -> str:
    """Create ``spec`` (a Feed Token exists) but never write/publish its file."""
    conn = open_db(tmp_path)
    try:
        return create_output(conn, spec)
    finally:
        conn.close()


def test_valid_token_by_query_string_serves_the_file(client: TestClient, tmp_path: Path) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n45.9.20.2\n")
    response = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    assert response.status_code == 200
    assert response.text == "45.9.20.1\n45.9.20.2\n"
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.headers["cache-control"] == "no-cache"


def test_valid_token_by_path_segment_serves_the_file(client: TestClient, tmp_path: Path) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    response = client.get(f"/o/{PLAIN_SPEC.name}/{token}")
    assert response.status_code == 200
    assert response.text == "45.9.20.1\n"


@pytest.mark.parametrize(
    ("spec", "expected_content_type"),
    [
        (JSON_SPEC, "application/json"),
        (CSV_SPEC, "text/csv; charset=utf-8"),
        (HOSTS_SPEC, "text/plain; charset=utf-8"),
    ],
)
def test_content_type_follows_output_format(
    client: TestClient, tmp_path: Path, spec: OutputSpec, expected_content_type: str
) -> None:
    token = _seed(tmp_path, spec, "x\n")
    response = client.get(f"/o/{spec.name}", params={"token": token})
    assert response.status_code == 200
    assert response.headers["content-type"] == expected_content_type


def test_wrong_token_is_404(client: TestClient, tmp_path: Path) -> None:
    _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    response = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": "wrong"})
    assert response.status_code == 404
    assert response.text == "not found"


def test_token_of_one_output_does_not_serve_another(client: TestClient, tmp_path: Path) -> None:
    token_a = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    _seed(tmp_path, JSON_SPEC, "[]\n")
    response = client.get(f"/o/{JSON_SPEC.name}", params={"token": token_a})
    assert response.status_code == 404
    assert response.text == "not found"


def test_unknown_output_name_is_404(client: TestClient, tmp_path: Path) -> None:
    response = client.get("/o/does-not-exist", params={"token": "whatever"})
    assert response.status_code == 404
    assert response.text == "not found"


def test_never_published_output_is_404_with_same_body(client: TestClient, tmp_path: Path) -> None:
    token = _create_unpublished(tmp_path, PLAIN_SPEC)
    response = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    assert response.status_code == 404
    assert response.text == "not found"


@pytest.mark.parametrize("name", ["UPPER", "a_b", "-leading", ".hidden", "x" * 100])
def test_invalid_output_name_is_404_without_touching_the_filesystem(
    client: TestClient, tmp_path: Path, name: str
) -> None:
    # Names that don't match the Output-name pattern must be rejected before
    # any filesystem path is built from them (no path traversal).
    response = client.get(f"/o/{name}", params={"token": "whatever"})
    assert response.status_code == 404
    assert response.text == "not found"


def test_if_none_match_with_returned_etag_is_304(client: TestClient, tmp_path: Path) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    first = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    assert first.status_code == 200
    etag = first.headers["etag"]
    second = client.get(
        f"/o/{PLAIN_SPEC.name}",
        params={"token": token},
        headers={"If-None-Match": etag},
    )
    assert second.status_code == 304
    assert second.text == ""


def test_if_none_match_with_a_different_etag_still_serves_the_file(
    client: TestClient, tmp_path: Path
) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    response = client.get(
        f"/o/{PLAIN_SPEC.name}",
        params={"token": token},
        headers={"If-None-Match": '"stale-etag"'},
    )
    assert response.status_code == 200
    assert response.text == "45.9.20.1\n"


def test_if_modified_since_in_the_past_still_serves_the_file(
    client: TestClient, tmp_path: Path
) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    response = client.get(
        f"/o/{PLAIN_SPEC.name}",
        params={"token": token},
        headers={"If-Modified-Since": "Mon, 01 Jan 2001 00:00:00 GMT"},
    )
    assert response.status_code == 200
    assert response.text == "45.9.20.1\n"


def test_if_modified_since_with_returned_last_modified_is_304(
    client: TestClient, tmp_path: Path
) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    first = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    last_modified = first.headers["last-modified"]
    second = client.get(
        f"/o/{PLAIN_SPEC.name}",
        params={"token": token},
        headers={"If-Modified-Since": last_modified},
    )
    assert second.status_code == 304


def test_response_never_sets_a_session_cookie(client: TestClient, tmp_path: Path) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    # Even with an existing (unrelated) session cookie sent along, the feed
    # route must never touch the session, so it must never set one either.
    client.cookies.set("threatcull_session", "not-a-real-session-value")
    response = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    assert response.status_code == 200
    assert "set-cookie" not in response.headers


# --- Review fix round 1 -----------------------------------------------------------


def test_feeds_reuses_the_store_output_name_pattern() -> None:
    # No duplicated regex: the same compiled pattern object, not a copy of it.
    # (getattr, not a static `feeds.NAME_PATTERN` access: it's imported, not
    # re-exported, and mypy --strict flags accessing an un-reexported name.)
    assert getattr(feeds, "NAME_PATTERN") is store_outputs.NAME_PATTERN  # noqa: B009


def test_verify_token_runs_once_whether_the_name_is_invalid_unknown_or_wrong(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid/unknown name must not let ``verify_token`` be skipped entirely.

    Skipping it would make "no DB+hash check ran" an observable (faster)
    signal that the name doesn't exist — the existence-timing oracle this
    fix closes.
    """
    _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    calls: list[tuple[str, str]] = []
    original = store_outputs.verify_token  # same function object feeds.py imported

    def spy(conn: sqlite3.Connection, name: str, token: str) -> bool:
        calls.append((name, token))
        return original(conn, name, token)

    monkeypatch.setattr(feeds, "verify_token", spy)

    client.get("/o/UPPER", params={"token": "whatever"})  # regex-invalid shape
    client.get("/o/does-not-exist", params={"token": "whatever"})  # valid shape, unknown
    client.get(f"/o/{PLAIN_SPEC.name}", params={"token": "wrong"})  # known, wrong token

    assert [name for name, _token in calls] == [
        feeds._DUMMY_NAME,
        "does-not-exist",
        PLAIN_SPEC.name,
    ]


def test_if_none_match_wildcard_is_304(client: TestClient, tmp_path: Path) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    response = client.get(
        f"/o/{PLAIN_SPEC.name}", params={"token": token}, headers={"If-None-Match": "*"}
    )
    assert response.status_code == 304


def test_if_none_match_comma_list_matches_any_entry(client: TestClient, tmp_path: Path) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    first = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    etag = first.headers["etag"]
    header = f'"decoy-one", {etag}, "decoy-two"'
    second = client.get(
        f"/o/{PLAIN_SPEC.name}", params={"token": token}, headers={"If-None-Match": header}
    )
    assert second.status_code == 304


def test_if_none_match_comma_list_with_no_matching_entry_serves_the_file(
    client: TestClient, tmp_path: Path
) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    response = client.get(
        f"/o/{PLAIN_SPEC.name}",
        params={"token": token},
        headers={"If-None-Match": '"decoy-one", "decoy-two"'},
    )
    assert response.status_code == 200


def test_if_none_match_weak_validator_matches_by_opaque_value(
    client: TestClient, tmp_path: Path
) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    first = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    etag = first.headers["etag"]
    second = client.get(
        f"/o/{PLAIN_SPEC.name}",
        params={"token": token},
        headers={"If-None-Match": f"W/{etag}"},
    )
    assert second.status_code == 304


def test_if_none_match_takes_precedence_over_if_modified_since(
    client: TestClient, tmp_path: Path
) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    first = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    last_modified = first.headers["last-modified"]
    # A non-matching If-None-Match must serve the file even though
    # If-Modified-Since (sent alongside it) would otherwise say "not modified".
    second = client.get(
        f"/o/{PLAIN_SPEC.name}",
        params={"token": token},
        headers={"If-None-Match": '"decoy"', "If-Modified-Since": last_modified},
    )
    assert second.status_code == 200


def test_file_gone_when_opened_is_404(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")

    def vanished(path: Path) -> BinaryIO:
        raise FileNotFoundError(path)

    monkeypatch.setattr(feeds, "_open_output", vanished)
    response = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    assert response.status_code == 404
    assert response.text == "not found"


def test_a_directory_where_the_file_should_be_is_404(client: TestClient, tmp_path: Path) -> None:
    token = _create_unpublished(tmp_path, PLAIN_SPEC)
    output_path(tmp_path / "outputs", PLAIN_SPEC).mkdir(parents=True)
    response = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    assert response.status_code == 404
    assert response.text == "not found"


def test_a_republish_after_open_still_serves_the_opened_file_whole(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Compile's atomic replace between open and send can't break Content-Length."""
    old = "45.9.20.1\n"
    new = "45.9.20.1\n45.9.20.2\n45.9.20.3\n"
    token = _seed(tmp_path, PLAIN_SPEC, old)
    real_open = feeds._open_output

    def open_then_republish(path: Path) -> BinaryIO:
        handle = real_open(path)
        staged = path.with_name(path.name + ".new")
        staged.write_text(new, encoding="utf-8")
        staged.replace(path)
        return handle

    monkeypatch.setattr(feeds, "_open_output", open_then_republish)
    response = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    assert response.status_code == 200
    assert response.text == old
    assert response.headers["content-length"] == str(len(old))

    monkeypatch.setattr(feeds, "_open_output", real_open)
    again = client.get(
        f"/o/{PLAIN_SPEC.name}",
        params={"token": token},
        headers={"If-None-Match": response.headers["etag"]},
    )
    assert again.status_code == 200  # the new file has a new ETag
    assert again.text == new


def test_head_returns_the_headers_without_a_body(client: TestClient, tmp_path: Path) -> None:
    body = "45.9.20.1\n45.9.20.2\n"
    token = _seed(tmp_path, PLAIN_SPEC, body)
    get = client.get(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    head = client.head(f"/o/{PLAIN_SPEC.name}", params={"token": token})
    assert head.status_code == 200
    assert head.content == b""
    for name in ("content-length", "content-type", "etag", "last-modified", "cache-control"):
        assert head.headers[name] == get.headers[name]
    assert head.headers["content-length"] == str(len(body))


def test_head_by_path_token_and_conditional(client: TestClient, tmp_path: Path) -> None:
    token = _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    head = client.head(f"/o/{PLAIN_SPEC.name}/{token}")
    assert head.status_code == 200
    again = client.head(
        f"/o/{PLAIN_SPEC.name}/{token}", headers={"If-None-Match": head.headers["etag"]}
    )
    assert again.status_code == 304


def test_head_with_a_wrong_token_is_404(client: TestClient, tmp_path: Path) -> None:
    _seed(tmp_path, PLAIN_SPEC, "45.9.20.1\n")
    assert client.head(f"/o/{PLAIN_SPEC.name}", params={"token": "nope"}).status_code == 404


def _access_record(path: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:54321", "GET", path, "1.1", 200),
        exc_info=None,
    )


def test_access_filter_redacts_a_query_string_token() -> None:
    record = _access_record("/o/ip-high?token=SUPERSECRETVALUE")
    assert feeds.FeedTokenAccessFilter().filter(record) is True
    message = record.getMessage()
    assert "SUPERSECRETVALUE" not in message
    assert "/o/ip-high?token=<redacted>" in message


def test_access_filter_redacts_a_path_segment_token() -> None:
    record = _access_record("/o/ip-high/SUPERSECRETVALUE")
    feeds.FeedTokenAccessFilter().filter(record)
    message = record.getMessage()
    assert "SUPERSECRETVALUE" not in message
    assert "/o/ip-high/<redacted>" in message


def test_access_filter_leaves_other_query_params_and_paths_alone() -> None:
    record = _access_record("/o/ip-high?foo=bar&token=SUPERSECRETVALUE&other=1")
    feeds.FeedTokenAccessFilter().filter(record)
    message = record.getMessage()
    assert "foo=bar" in message
    assert "other=1" in message
    assert "SUPERSECRETVALUE" not in message

    healthz = _access_record("/healthz")
    feeds.FeedTokenAccessFilter().filter(healthz)
    assert healthz.getMessage().count("/healthz") == 1


def test_access_filter_never_drops_the_record() -> None:
    record = _access_record("/o/ip-high?token=SUPERSECRETVALUE")
    assert feeds.FeedTokenAccessFilter().filter(record) is True


def test_access_filter_ignores_records_shaped_unlike_an_access_log_line() -> None:
    # e.g. uvicorn.error log records, which don't carry a (client, method,
    # path, version, status) args tuple: must pass through unmodified.
    odd = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="Started server process [%d]",
        args=(1234,),
        exc_info=None,
    )
    assert feeds.FeedTokenAccessFilter().filter(odd) is True
    assert odd.getMessage() == "Started server process [1234]"


def test_install_feed_token_redaction_is_idempotent() -> None:
    logger = logging.getLogger("uvicorn.access")
    for existing in list(logger.filters):
        if isinstance(existing, feeds.FeedTokenAccessFilter):
            logger.removeFilter(existing)
    try:
        feeds.install_feed_token_redaction()
        feeds.install_feed_token_redaction()
        installed = [f for f in logger.filters if isinstance(f, feeds.FeedTokenAccessFilter)]
        assert len(installed) == 1
    finally:
        for existing in list(logger.filters):
            if isinstance(existing, feeds.FeedTokenAccessFilter):
                logger.removeFilter(existing)
