# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /o/{name}``: serving Outputs to devices via Feed Tokens."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatcull.clock import utcnow
from threatcull.outputs.files import output_path
from threatcull.store.outputs import OutputSpec, create_output, record_published
from threatcull.web.deps import open_db

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
