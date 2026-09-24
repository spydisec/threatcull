# SPDX-License-Identifier: AGPL-3.0-only
"""Rotating Feed Tokens and creating Outputs from the Outputs page and API."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from threatcull.store.outputs import OutputSpec, create_output, verify_token
from threatcull.web.deps import open_db

SPEC = OutputSpec("ip-high", "ip", frozenset({"malicious"}), "high", None, "plain")

_QUERY_TOKEN = re.compile(r"/o/ip-high\?token=([A-Za-z0-9_-]+)")


def _seed(tmp_path: Path) -> str:
    conn = open_db(tmp_path)
    try:
        return create_output(conn, SPEC)
    finally:
        conn.close()


# --- Rotate --------------------------------------------------------------------


def test_rotate_shows_the_new_token_once_and_invalidates_the_old_one(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    old_token = _seed(tmp_path)

    response = client.post(
        f"/outputs/{SPEC.name}/rotate", data={"csrf": logged_in}, follow_redirects=False
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    match = _QUERY_TOKEN.search(response.text)
    assert match is not None, response.text
    new_token = match.group(1)
    assert new_token != old_token
    assert f"/o/{SPEC.name}/{new_token}" in response.text
    assert "stopped working" in response.text

    still_old = client.get(f"/o/{SPEC.name}", params={"token": old_token})
    assert still_old.status_code == 404

    now_works = client.get(f"/o/{SPEC.name}", params={"token": new_token})
    # Never published, so 404 - but a *different* 404 path than "wrong token"
    # would be, i.e. verify_token accepts it: check via the store directly.
    assert now_works.status_code == 404  # unpublished, not a token problem
    conn = open_db(tmp_path)
    try:
        assert verify_token(conn, SPEC.name, new_token)
        assert not verify_token(conn, SPEC.name, old_token)
    finally:
        conn.close()


def test_rotate_unknown_output_is_404(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/outputs/does-not-exist/rotate", data={"csrf": logged_in}, follow_redirects=False
    )
    assert response.status_code == 404


def test_rotate_without_csrf_is_refused_and_does_not_rotate(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    old_token = _seed(tmp_path)
    response = client.post(f"/outputs/{SPEC.name}/rotate", data={}, follow_redirects=False)
    assert response.status_code == 403
    conn = open_db(tmp_path)
    try:
        assert verify_token(conn, SPEC.name, old_token)
    finally:
        conn.close()


# --- Create ----------------------------------------------------------------------


def test_create_output_shows_the_token_once(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/outputs",
        data={
            "csrf": logged_in,
            "name": "my-output",
            "kind": "ip",
            "categories": ["malicious", "c2"],
            "min_tier": "medium",
            "max_entries": "",
            "format": "plain",
        },
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "my-output" in response.text
    match = re.search(r"/o/my-output\?token=([A-Za-z0-9_-]+)", response.text)
    assert match is not None, response.text


def test_create_output_with_a_hosts_format_on_an_ip_output_is_400(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/outputs",
        data={
            "csrf": logged_in,
            "name": "bad-output",
            "kind": "ip",
            "categories": ["malicious"],
            "min_tier": "high",
            "max_entries": "",
            "format": "hosts",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "only suits domain Outputs" in response.text
    conn = open_db(tmp_path)
    try:
        rows = conn.execute("SELECT name FROM outputs").fetchall()
    finally:
        conn.close()
    assert rows == []


def test_create_output_with_non_numeric_max_entries_is_an_inline_400_not_422(
    client: TestClient, logged_in: str
) -> None:
    response = client.post(
        "/outputs",
        data={
            "csrf": logged_in,
            "name": "cap-output",
            "kind": "ip",
            "categories": ["malicious"],
            "min_tier": "high",
            "max_entries": "not-a-number",
            "format": "plain",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("text/html")


def test_create_output_with_no_categories_is_400(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/outputs",
        data={
            "csrf": logged_in,
            "name": "no-cat-output",
            "kind": "ip",
            "min_tier": "high",
            "max_entries": "",
            "format": "plain",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_create_output_duplicate_name_is_400(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    response = client.post(
        "/outputs",
        data={
            "csrf": logged_in,
            "name": SPEC.name,
            "kind": "ip",
            "categories": ["malicious"],
            "min_tier": "high",
            "max_entries": "",
            "format": "plain",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "already exists" in response.text


def test_create_output_without_csrf_is_refused(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/outputs",
        data={
            "name": "no-csrf-output",
            "kind": "ip",
            "categories": ["malicious"],
            "min_tier": "high",
            "max_entries": "",
            "format": "plain",
        },
        follow_redirects=False,
    )
    assert response.status_code == 403


# --- API mirror: rotate only -----------------------------------------------------


def test_api_rotate_requires_csrf_header(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    old_token = _seed(tmp_path)
    refused = client.post(f"/api/v1/outputs/{SPEC.name}/rotate")
    assert refused.status_code == 403

    response = client.post(
        f"/api/v1/outputs/{SPEC.name}/rotate", headers={"X-CSRF-Token": logged_in}
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["name"] == SPEC.name
    assert body["token"] != old_token

    conn = open_db(tmp_path)
    try:
        assert verify_token(conn, SPEC.name, body["token"])
        assert not verify_token(conn, SPEC.name, old_token)
    finally:
        conn.close()


def test_api_rotate_unknown_output_is_404(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/api/v1/outputs/does-not-exist/rotate", headers={"X-CSRF-Token": logged_in}
    )
    assert response.status_code == 404
