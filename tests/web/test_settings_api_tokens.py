# SPDX-License-Identifier: AGPL-3.0-only
"""The API tokens card on Settings: list, create (shown once) and revoke."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatcull.clock import utcnow
from threatcull.store.api_tokens import ApiTokenInfo, create_api_token, list_api_tokens
from threatcull.store.users import create_user
from threatcull.web.deps import open_db

_REVEALED = re.compile(r'value="(tc_[A-Za-z0-9_-]+)"')


def _seed(data_dir: Path, name: str = "script") -> str:
    conn = open_db(data_dir)
    try:
        return create_api_token(conn, name, "admin", now=utcnow())
    finally:
        conn.close()


def _tokens(data_dir: Path) -> list[ApiTokenInfo]:
    conn = open_db(data_dir)
    try:
        return list_api_tokens(conn)
    finally:
        conn.close()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create(client: TestClient, csrf: str, name: str) -> str:
    response = client.post("/settings/api-tokens", data={"csrf": csrf, "name": name})
    assert response.status_code == 200, response.text
    match = _REVEALED.search(response.text)
    assert match is not None, response.text
    return match.group(1)


# --- List ----------------------------------------------------------------------


def test_settings_lists_every_token_without_its_value(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    token = _seed(tmp_path, "monitoring")

    page = client.get("/settings")

    assert page.status_code == 200
    assert "API tokens" in page.text
    assert "monitoring" in page.text
    assert "admin" in page.text
    assert "never" in page.text  # not used yet
    assert token not in page.text
    assert "docs/API.md" in page.text


def test_settings_says_so_when_there_are_no_tokens(client: TestClient, logged_in: str) -> None:
    assert "No API tokens yet." in client.get("/settings").text


# --- Create --------------------------------------------------------------------


def test_create_shows_the_token_once_and_it_authenticates(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post("/settings/api-tokens", data={"csrf": logged_in, "name": "backup-job"})

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    match = _REVEALED.search(response.text)
    assert match is not None, response.text
    token = match.group(1)
    assert "shown once" in response.text

    assert [(t.name, t.username) for t in _tokens(tmp_path)] == [("backup-job", "admin")]
    assert token not in client.get("/settings").text  # a reload doesn't show it again

    client.cookies.clear()
    status = client.get("/api/v1/status", headers=_bearer(token))
    assert status.status_code == 200


@pytest.mark.parametrize("name", ["", "has space", "x" * 65])
def test_create_rejects_an_invalid_name(
    client: TestClient, logged_in: str, tmp_path: Path, name: str
) -> None:
    response = client.post("/settings/api-tokens", data={"csrf": logged_in, "name": name})

    assert response.status_code == 400
    assert "must be 1-64 characters" in response.text
    assert _REVEALED.search(response.text) is None
    assert _tokens(tmp_path) == []


def test_create_rejects_a_duplicate_name(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, "script")

    response = client.post("/settings/api-tokens", data={"csrf": logged_in, "name": "script"})

    assert response.status_code == 400
    assert "already exists" in response.text
    assert _REVEALED.search(response.text) is None
    assert len(_tokens(tmp_path)) == 1


# --- Revoke --------------------------------------------------------------------


def test_revoke_removes_the_token_and_it_stops_working(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    token = _create(client, logged_in, "script")

    response = client.post(
        "/settings/api-tokens/revoke",
        data={"name": "script", "csrf": logged_in, "confirm": "true"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/settings"
    assert _tokens(tmp_path) == []
    assert "API token revoked." in client.get("/settings").text

    client.cookies.clear()
    assert client.get("/api/v1/status", headers=_bearer(token)).status_code == 401


def test_revoke_needs_the_confirm_box(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    _seed(tmp_path, "script")

    response = client.post(
        "/settings/api-tokens/revoke", data={"name": "script", "csrf": logged_in}
    )

    assert response.status_code == 400
    assert "Tick the confirm box" in response.text
    assert len(_tokens(tmp_path)) == 1


def test_revoke_of_a_token_that_is_already_gone_shows_a_message(
    client: TestClient, logged_in: str
) -> None:
    response = client.post(
        "/settings/api-tokens/revoke", data={"name": "gone", "csrf": logged_in, "confirm": "true"}
    )

    assert response.status_code == 404
    assert "no API token" in response.text


# --- Who may create and revoke -------------------------------------------------


def test_create_and_revoke_need_a_csrf_token(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, "script")

    created = client.post("/settings/api-tokens", data={"name": "other"})
    revoked = client.post("/settings/api-tokens/revoke", data={"name": "script", "confirm": "true"})

    assert created.status_code == 403
    assert revoked.status_code == 403
    assert [t.name for t in _tokens(tmp_path)] == ["script"]


def test_an_api_token_cannot_create_or_revoke_tokens(
    client: TestClient, admin: str, tmp_path: Path
) -> None:
    token = _seed(tmp_path, "script")

    created = client.post(
        "/settings/api-tokens",
        data={"name": "other"},
        headers=_bearer(token),
        follow_redirects=False,
    )
    revoked = client.post(
        "/settings/api-tokens/revoke",
        data={"name": "script", "confirm": "true"},
        headers=_bearer(token),
        follow_redirects=False,
    )

    # 403 from the CSRF check: a bearer token gives a page route no session.
    assert created.status_code == 403
    assert revoked.status_code == 403
    assert [t.name for t in _tokens(tmp_path)] == ["script"]


def test_no_token_route_exists_under_the_api(client: TestClient, logged_in: str) -> None:
    response = client.post("/api/v1/tokens", json={"name": "other"})
    assert response.status_code in (404, 405)


# --- Logging -------------------------------------------------------------------


def test_create_and_revoke_are_logged_without_the_token(
    client: TestClient, logged_in: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="threatcull.web.routes.pages"):
        token = _create(client, logged_in, "script")
        client.post(
            "/settings/api-tokens/revoke",
            data={"name": "script", "csrf": logged_in, "confirm": "true"},
        )

    messages = [record.getMessage() for record in caplog.records]
    assert any("created" in m and "script" in m and "admin" in m for m in messages), messages
    assert any("revoked" in m and "script" in m and "admin" in m for m in messages), messages
    assert all(token not in m for m in messages)


# --- Owner, odd names and where the messages show --------------------------------


def _seed_for(data_dir: Path, username: str, name: str) -> None:
    conn = open_db(data_dir)
    try:
        create_user(conn, username, "a-long-enough-password", now=utcnow())
        create_api_token(conn, name, username, now=utcnow())
    finally:
        conn.close()


def test_only_the_owner_can_revoke_a_token(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed_for(tmp_path, "bob", "bob-script")

    page = client.get("/settings").text
    response = client.post(
        "/settings/api-tokens/revoke",
        data={"csrf": logged_in, "name": "bob-script", "confirm": "true"},
        follow_redirects=False,
    )

    assert "Only bob can revoke it" in page
    assert 'name="name" value="bob-script"' not in page
    assert response.status_code == 403
    assert "belongs to bob" in response.text
    assert [t.name for t in _tokens(tmp_path)] == ["bob-script"]


@pytest.mark.parametrize("name", [".", "..", "a.b"])
def test_a_token_named_with_dots_can_be_revoked(
    client: TestClient, logged_in: str, tmp_path: Path, name: str
) -> None:
    _create(client, logged_in, name)

    response = client.post(
        "/settings/api-tokens/revoke",
        data={"csrf": logged_in, "name": name, "confirm": "true"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert _tokens(tmp_path) == []


def test_revoke_with_an_odd_confirm_value_shows_the_page(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)

    response = client.post(
        "/settings/api-tokens/revoke",
        data={"csrf": logged_in, "name": "script", "confirm": "maybe"},
    )

    assert response.status_code == 400
    assert "Tick the confirm box" in response.text
    assert [t.name for t in _tokens(tmp_path)] == ["script"]


def test_an_error_shows_above_the_first_card(client: TestClient, logged_in: str) -> None:
    _create(client, logged_in, "script")

    response = client.post("/settings/api-tokens", data={"csrf": logged_in, "name": "script"})

    assert response.status_code == 400
    assert response.text.index('role="alert"') < response.text.index("<h2>Pipeline</h2>")
