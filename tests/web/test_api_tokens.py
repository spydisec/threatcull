# SPDX-License-Identifier: AGPL-3.0-only
"""API tokens: ``Authorization: Bearer`` on ``/api/``, CSRF only for cookie sessions."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.web.conftest import login
from threatcull import cli
from threatcull.clock import utcnow
from threatcull.store.api_tokens import create_api_token, revoke_api_token
from threatcull.web.deps import open_db


def _token(data_dir: Path, name: str = "script", user: str = "admin") -> str:
    conn = open_db(data_dir)
    try:
        return create_api_token(conn, name, user, now=utcnow())
    finally:
        conn.close()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _allowlisted(data_dir: Path) -> list[str]:
    conn = open_db(data_dir)
    try:
        return [row[0] for row in conn.execute("SELECT value FROM allowlist ORDER BY value")]
    finally:
        conn.close()


def test_bearer_token_authenticates_an_api_read(
    client: TestClient, admin: str, tmp_path: Path
) -> None:
    response = client.get("/api/v1/me", headers=_bearer(_token(tmp_path)))
    assert response.status_code == 200
    assert response.json() == {"username": admin}


def test_bearer_scheme_is_case_insensitive(client: TestClient, admin: str, tmp_path: Path) -> None:
    token = _token(tmp_path)
    response = client.get("/api/v1/me", headers={"Authorization": f"bearer {token}"})
    assert response.status_code == 200


def test_bearer_post_needs_no_csrf_token(client: TestClient, admin: str, tmp_path: Path) -> None:
    response = client.post(
        "/api/v1/allowlist",
        json={"value": "1.2.3.4", "note": "from a script"},
        headers=_bearer(_token(tmp_path)),
    )
    assert response.status_code == 200, response.text
    assert _allowlisted(tmp_path) == ["1.2.3.4"]


def test_bearer_delete_needs_no_csrf_token(client: TestClient, admin: str, tmp_path: Path) -> None:
    headers = _bearer(_token(tmp_path))
    client.post("/api/v1/allowlist", json={"value": "1.2.3.4", "note": ""}, headers=headers)
    response = client.delete("/api/v1/allowlist", params={"value": "1.2.3.4"}, headers=headers)
    assert response.status_code == 200, response.text
    assert _allowlisted(tmp_path) == []


def test_session_post_without_csrf_is_still_403(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post("/api/v1/allowlist", json={"value": "1.2.3.4", "note": ""})
    assert response.status_code == 403
    assert _allowlisted(tmp_path) == []


def test_invalid_bearer_is_401_even_with_a_valid_session(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    headers = {**_bearer("tc_wrong"), "X-CSRF-Token": logged_in}
    assert client.get("/api/v1/me", headers=headers).status_code == 401
    response = client.post(
        "/api/v1/allowlist", json={"value": "1.2.3.4", "note": ""}, headers=headers
    )
    assert response.status_code == 401
    assert _allowlisted(tmp_path) == []


@pytest.mark.parametrize("header", ["Bearer", "Bearer ", "Bearer  ", "Bearer a b"])
def test_malformed_bearer_is_401(client: TestClient, admin: str, header: str) -> None:
    assert client.get("/api/v1/me", headers={"Authorization": header}).status_code == 401


def test_revoked_token_is_401(client: TestClient, admin: str, tmp_path: Path) -> None:
    token = _token(tmp_path)
    assert client.get("/api/v1/me", headers=_bearer(token)).status_code == 200
    conn = open_db(tmp_path)
    try:
        revoke_api_token(conn, "script")
    finally:
        conn.close()
    assert client.get("/api/v1/me", headers=_bearer(token)).status_code == 401


def test_token_of_a_deleted_user_is_401(client: TestClient, admin: str, tmp_path: Path) -> None:
    token = _token(tmp_path)
    conn = open_db(tmp_path)
    try:
        conn.execute("DELETE FROM users WHERE username = ?", (admin,))
    finally:
        conn.close()
    assert client.get("/api/v1/me", headers=_bearer(token)).status_code == 401


def test_bearer_is_not_accepted_on_html_pages(
    client: TestClient, admin: str, tmp_path: Path
) -> None:
    token = _token(tmp_path)
    response = client.get("/outputs", headers=_bearer(token), follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_bearer_does_not_skip_csrf_on_html_form_posts(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    token = _token(tmp_path)
    response = client.post(
        "/allowlist",
        data={"value": "1.2.3.4", "note": ""},
        headers=_bearer(token),
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert _allowlisted(tmp_path) == []


def test_bearer_request_sets_no_session_cookie(
    client: TestClient, admin: str, tmp_path: Path
) -> None:
    response = client.get("/api/v1/me", headers=_bearer(_token(tmp_path)))
    assert "set-cookie" not in response.headers


def test_session_login_still_works_alongside_tokens(
    client: TestClient, admin: str, tmp_path: Path
) -> None:
    _token(tmp_path)
    csrf = login(client)
    response = client.post(
        "/api/v1/allowlist",
        json={"value": "1.2.3.4", "note": ""},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200


# --- CLI: threatcull api-token ---------------------------------------------------


def test_cli_create_prints_the_token_once_and_it_works(
    client: TestClient, admin: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    argv = ["--data-dir", str(tmp_path), "api-token", "create", "backup", "--user", admin]
    assert cli.main(argv) == cli.EXIT_OK
    out = capsys.readouterr().out
    token = next(word for word in out.split() if word.startswith("tc_"))
    assert "shown once" in out
    assert client.get("/api/v1/me", headers=_bearer(token)).status_code == 200

    assert cli.main(["--data-dir", str(tmp_path), "api-token", "list"]) == cli.EXIT_OK
    listing = capsys.readouterr().out
    assert "backup" in listing
    assert admin in listing
    assert token not in listing

    assert cli.main(["--data-dir", str(tmp_path), "api-token", "revoke", "backup"]) == cli.EXIT_OK
    assert "revoked" in capsys.readouterr().out
    assert client.get("/api/v1/me", headers=_bearer(token)).status_code == 401


def test_cli_create_for_an_unknown_user_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["--data-dir", str(tmp_path), "api-token", "create", "backup", "--user", "ghost"]
    assert cli.main(argv) == cli.EXIT_ERROR
    captured = capsys.readouterr()
    assert "ghost" in captured.err
    assert "tc_" not in captured.out


def test_cli_revoke_unknown_token_fails(tmp_path: Path) -> None:
    argv = ["--data-dir", str(tmp_path), "api-token", "revoke", "nope"]
    assert cli.main(argv) == cli.EXIT_ERROR


def test_other_authorization_schemes_are_ignored(client: TestClient, logged_in: str) -> None:
    # Not a bearer token: the session decides, as if no header were sent.
    response = client.get("/api/v1/me", headers={"Authorization": "Basic YWRtaW46eA=="})
    assert response.status_code == 200
    client.cookies.clear()
    response = client.get("/api/v1/me", headers={"Authorization": "Basic YWRtaW46eA=="})
    assert response.status_code == 401


@pytest.mark.parametrize("name", ["backup", "bad name"])
def test_cli_create_with_a_duplicate_or_bad_name_fails_without_a_token(
    admin: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    _token(tmp_path, name="backup")
    capsys.readouterr()
    argv = ["--data-dir", str(tmp_path), "api-token", "create", name, "--user", admin]
    assert cli.main(argv) == cli.EXIT_ERROR
    captured = capsys.readouterr()
    assert "tc_" not in captured.out
    assert "error:" in captured.err
