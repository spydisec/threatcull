# SPDX-License-Identifier: AGPL-3.0-only
"""Settings page: export and import the configuration as YAML."""

from __future__ import annotations

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from threatcull.cli import main
from threatcull.clock import utcnow
from threatcull.store.api_tokens import create_api_token, verify_api_token
from threatcull.store.config import dump_config
from threatcull.store.db import connect
from threatcull.store.outputs import rotate_token, verify_token
from threatcull.store.users import create_user
from threatcull.web.deps import open_db


def test_export_needs_a_login(client: TestClient) -> None:
    response = client.get("/settings/export", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_export_downloads_the_configuration(client: TestClient, logged_in: str) -> None:
    response = client.get("/settings/export")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/yaml")
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="threatcull-config-')
    assert disposition.endswith('.yaml"')
    assert yaml.safe_load(response.text)["threatcull_config"] == 1


def test_settings_page_offers_the_export(client: TestClient, logged_in: str) -> None:
    page = client.get("/settings").text
    assert 'href="/settings/export"' in page
    assert "No passwords, raw tokens or threat data" in page


_NEW_OUTPUT = (
    b"threatcull_config: 1\n"
    b"allowlist:\n  - {value: pay.example.com, note: payments}\n"
    b"outputs:\n"
    b"  - {name: partner-ips, kind: ip, categories: [malicious], min_tier: high,\n"
    b"     max_entries: null, format: plain}\n"
)


def test_import_applies_the_file_and_shows_new_feed_tokens_once(
    client: TestClient, logged_in: str
) -> None:
    response = client.post(
        "/settings/import",
        data={"csrf": logged_in},
        files={"file": ("config.yaml", _NEW_OUTPUT, "application/yaml")},
    )
    assert response.status_code == 200
    assert "added Allowlist entry pay.example.com" in response.text
    assert "created Output partner-ips" in response.text
    assert "New Feed Token for partner-ips" in response.text
    assert "shown once" in response.text
    assert "pay.example.com" in client.get("/allowlist").text


def test_import_refuses_a_bad_file_with_a_400(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/settings/import",
        data={"csrf": logged_in},
        files={"file": ("config.yaml", b"threatcull_config: 7\n", "application/yaml")},
    )
    assert response.status_code == 400
    assert "threatcull_config" in response.text


def test_import_needs_the_csrf_token(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/settings/import",
        data={"csrf": "wrong"},
        files={"file": ("config.yaml", _NEW_OUTPUT, "application/yaml")},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert "pay.example.com" not in client.get("/allowlist").text


def test_import_needs_a_login(client: TestClient) -> None:
    response = client.post("/settings/import", follow_redirects=False)
    assert response.status_code in {303, 403}


def test_the_settings_page_title_is_plain_text(client: TestClient, logged_in: str) -> None:
    page = client.get("/settings").text
    title = page.split("<title>", 1)[1].split("</title>", 1)[0]
    assert title == "Settings · ThreatCull"
    assert page.count('id="configuration"') == 1


def test_settings_page_shows_storage(client: TestClient, logged_in: str) -> None:
    page = client.get("/settings").text
    assert 'id="storage"' in page
    assert "Sightings." in page


def test_dashboard_footer_shows_the_database_size(client: TestClient, logged_in: str) -> None:
    assert "Database " in client.get("/").text


def _backup_with_rotated_token(tmp_path: Path) -> tuple[bytes, str]:
    data = ["--data-dir", str(tmp_path / "old")]
    assert main([*data, "outputs", "list"]) == 0

    conn = connect(tmp_path / "old" / "threatcull.db")
    try:
        raw = rotate_token(conn, "ip-high")
        return dump_config(conn, now=utcnow()).encode(), raw
    finally:
        conn.close()


def _token_ok(tmp_path: Path, raw: str) -> bool:
    conn = open_db(tmp_path)
    try:
        return verify_token(conn, "ip-high", raw)
    finally:
        conn.close()


def test_import_restores_tokens_only_when_asked(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    data, raw = _backup_with_rotated_token(tmp_path)
    files = {"file": ("config.yaml", data, "application/yaml")}

    response = client.post("/settings/import", data={"csrf": logged_in}, files=files)
    assert response.status_code == 200
    assert not _token_ok(tmp_path, raw)
    assert "Feeds stay empty" not in response.text

    response = client.post(
        "/settings/import", data={"csrf": logged_in, "restore_tokens": "on"}, files=files
    )
    assert response.status_code == 200
    assert _token_ok(tmp_path, raw)
    assert "restored Feed Token for Output ip-high" in response.text
    assert (
        "Feeds stay empty until the next Compile: click Run now or wait for the schedule."
        in response.text
    )


def test_settings_page_offers_the_restore_checkbox_unchecked(
    client: TestClient, logged_in: str
) -> None:
    page = client.get("/settings").text
    assert "Restore Feed Tokens from the file" in page
    assert "threatcull config import --restore-tokens" in page  # API tokens: CLI only
    assert 'name="restore_tokens"' in page
    assert "checked" not in page.split('name="restore_tokens"')[1].split(">")[0]
    assert "No passwords, raw tokens or threat data" in page


def test_web_restore_never_restores_api_tokens(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    assert main(["--data-dir", str(tmp_path / "old"), "outputs", "list"]) == 0
    conn = connect(tmp_path / "old" / "threatcull.db")
    try:
        create_user(conn, "admin", "old-install-password-1", now=utcnow())
        raw_api = create_api_token(conn, "script", "admin", now=utcnow())
        data = dump_config(conn, now=utcnow()).encode()
    finally:
        conn.close()
    files = {"file": ("config.yaml", data, "application/yaml")}
    response = client.post(
        "/settings/import", data={"csrf": logged_in, "restore_tokens": "on"}, files=files
    )
    assert response.status_code == 200
    assert "skipped API tokens" in response.text
    assert "threatcull config import --restore-tokens" in response.text
    web = open_db(tmp_path)
    try:
        assert verify_api_token(web, raw_api, now=utcnow()) is None
    finally:
        web.close()
