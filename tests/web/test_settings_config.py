# SPDX-License-Identifier: AGPL-3.0-only
"""Settings page: export and import the configuration as YAML."""

from __future__ import annotations

import yaml
from fastapi.testclient import TestClient


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
    assert "No passwords, tokens or threat data" in page


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
