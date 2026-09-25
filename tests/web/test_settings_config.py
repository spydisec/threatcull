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
    assert "no passwords, tokens or threat data" in page
