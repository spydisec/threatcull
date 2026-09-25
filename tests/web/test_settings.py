# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /settings``: the read-only pipeline settings (Business Mode was removed)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_settings_page_requires_login(client: TestClient) -> None:
    response = client.get("/settings", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_settings_page_shows_the_pipeline_settings(client: TestClient, logged_in: str) -> None:
    response = client.get("/settings")
    assert response.status_code == 200
    assert "Pipeline settings" in response.text
    assert "Stale after (hours)" in response.text
    assert "Business Mode" not in response.text


def test_the_business_mode_toggle_is_gone(client: TestClient, logged_in: str) -> None:
    response = client.post("/settings/business-mode", data={"csrf": logged_in, "on": "false"})
    assert response.status_code in {404, 405}
