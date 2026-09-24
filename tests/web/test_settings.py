# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /settings`` and ``POST /settings/business-mode``."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from tests.factories import make_entry
from threatcull.store.settings import load_settings
from threatcull.store.sources import get_source, set_business_mode, set_enabled, sync_catalog
from threatcull.web.deps import open_db

NON_BUSINESS = make_entry(
    id="nc-list",
    url="https://example.com/nc.txt",
    licence_class="noncommercial",
    business_use="forbidden",
)


def _seed(tmp_path: Path) -> None:
    conn = open_db(tmp_path)
    try:
        sync_catalog(conn, [NON_BUSINESS])
    finally:
        conn.close()


def test_settings_page_requires_login(client: TestClient) -> None:
    response = client.get("/settings", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_settings_page_shows_business_mode(client: TestClient, logged_in: str) -> None:
    response = client.get("/settings")
    assert response.status_code == 200
    assert "Business Mode" in response.text
    assert "On" in response.text


def test_turning_business_mode_off_then_on_again(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post("/settings/business-mode", data={"csrf": logged_in, "on": "false"})
    assert response.status_code == 200
    conn = open_db(tmp_path)
    try:
        assert load_settings(conn).business_mode is False
    finally:
        conn.close()

    response = client.post("/settings/business-mode", data={"csrf": logged_in, "on": "true"})
    assert response.status_code == 200
    conn = open_db(tmp_path)
    try:
        assert load_settings(conn).business_mode is True
    finally:
        conn.close()


def test_turning_business_mode_on_disables_a_non_business_source_and_lists_it(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    conn = open_db(tmp_path)
    try:
        set_business_mode(conn, False)
        set_enabled(conn, "nc-list", True)
    finally:
        conn.close()

    response = client.post("/settings/business-mode", data={"csrf": logged_in, "on": "true"})
    assert response.status_code == 200
    assert "nc-list" in response.text

    conn = open_db(tmp_path)
    try:
        assert get_source(conn, "nc-list").enabled is False
    finally:
        conn.close()


def test_business_mode_toggle_without_csrf_is_refused(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    conn = open_db(tmp_path)
    try:
        before = load_settings(conn).business_mode
    finally:
        conn.close()
    response = client.post("/settings/business-mode", data={"on": "false"})
    assert response.status_code == 403
    conn = open_db(tmp_path)
    try:
        assert load_settings(conn).business_mode == before
    finally:
        conn.close()


def test_business_mode_toggle_calls_the_on_sources_changed_hook(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    calls: list[None] = []
    client.app.state.on_sources_changed = lambda: calls.append(None)  # type: ignore[attr-defined]
    client.post("/settings/business-mode", data={"csrf": logged_in, "on": "false"})
    assert calls == [None]
