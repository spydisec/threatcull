# SPDX-License-Identifier: AGPL-3.0-only
"""Enable/disable Sources and add custom Sources from the Sources page and API."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.factories import make_entry
from threatcull.store.sources import get_source, sync_catalog
from threatcull.web.deps import open_db

ALLOWED = make_entry(id="allowed-list", default_enabled=False)
FORBIDDEN = make_entry(
    id="nc-list",
    url="https://example.com/nc.txt",
    licence_class="noncommercial",
    business_use="forbidden",
)
RESTRICTED = make_entry(
    id="restricted-list",
    url="https://example.com/r.txt",
    licence_class="restricted",
    business_use="allowed",
)


def _seed(tmp_path: Path, *entries: object) -> None:
    conn = open_db(tmp_path)
    try:
        sync_catalog(conn, list(entries))  # type: ignore[arg-type]
    finally:
        conn.close()


def _enabled(tmp_path: Path, source_id: str) -> bool:
    conn = open_db(tmp_path)
    try:
        return get_source(conn, source_id).enabled
    finally:
        conn.close()


def test_enabling_an_allowed_source_redirects_and_enables_it(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, ALLOWED)
    response = client.post(
        "/sources/allowed-list/enable", data={"csrf": logged_in}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/sources"
    assert _enabled(tmp_path, "allowed-list") is True


def test_disabling_an_enabled_source_works(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, make_entry(id="allowed-list", default_enabled=True))
    response = client.post(
        "/sources/allowed-list/disable", data={"csrf": logged_in}, follow_redirects=False
    )
    assert response.status_code == 303
    assert _enabled(tmp_path, "allowed-list") is False


def test_enabling_a_forbidden_source_under_business_mode_is_refused(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, FORBIDDEN)  # Business Mode is on by default.
    response = client.post(
        "/sources/nc-list/enable", data={"csrf": logged_in}, follow_redirects=False
    )
    assert response.status_code == 400
    assert "business use" in response.text
    assert _enabled(tmp_path, "nc-list") is False


def test_restricted_source_needs_acknowledgement(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, RESTRICTED)
    refused = client.post(
        "/sources/restricted-list/enable", data={"csrf": logged_in}, follow_redirects=False
    )
    assert refused.status_code == 400
    assert "acknowledge" in refused.text
    assert _enabled(tmp_path, "restricted-list") is False

    accepted = client.post(
        "/sources/restricted-list/enable",
        data={"csrf": logged_in, "acknowledge_restricted": "true"},
        follow_redirects=False,
    )
    assert accepted.status_code == 303
    assert _enabled(tmp_path, "restricted-list") is True


def test_enabling_an_unknown_source_is_a_404(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/sources/does-not-exist/enable", data={"csrf": logged_in}, follow_redirects=False
    )
    assert response.status_code == 404


@pytest.mark.parametrize("action", ["enable", "disable"])
def test_enable_disable_without_csrf_is_refused_and_makes_no_change(
    client: TestClient, logged_in: str, tmp_path: Path, action: str
) -> None:
    _seed(tmp_path, ALLOWED)
    before = _enabled(tmp_path, "allowed-list")
    response = client.post(f"/sources/allowed-list/{action}", data={}, follow_redirects=False)
    assert response.status_code == 403
    assert _enabled(tmp_path, "allowed-list") == before


def test_htmx_request_gets_a_row_fragment_not_a_full_page(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, ALLOWED)
    response = client.post(
        "/sources/allowed-list/enable",
        data={"csrf": logged_in},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "<html" not in response.text
    assert "source-row-allowed-list" in response.text


_HX = {"HX-Request": "true"}


@pytest.mark.parametrize(
    "case",
    [
        (RESTRICTED, "restricted-list", "acknowledge"),
        (FORBIDDEN, "nc-list", "business use"),
    ],
    ids=["restricted-without-ack", "business-mode-forbidden"],
)
def test_htmx_refusal_comes_back_as_the_row_with_an_inline_error(
    client: TestClient, logged_in: str, tmp_path: Path, case: tuple[object, str, str]
) -> None:
    entry, source_id, message = case
    _seed(tmp_path, entry)
    response = client.post(f"/sources/{source_id}/enable", data={"csrf": logged_in}, headers=_HX)
    # 200 so htmx swaps it in (it ignores 4xx bodies by default).
    assert response.status_code == 200
    assert "<html" not in response.text
    assert response.text.lstrip().startswith(f'<tr id="source-row-{source_id}"')
    assert 'role="alert"' in response.text
    assert message in response.text
    assert _enabled(tmp_path, source_id) is False


def test_htmx_unknown_source_comes_back_as_an_error_row(client: TestClient, logged_in: str) -> None:
    response = client.post("/sources/gone/enable", data={"csrf": logged_in}, headers=_HX)
    assert response.status_code == 200
    assert response.text.lstrip().startswith('<tr id="source-row-gone"')
    assert "gone" in response.text
    assert 'role="alert"' in response.text


def test_custom_source_happy_path(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    response = client.post(
        "/sources/custom",
        data={
            "csrf": logged_in,
            "id": "custom-honeypot",
            "name": "Our honeypot",
            "url": "file:///data/hp.txt",
            "format": "plain",
            "kind": "ip",
            "category": "scanner",
            "csv_column": "0",
            "json_keys": "",
            "business_use": "unknown",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/sources"
    conn = open_db(tmp_path)
    try:
        source = get_source(conn, "custom-honeypot")
    finally:
        conn.close()
    assert source.custom is True
    assert source.enabled is False


def test_custom_source_invalid_id_is_rejected(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/sources/custom",
        data={
            "csrf": logged_in,
            "id": "not-custom-prefixed",
            "name": "Bad",
            "url": "https://example.com/x",
            "format": "plain",
            "kind": "ip",
            "category": "malicious",
            "csv_column": "0",
            "json_keys": "",
            "business_use": "unknown",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    conn = open_db(tmp_path)
    try:
        rows = conn.execute("SELECT id FROM sources").fetchall()
    finally:
        conn.close()
    assert rows == []


def test_custom_source_invalid_category_is_rejected_at_runtime(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    # The Plan 1 final review flagged: category is a plain Literal with no
    # runtime check of its own. This must be caught here, not crash or insert.
    response = client.post(
        "/sources/custom",
        data={
            "csrf": logged_in,
            "id": "custom-bogus",
            "name": "Bad category",
            "url": "https://example.com/x",
            "format": "plain",
            "kind": "ip",
            "category": "not-a-real-category",
            "csv_column": "0",
            "json_keys": "",
            "business_use": "unknown",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    conn = open_db(tmp_path)
    try:
        rows = conn.execute("SELECT id FROM sources").fetchall()
    finally:
        conn.close()
    assert rows == []


def test_custom_source_name_with_control_characters_is_rejected_by_the_store(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    # Passes the schema (any non-empty string), rejected by add_custom_source
    # itself (Source names end up in Output comment headers).
    response = client.post(
        "/sources/custom",
        data={
            "csrf": logged_in,
            "id": "custom-tabbed",
            "name": "Evil\tname",
            "url": "https://example.com/x",
            "format": "plain",
            "kind": "ip",
            "category": "malicious",
            "csv_column": "0",
            "json_keys": "",
            "business_use": "unknown",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "control characters" in response.text
    conn = open_db(tmp_path)
    try:
        rows = conn.execute("SELECT id FROM sources").fetchall()
    finally:
        conn.close()
    assert rows == []


def test_custom_source_without_csrf_is_refused(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/sources/custom",
        data={
            "id": "custom-nope",
            "name": "Nope",
            "url": "https://example.com/x",
            "format": "plain",
            "kind": "ip",
            "category": "malicious",
        },
        follow_redirects=False,
    )
    assert response.status_code == 403
    conn = open_db(tmp_path)
    try:
        rows = conn.execute("SELECT id FROM sources").fetchall()
    finally:
        conn.close()
    assert rows == []


# --- API mirror -------------------------------------------------------------


def test_api_enable_source_requires_session_and_csrf_header(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, ALLOWED)
    refused = client.post("/api/v1/sources/allowed-list", json={"enabled": True})
    assert refused.status_code == 403
    assert _enabled(tmp_path, "allowed-list") is False

    response = client.post(
        "/api/v1/sources/allowed-list",
        json={"enabled": True},
        headers={"X-CSRF-Token": logged_in},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert _enabled(tmp_path, "allowed-list") is True


def test_api_enable_forbidden_source_is_a_400(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, FORBIDDEN)
    response = client.post(
        "/api/v1/sources/nc-list",
        json={"enabled": True},
        headers={"X-CSRF-Token": logged_in},
    )
    assert response.status_code == 400
    assert _enabled(tmp_path, "nc-list") is False


def test_api_enable_unknown_source_is_a_404(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/api/v1/sources/does-not-exist",
        json={"enabled": True},
        headers={"X-CSRF-Token": logged_in},
    )
    assert response.status_code == 404


def test_api_enable_restricted_source_needs_acknowledgement(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, RESTRICTED)
    refused = client.post(
        "/api/v1/sources/restricted-list",
        json={"enabled": True},
        headers={"X-CSRF-Token": logged_in},
    )
    assert refused.status_code == 400
    accepted = client.post(
        "/api/v1/sources/restricted-list",
        json={"enabled": True, "acknowledge_restricted": True},
        headers={"X-CSRF-Token": logged_in},
    )
    assert accepted.status_code == 200
    assert _enabled(tmp_path, "restricted-list") is True


def test_source_actions_call_the_on_sources_changed_hook(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, ALLOWED)
    calls: list[None] = []
    client.app.state.on_sources_changed = lambda: calls.append(None)  # type: ignore[attr-defined]
    client.post("/sources/allowed-list/enable", data={"csrf": logged_in}, follow_redirects=False)
    assert calls == [None]
