# SPDX-License-Identifier: AGPL-3.0-only
"""Enable/disable Sources and add custom Sources from the Sources page and API."""

from __future__ import annotations

import sqlite3
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


def test_a_source_not_cleared_for_business_use_can_be_enabled(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, FORBIDDEN)
    response = client.post(
        "/sources/nc-list/enable", data={"csrf": logged_in}, follow_redirects=False
    )
    assert response.status_code == 303
    assert _enabled(tmp_path, "nc-list") is True


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
    ],
    ids=["restricted-without-ack"],
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


def _custom_form(csrf: str, url: str) -> dict[str, str]:
    return {
        "csrf": csrf,
        "id": "custom-honeypot",
        "name": "Our honeypot",
        "url": url,
        "format": "plain",
        "kind": "ip",
        "category": "scanner",
        "csv_column": "0",
        "json_keys": "",
        "business_use": "unknown",
    }


def _custom_ids(tmp_path: Path) -> list[str]:
    conn = open_db(tmp_path)
    try:
        return [row[0] for row in conn.execute("SELECT id FROM sources WHERE custom = 1")]
    finally:
        conn.close()


def test_app_creates_the_imports_dir(client: TestClient, tmp_path: Path) -> None:
    assert (tmp_path / "imports").is_dir()


def test_web_file_source_under_data_imports_is_accepted(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    feed = tmp_path / "imports" / "sub dir" / "hp.txt"
    feed.parent.mkdir(parents=True)
    feed.write_text("45.9.21.1\n", encoding="utf-8")
    response = client.post(
        "/sources/custom", data=_custom_form(logged_in, feed.as_uri()), follow_redirects=False
    )
    assert response.status_code == 303, response.text
    assert _custom_ids(tmp_path) == ["custom-honeypot"]


def _escapes(tmp_path: Path) -> list[str]:
    imports = tmp_path / "imports"
    outside = tmp_path / "secret.txt"
    outside.write_text("45.9.21.1\n", encoding="utf-8")
    link = imports / "link.txt"
    link.symlink_to(outside)
    return [
        "file:///etc/passwd",
        outside.as_uri(),
        f"file://{imports}/../secret.txt",
        f"file://{imports}/%2e%2e/secret.txt",
        link.as_uri(),
        f"file://{tmp_path}/imports-evil/x.txt",  # a sibling, not a child
        f"file://otherhost{imports}/x.txt",
        imports.as_uri(),  # the directory itself
    ]


def test_web_file_source_outside_data_imports_is_refused(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    for url in _escapes(tmp_path):
        response = client.post(
            "/sources/custom", data=_custom_form(logged_in, url), follow_redirects=False
        )
        assert response.status_code == 400, url
        assert "imports" in response.text, url
    assert _custom_ids(tmp_path) == []


def test_custom_source_happy_path(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    response = client.post(
        "/sources/custom",
        data={
            "csrf": logged_in,
            "id": "custom-honeypot",
            "name": "Our honeypot",
            "url": (tmp_path / "imports" / "hp.txt").as_uri(),
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
    assert source.enabled is True  # "Add and enable": the next fetch downloads it
    assert source.role == "blocklist"
    assert "Added Our honeypot as a blocklist Source" in client.get("/sources").text


def test_custom_allowlist_with_only_the_required_fields(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    form = {
        "csrf": logged_in,
        "name": "  My Whitelist (CDN) ",
        "url": "https://example.com/wl.txt",
        "kind": "ip",
        "role": "allowlist",
    }
    assert client.post("/sources/custom", data=form, follow_redirects=False).status_code == 303
    assert client.post("/sources/custom", data=form, follow_redirects=False).status_code == 303
    assert _custom_ids(tmp_path) == ["custom-my-whitelist-cdn", "custom-my-whitelist-cdn-2"]
    conn = open_db(tmp_path)
    try:
        source = get_source(conn, "custom-my-whitelist-cdn")
    finally:
        conn.close()
    assert (source.name, source.role, source.format, source.category, source.enabled) == (
        "My Whitelist (CDN)",
        "allowlist",
        "plain",
        "infrastructure",
        True,
    )
    page = client.get("/allowlist").text
    assert "My Whitelist (CDN)" in page
    assert 'href="/sources?add=1#add-custom"' in page


def test_add_link_opens_the_form(client: TestClient, logged_in: str) -> None:
    assert '<details class="card" id="add-custom">' in client.get("/sources").text
    assert '<details class="card" id="add-custom" open>' in client.get("/sources?add=1").text


def test_custom_source_taken_id_is_refused(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    form = _custom_form(logged_in, "https://example.com/x.txt")
    assert client.post("/sources/custom", data=form, follow_redirects=False).status_code == 303
    again = client.post("/sources/custom", data=form, follow_redirects=False)
    assert again.status_code == 400
    assert "custom-honeypot is already taken" in again.text
    assert _custom_ids(tmp_path) == ["custom-honeypot"]


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
    assert "ids look like custom-my-feed" in response.text
    assert "should match pattern" not in response.text
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


def test_api_enables_a_source_not_cleared_for_business_use(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path, FORBIDDEN)
    response = client.post(
        "/api/v1/sources/nc-list",
        json={"enabled": True},
        headers={"X-CSRF-Token": logged_in},
    )
    assert response.status_code == 200
    assert _enabled(tmp_path, "nc-list") is True


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


def test_a_locked_database_is_a_503_not_a_500(
    client: TestClient, logged_in: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A large Fetch holds the write lock; a save that waits it out gets a retry page."""

    def locked(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("threatcull.web.routes.pages.add_custom_source", locked)
    response = client.post(
        "/sources/custom", data=_custom_form(logged_in, "https://example.com/x.txt")
    )
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    assert "Busy saving a fetch" in response.text
    assert _custom_ids(tmp_path) == []
