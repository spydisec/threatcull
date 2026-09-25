# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /allowlist``, add/remove entries, and the ``/api/v1/allowlist`` mirror."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi.testclient import TestClient

from tests.factories import make_entry
from threatcull.clock import utcnow
from threatcull.indicators import Indicator
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import sync_catalog
from threatcull.web.deps import open_db


def _seed_builtin(tmp_path: Path, now: datetime) -> None:
    conn = open_db(tmp_path)
    try:
        sync_catalog(
            conn,
            [
                make_entry(
                    id="cdn",
                    role="allowlist",
                    category="infrastructure",
                    business_use="unknown",
                    default_enabled=True,
                )
            ],
        )
        record_fetch_success(
            conn,
            "cdn",
            {Indicator("104.16.0.0/13", "cidr")},
            now=now,
            etag=None,
            last_modified=None,
        )
    finally:
        conn.close()


def _operator_values(tmp_path: Path) -> list[str]:
    conn = open_db(tmp_path)
    try:
        rows = conn.execute("SELECT value FROM allowlist ORDER BY value").fetchall()
    finally:
        conn.close()
    return [row["value"] for row in rows]


# --- HTML page ---------------------------------------------------------------


def test_allowlist_page_redirects_to_login_when_logged_out(client: TestClient) -> None:
    response = client.get("/allowlist", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_allowlist_page_shows_builtin_counts_per_source(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed_builtin(tmp_path, utcnow())
    response = client.get("/allowlist")
    assert response.status_code == 200
    assert "Test Source" in response.text
    assert "104.16.0.0/13" not in response.text  # built-in values are a count, not a list


def test_add_entry_normalises_value_and_redirects(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/allowlist",
        data={"csrf": logged_in, "value": " Pay.Example.COM. ", "note": "payment provider"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/allowlist"
    assert _operator_values(tmp_path) == ["pay.example.com"]

    page = client.get("/allowlist")
    assert "pay.example.com" in page.text
    assert "payment provider" in page.text


def test_add_entry_with_invalid_value_is_400_and_keeps_input(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/allowlist",
        data={"csrf": logged_in, "value": "not a value", "note": "<script>bad</script>"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "not a public IP" in response.text
    assert "not a value" in response.text
    assert "<script>bad</script>" not in response.text
    assert "&lt;script&gt;bad&lt;/script&gt;" in response.text
    assert _operator_values(tmp_path) == []


def test_add_entry_with_an_empty_value_is_a_400(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    # min_length=1 on the schema, not the store's own normalisation.
    response = client.post(
        "/allowlist", data={"csrf": logged_in, "value": "", "note": ""}, follow_redirects=False
    )
    assert response.status_code == 400
    assert _operator_values(tmp_path) == []


def test_add_entry_without_csrf_is_refused(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/allowlist", data={"value": "1.2.3.4", "note": ""}, follow_redirects=False
    )
    assert response.status_code == 403
    assert _operator_values(tmp_path) == []


def test_remove_entry_redirects_and_removes_it(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    client.post("/allowlist", data={"csrf": logged_in, "value": "1.2.3.4", "note": ""})
    assert _operator_values(tmp_path) == ["1.2.3.4"]

    response = client.post(
        "/allowlist/remove", data={"csrf": logged_in, "value": "1.2.3.4"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/allowlist"
    assert _operator_values(tmp_path) == []


def test_remove_unknown_entry_is_404(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/allowlist/remove", data={"csrf": logged_in, "value": "9.9.9.9"}, follow_redirects=False
    )
    assert response.status_code == 404


def test_remove_entry_with_an_invalid_value_is_400(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/allowlist/remove",
        data={"csrf": logged_in, "value": "not a value"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "not a public IP" in response.text


def test_remove_entry_without_csrf_is_refused(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    client.post("/allowlist", data={"csrf": logged_in, "value": "1.2.3.4", "note": ""})
    response = client.post("/allowlist/remove", data={"value": "1.2.3.4"}, follow_redirects=False)
    assert response.status_code == 403
    assert _operator_values(tmp_path) == ["1.2.3.4"]


# --- API mirror ----------------------------------------------------------------


def test_api_allowlist_is_401_when_logged_out(client: TestClient) -> None:
    response = client.get("/api/v1/allowlist")
    assert response.status_code == 401


def test_api_allowlist_returns_exactly_the_allow_listed_keys(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed_builtin(tmp_path, utcnow())
    body = client.get("/api/v1/allowlist").json()
    assert len(body) == 1
    assert set(body[0].keys()) == {"value", "kind", "note", "origin"}
    assert body[0]["origin"] == "cdn"


def test_api_add_entry_requires_csrf_header(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    refused = client.post("/api/v1/allowlist", json={"value": "1.2.3.4"})
    assert refused.status_code == 403
    assert _operator_values(tmp_path) == []

    response = client.post(
        "/api/v1/allowlist",
        json={"value": "1.2.3.4", "note": "n"},
        headers={"X-CSRF-Token": logged_in},
    )
    assert response.status_code == 200
    body = response.json()
    assert body == {"value": "1.2.3.4", "kind": "ip", "note": "n", "origin": "operator"}
    assert _operator_values(tmp_path) == ["1.2.3.4"]


def test_api_add_entry_invalid_value_is_400(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/api/v1/allowlist", json={"value": "nope"}, headers={"X-CSRF-Token": logged_in}
    )
    assert response.status_code == 400


def test_api_remove_entry_with_an_invalid_value_is_400(client: TestClient, logged_in: str) -> None:
    response = client.delete(
        "/api/v1/allowlist",
        params={"value": "not a value"},
        headers={"X-CSRF-Token": logged_in},
    )
    assert response.status_code == 400


def test_api_remove_entry_requires_csrf_and_returns_404_for_unknown(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    client.post(
        "/api/v1/allowlist",
        json={"value": "1.2.3.4"},
        headers={"X-CSRF-Token": logged_in},
    )
    refused = client.delete("/api/v1/allowlist", params={"value": "1.2.3.4"})
    assert refused.status_code == 403
    assert _operator_values(tmp_path) == ["1.2.3.4"]

    response = client.delete(
        "/api/v1/allowlist",
        params={"value": "1.2.3.4"},
        headers={"X-CSRF-Token": logged_in},
    )
    assert response.status_code == 200
    assert _operator_values(tmp_path) == []

    missing = client.delete(
        "/api/v1/allowlist",
        params={"value": "1.2.3.4"},
        headers={"X-CSRF-Token": logged_in},
    )
    assert missing.status_code == 404


def test_import_file_adds_entries_and_reports_skipped_lines(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    upload = b"# partners\npay.example.com,payments\n8.8.8.8\nnot a value\n"
    response = client.post(
        "/allowlist/import",
        data={"csrf": logged_in},
        files={"file": ("list.csv", upload, "text/csv")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/allowlist"
    assert _operator_values(tmp_path) == ["8.8.8.8", "pay.example.com"]

    page = client.get("/allowlist")
    assert "Imported 2 new entries" in page.text
    assert "1 line skipped" in page.text
    assert "line 4" in page.text


def test_import_refuses_a_file_that_is_not_utf8(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/allowlist/import",
        data={"csrf": logged_in},
        files={"file": ("list.txt", b"\xff\xfe\x00", "text/plain")},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "not UTF-8" in response.text
    assert _operator_values(tmp_path) == []


def test_import_without_a_file_is_a_400(client: TestClient, logged_in: str) -> None:
    response = client.post("/allowlist/import", data={"csrf": logged_in}, follow_redirects=False)
    assert response.status_code == 400
    assert "Choose a file" in response.text


def test_import_needs_the_csrf_token(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    response = client.post(
        "/allowlist/import",
        data={"csrf": "wrong"},
        files={"file": ("list.txt", b"8.8.8.8\n", "text/plain")},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert _operator_values(tmp_path) == []
