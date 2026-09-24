# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /``, ``/sources``, ``/outputs``, ``/runs``: the read-only pages."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.factories import make_entry
from threatcull.clock import utcnow
from threatcull.store.outputs import OutputSpec, create_output, record_published
from threatcull.store.runs import finish_run, start_run
from threatcull.store.sources import sync_catalog
from threatcull.web.deps import open_db

SOURCE = make_entry(
    id="test-source",
    name="Test Source",
    default_enabled=True,
    licence="Test licence",
    licence_url="https://example.com/licence",
)
OUTPUT_SPEC = OutputSpec("ip-high", "ip", frozenset({"malicious"}), "high", None, "plain")


def _seed(tmp_path: Path) -> None:
    conn = open_db(tmp_path)
    try:
        sync_catalog(conn, [SOURCE])
        create_output(conn, OUTPUT_SPEC)
        record_published(conn, OUTPUT_SPEC.name, 3, now=utcnow())
        run_id = start_run(conn, "compile", now=utcnow())
        finish_run(conn, run_id, "ok", now=utcnow(), counts={OUTPUT_SPEC.name: 3})
    finally:
        conn.close()


@pytest.mark.parametrize("path", ["/", "/sources", "/outputs", "/runs"])
def test_pages_redirect_to_login_when_logged_out(client: TestClient, path: str) -> None:
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_dashboard_shows_business_mode_and_an_output(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    response = client.get("/")
    assert response.status_code == 200
    assert "Business Mode" in response.text
    assert OUTPUT_SPEC.name in response.text


def test_sources_page_lists_a_source(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    _seed(tmp_path)
    response = client.get("/sources")
    assert response.status_code == 200
    assert SOURCE.name in response.text
    assert 'rel="noopener noreferrer"' in response.text


def test_sources_page_escapes_a_script_in_last_error(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    conn = open_db(tmp_path)
    try:
        conn.execute(
            "UPDATE sources SET last_error = ? WHERE id = ?",
            ("<script>alert(1)</script>", SOURCE.id),
        )
    finally:
        conn.close()
    response = client.get("/sources")
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


def test_outputs_page_shows_the_url_pattern_using_the_request_host(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    response = client.get("/outputs")
    assert response.status_code == 200
    assert f"http://testserver/o/{OUTPUT_SPEC.name}?token=" in response.text
    assert "Rotate the token" in response.text


def test_runs_page_shows_a_run_status(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    _seed(tmp_path)
    response = client.get("/runs")
    assert response.status_code == 200
    assert "compile" in response.text
    assert "ok" in response.text
