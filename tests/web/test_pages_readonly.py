# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /``, ``/sources``, ``/outputs``, ``/runs``: the read-only pages."""

from __future__ import annotations

from datetime import timedelta
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


def test_dashboard_shows_an_output(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    _seed(tmp_path)
    response = client.get("/")
    assert response.status_code == 200
    assert OUTPUT_SPEC.name in response.text


def test_dashboard_says_no_compile_yet_on_a_fresh_install(
    client: TestClient, logged_in: str
) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "No Compile has run yet." in response.text


def test_dashboard_still_shows_the_last_compile_behind_many_later_fetches(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    # Reproduces the scheduler's own Fetch cadence (Task 8): a Compile Run
    # followed by well over 100 Fetch Runs must still surface on the
    # dashboard, not fall out of a capped scan.
    conn = open_db(tmp_path)
    try:
        now = utcnow()
        compile_id = start_run(conn, "compile", now=now)
        finish_run(conn, compile_id, "ok", now=now, counts={"ip-high": 3})
        for i in range(150):
            later = now + timedelta(minutes=i + 1)
            fetch_id = start_run(conn, "fetch", now=later, source_id=f"s{i}")
            finish_run(conn, fetch_id, "ok", now=later)
    finally:
        conn.close()
    response = client.get("/")
    assert response.status_code == 200
    assert "No Compile has run yet." not in response.text
    assert "ok" in response.text


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
