# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /api/v1/sources``, ``/outputs``, ``/runs``, ``/settings``: the read API."""

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

SOURCE = make_entry(id="test-source", name="Test Source", default_enabled=True)
OUTPUT_SPEC = OutputSpec("ip-high", "ip", frozenset({"malicious"}), "high", None, "plain")

SOURCE_KEYS = {
    "id",
    "name",
    "family",
    "url",
    "format",
    "kind",
    "role",
    "category",
    "licence_class",
    "business_use",
    "licence",
    "licence_url",
    "refresh_minutes",
    "custom",
    "enabled",
    "disabled_reason",
    "last_success_at",
    "last_attempt_at",
    "last_error",
}
OUTPUT_KEYS = {
    "name",
    "kind",
    "categories",
    "min_tier",
    "max_entries",
    "format",
    "last_count",
    "last_published_at",
}
RUN_KEYS = {
    "id",
    "type",
    "source_id",
    "started_at",
    "finished_at",
    "status",
    "counts",
    "error",
}
SETTINGS_KEYS = {
    "business_mode",
    "active_window_days",
    "retention_days",
    "stale_after_hours",
    "tier_high",
    "tier_medium",
    "max_shrink",
    "max_stale_ratio",
}


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


@pytest.mark.parametrize(
    "path", ["/api/v1/sources", "/api/v1/outputs", "/api/v1/runs", "/api/v1/settings"]
)
def test_read_api_is_401_json_when_logged_out(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 401
    assert response.json() == {"detail": "authentication required"}


def test_api_sources_lists_a_source(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    _seed(tmp_path)
    response = client.get("/api/v1/sources")
    assert response.status_code == 200
    body = response.json()
    assert any(source["name"] == SOURCE.name for source in body)


def test_api_sources_returns_exactly_the_allow_listed_keys(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    body = client.get("/api/v1/sources").json()
    assert len(body) == 1
    assert set(body[0].keys()) == SOURCE_KEYS


def test_api_outputs_never_contains_a_feed_token_hash(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    response = client.get("/api/v1/outputs")
    assert response.status_code == 200
    assert "feed_token_hash" not in response.text
    assert "token" not in response.text.lower()
    body = response.json()
    assert any(output["name"] == OUTPUT_SPEC.name for output in body)


def test_api_outputs_returns_exactly_the_allow_listed_keys(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    body = client.get("/api/v1/outputs").json()
    assert len(body) == 1
    assert set(body[0].keys()) == OUTPUT_KEYS


def test_api_runs_default_limit_returns_recent_runs(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    response = client.get("/api/v1/runs")
    assert response.status_code == 200
    body = response.json()
    assert any(run["status"] == "ok" for run in body)


def test_api_runs_returns_exactly_the_allow_listed_keys(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _seed(tmp_path)
    body = client.get("/api/v1/runs").json()
    assert len(body) == 1
    assert set(body[0].keys()) == RUN_KEYS


@pytest.mark.parametrize("limit", [0, 201, -1])
def test_api_runs_limit_out_of_range_is_422(client: TestClient, logged_in: str, limit: int) -> None:
    response = client.get("/api/v1/runs", params={"limit": limit})
    assert response.status_code == 422


@pytest.mark.parametrize("limit", [1, 200])
def test_api_runs_limit_boundary_is_accepted(
    client: TestClient, logged_in: str, limit: int
) -> None:
    response = client.get("/api/v1/runs", params={"limit": limit})
    assert response.status_code == 200


def test_api_settings_returns_business_mode(client: TestClient, logged_in: str) -> None:
    response = client.get("/api/v1/settings")
    assert response.status_code == 200
    assert "business_mode" in response.json()


def test_api_settings_returns_exactly_the_allow_listed_keys(
    client: TestClient, logged_in: str
) -> None:
    body = client.get("/api/v1/settings").json()
    assert set(body.keys()) == SETTINGS_KEYS


def test_api_me_returns_exactly_the_username_key(client: TestClient, logged_in: str) -> None:
    body = client.get("/api/v1/me").json()
    assert set(body.keys()) == {"username"}
