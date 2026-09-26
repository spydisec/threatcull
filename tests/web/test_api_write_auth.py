# SPDX-License-Identifier: AGPL-3.0-only
"""Every ``/api/`` write: 401 logged out, 403 without CSRF, ok with a bearer token.

Also: bearer authentication never blocks the event loop while the database
is busy.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.factories import make_entry
from threatcull.clock import utcnow
from threatcull.home_detect import Candidate
from threatcull.store.allowlist import add_entry
from threatcull.store.api_tokens import create_api_token
from threatcull.store.outputs import ensure_default_outputs
from threatcull.store.sources import sync_catalog
from threatcull.web.deps import open_db

SOURCE = make_entry(id="allowed-list", default_enabled=False)

# (method, path, keyword arguments for the request)
API_WRITES: list[tuple[str, str, dict[str, Any]]] = [
    ("POST", "/api/v1/sources/allowed-list", {"json": {"enabled": True}}),
    ("POST", "/api/v1/outputs/ip-high/rotate", {}),
    ("POST", "/api/v1/allowlist", {"json": {"value": "1.2.3.4", "note": ""}}),
    ("DELETE", "/api/v1/allowlist", {"params": {"value": "5.6.7.8"}}),
    ("POST", "/api/v1/allowlist/detect", {}),
]
_IDS = [f"{method} {path}" for method, path, _ in API_WRITES]


def _no_candidates(**_: object) -> list[Candidate]:
    return []


@pytest.fixture
def seeded(client: TestClient, admin: str, tmp_path: Path) -> TestClient:
    """The ``admin`` user, a Source, default Outputs and one Allowlist entry to delete."""
    conn = open_db(tmp_path)
    try:
        sync_catalog(conn, [SOURCE])
        ensure_default_outputs(conn)
        add_entry(conn, "5.6.7.8", "", now=utcnow())
    finally:
        conn.close()
    client.app.state.home_detector = _no_candidates  # type: ignore[attr-defined]
    return client


def _token(data_dir: Path) -> str:
    conn = open_db(data_dir)
    try:
        return create_api_token(conn, "script", "admin", now=utcnow())
    finally:
        conn.close()


@pytest.mark.parametrize(("method", "path", "kwargs"), API_WRITES, ids=_IDS)
def test_logged_out_api_write_is_401_json(
    seeded: TestClient, method: str, path: str, kwargs: dict[str, Any]
) -> None:
    response = seeded.request(method, path, **kwargs)
    assert response.status_code == 401
    assert response.json() == {"detail": "authentication required"}


@pytest.mark.parametrize(("method", "path", "kwargs"), API_WRITES, ids=_IDS)
def test_logged_in_api_write_without_csrf_is_403(
    seeded: TestClient, logged_in: str, method: str, path: str, kwargs: dict[str, Any]
) -> None:
    response = seeded.request(method, path, **kwargs)
    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF token missing or invalid"}


@pytest.mark.parametrize(("method", "path", "kwargs"), API_WRITES, ids=_IDS)
def test_bearer_api_write_is_ok(
    seeded: TestClient, tmp_path: Path, method: str, path: str, kwargs: dict[str, Any]
) -> None:
    headers = {"Authorization": f"Bearer {_token(tmp_path)}"}
    response = seeded.request(method, path, headers=headers, **kwargs)
    assert response.status_code == 200, response.text


def test_bearer_post_on_a_busy_database_does_not_block_other_requests(
    client: TestClient, admin: str, tmp_path: Path
) -> None:
    token = _token(tmp_path)
    holder = open_db(tmp_path)
    holder.execute("BEGIN IMMEDIATE")  # hold the write lock
    result: dict[str, int] = {}

    def bearer_post() -> None:
        response = client.post(
            "/api/v1/allowlist",
            json={"value": "1.2.3.4", "note": ""},
            headers={"Authorization": f"Bearer {token}"},
        )
        result["status"] = response.status_code

    worker = threading.Thread(target=bearer_post)
    try:
        worker.start()
        time.sleep(0.5)  # let the POST reach its (busy) bearer check
        started = time.monotonic()
        assert client.get("/healthz").status_code == 200
        assert time.monotonic() - started < 1.5
    finally:
        holder.execute("ROLLBACK")
        holder.close()
        worker.join(timeout=10)
    assert result.get("status") == 200
