# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

import threatcull
from threatcull.web.app import DB_NAME, open_db
from threatcull.web.deps import get_conn
from threatcull.web.security import load_or_create_secret

_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def test_healthz_reports_ok_and_version(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": threatcull.__version__}


@pytest.mark.parametrize("path", ["/healthz", "/no-such-route"])
def test_every_response_carries_security_headers(client: TestClient, path: str) -> None:
    response = client.get(path)
    for name, value in _SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_unknown_route_is_a_404(client: TestClient) -> None:
    assert client.get("/no-such-route").status_code == 404


def test_load_or_create_secret_creates_a_32_byte_0600_file(tmp_path: Path) -> None:
    secret = load_or_create_secret(tmp_path)
    path = tmp_path / "secret.key"
    assert len(secret) == 32
    assert path.exists()
    assert (path.stat().st_mode & 0o777) == 0o600


def test_load_or_create_secret_is_stable_across_calls(tmp_path: Path) -> None:
    first = load_or_create_secret(tmp_path)
    second = load_or_create_secret(tmp_path)
    assert first == second


def test_open_db_migrates_but_does_not_seed_catalog_or_outputs(tmp_path: Path) -> None:
    conn = open_db(tmp_path)
    try:
        assert (tmp_path / DB_NAME).exists()
        assert conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM outputs").fetchone()[0] == 0
    finally:
        conn.close()


def test_get_conn_yields_a_connection_and_closes_it_after_use(tmp_path: Path) -> None:
    request: Any = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(data_dir=tmp_path)))
    generator = get_conn(request)
    conn = next(generator)
    assert conn.execute("SELECT 1").fetchone()[0] == 1
    with pytest.raises(StopIteration):
        next(generator)
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")
