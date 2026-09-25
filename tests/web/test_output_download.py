# SPDX-License-Identifier: AGPL-3.0-only
"""``GET /outputs/<name>/download``: a logged-in operator downloads an Output file."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from tests.test_compiling import _setup
from threatcull.clock import utcnow
from threatcull.compiling import compile_outputs
from threatcull.web.deps import open_db


def _publish(tmp_path: Path) -> None:
    conn = open_db(tmp_path)
    try:
        _setup(conn, utcnow())
        compile_outputs(conn, tmp_path / "outputs", now=utcnow())
    finally:
        conn.close()


def test_download_serves_the_published_file_as_an_attachment(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    _publish(tmp_path)
    response = client.get("/outputs/ips/download")
    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="ips.txt"'
    assert "45.9.20.1" in response.text


def test_download_needs_a_login(client: TestClient, tmp_path: Path) -> None:
    _publish(tmp_path)
    response = client.get("/outputs/ips/download", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_download_of_an_unknown_or_unpublished_output_is_404(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    assert client.get("/outputs/nope/download").status_code == 404
    assert client.get("/outputs/..%2Fsecret.key/download").status_code == 404
