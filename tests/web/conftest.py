# SPDX-License-Identifier: AGPL-3.0-only
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatcull.clock import utcnow
from threatcull.store.users import create_user
from threatcull.web.app import create_app
from threatcull.web.deps import open_db

ADMIN_USER = "admin"
ADMIN_PASSWORD = "correct horse battery"  # noqa: S105 - test-only credential

_CSRF_FIELD = re.compile(r'name="csrf" value="([^"]+)"')


def csrf_from(html: str) -> str:
    """Pull the hidden ``csrf`` form field out of a rendered page."""
    match = _CSRF_FIELD.search(html)
    assert match is not None, "no csrf field in page"
    return match.group(1)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(tmp_path, start_scheduler=False)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin(tmp_path: Path) -> str:
    """Create the ``admin`` user in the test data dir; returns the username."""
    conn = open_db(tmp_path)
    try:
        create_user(conn, ADMIN_USER, ADMIN_PASSWORD, now=utcnow())
    finally:
        conn.close()
    return ADMIN_USER


def login(client: TestClient, username: str = ADMIN_USER, password: str = ADMIN_PASSWORD) -> str:
    """Log ``client`` in; returns the post-login CSRF token."""
    token = csrf_from(client.get("/login").text)
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf": token},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return csrf_from(client.get("/").text)


@pytest.fixture
def logged_in(client: TestClient, admin: str) -> str:
    """Log the shared ``client`` in as ``admin``; returns its CSRF token."""
    return login(client)
