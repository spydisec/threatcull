# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from tests.fixture_server import FixtureServer
from threatcull.store import users
from threatcull.store.db import connect


@pytest.fixture(autouse=True)
def _utc_display(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests expect UTC display unless they set ``TZ`` themselves."""
    monkeypatch.delenv("TZ", raising=False)


@pytest.fixture(autouse=True)
def _cheap_password_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Argon2id at minimum cost: the production defaults spend ~0.1 s per hash,
    which most tests pay several times. Tests of the hashing itself patch or
    undo this."""
    monkeypatch.setattr(users, "_HASHER", PasswordHasher(time_cost=1, memory_cost=1024))


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = connect(tmp_path / "test.db")
    yield connection
    connection.close()


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


@pytest.fixture
def fixture_server() -> Iterator[FixtureServer]:
    server = FixtureServer()
    server.start()
    yield server
    server.stop()
