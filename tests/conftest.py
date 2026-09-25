# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.fixture_server import FixtureServer
from threatcull.store.db import connect


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
