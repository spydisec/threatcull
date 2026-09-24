# SPDX-License-Identifier: AGPL-3.0-only
"""Home Network entries: storage, normalisation and the private-address message."""

import sqlite3
from datetime import datetime

import pytest

from threatcull.store.db import SCHEMA_VERSION
from threatcull.store.errors import NotFoundError
from threatcull.store.home import (
    PRIVATE_MESSAGE,
    HomeEntry,
    add_home,
    home_allow_entries,
    home_entries,
    remove_home,
)


def test_schema_has_the_home_network_table(conn: sqlite3.Connection) -> None:
    assert SCHEMA_VERSION == 4
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(home_network)")}
    assert columns == {"id", "value", "kind", "note", "origin", "created_at"}
    assert "home_hits" in {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}


def test_add_normalises_and_lists(conn: sqlite3.Connection, now: datetime) -> None:
    entry = add_home(conn, " Office.Example.COM. ", "office", now=now)
    assert entry == HomeEntry("office.example.com", "domain", "office", "manual")
    add_home(conn, "45.9.20.7/24", now=now, origin="auto")
    assert home_entries(conn) == [
        HomeEntry("45.9.20.0/24", "cidr", "", "auto"),
        HomeEntry("office.example.com", "domain", "office", "manual"),
    ]


def test_adding_again_updates_note_and_origin(conn: sqlite3.Connection, now: datetime) -> None:
    add_home(conn, "45.9.20.7", now=now, origin="auto")
    add_home(conn, "45.9.20.7", "our WAN", now=now)
    assert home_entries(conn) == [HomeEntry("45.9.20.7", "ip", "our WAN", "manual")]


@pytest.mark.parametrize("raw", ["192.168.1.10", "10.0.0.0/8", "fd00::1", "127.0.0.1", "::1"])
def test_private_and_special_values_are_rejected_with_the_explanation(
    conn: sqlite3.Connection, now: datetime, raw: str
) -> None:
    with pytest.raises(ValueError, match="no Home Network entry is needed"):
        add_home(conn, raw, now=now)
    assert home_entries(conn) == []
    assert "private and special-purpose addresses are never published" in PRIVATE_MESSAGE


def test_garbage_is_rejected_as_not_a_value(conn: sqlite3.Connection, now: datetime) -> None:
    with pytest.raises(ValueError, match="not a public IP, CIDR or domain"):
        add_home(conn, "not a value", now=now)


def test_unknown_origin_is_rejected(conn: sqlite3.Connection, now: datetime) -> None:
    with pytest.raises(ValueError, match="origin"):
        add_home(conn, "45.9.20.7", now=now, origin="home")  # type: ignore[arg-type]


def test_remove(conn: sqlite3.Connection, now: datetime) -> None:
    add_home(conn, "45.9.20.7", now=now)
    remove_home(conn, " 45.9.20.7 ")
    assert home_entries(conn) == []
    with pytest.raises(NotFoundError):
        remove_home(conn, "45.9.20.7")


def test_allow_entries_read_as_home_network(conn: sqlite3.Connection, now: datetime) -> None:
    add_home(conn, "45.9.20.7", "office", now=now)
    add_home(conn, "home.example.com", now=now)
    notes = {(e.value, e.note, e.origin) for e in home_allow_entries(conn)}
    assert notes == {
        ("45.9.20.7", "Home Network: office", "home"),
        ("home.example.com", "Home Network", "home"),
    }
