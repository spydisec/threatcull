# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime

import pytest

from tests.factories import make_entry
from threatcull.indicators import Indicator
from threatcull.policy.allowlist import Allowlist
from threatcull.store.allowlist import (
    AllowlistEntry,
    add_entry,
    builtin_entries,
    operator_entries,
    remove_entry,
)
from threatcull.store.errors import NotFoundError
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import sync_catalog


def _entry(value: str, kind: str) -> AllowlistEntry:
    return AllowlistEntry(value, kind, "note", "operator")  # type: ignore[arg-type]


ALLOW = Allowlist(
    [
        _entry("104.16.0.0/13", "cidr"),
        _entry("8.8.8.8", "ip"),
        _entry("2606:4700::/32", "cidr"),
        _entry("example.com", "domain"),
    ]
)


@pytest.mark.parametrize(
    ("value", "kind", "expected"),
    [
        ("8.8.8.8", "ip", "8.8.8.8"),
        ("104.17.1.1", "ip", "104.16.0.0/13"),
        ("104.18.0.0/16", "cidr", "104.16.0.0/13"),
        ("104.16.0.0/12", "cidr", "104.16.0.0/13"),
        ("2606:4700:10::1", "ip", "2606:4700::/32"),
        ("example.com", "domain", "example.com"),
        ("cdn.assets.example.com", "domain", "example.com"),
    ],
)
def test_matches_exact_contained_and_overlapping(value: str, kind: str, expected: str) -> None:
    hit = ALLOW.match(value, kind)  # type: ignore[arg-type]
    assert hit is not None
    assert hit.value == expected


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("1.1.1.1", "ip"),
        ("45.9.20.0/24", "cidr"),
        ("notexample.com", "domain"),
        ("example.com.evil.net", "domain"),
        ("2001:4860::1", "ip"),
    ],
)
def test_does_not_match_unrelated(value: str, kind: str) -> None:
    assert ALLOW.match(value, kind) is None  # type: ignore[arg-type]


SUBDOMAIN_ALLOW = Allowlist(
    [_entry("login.example.com", "domain"), _entry("a.b.example.org", "domain")]
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "login.example.com"),
        ("login.example.com", "login.example.com"),
        ("x.login.example.com", "login.example.com"),
        ("b.example.org", "a.b.example.org"),
        ("example.org", "a.b.example.org"),
    ],
)
def test_parent_of_an_allowlisted_domain_is_excluded(value: str, expected: str) -> None:
    hit = SUBDOMAIN_ALLOW.match(value, "domain")
    assert hit is not None
    assert hit.value == expected


@pytest.mark.parametrize("value", ["other.example.com", "gin.example.com", "c.example.org"])
def test_siblings_of_an_allowlisted_domain_are_not_excluded(value: str) -> None:
    assert SUBDOMAIN_ALLOW.match(value, "domain") is None


def test_operator_entries_are_normalised(conn: sqlite3.Connection, now: datetime) -> None:
    entry = add_entry(conn, " Pay.Example.COM. ", "payment provider", now=now)
    assert (entry.value, entry.kind, entry.origin) == ("pay.example.com", "domain", "operator")
    with pytest.raises(ValueError, match="not a public IP"):
        add_entry(conn, "203.0.113.0/24", now=now)  # documentation range
    with pytest.raises(ValueError, match="not a public IP"):
        add_entry(conn, "192.168.0.0/15", now=now)  # overlaps private space
    assert [e.value for e in operator_entries(conn)] == ["pay.example.com"]


def test_rejects_values_that_are_not_indicators(conn: sqlite3.Connection, now: datetime) -> None:
    with pytest.raises(ValueError, match="not a public IP"):
        add_entry(conn, "not a value", now=now)


def test_remove_entry(conn: sqlite3.Connection, now: datetime) -> None:
    add_entry(conn, "1.2.3.4", now=now)
    remove_entry(conn, "1.2.3.4")
    assert operator_entries(conn) == []
    with pytest.raises(NotFoundError):
        remove_entry(conn, "1.2.3.4")


def test_builtin_entries_come_from_enabled_allowlist_sources(
    conn: sqlite3.Connection, now: datetime
) -> None:
    sync_catalog(
        conn,
        [
            make_entry(
                id="cdn",
                role="allowlist",
                category="infrastructure",
                business_use="unknown",
                default_enabled=True,
            )
        ],
    )
    record_fetch_success(
        conn, "cdn", {Indicator("104.16.0.0/13", "cidr")}, now=now, etag=None, last_modified=None
    )
    (entry,) = builtin_entries(conn)
    assert (entry.value, entry.origin) == ("104.16.0.0/13", "cdn")
    assert entry.note == "Built-in Allowlist: Test Source"
