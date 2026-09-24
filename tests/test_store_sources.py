# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3

import pytest

from tests.factories import make_entry
from threatcull.catalog import BusinessUse
from threatcull.store.errors import NotFoundError, PolicyError
from threatcull.store.settings import load_settings
from threatcull.store.sources import (
    BUSINESS_MODE_REASON,
    REMOVED_FROM_CATALOG_REASON,
    add_custom_source,
    get_source,
    list_sources,
    set_business_mode,
    set_enabled,
    sync_catalog,
)

ALLOWED = make_entry(id="allowed-list", default_enabled=True)
NONCOMMERCIAL = make_entry(
    id="nc-list",
    url="https://example.com/nc.txt",
    licence_class="noncommercial",
    business_use="forbidden",
)
RESTRICTED = make_entry(
    id="restricted-list",
    url="https://example.com/r.txt",
    licence_class="restricted",
    business_use="allowed",
)
ALLOW_SOURCE = make_entry(
    id="cdn-ranges",
    url="https://example.com/cdn.txt",
    role="allowlist",
    category="infrastructure",
    business_use="unknown",
    default_enabled=True,
)


def test_sync_inserts_catalog_sources_with_default_enablement(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [ALLOWED, NONCOMMERCIAL, ALLOW_SOURCE])
    enabled = {s.id for s in list_sources(conn, enabled_only=True)}
    assert enabled == {"allowed-list", "cdn-ranges"}
    assert get_source(conn, "nc-list").licence_class == "noncommercial"


def test_resync_updates_metadata_but_keeps_operator_choices(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [ALLOWED])
    set_enabled(conn, "allowed-list", False)
    sync_catalog(conn, [make_entry(id="allowed-list", name="Renamed", default_enabled=True)])
    source = get_source(conn, "allowed-list")
    assert (source.name, source.enabled) == ("Renamed", False)


def test_sources_dropped_from_catalog_are_disabled_with_reason(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [ALLOWED])
    sync_catalog(conn, [])
    source = get_source(conn, "allowed-list")
    assert (source.enabled, source.disabled_reason) == (False, REMOVED_FROM_CATALOG_REASON)


def test_business_mode_blocks_enabling_forbidden_sources(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [NONCOMMERCIAL])
    with pytest.raises(PolicyError, match="business use"):
        set_enabled(conn, "nc-list", True)


def test_without_business_mode_forbidden_sources_can_be_enabled(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [NONCOMMERCIAL])
    set_business_mode(conn, False)
    assert set_enabled(conn, "nc-list", True).enabled


def test_restricted_sources_need_acknowledgement(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [RESTRICTED])
    with pytest.raises(PolicyError, match="acknowledge"):
        set_enabled(conn, "restricted-list", True)
    assert set_enabled(conn, "restricted-list", True, acknowledge_restricted=True).enabled


def test_turning_business_mode_on_disables_non_business_sources(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [ALLOWED, NONCOMMERCIAL, ALLOW_SOURCE])
    set_business_mode(conn, False)
    set_enabled(conn, "nc-list", True)
    assert set_business_mode(conn, True) == ["nc-list"]
    assert load_settings(conn).business_mode is True
    source = get_source(conn, "nc-list")
    assert (source.enabled, source.disabled_reason) == (False, BUSINESS_MODE_REASON)
    assert get_source(conn, "cdn-ranges").enabled


def test_catalog_reclassification_is_enforced_on_sync(conn: sqlite3.Connection) -> None:
    sync_catalog(conn, [ALLOWED])
    sync_catalog(conn, [make_entry(id="allowed-list", business_use="forbidden")])
    assert get_source(conn, "allowed-list").enabled is False


def test_custom_sources(conn: sqlite3.Connection) -> None:
    source = add_custom_source(
        conn,
        source_id="custom-honeypot",
        name="Our honeypot",
        url="file:///data/hp.txt",
        fmt="plain",
        kind="ip",
        category="scanner",
        business_use=BusinessUse.ALLOWED,
    )
    assert (source.custom, source.enabled, source.licence_class) == (True, False, "unknown")
    assert set_enabled(conn, "custom-honeypot", True).enabled


@pytest.mark.parametrize(
    ("source_id", "url"),
    [("honeypot", "file:///x"), ("custom-ok", "ftp://example.com/x")],
)
def test_custom_source_validation(conn: sqlite3.Connection, source_id: str, url: str) -> None:
    with pytest.raises(ValueError, match="custom"):
        add_custom_source(
            conn,
            source_id=source_id,
            name="x",
            url=url,
            fmt="plain",
            kind="ip",
            category="malicious",
        )


def test_unknown_source_raises(conn: sqlite3.Connection) -> None:
    with pytest.raises(NotFoundError):
        get_source(conn, "missing")
