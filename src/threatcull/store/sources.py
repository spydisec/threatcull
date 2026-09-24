# SPDX-License-Identifier: AGPL-3.0-only
"""Sources: Catalog sync, enablement and Business Mode policy."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, replace

from threatcull.catalog import (
    BusinessUse,
    CatalogEntry,
    Category,
    LicenceClass,
    SourceRole,
    business_use_permitted,
)
from threatcull.indicators import SourceKind
from threatcull.parsers import SourceFormat
from threatcull.store.db import transaction
from threatcull.store.errors import NotFoundError, PolicyError
from threatcull.store.settings import load_settings, save_settings

BUSINESS_MODE_REASON = "Disabled by Business Mode: not cleared for business use"
REMOVED_FROM_CATALOG_REASON = "Removed from the Catalog"
_CUSTOM_ID = re.compile(r"^custom-[a-z0-9][a-z0-9-]{0,54}$")
_CUSTOM_SCHEMES = ("https://", "http://", "file://")


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    name: str
    family: str
    url: str
    format: SourceFormat
    kind: SourceKind
    role: SourceRole
    category: str
    licence_class: LicenceClass
    business_use: BusinessUse
    licence: str
    licence_url: str
    refresh_minutes: int
    csv_column: int
    json_keys: tuple[str, ...]
    custom: bool
    enabled: bool
    disabled_reason: str | None
    etag: str | None
    last_modified: str | None
    last_success_at: str | None
    last_attempt_at: str | None
    last_error: str | None


def _to_source(row: sqlite3.Row) -> Source:
    return Source(
        id=row["id"],
        name=row["name"],
        family=row["family"],
        url=row["url"],
        format=row["format"],
        kind=row["kind"],
        role=row["role"],
        category=row["category"],
        licence_class=LicenceClass(row["licence_class"]),
        business_use=BusinessUse(row["business_use"]),
        licence=row["licence"],
        licence_url=row["licence_url"],
        refresh_minutes=row["refresh_minutes"],
        csv_column=row["csv_column"],
        json_keys=tuple(json.loads(row["json_keys"])),
        custom=bool(row["custom"]),
        enabled=bool(row["enabled"]),
        disabled_reason=row["disabled_reason"],
        etag=row["etag"],
        last_modified=row["last_modified"],
        last_success_at=row["last_success_at"],
        last_attempt_at=row["last_attempt_at"],
        last_error=row["last_error"],
    )


def sync_catalog(conn: sqlite3.Connection, entries: Sequence[CatalogEntry]) -> None:
    """Insert new Catalog Sources and refresh metadata, never overriding operator choices."""
    business_mode = load_settings(conn).business_mode
    with transaction(conn):
        for entry in entries:
            enabled = entry.default_enabled and (
                not business_mode or business_use_permitted(entry.role, entry.business_use)
            )
            params = entry.model_dump(mode="json", exclude={"default_enabled", "notes"})
            params["json_keys"] = json.dumps(list(entry.json_keys))
            params["enabled"] = int(enabled)
            conn.execute(
                """
                INSERT INTO sources (id, name, family, url, format, kind, role, category,
                    licence_class, business_use, licence, licence_url, refresh_minutes,
                    csv_column, json_keys, custom, enabled)
                VALUES (:id, :name, :family, :url, :format, :kind, :role, :category,
                    :licence_class, :business_use, :licence, :licence_url, :refresh_minutes,
                    :csv_column, :json_keys, 0, :enabled)
                ON CONFLICT (id) DO UPDATE SET
                    name = excluded.name, family = excluded.family, url = excluded.url,
                    format = excluded.format, kind = excluded.kind, role = excluded.role,
                    category = excluded.category, licence_class = excluded.licence_class,
                    business_use = excluded.business_use, licence = excluded.licence,
                    licence_url = excluded.licence_url, refresh_minutes = excluded.refresh_minutes,
                    csv_column = excluded.csv_column, json_keys = excluded.json_keys
                """,
                params,
            )
        known = [entry.id for entry in entries]
        stale_ids = [
            row["id"]
            for row in conn.execute("SELECT id FROM sources WHERE custom = 0 AND enabled = 1")
            if row["id"] not in known
        ]
        conn.executemany(
            "UPDATE sources SET enabled = 0, disabled_reason = ? WHERE id = ?",
            [(REMOVED_FROM_CATALOG_REASON, source_id) for source_id in stale_ids],
        )
        if business_mode:
            _disable_non_business(conn)


def list_sources(
    conn: sqlite3.Connection, *, enabled_only: bool = False, role: SourceRole | None = None
) -> list[Source]:
    rows = conn.execute(
        """
        SELECT * FROM sources
        WHERE (:enabled_only = 0 OR enabled = 1) AND (:role IS NULL OR role = :role)
        ORDER BY role DESC, id
        """,
        {"enabled_only": int(enabled_only), "role": role},
    )
    return [_to_source(row) for row in rows]


def get_source(conn: sqlite3.Connection, source_id: str) -> Source:
    row = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"no Source with id {source_id!r}")
    return _to_source(row)


def set_enabled(
    conn: sqlite3.Connection,
    source_id: str,
    enabled: bool,
    *,
    acknowledge_restricted: bool = False,
) -> Source:
    source = get_source(conn, source_id)
    if enabled:
        business_mode = load_settings(conn).business_mode
        if business_mode and not business_use_permitted(source.role, source.business_use):
            raise PolicyError(
                f"{source.name} is not cleared for business use ({source.business_use}); "
                "turn off Business Mode to enable it"
            )
        if source.licence_class is LicenceClass.RESTRICTED and not acknowledge_restricted:
            raise PolicyError(
                f"{source.name} has restricted terms ({source.licence}); read "
                f"{source.licence_url} and acknowledge them to enable it"
            )
    conn.execute(
        "UPDATE sources SET enabled = ?, disabled_reason = NULL WHERE id = ?",
        (int(enabled), source_id),
    )
    return get_source(conn, source_id)


def add_custom_source(
    conn: sqlite3.Connection,
    *,
    source_id: str,
    name: str,
    url: str,
    fmt: SourceFormat,
    kind: SourceKind,
    category: Category,
    csv_column: int = 0,
    json_keys: tuple[str, ...] = (),
    business_use: BusinessUse = BusinessUse.UNKNOWN,
) -> Source:
    if not _CUSTOM_ID.fullmatch(source_id):
        raise ValueError("custom Source ids look like custom-<name> (lowercase, digits, dashes)")
    if not url.startswith(_CUSTOM_SCHEMES):
        raise ValueError("custom Source URLs must use https://, http:// or file://")
    conn.execute(
        """
        INSERT INTO sources (id, name, family, url, format, kind, role, category, licence_class,
            business_use, licence, licence_url, refresh_minutes, csv_column, json_keys, custom,
            enabled)
        VALUES (?, ?, ?, ?, ?, ?, 'blocklist', ?, 'unknown', ?, 'Operator-supplied', '', 60, ?, ?,
            1, 0)
        """,
        (
            source_id,
            name,
            source_id,
            url,
            fmt,
            kind,
            category,
            str(business_use),
            csv_column,
            json.dumps(list(json_keys)),
        ),
    )
    return get_source(conn, source_id)


def set_business_mode(conn: sqlite3.Connection, on: bool) -> list[str]:
    """Persist Business Mode; turning it on disables blocklist Sources not cleared for business."""
    with transaction(conn):
        save_settings(conn, replace(load_settings(conn), business_mode=on))
        return _disable_non_business(conn) if on else []


def _disable_non_business(conn: sqlite3.Connection) -> list[str]:
    ids = [
        row["id"]
        for row in conn.execute(
            "SELECT id FROM sources WHERE enabled = 1 AND role = 'blocklist' "
            "AND business_use != 'allowed' ORDER BY id"
        )
    ]
    conn.executemany(
        "UPDATE sources SET enabled = 0, disabled_reason = ? WHERE id = ?",
        [(BUSINESS_MODE_REASON, source_id) for source_id in ids],
    )
    return ids
