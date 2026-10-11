# SPDX-License-Identifier: AGPL-3.0-only
"""Sources: Catalog sync and enablement."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from threatcull.catalog import CatalogEntry, Category, SourceRole
from threatcull.indicators import SourceKind
from threatcull.parsers import SourceFormat
from threatcull.store.db import transaction
from threatcull.store.errors import NotFoundError

REMOVED_FROM_CATALOG_REASON = "Removed from the Catalog"
_CUSTOM_ID = re.compile(r"^custom-[a-z0-9][a-z0-9-]{0,54}$")
_CUSTOM_SCHEMES = ("https://", "http://", "file://")
# Source names end up in Output comment headers: a newline there could inject lines.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


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
    last_changed_at: str | None


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
        last_changed_at=row["last_changed_at"],
    )


def sync_catalog(
    conn: sqlite3.Connection, entries: Sequence[CatalogEntry], *, enable_new: bool = True
) -> None:
    """Insert new Catalog Sources and refresh metadata, never overriding operator choices.

    ``enable_new=False`` (a Catalog update) adds new Sources disabled even when the
    Catalog marks them ``default_enabled``: the operator decides.
    """
    with transaction(conn):
        for entry in entries:
            enabled = entry.default_enabled and enable_new
            params = entry.model_dump(mode="json", exclude={"default_enabled", "notes"})
            params["json_keys"] = json.dumps(list(entry.json_keys))
            params["enabled"] = int(enabled)
            conn.execute(
                """
                INSERT INTO sources (id, name, family, url, format, kind, role, category,
                    refresh_minutes, csv_column, json_keys, custom, enabled)
                VALUES (:id, :name, :family, :url, :format, :kind, :role, :category,
                    :refresh_minutes, :csv_column, :json_keys, 0, :enabled)
                ON CONFLICT (id) DO UPDATE SET
                    name = excluded.name, family = excluded.family, url = excluded.url,
                    format = excluded.format, kind = excluded.kind, role = excluded.role,
                    category = excluded.category, refresh_minutes = excluded.refresh_minutes,
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


def set_enabled(conn: sqlite3.Connection, source_id: str, enabled: bool) -> Source:
    get_source(conn, source_id)  # NotFoundError for an unknown id
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
    role: SourceRole = "blocklist",
) -> Source:
    """Add a custom Source, disabled. An allowlist Source feeds the Allowlist;
    a blocklist Source is scored like any Catalog blocklist."""
    _check_custom(source_id, name, url)
    conn.execute(
        """
        INSERT INTO sources (id, name, family, url, format, kind, role, category,
            refresh_minutes, csv_column, json_keys, custom, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 60, ?, ?, 1, 0)
        """,
        (
            source_id,
            name,
            source_id,
            url,
            fmt,
            kind,
            role,
            category,
            csv_column,
            json.dumps(list(json_keys)),
        ),
    )
    return get_source(conn, source_id)


def new_custom_id(conn: sqlite3.Connection, name: str) -> str:
    """A free ``custom-<slug>`` id made from ``name``, with ``-2``, ``-3``... on a clash."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48].strip("-") or "source"
    candidate, n = f"custom-{slug}", 1
    while conn.execute("SELECT 1 FROM sources WHERE id = ?", (candidate,)).fetchone():
        n += 1
        candidate = f"custom-{slug}-{n}"
    return candidate


def _check_custom(source_id: str, name: str, url: str) -> None:
    if not _CUSTOM_ID.fullmatch(source_id):
        raise ValueError(
            "custom Source ids look like custom-my-feed: lowercase letters, digits and dashes"
        )
    if _CONTROL_CHARS.search(name):
        raise ValueError("custom Source names cannot contain control characters")
    if not url.startswith(_CUSTOM_SCHEMES):
        raise ValueError("custom Source URLs must use https://, http:// or file://")
    try:
        parts = urlsplit(url)
        valid = bool(parts.path) if parts.scheme == "file" else bool(parts.hostname)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(f"{url!r} is not a valid URL")
    if _CONTROL_CHARS.search(url):
        raise ValueError("custom Source URLs cannot contain control characters")


def update_custom_source(
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
    role: SourceRole = "blocklist",
) -> Source:
    """Replace the definition of an existing custom Source (its enabled state stays)."""
    _check_custom(source_id, name, url)
    updated = conn.execute(
        "UPDATE sources SET name = ?, url = ?, format = ?, kind = ?, role = ?, category = ?, "
        "csv_column = ?, json_keys = ? WHERE id = ? AND custom = 1",
        (
            name,
            url,
            fmt,
            kind,
            role,
            category,
            csv_column,
            json.dumps(list(json_keys)),
            source_id,
        ),
    ).rowcount
    if updated == 0:
        raise NotFoundError(f"no custom Source {source_id}")
    return get_source(conn, source_id)
