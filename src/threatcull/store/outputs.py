# SPDX-License-Identifier: AGPL-3.0-only
"""Output definitions and their Feed Tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from threatcull.clock import ts
from threatcull.indicators import SourceKind
from threatcull.policy.scoring import Tier
from threatcull.store.errors import NotFoundError

OutputFormat = Literal["plain", "hosts", "adguard", "rpz", "csv", "json"]
DOMAIN_ONLY_FORMATS: frozenset[str] = frozenset({"hosts", "adguard", "rpz"})
# Public so callers that must validate a name before it becomes an OutputSpec
# (e.g. the web layer's /o/{name} route, before it ever touches the
# database) can reuse this exact pattern instead of duplicating it.
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_IP_CATEGORIES = frozenset({"malicious", "c2", "scanner"})


@dataclass(frozen=True, slots=True)
class OutputSpec:
    name: str
    kind: SourceKind
    categories: frozenset[str]
    min_tier: Tier
    max_entries: int | None
    format: OutputFormat
    last_count: int | None = None
    last_published_at: str | None = None
    # Sources that could feed this Output when it was last published (the Shrink
    # Guard's baseline); None if it was published before this was recorded.
    last_sources: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if not NAME_PATTERN.fullmatch(self.name):
            raise ValueError(f"Output name {self.name!r} must be lowercase letters, digits, dashes")
        if self.kind == "ip" and self.format in DOMAIN_ONLY_FORMATS:
            raise ValueError(f"Output format {self.format} only suits domain Outputs")
        if not self.categories:
            raise ValueError("an Output needs at least one category")
        if self.max_entries is not None and self.max_entries < 1:
            raise ValueError("Output max_entries must be positive")


DEFAULT_OUTPUTS: tuple[OutputSpec, ...] = (
    OutputSpec("ip-high", "ip", _IP_CATEGORIES, "high", None, "plain"),
    OutputSpec("ip-medium", "ip", _IP_CATEGORIES, "medium", 25_000, "plain"),
    OutputSpec(
        "domains-malicious",
        "domain",
        frozenset({"malicious", "c2", "phishing"}),
        "low",
        None,
        "plain",
    ),
    OutputSpec("domains-spam", "domain", frozenset({"spam"}), "low", None, "plain"),
    OutputSpec("domains-ads", "domain", frozenset({"ads_tracking"}), "low", None, "plain"),
)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_output(conn: sqlite3.Connection, spec: OutputSpec) -> str:
    """Store ``spec`` and return its new Feed Token (only its hash is kept)."""
    token = secrets.token_urlsafe(24)
    conn.execute(
        """
        INSERT INTO outputs (name, kind, categories, min_tier, max_entries, format, feed_token_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            spec.name,
            spec.kind,
            json.dumps(sorted(spec.categories)),
            spec.min_tier,
            spec.max_entries,
            spec.format,
            _hash(token),
        ),
    )
    return token


def ensure_default_outputs(conn: sqlite3.Connection) -> dict[str, str]:
    existing = {row["name"] for row in conn.execute("SELECT name FROM outputs")}
    return {
        spec.name: create_output(conn, spec)
        for spec in DEFAULT_OUTPUTS
        if spec.name not in existing
    }


def _to_spec(row: sqlite3.Row) -> OutputSpec:
    return OutputSpec(
        name=row["name"],
        kind=row["kind"],
        categories=frozenset(json.loads(row["categories"])),
        min_tier=row["min_tier"],
        max_entries=row["max_entries"],
        format=row["format"],
        last_count=row["last_count"],
        last_published_at=row["last_published_at"],
        last_sources=(
            frozenset(json.loads(row["last_sources"])) if row["last_sources"] is not None else None
        ),
    )


def list_outputs(conn: sqlite3.Connection) -> list[OutputSpec]:
    return [_to_spec(row) for row in conn.execute("SELECT * FROM outputs ORDER BY name")]


def get_output(conn: sqlite3.Connection, name: str) -> OutputSpec:
    row = conn.execute("SELECT * FROM outputs WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise NotFoundError(f"no Output named {name!r}")
    return _to_spec(row)


def rotate_token(conn: sqlite3.Connection, name: str) -> str:
    get_output(conn, name)
    token = secrets.token_urlsafe(24)
    conn.execute("UPDATE outputs SET feed_token_hash = ? WHERE name = ?", (_hash(token), name))
    return token


def verify_token(conn: sqlite3.Connection, name: str, token: str) -> bool:
    row = conn.execute("SELECT feed_token_hash FROM outputs WHERE name = ?", (name,)).fetchone()
    return row is not None and hmac.compare_digest(row["feed_token_hash"], _hash(token))


def record_published(
    conn: sqlite3.Connection,
    name: str,
    count: int,
    *,
    now: datetime,
    sources: Iterable[str] = (),
) -> None:
    conn.execute(
        "UPDATE outputs SET last_count = ?, last_published_at = ?, last_sources = ? WHERE name = ?",
        (count, ts(now), json.dumps(sorted(sources)), name),
    )
