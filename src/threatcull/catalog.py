# SPDX-License-Identifier: AGPL-3.0-only
"""The Catalog: curated Source definitions (public threat feeds)."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from threatcull import __version__
from threatcull.indicators import SourceKind
from threatcull.parsers import SourceFormat

Category = Literal[
    "malicious", "c2", "scanner", "phishing", "spam", "ads_tracking", "infrastructure"
]
SourceRole = Literal["blocklist", "allowlist"]
SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}$"
# Source fields removed in 2.0; older Catalog and configuration files still load.
LEGACY_FIELDS = frozenset({"licence", "licence_url", "licence_class", "business_use"})


class CatalogError(ValueError):
    """The Catalog file is malformed."""


class CatalogEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=SLUG_PATTERN)
    name: str = Field(min_length=1)
    family: str = Field(pattern=SLUG_PATTERN)
    url: str = Field(pattern=r"^(https?://|file://)")
    format: SourceFormat
    kind: SourceKind
    role: SourceRole = "blocklist"
    category: Category
    refresh_minutes: int = Field(ge=15, le=10080)
    default_enabled: bool = False
    csv_column: int = Field(default=0, ge=0)
    json_keys: tuple[str, ...] = ()
    notes: str = ""

    @model_validator(mode="before")
    @classmethod
    def _default_family(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        # Catalogs before 2.0 carried licence fields; they are accepted and dropped.
        data = {key: value for key, value in data.items() if key not in LEGACY_FIELDS}
        if not data.get("family"):
            data["family"] = data.get("id", "")
        return data

    @model_validator(mode="after")
    def _check_consistency(self) -> CatalogEntry:
        if self.format == "json" and not self.json_keys:
            raise ValueError("json Sources need json_keys")
        return self


@dataclass(frozen=True, slots=True)
class Catalog:
    """A parsed Catalog file: its revision, the oldest ThreatCull it supports, its Sources."""

    revision: int
    requires: str | None
    entries: tuple[CatalogEntry, ...]


class _NoAliasLoader(yaml.SafeLoader):
    """The safe loader, minus YAML aliases: an alias bomb expands exponentially."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise CatalogError("the Catalog uses YAML aliases, which ThreatCull does not accept")
        return super().compose_node(parent, index)


def feed_label(url: str) -> str:
    """Who publishes a feed, for display: its host, or ``github.com/owner/repo`` for a
    raw GitHub file, or "local file" for a file:// Source."""
    if url.startswith("file://"):
        return "local file"
    parts = urlparse(url)
    segments = [segment for segment in parts.path.split("/") if segment]
    if parts.hostname == "raw.githubusercontent.com" and len(segments) >= 2:  # noqa: PLR2004
        return f"github.com/{segments[0]}/{segments[1]}"
    return parts.hostname or url


def parse_catalog(text: str, *, allow_file_urls: bool = True) -> Catalog:
    """Parse and validate Catalog YAML.

    A Catalog downloaded or uploaded as an update passes ``allow_file_urls=False``:
    a ``file://`` Source there could read files on the ThreatCull host.
    """
    try:
        # _NoAliasLoader subclasses yaml.SafeLoader (no Python tags) and refuses aliases.
        raw = yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506  # nosec B506
    except RecursionError as exc:
        raise CatalogError("the Catalog nests too deeply") from exc
    except yaml.YAMLError as exc:
        raise CatalogError(f"the Catalog is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("sources"), list):
        raise CatalogError("the Catalog must be a mapping with a 'sources' list")
    revision = raw.get("revision", 0)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise CatalogError("the Catalog 'revision' must be a whole number")
    requires = raw.get("requires")
    if requires is not None and not isinstance(requires, str):
        raise CatalogError("the Catalog 'requires' must be a version string such as 1.3.0")
    if requires and _version_tuple(requires) > _version_tuple(__version__):
        raise CatalogError(
            f"this Catalog needs ThreatCull {requires} or newer (this is {__version__})"
        )
    entries = tuple(CatalogEntry.model_validate(item) for item in raw["sources"])
    counts = Counter(entry.id for entry in entries)
    duplicates = sorted(source_id for source_id, n in counts.items() if n > 1)
    if duplicates:
        raise CatalogError(f"duplicate Source ids: {', '.join(duplicates)}")
    if not allow_file_urls:
        local = sorted(entry.id for entry in entries if entry.url.startswith("file://"))
        if local:
            raise CatalogError(f"a Catalog update cannot use file:// URLs: {', '.join(local)}")
    return Catalog(revision, requires, entries)


def shipped_catalog() -> Catalog:
    """The Catalog that ships inside this ThreatCull release."""
    text = resources.files("threatcull").joinpath("catalog.yaml").read_text(encoding="utf-8")
    return parse_catalog(text)


def load_catalog(path: Path | None = None) -> list[CatalogEntry]:
    """Load and validate the Catalog (the shipped one when ``path`` is None)."""
    catalog = shipped_catalog() if path is None else parse_catalog(path.read_text("utf-8"))
    return list(catalog.entries)


def _version_tuple(value: str) -> tuple[int, ...]:
    """``1.2.0`` -> (1, 2, 0) and ``1.2`` -> (1, 2, 0); a suffix such as ``rc1`` is ignored."""
    parts = []
    for part in value.split("."):
        digits = re.match(r"\d+", part)
        if digits is None:
            break
        parts.append(int(digits.group()))
    return tuple(parts + [0] * (3 - len(parts)))
