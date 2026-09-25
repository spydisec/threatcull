# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration export/import as YAML: settings, Source choices, custom Sources, the
Allowlist, the Home Network and Output definitions.

A configuration file never holds passwords, API tokens, Feed Tokens, their hashes, the
session secret or threat data (Sightings, Runs, Indicators): it is safe to keep next to
backups and to move between installs.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from threatcull.catalog import BusinessUse, Category
from threatcull.clock import ts
from threatcull.indicators import SourceKind
from threatcull.parsers import SourceFormat
from threatcull.policy.scoring import Tier
from threatcull.store.allowlist import add_entry, normalize_allow_value, operator_entries
from threatcull.store.db import transaction
from threatcull.store.home import HomeOrigin, add_home, home_entries, normalize_home_value
from threatcull.store.outputs import OutputFormat, OutputSpec, create_output, list_outputs
from threatcull.store.settings import load_settings, save_settings
from threatcull.store.sources import (
    add_custom_source,
    list_sources,
    set_enabled,
    update_custom_source,
)

CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 1024 * 1024

_HEADER = (
    "# ThreatCull configuration (format {version}).\n"
    "# It contains no passwords, tokens or threat data.\n"
)


def export_config(conn: sqlite3.Connection, *, now: datetime) -> dict[str, Any]:
    sources = list_sources(conn)
    return {
        "threatcull_config": CONFIG_VERSION,
        "exported_at": ts(now),
        "settings": asdict(load_settings(conn)),
        "catalog_sources": {
            s.id: s.enabled for s in sorted(sources, key=lambda s: s.id) if not s.custom
        },
        "custom_sources": [
            {
                "id": s.id,
                "name": s.name,
                "url": s.url,
                "format": str(s.format),
                "kind": str(s.kind),
                "category": s.category,
                "business_use": str(s.business_use),
                "csv_column": s.csv_column,
                "json_keys": list(s.json_keys),
                "enabled": s.enabled,
            }
            for s in sorted(sources, key=lambda s: s.id)
            if s.custom
        ],
        "allowlist": [
            {"value": e.value, "note": e.note}
            for e in sorted(operator_entries(conn), key=lambda e: e.value)
        ],
        "home_network": [
            {"value": e.value, "note": e.note, "origin": e.origin}
            for e in sorted(home_entries(conn), key=lambda e: e.value)
        ],
        "outputs": [
            {
                "name": o.name,
                "kind": o.kind,
                "categories": sorted(o.categories),
                "min_tier": o.min_tier,
                "max_entries": o.max_entries,
                "format": o.format,
            }
            for o in sorted(list_outputs(conn), key=lambda o: o.name)
        ],
    }


def dump_config(conn: sqlite3.Connection, *, now: datetime) -> str:
    body = yaml.safe_dump(
        export_config(conn, now=now), sort_keys=False, allow_unicode=True, width=100
    )
    return _HEADER.format(version=CONFIG_VERSION) + body


# ---- import -----------------------------------------------------------------------------


class ConfigError(ValueError):
    """A configuration file ThreatCull refuses; the message is one line for the operator."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _SettingsIn(_Strict):
    """Any subset of the Settings fields; the rest keep their current values."""

    active_window_days: int | None = None
    retention_days: int | None = None
    stale_after_hours: int | None = None
    tier_high: int | None = None
    tier_medium: int | None = None
    max_shrink: float | None = None
    max_stale_ratio: float | None = None


class _CustomSourceIn(_Strict):
    id: str
    name: str
    url: str
    format: SourceFormat
    kind: SourceKind
    category: Category
    business_use: BusinessUse = BusinessUse.UNKNOWN
    csv_column: int = Field(default=0, ge=0)
    json_keys: list[str] = Field(default_factory=list)
    enabled: bool = False


class _AllowIn(_Strict):
    value: str
    note: str = ""


class _HomeIn(_Strict):
    value: str
    note: str = ""
    origin: HomeOrigin = "manual"


class _OutputIn(_Strict):
    name: str
    kind: SourceKind
    categories: list[Category] = Field(min_length=1)
    min_tier: Tier
    max_entries: int | None = Field(default=None, ge=1)
    format: OutputFormat


class ConfigDocument(_Strict):
    """A parsed configuration file. Every section is optional: a partial file applies
    only what it contains."""

    threatcull_config: Literal[1]
    exported_at: str | None = None
    settings: _SettingsIn | None = None
    catalog_sources: dict[str, bool] = Field(default_factory=dict)
    custom_sources: list[_CustomSourceIn] = Field(default_factory=list)
    allowlist: list[_AllowIn] = Field(default_factory=list)
    home_network: list[_HomeIn] = Field(default_factory=list)
    outputs: list[_OutputIn] = Field(default_factory=list)


class _NoAliasLoader(yaml.SafeLoader):
    """The safe loader, minus YAML aliases: an alias bomb expands exponentially."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise ConfigError("the file uses YAML aliases, which ThreatCull does not accept")
        return super().compose_node(parent, index)


def parse_config(data: bytes) -> ConfigDocument:
    """Validate a configuration file; raises ``ConfigError`` for a file ThreatCull refuses."""
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError("the file is larger than 1 MiB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError("the file is not UTF-8 text") from exc
    try:
        # _NoAliasLoader subclasses yaml.SafeLoader (no Python tags) and refuses aliases.
        raw = yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506  # nosec B506
    except yaml.YAMLError as exc:
        raise ConfigError(f"the file is not a valid ThreatCull configuration: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("the file must be a YAML mapping (key: value) at the top level")
    try:
        doc = ConfigDocument.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or "file"
        raise ConfigError(f"{where}: {first['msg']}") from exc
    return doc


@dataclass(slots=True)
class ImportResult:
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    new_feed_tokens: dict[str, str] = field(default_factory=dict)


def apply_config(
    conn: sqlite3.Connection,
    doc: ConfigDocument,
    *,
    now: datetime,
    url_check: Callable[[str], str | None] | None = None,
) -> ImportResult:
    """Merge ``doc`` into the database in one transaction; never deletes anything.

    ``url_check`` returns why a custom Source URL is refused (the web UI confines
    ``file://`` URLs to the imports directory); the CLI passes none.
    """
    result = ImportResult()
    with transaction(conn):
        if doc.settings is not None:
            given = doc.settings.model_dump(exclude_none=True)
            try:
                merged = replace(load_settings(conn), **given)
            except ValueError as exc:
                raise ConfigError(f"settings: {exc}") from exc
            save_settings(conn, merged)
            result.applied.append(f"updated settings: {', '.join(sorted(given)) or 'none'}")
        _apply_sources(conn, doc, result, url_check)
        _apply_lists(conn, doc, result, now)
        _apply_outputs(conn, doc, result)
    return result


def _apply_sources(
    conn: sqlite3.Connection,
    doc: ConfigDocument,
    result: ImportResult,
    url_check: Callable[[str], str | None] | None,
) -> None:
    sources = {s.id: s for s in list_sources(conn)}
    for source_id, enabled in doc.catalog_sources.items():
        source = sources.get(source_id)
        if source is None or source.custom:
            result.skipped.append(f"skipped Source {source_id}: not in this Catalog")
            continue
        if source.enabled == enabled:
            continue
        restricted = str(source.licence_class) == "restricted"
        set_enabled(conn, source_id, enabled, acknowledge_restricted=True)
        verb = "enabled" if enabled else "disabled"
        note = (
            " (restricted terms acknowledged in the imported file)"
            if enabled and restricted
            else ""
        )
        result.applied.append(f"{verb} Source {source_id}{note}")
    for custom in doc.custom_sources:
        existing = sources.get(custom.id)
        if existing is not None and not existing.custom:
            result.skipped.append(
                f"skipped custom Source {custom.id}: id belongs to a Catalog Source"
            )
            continue
        refusal = url_check(custom.url) if url_check else None
        if refusal:
            result.skipped.append(f"skipped custom Source {custom.id}: {refusal}")
            continue
        write = add_custom_source if existing is None else update_custom_source
        try:
            write(
                conn,
                source_id=custom.id,
                name=custom.name,
                url=custom.url,
                fmt=custom.format,
                kind=custom.kind,
                category=custom.category,
                csv_column=custom.csv_column,
                json_keys=tuple(custom.json_keys),
                business_use=custom.business_use,
            )
        except ValueError as exc:
            result.skipped.append(f"skipped custom Source {custom.id}: {exc}")
            continue
        verb = "added" if existing is None else "updated"
        result.applied.append(f"{verb} custom Source {custom.id}")
        set_enabled(conn, custom.id, custom.enabled, acknowledge_restricted=True)


def _apply_lists(
    conn: sqlite3.Connection, doc: ConfigDocument, result: ImportResult, now: datetime
) -> None:
    allowed = {e.value for e in operator_entries(conn)}
    for entry in doc.allowlist:
        try:
            value = normalize_allow_value(entry.value).value
        except ValueError as exc:
            result.skipped.append(f"skipped Allowlist entry {entry.value!r}: {exc}")
            continue
        if value not in allowed:
            add_entry(conn, entry.value, entry.note, now=now)
            allowed.add(value)
            result.applied.append(f"added Allowlist entry {value}")
    home = {e.value for e in home_entries(conn)}
    for item in doc.home_network:
        try:
            value = normalize_home_value(item.value).value
        except ValueError as exc:
            result.skipped.append(f"skipped Home Network entry {item.value!r}: {exc}")
            continue
        if value not in home:
            add_home(conn, item.value, item.note, origin=item.origin, now=now)
            home.add(value)
            result.applied.append(f"added Home Network entry {value}")


def _apply_outputs(conn: sqlite3.Connection, doc: ConfigDocument, result: ImportResult) -> None:
    existing = {o.name: o for o in list_outputs(conn)}
    for item in doc.outputs:
        try:
            spec = OutputSpec(
                item.name,
                item.kind,
                frozenset(item.categories),
                item.min_tier,
                item.max_entries,
                item.format,
            )
        except ValueError as exc:
            result.skipped.append(f"skipped Output {item.name}: {exc}")
            continue
        current = existing.get(spec.name)
        if current is None:
            result.new_feed_tokens[spec.name] = create_output(conn, spec)
            result.applied.append(f"created Output {spec.name}")
            continue
        same = (
            current.kind,
            current.categories,
            current.min_tier,
            current.max_entries,
            current.format,
        ) == (spec.kind, spec.categories, spec.min_tier, spec.max_entries, spec.format)
        if not same:
            result.skipped.append(
                f"skipped Output {spec.name}: exists with a different definition; "
                "edit it on the Outputs page"
            )


def _definition(spec: OutputSpec) -> tuple[object, ...]:
    return (spec.kind, spec.categories, spec.min_tier, spec.max_entries, spec.format)
