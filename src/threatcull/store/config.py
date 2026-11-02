# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration export/import as YAML: settings, Source choices, custom Sources, the
Allowlist (including the operator's own network) and Output definitions.

A configuration file holds no passwords, no raw tokens, no session secret and no threat
data (Sightings, Runs, Indicators). It does hold Feed Token and API token hashes, so a
restore keeps feed URLs and API tokens working; the import adopts them only on request.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from threatcull.catalog import LEGACY_FIELDS, Category, SourceRole
from threatcull.clock import ts
from threatcull.indicators import SourceKind
from threatcull.outputs.files import output_path
from threatcull.parsers import SourceFormat
from threatcull.policy.scoring import Tier
from threatcull.store.allowlist import add_entry, normalize_allow_value, operator_entries, set_mine
from threatcull.store.api_tokens import ApiTokenRecord, export_api_tokens, import_api_token
from threatcull.store.db import transaction
from threatcull.store.errors import NotFoundError
from threatcull.store.outputs import (
    TOKEN_HASH,
    OutputFormat,
    OutputSpec,
    create_output,
    feed_token_hashes,
    list_outputs,
    set_feed_token_hash,
    update_output,
)
from threatcull.store.settings import load_settings, save_settings
from threatcull.store.sources import (
    add_custom_source,
    list_sources,
    set_enabled,
    update_custom_source,
)

CONFIG_VERSION = 1
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00")
MAX_CONFIG_BYTES = 1024 * 1024
FEEDS_EMPTY_NOTE = (
    "Feeds stay empty until the next Compile: click Run now or wait for the schedule."
)

_HEADER = (
    "# ThreatCull configuration (format {version}).\n"
    "# It contains no passwords, no raw tokens and no threat data. It holds Feed Token and\n"
    "# API token hashes so a restore keeps feed URLs and API tokens working.\n"
)


def export_config(conn: sqlite3.Connection, *, now: datetime) -> dict[str, Any]:
    sources = list_sources(conn)
    hashes = feed_token_hashes(conn)
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
                "role": s.role,
                "format": str(s.format),
                "kind": str(s.kind),
                "category": s.category,
                "csv_column": s.csv_column,
                "json_keys": list(s.json_keys),
                "enabled": s.enabled,
            }
            for s in sorted(sources, key=lambda s: s.id)
            if s.custom
        ],
        "allowlist": [
            {"value": e.value, "note": e.note, "mine": e.mine}
            for e in sorted(operator_entries(conn), key=lambda e: e.value)
        ],
        "outputs": [
            {
                "name": o.name,
                "kind": o.kind,
                "categories": sorted(o.categories),
                "min_tier": o.min_tier,
                "max_entries": o.max_entries,
                "format": o.format,
                "feed_token_hash": hashes[o.name],
            }
            for o in sorted(list_outputs(conn), key=lambda o: o.name)
        ],
        "api_tokens": [
            {
                "name": t.name,
                "user": t.username,
                "token_hash": t.token_hash,
                "created_at": t.created_at,
            }
            for t in export_api_tokens(conn)
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

    active_window_days: int | None = Field(default=None, ge=1, le=365)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    stale_after_hours: int | None = Field(default=None, ge=1, le=8760)
    tier_high: int | None = Field(default=None, ge=1, le=100)
    tier_medium: int | None = Field(default=None, ge=1, le=100)
    max_shrink: float | None = None
    max_stale_ratio: float | None = None
    frozen_after_days: int | None = Field(default=None, ge=1, le=3650)


class _CustomSourceIn(_Strict):
    id: str
    name: str
    url: str
    role: SourceRole = "blocklist"
    format: SourceFormat
    kind: SourceKind
    category: Category
    csv_column: int = Field(default=0, ge=0)
    json_keys: list[str] = Field(default_factory=list)
    enabled: bool = False

    @model_validator(mode="before")
    @classmethod
    def _drop_legacy(cls, data: Any) -> Any:
        """Files exported before 2.0 carry business_use; accept and ignore it."""
        if isinstance(data, dict):
            return {key: value for key, value in data.items() if key not in LEGACY_FIELDS}
        return data


class _AllowIn(_Strict):
    value: str
    note: str = ""
    mine: bool = False  # the operator's own network: alert when a Source lists it


class _HomeIn(_Strict):
    """A ``home_network`` entry from a file exported before v1.1: imported as an
    Allowlist entry flagged ``mine``."""

    value: str
    note: str = ""
    origin: Literal["manual", "auto"] = "manual"


class _OutputIn(_Strict):
    name: str
    kind: SourceKind
    categories: list[Category] = Field(min_length=1)
    min_tier: Tier
    max_entries: int | None = Field(default=None, ge=1)
    format: OutputFormat
    feed_token_hash: str | None = None  # only adopted when the import asks for it


class _ApiTokenIn(_Strict):
    name: str
    user: str
    token_hash: str
    created_at: str


class ConfigDocument(_Strict):
    """A parsed configuration file. Every section is optional: a partial file applies
    only what it contains."""

    threatcull_config: Literal[1]
    exported_at: str | None = None
    settings: _SettingsIn | None = None
    catalog_sources: dict[str, bool] = Field(default_factory=dict)
    custom_sources: list[_CustomSourceIn] = Field(default_factory=list)
    allowlist: list[_AllowIn] = Field(default_factory=list)
    home_network: list[_HomeIn] = Field(default_factory=list)  # before v1.1
    outputs: list[_OutputIn] = Field(default_factory=list)
    api_tokens: list[_ApiTokenIn] = Field(default_factory=list)


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
        raw = yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506
    except RecursionError as exc:  # e.g. 200,000 "[" in a row: fits in 1 MiB
        raise ConfigError("the file nests too deeply to be a ThreatCull configuration") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(_yaml_problem(exc)) from exc
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
    restored: list[str] = field(default_factory=list)


def apply_config(
    conn: sqlite3.Connection,
    doc: ConfigDocument,
    *,
    now: datetime,
    url_check: Callable[[str], str | None] | None = None,
    restore_tokens: bool = False,
    outputs_dir: Path | None = None,
) -> ImportResult:
    """Merge ``doc`` into the database in one transaction; never deletes anything.

    ``url_check`` returns why a custom Source URL is refused (the web UI confines
    ``file://`` URLs to the imports directory); the CLI passes none. ``restore_tokens``
    adopts the file's Feed Token and API token hashes; without it they are ignored.
    ``outputs_dir`` is where Outputs are published: when a restore changes an Output's
    definition, its old published file is removed after the import commits, so the feed
    is empty until the next Compile instead of serving the old list.
    """
    result = ImportResult()
    stale: list[OutputSpec] = []
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
        stale = _apply_outputs(conn, doc, result, restore_tokens)
        if restore_tokens:
            _apply_api_tokens(conn, doc, result)
    if outputs_dir is not None:
        for old in stale:
            output_path(outputs_dir, old).unlink(missing_ok=True)
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
        set_enabled(conn, source_id, enabled)
        verb = "enabled" if enabled else "disabled"
        result.applied.append(f"{verb} Source {source_id}")
    seen: set[str] = set()
    for custom in doc.custom_sources:
        if custom.id in seen:
            result.skipped.append(f"skipped custom Source {custom.id}: listed twice in the file")
            continue
        seen.add(custom.id)
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
                role=custom.role,
            )
        except ValueError as exc:
            result.skipped.append(f"skipped custom Source {custom.id}: {exc}")
            continue
        verb = "added" if existing is None else "updated"
        result.applied.append(f"{verb} custom Source {custom.id}")
        set_enabled(conn, custom.id, custom.enabled)


def _apply_lists(
    conn: sqlite3.Connection, doc: ConfigDocument, result: ImportResult, now: datetime
) -> None:
    # Files exported before v1.1 list the operator's own network separately.
    wanted = [
        *doc.allowlist,
        *(_AllowIn(value=h.value, note=h.note, mine=True) for h in doc.home_network),
    ]
    allowed = {e.value for e in operator_entries(conn)}
    added: dict[str, bool] = {}
    for entry in wanted:
        try:
            value = normalize_allow_value(entry.value).value
        except ValueError as exc:
            result.skipped.append(f"skipped Allowlist entry {entry.value!r}: {exc}")
            continue
        if value in added:  # listed twice in this file: keep the "mine" flag if either has it
            if entry.mine and not added[value]:
                set_mine(conn, value, True)
                added[value] = True
            continue
        if value not in allowed:
            add_entry(conn, entry.value, entry.note, mine=entry.mine, now=now)
            added[value] = entry.mine
            label = "My network entry" if entry.mine else "Allowlist entry"
            result.applied.append(f"added {label} {value}")


def _apply_outputs(
    conn: sqlite3.Connection, doc: ConfigDocument, result: ImportResult, restore_tokens: bool
) -> list[OutputSpec]:
    """Apply the file's Outputs; return the previous definitions a restore replaced."""
    existing = {o.name: o for o in list_outputs(conn)}
    hashes = feed_token_hashes(conn) if restore_tokens else {}
    replaced: list[OutputSpec] = []
    seen: set[str] = set()
    for item in doc.outputs:
        if item.name in seen:
            result.skipped.append(f"skipped Output {item.name}: listed twice in the file")
            continue
        seen.add(item.name)
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
        token_hash = item.feed_token_hash if restore_tokens else None
        if token_hash is not None and not TOKEN_HASH.fullmatch(token_hash):
            result.skipped.append(
                f"skipped Feed Token for Output {spec.name}: the hash must be 64 lowercase "
                "hex characters"
            )
            token_hash = None
        current = existing.get(spec.name)
        if current is None:
            raw = create_output(conn, spec, token_hash=token_hash)
            if raw is not None:
                result.new_feed_tokens[spec.name] = raw
            result.applied.append(f"created Output {spec.name}")
            if token_hash is not None:
                result.restored.append(f"restored Feed Token for Output {spec.name}")
            continue
        if token_hash is None:
            if _definition(current) != _definition(spec):
                result.skipped.append(
                    f"skipped Output {spec.name}: exists with a different definition; "
                    "edit it on the Outputs page"
                )
            continue
        if _definition(current) != _definition(spec):
            update_output(conn, spec)  # also clears its publish baseline
            replaced.append(current)
            result.applied.append(f"restored Output {spec.name} from the file")
        if hashes.get(spec.name) != token_hash:
            set_feed_token_hash(conn, spec.name, token_hash)
            hashes[spec.name] = token_hash
            result.restored.append(f"restored Feed Token for Output {spec.name}")
    return replaced


def _apply_api_tokens(conn: sqlite3.Connection, doc: ConfigDocument, result: ImportResult) -> None:
    for item in doc.api_tokens:
        label = f"skipped API token {item.name}: "
        if not _is_timestamp(item.created_at):
            result.skipped.append(
                label + "created_at must be a UTC timestamp like 2026-01-31T12:00:00+00:00"
            )
            continue
        record = ApiTokenRecord(item.name, item.user, item.token_hash, item.created_at)
        try:
            import_api_token(conn, record)
        except NotFoundError:
            result.skipped.append(label + f"user {item.user} doesn't exist")
        except ValueError as exc:
            if "already exists" in str(exc):
                result.skipped.append(label + "a token with this name already exists")
            else:
                result.skipped.append(label + str(exc))
        else:
            result.restored.append(f"restored API token {item.name} for user {item.user}")


def _is_timestamp(value: str) -> bool:
    """True for exactly what ``ts()`` writes: UTC, ISO-8601, second precision."""
    if not _TIMESTAMP.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.utcoffset() is not None and ts(parsed.astimezone(UTC)) == value


def _yaml_problem(exc: yaml.YAMLError) -> str:
    """One line for the operator: PyYAML's own message spans several lines."""
    problem = getattr(exc, "problem", None) or "unreadable YAML"
    mark = getattr(exc, "problem_mark", None)
    where = f" (line {mark.line + 1})" if mark is not None else ""
    return f"the file is not a valid ThreatCull configuration: {problem}{where}"


def _definition(spec: OutputSpec) -> tuple[object, ...]:
    return (spec.kind, spec.categories, spec.min_tier, spec.max_entries, spec.format)
