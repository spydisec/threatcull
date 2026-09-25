# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration export/import as YAML: settings, Source choices, custom Sources, the
Allowlist, the Home Network and Output definitions.

A configuration file never holds passwords, API tokens, Feed Tokens, their hashes, the
session secret or threat data (Sightings, Runs, Indicators): it is safe to keep next to
backups and to move between installs.
"""

from __future__ import annotations

import sqlite3
from dataclasses import asdict
from datetime import datetime
from typing import Any

import yaml

from threatcull.clock import ts
from threatcull.store.allowlist import operator_entries
from threatcull.store.home import home_entries
from threatcull.store.outputs import list_outputs
from threatcull.store.settings import load_settings
from threatcull.store.sources import list_sources

CONFIG_VERSION = 1

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
