# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration export and import (YAML): settings, Source choices, lists, Outputs."""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from tests.factories import make_entry
from threatcull.cli import main
from threatcull.store.allowlist import add_entry
from threatcull.store.api_tokens import create_api_token
from threatcull.store.config import CONFIG_VERSION, dump_config, export_config
from threatcull.store.home import add_home
from threatcull.store.outputs import OutputSpec, create_output
from threatcull.store.sources import add_custom_source, set_enabled, sync_catalog
from threatcull.store.users import create_user


def _seed(conn: sqlite3.Connection, now: datetime) -> dict[str, str]:
    """A small install: two Catalog Sources (one disabled), a custom Source, lists, Outputs."""
    sync_catalog(
        conn,
        [
            make_entry(id="cat-a", default_enabled=True),
            make_entry(id="cat-b", default_enabled=True),
        ],
    )
    set_enabled(conn, "cat-b", False)
    add_custom_source(
        conn,
        source_id="custom-mine",
        name="My feed",
        url="https://feeds.example/mine.txt",
        fmt="plain",
        kind="domain",
        category="phishing",
    )
    add_entry(conn, "pay.example.com", "payment provider", now=now)
    add_entry(conn, "8.8.8.8", "dns", now=now)
    add_home(conn, "45.9.20.1", "office", now=now)
    tokens = {
        "zz-ips": create_output(
            conn, OutputSpec("zz-ips", "ip", frozenset({"malicious"}), "high", 500, "csv")
        ),
        "aa-domains": create_output(
            conn,
            OutputSpec("aa-domains", "domain", frozenset({"phishing", "spam"}), "low", None, "rpz"),
        ),
    }
    return tokens


def test_export_has_every_section_in_order_with_database_values(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _seed(conn, now)
    doc = export_config(conn, now=now)
    assert list(doc) == [
        "threatcull_config",
        "exported_at",
        "settings",
        "catalog_sources",
        "custom_sources",
        "allowlist",
        "home_network",
        "outputs",
    ]
    assert doc["threatcull_config"] == CONFIG_VERSION == 1
    assert doc["settings"]["stale_after_hours"] == 72
    assert doc["catalog_sources"] == {"cat-a": True, "cat-b": False}
    assert doc["custom_sources"] == [
        {
            "id": "custom-mine",
            "name": "My feed",
            "url": "https://feeds.example/mine.txt",
            "format": "plain",
            "kind": "domain",
            "category": "phishing",
            "business_use": "unknown",
            "csv_column": 0,
            "json_keys": [],
            "enabled": False,  # custom Sources start disabled
        }
    ]
    assert doc["allowlist"] == [
        {"value": "8.8.8.8", "note": "dns"},
        {"value": "pay.example.com", "note": "payment provider"},
    ]
    assert doc["home_network"] == [{"value": "45.9.20.1", "note": "office", "origin": "manual"}]
    assert [o["name"] for o in doc["outputs"]] == ["aa-domains", "zz-ips"]
    assert doc["outputs"][0] == {
        "name": "aa-domains",
        "kind": "domain",
        "categories": ["phishing", "spam"],
        "min_tier": "low",
        "max_entries": None,
        "format": "rpz",
    }


def test_export_contains_no_passwords_tokens_or_secret_key(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    feed_tokens = _seed(conn, now)
    create_user(conn, "admin", "correct horse battery staple", now=now)
    api_token = create_api_token(conn, "script", "admin", now=now)
    hashes = [row[0] for row in conn.execute("SELECT feed_token_hash FROM outputs")]
    hashes += [row[0] for row in conn.execute("SELECT password_hash FROM users")]
    hashes += [row[0] for row in conn.execute("SELECT token_hash FROM api_tokens")]
    secret = (tmp_path / "secret.key").read_bytes() if (tmp_path / "secret.key").exists() else b""

    text = dump_config(conn, now=now)

    for forbidden in [*feed_tokens.values(), api_token, *hashes, "$argon2"]:
        assert forbidden not in text
    if secret:
        assert secret.hex() not in text
    parsed = yaml.safe_load(text)
    assert not {"password", "token", "feed_token", "feed_token_hash"} & _all_keys(parsed)


def _all_keys(node: object) -> set[str]:
    if isinstance(node, dict):
        return set(node) | {k for value in node.values() for k in _all_keys(value)}
    if isinstance(node, list):
        return {k for item in node for k in _all_keys(item)}
    return set()


def test_two_exports_of_the_same_state_differ_only_in_exported_at(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _seed(conn, now)
    first = dump_config(conn, now=now).splitlines()
    second = dump_config(conn, now=now + timedelta(hours=1)).splitlines()
    differing = [a for a, b in zip(first, second, strict=True) if a != b]
    assert len(differing) == 1
    assert differing[0].startswith("exported_at:")
    assert first[0].startswith("# ThreatCull configuration")


def test_cli_export_writes_a_private_file_or_prints_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = ["--data-dir", str(tmp_path / "data")]
    target = tmp_path / "backup.yaml"
    assert main([*data, "config", "export", "-o", str(target)]) == 0
    assert target.stat().st_mode & 0o777 == 0o600
    assert yaml.safe_load(target.read_text())["threatcull_config"] == 1
    capsys.readouterr()
    assert main([*data, "config", "export"]) == 0
    assert yaml.safe_load(capsys.readouterr().out)["threatcull_config"] == 1
