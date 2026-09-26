# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration export and import (YAML): settings, Source choices, lists, Outputs."""

import io
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from tests.factories import make_entry
from threatcull.cli import main
from threatcull.store.allowlist import add_entry
from threatcull.store.api_tokens import create_api_token
from threatcull.store.config import (
    CONFIG_VERSION,
    MAX_CONFIG_BYTES,
    ConfigError,
    apply_config,
    dump_config,
    export_config,
    parse_config,
)
from threatcull.store.db import connect
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
    add_entry(conn, "45.9.20.1", "office", mine=True, now=now)
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
        {"value": "45.9.20.1", "note": "office", "mine": True},
        {"value": "8.8.8.8", "note": "dns", "mine": False},
        {"value": "pay.example.com", "note": "payment provider", "mine": False},
    ]
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


# ---- import -------------------------------------------------------------------------


def _fresh(tmp_path: Path, name: str) -> sqlite3.Connection:
    conn = connect(tmp_path / f"{name}.db")
    sync_catalog(
        conn,
        [
            make_entry(id="cat-a", default_enabled=True),
            make_entry(id="cat-b", default_enabled=True),
        ],
    )
    return conn


def _without_exported_at(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.startswith("exported_at:")]


def test_import_round_trips_an_export_into_a_fresh_install(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _seed(conn, now)
    exported = dump_config(conn, now=now)
    other = _fresh(tmp_path, "other")
    try:
        result = apply_config(other, parse_config(exported.encode()), now=now)
        assert sorted(result.new_feed_tokens) == ["aa-domains", "zz-ips"]
        assert result.skipped == []
        assert _without_exported_at(dump_config(other, now=now)) == _without_exported_at(exported)
    finally:
        other.close()


def test_import_merges_lists_and_keeps_existing_notes(
    conn: sqlite3.Connection, now: datetime
) -> None:
    add_entry(conn, "pay.example.com", "keep", now=now)
    doc = parse_config(
        b"threatcull_config: 1\n"
        b"allowlist:\n"
        b"  - {value: pay.example.com, note: other}\n"
        b"  - {value: cdn.example.net, note: cdn}\n"
    )
    apply_config(conn, doc, now=now)
    notes = {e["value"]: e["note"] for e in export_config(conn, now=now)["allowlist"]}
    assert notes == {"pay.example.com": "keep", "cdn.example.net": "cdn"}


def test_import_skips_what_it_cannot_apply_and_applies_the_rest(
    conn: sqlite3.Connection, now: datetime
) -> None:
    sync_catalog(conn, [make_entry(id="cat-a", default_enabled=True)])
    create_output(conn, OutputSpec("ips", "ip", frozenset({"malicious"}), "high", None, "plain"))
    doc = parse_config(
        b"threatcull_config: 1\n"
        b"catalog_sources: {cat-a: false, gone-feed: true}\n"
        b"custom_sources:\n"
        b"  - {id: cat-a, name: Clash, url: 'https://x.example/l.txt', format: plain,\n"
        b"     kind: ip, category: malicious, business_use: unknown, csv_column: 0,\n"
        b"     json_keys: [], enabled: true}\n"
        b"allowlist:\n"
        b"  - {value: not a value, note: ''}\n"
        b"  - {value: 8.8.8.8, note: dns}\n"
        b"outputs:\n"
        b"  - {name: ips, kind: ip, categories: [malicious], min_tier: low, max_entries: null,\n"
        b"     format: plain}\n"
    )
    result = apply_config(conn, doc, now=now)
    skipped = "\n".join(result.skipped)
    assert "gone-feed: not in this Catalog" in skipped
    assert "cat-a: id belongs to a Catalog Source" in skipped
    assert "not a value" in skipped
    assert "ips: exists with a different definition" in skipped
    exported = export_config(conn, now=now)
    assert exported["catalog_sources"] == {"cat-a": False}
    assert exported["allowlist"] == [{"value": "8.8.8.8", "note": "dns", "mine": False}]


def test_import_updates_an_existing_custom_source(conn: sqlite3.Connection, now: datetime) -> None:
    _seed(conn, now)
    doc = parse_config(
        b"threatcull_config: 1\n"
        b"custom_sources:\n"
        b"  - {id: custom-mine, name: Renamed, url: 'https://feeds.example/new.txt',\n"
        b"     format: plain, kind: domain, category: spam, business_use: allowed,\n"
        b"     csv_column: 0, json_keys: [], enabled: true}\n"
    )
    apply_config(conn, doc, now=now)
    (mine,) = export_config(conn, now=now)["custom_sources"]
    assert (mine["name"], mine["url"], mine["category"], mine["enabled"]) == (
        "Renamed",
        "https://feeds.example/new.txt",
        "spam",
        True,
    )


def test_importing_an_enabled_restricted_source_counts_as_the_acknowledgement(
    conn: sqlite3.Connection, now: datetime
) -> None:
    sync_catalog(
        conn, [make_entry(id="strict", licence_class="restricted", business_use="unknown")]
    )
    result = apply_config(
        conn, parse_config(b"threatcull_config: 1\ncatalog_sources: {strict: true}\n"), now=now
    )
    assert export_config(conn, now=now)["catalog_sources"] == {"strict": True}
    assert any("restricted terms acknowledged" in line for line in result.applied)


def test_a_web_import_confines_file_urls(conn: sqlite3.Connection, now: datetime) -> None:
    doc = parse_config(
        b"threatcull_config: 1\n"
        b"custom_sources:\n"
        b"  - {id: custom-local, name: Local, url: 'file:///etc/passwd', format: plain,\n"
        b"     kind: ip, category: malicious, business_use: unknown, csv_column: 0,\n"
        b"     json_keys: [], enabled: false}\n"
    )
    result = apply_config(conn, doc, now=now, url_check=lambda url: "outside imports")
    assert any("custom-local: outside imports" in line for line in result.skipped)
    assert export_config(conn, now=now)["custom_sources"] == []


ALIAS_BOMB = b"threatcull_config: 1\n" + b"\n".join(
    [b'a0: &a0 ["x", "x"]'] + [f"a{i}: &a{i} [*a{i - 1}, *a{i - 1}]".encode() for i in range(1, 12)]
)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"threatcull_config: 2\n", "threatcull_config"),
        (b"threatcull_config: 1\nsurprise: true\n", "surprise"),
        (b"threatcull_config: 1\nsettings: {tier_high: 1, tier_medium: 2}\n", "tier"),
        (b"#" * (MAX_CONFIG_BYTES + 1), "larger than 1 MiB"),
        (b"\xff\xfe\x00", "not UTF-8"),
        (ALIAS_BOMB, "aliases"),
        (b'!!python/object/apply:os.system ["true"]\n', "not a valid"),
        (b"- a list\n", "mapping"),
        (b"threatcull_config: 1\noutputs:\n  - {name: x, kind: ip}\n", "outputs"),
    ],
    ids=[
        "version",
        "unknown-key",
        "bad-settings",
        "too-large",
        "not-utf8",
        "alias-bomb",
        "python-tag",
        "top-level-list",
        "missing-fields",
    ],
)
def test_a_refused_file_changes_nothing(
    conn: sqlite3.Connection, now: datetime, data: bytes, message: str
) -> None:
    _seed(conn, now)
    before = dump_config(conn, now=now)
    with pytest.raises(ConfigError, match=message):
        apply_config(conn, parse_config(data), now=now)
    assert dump_config(conn, now=now) == before


def test_cli_import_prints_what_it_did_from_a_file_or_stdin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    source = ["--data-dir", str(tmp_path / "a")]
    target = ["--data-dir", str(tmp_path / "b")]
    backup = tmp_path / "backup.yaml"
    assert main([*source, "allow", "add", "8.8.8.8", "--note", "dns"]) == 0
    assert main([*source, "config", "export", "-o", str(backup)]) == 0
    assert main([*target, "outputs", "list"]) == 0  # fresh install with default Outputs
    capsys.readouterr()

    assert main([*target, "config", "import", str(backup)]) == 0
    out = capsys.readouterr().out
    assert "added Allowlist entry 8.8.8.8" in out

    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(backup.read_bytes())))
    assert main([*target, "config", "import", "-"]) == 0
    assert "added Allowlist entry" not in capsys.readouterr().out  # already there now


def test_cli_import_of_a_refused_file_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("threatcull_config: 9\n")
    assert main(["--data-dir", str(tmp_path / "d"), "config", "import", str(bad)]) == 1
    assert "threatcull_config" in capsys.readouterr().err


# ---- final review fixes ------------------------------------------------------------------


def test_deeply_nested_yaml_is_refused_not_a_crash(conn: sqlite3.Connection, now: datetime) -> None:
    _seed(conn, now)
    before = dump_config(conn, now=now)
    with pytest.raises(ConfigError, match="nests too deeply"):
        parse_config(b"threatcull_config: 1\nsettings: " + b"[" * 200_000)
    assert dump_config(conn, now=now) == before


def test_a_name_listed_twice_in_the_file_is_skipped_not_a_crash(
    conn: sqlite3.Connection, now: datetime
) -> None:
    output = (
        b"  - {name: twice, kind: ip, categories: [malicious], min_tier: high,\n"
        b"     max_entries: null, format: plain}\n"
    )
    custom = (
        b"  - {id: custom-twice, name: T, url: 'https://t.example/l.txt', format: plain,\n"
        b"     kind: ip, category: malicious}\n"
    )
    doc = parse_config(
        b"threatcull_config: 1\noutputs:\n" + output * 2 + b"custom_sources:\n" + custom * 2
    )
    result = apply_config(conn, doc, now=now)
    assert list(result.new_feed_tokens) == ["twice"]
    assert "skipped Output twice: listed twice in the file" in result.skipped
    assert "skipped custom Source custom-twice: listed twice in the file" in result.skipped


@pytest.mark.parametrize(
    "setting",
    [
        "retention_days: 1000000",
        "active_window_days: 0",
        "stale_after_hours: 10000000",
        "tier_high: 1000",
    ],
)
def test_an_out_of_range_setting_is_refused(
    conn: sqlite3.Connection, now: datetime, setting: str
) -> None:
    with pytest.raises(ConfigError, match="settings"):
        apply_config(
            conn, parse_config(f"threatcull_config: 1\nsettings: {{{setting}}}\n".encode()), now=now
        )


# ---- issue #15 ---------------------------------------------------------------------------


def test_a_yaml_syntax_error_is_one_line_with_the_line_number() -> None:
    with pytest.raises(ConfigError) as caught:
        parse_config(b"threatcull_config: 1\nsettings: {tier_high: [3,\n")
    message = str(caught.value)
    assert "\n" not in message
    assert "line " in message


def test_cli_import_reads_at_most_the_size_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stream = io.BytesIO(b"#" * (5 * MAX_CONFIG_BYTES))
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(stream))
    assert main(["--data-dir", str(tmp_path / "d"), "config", "import", "-"]) == 1
    assert "larger than 1 MiB" in capsys.readouterr().err
    assert stream.tell() <= MAX_CONFIG_BYTES + 1


def test_a_pre_v1_1_home_network_section_imports_as_my_network(
    conn: sqlite3.Connection, now: datetime
) -> None:
    doc = parse_config(
        b"threatcull_config: 1\n"
        b"allowlist:\n  - {value: 45.9.20.1, note: office}\n"
        b"home_network:\n"
        b"  - {value: 45.9.20.1, note: office, origin: manual}\n"
        b"  - {value: shop.example.com, note: shop, origin: auto}\n"
    )
    result = apply_config(conn, doc, now=now)
    assert "added My network entry shop.example.com" in result.applied
    assert export_config(conn, now=now)["allowlist"] == [
        {"value": "45.9.20.1", "note": "office", "mine": True},
        {"value": "shop.example.com", "note": "shop", "mine": True},
    ]
