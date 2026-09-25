# SPDX-License-Identifier: AGPL-3.0-only
"""The streamed Compile writes exactly what the in-memory select + render would."""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from tests.factories import make_entry
from threatcull.clock import ts
from threatcull.compiling import compile_outputs
from threatcull.indicators import Indicator
from threatcull.outputs.files import output_path
from threatcull.outputs.render import Attribution, RenderContext, render
from threatcull.outputs.select import select
from threatcull.policy.allowlist import Allowlist
from threatcull.policy.scoring import scored_indicators
from threatcull.store.allowlist import add_entry, builtin_entries, operator_entries
from threatcull.store.outputs import OutputSpec, create_output, list_outputs
from threatcull.store.settings import load_settings
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import list_sources, sync_catalog

SPECS = (
    OutputSpec("ip-plain", "ip", frozenset({"malicious", "c2"}), "low", None, "plain"),
    OutputSpec("ip-csv", "ip", frozenset({"malicious"}), "low", 4, "csv"),
    OutputSpec("ip-json", "ip", frozenset({"c2", "scanner"}), "medium", None, "json"),
    OutputSpec("ip-empty", "ip", frozenset({"scanner"}), "high", None, "json"),
    OutputSpec("dom-hosts", "domain", frozenset({"malicious", "phishing"}), "low", None, "hosts"),
    OutputSpec("dom-adguard", "domain", frozenset({"phishing"}), "medium", None, "adguard"),
    OutputSpec("dom-rpz", "domain", frozenset({"malicious", "spam"}), "low", 3, "rpz"),
    OutputSpec("dom-json", "domain", frozenset({"spam", "phishing"}), "low", 2, "json"),
    OutputSpec("dom-csv", "domain", frozenset({"malicious"}), "high", None, "csv"),
)


def _ips(*values: str) -> list[Indicator]:
    return [Indicator(v, "cidr" if "/" in v else "ip") for v in values]


def _domains(*values: str) -> list[Indicator]:
    return [Indicator(v, "domain") for v in values]


def _seed(conn: sqlite3.Connection, now: datetime) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="ip-a", url="https://a.example/1", name="IP A", default_enabled=True),
            make_entry(
                id="ip-b",
                url="https://b.example/1",
                name="IP B",
                category="c2",
                licence="MIT",
                default_enabled=True,
            ),
            make_entry(
                id="ip-a2",
                url="https://a.example/2",
                family="ip-a",
                name="IP A two",
                default_enabled=True,
            ),
            make_entry(
                id="dom-c",
                url="https://c.example/1",
                name="Domains C",
                kind="domain",
                category="phishing",
                default_enabled=True,
            ),
            make_entry(
                id="dom-d",
                url="https://d.example/1",
                name="Domains D",
                kind="domain",
                default_enabled=True,
            ),
            make_entry(
                id="dom-e",
                url="https://e.example/1",
                name="Domains E",
                kind="domain",
                category="spam",
                default_enabled=True,
            ),
            make_entry(
                id="dom-f",
                url="https://f.example/1",
                name="Domains F",
                kind="domain",
                default_enabled=True,
            ),
            make_entry(
                id="cdn",
                url="https://cdn.example/1",
                name="CDN ranges",
                role="allowlist",
                category="infrastructure",
                business_use="unknown",
                default_enabled=True,
            ),
        ],
    )
    fetches = [
        ("ip-a", _ips("45.9.20.1", "45.9.20.2", "45.9.20.3", "45.9.21.0/24", "81.2.69.1"), 3),
        ("ip-a2", _ips("45.9.20.1", "45.9.20.4", "104.16.1.1"), 2),
        ("ip-b", _ips("45.9.20.1", "45.9.20.2", "45.9.20.5", "81.2.69.1", "104.16.0.0/12"), 1),
        ("dom-c", _domains("evil.test", "phish.test", "bad.partner.test", "zz.test"), 3),
        ("dom-d", _domains("evil.test", "malware.test", "bad.partner.test", "aa.test"), 2),
        ("dom-e", _domains("spam.test", "evil.test", "zz.test", "aa.test"), 1),
        ("dom-f", _domains("evil.test", "phish.test", "mm.test"), 0),
        ("cdn", _ips("104.16.0.0/13"), 0),
    ]
    for source_id, indicators, hours_ago in fetches:
        record_fetch_success(
            conn,
            source_id,
            indicators,
            now=now - timedelta(hours=hours_ago),
            etag=None,
            last_modified=None,
        )
    add_entry(conn, "45.9.20.1", "top-ranked partner IP", now=now)
    add_entry(conn, "partner.test", "partner domains", now=now)
    for spec in SPECS:
        create_output(conn, spec)


def _expected(conn: sqlite3.Connection, now: datetime, out_dir: Path) -> dict[Path, str]:
    settings = load_settings(conn)
    allowlist = Allowlist([*operator_entries(conn), *builtin_entries(conn)])
    kept = [
        item
        for item in scored_indicators(conn, now=now, settings=settings)
        if allowlist.match(item.value, item.kind) is None
    ]
    sources = {source.id: source for source in list_sources(conn)}
    expected: dict[Path, str] = {}
    for spec in list_outputs(conn):
        items = select(kept, spec)
        contributing = sorted(
            {sid for item in items for sid in item.source_ids}, key=lambda s: sources[s].name
        )
        ctx = RenderContext(
            output_name=spec.name,
            generated_at=ts(now),
            attributions=tuple(
                Attribution(sources[s].name, sources[s].licence, sources[s].licence_url)
                for s in contributing
            ),
            source_names={s.id: s.name for s in sources.values()},
        )
        expected[output_path(out_dir, spec)] = render(spec.format, items, ctx)
    return expected


def test_streamed_compile_matches_in_memory_render(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    out_dir = tmp_path / "outputs"
    _seed(conn, now)
    expected = _expected(conn, now, out_dir)

    report = compile_outputs(conn, out_dir, now=now)

    assert report.status == "ok"
    assert report.allowlisted == 4  # 45.9.20.1, 104.16.1.1, 104.16.0.0/12, bad.partner.test
    for path, text in expected.items():
        assert path.read_text(encoding="utf-8") == text, path.name
    assert report.counts["ip-csv"] == 4
    assert report.counts["ip-empty"] == 0
    assert sorted(p.name for p in out_dir.iterdir()) == sorted(p.name for p in expected)
