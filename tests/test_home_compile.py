# SPDX-License-Identifier: AGPL-3.0-only
"""Home Network entries are excluded from every Output and raise listing alerts."""

import sqlite3
from datetime import datetime
from pathlib import Path

from tests.factories import make_entry
from threatcull.compiling import HOME_HITS_CAP, compile_outputs
from threatcull.indicators import Indicator
from threatcull.lookup import lookup
from threatcull.store.allowlist import add_entry
from threatcull.store.home import add_home
from threatcull.store.outputs import OutputSpec, create_output
from threatcull.store.runs import last_run
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import sync_catalog

IPS = {Indicator(f"45.9.20.{i}", "ip") for i in range(1, 11)}
DOMAINS = {
    Indicator("example.com", "domain"),
    Indicator("a.home.example.com", "domain"),
    Indicator("bad.example.net", "domain"),
}


def _setup(conn: sqlite3.Connection, now: datetime) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="a", url="https://a.example/1", default_enabled=True, name="A"),
            make_entry(id="b", url="https://b.example/1", default_enabled=True, name="B"),
            make_entry(
                id="d", url="https://d.example/1", default_enabled=True, name="D", kind="domain"
            ),
        ],
    )
    malicious = frozenset({"malicious"})
    create_output(conn, OutputSpec("ips", "ip", malicious, "low", None, "plain"))
    create_output(conn, OutputSpec("ips-csv", "ip", malicious, "low", None, "csv"))
    create_output(conn, OutputSpec("doms", "domain", malicious, "low", None, "plain"))
    record_fetch_success(conn, "a", IPS, now=now, etag=None, last_modified=None)
    record_fetch_success(
        conn,
        "b",
        {Indicator("45.9.20.3", "ip"), Indicator("45.9.0.0/16", "cidr")},
        now=now,
        etag=None,
        last_modified=None,
    )
    record_fetch_success(conn, "d", DOMAINS, now=now, etag=None, last_modified=None)


def _published(out: Path) -> set[str]:
    """Every published Indicator value, across all Outputs (comments and CSV header skipped)."""
    values: set[str] = set()
    for path in out.iterdir():
        for line in path.read_text().splitlines():
            if line and not line.startswith(("#", "indicator,")):
                values.add(line.split(",", 1)[0])
    return values


def test_home_entries_are_excluded_from_every_output(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    add_home(conn, "45.9.20.3", "office", now=now)
    add_home(conn, "home.example.com", now=now)
    report = compile_outputs(conn, tmp_path / "out", now=now)
    published = _published(tmp_path / "out")
    assert "45.9.20.3" not in published  # the Home Network IP itself
    assert "45.9.0.0/16" not in published  # a CIDR overlapping it
    assert "example.com" not in published  # a parent domain
    assert "a.home.example.com" not in published  # a subdomain
    assert {"45.9.20.4", "bad.example.net"} <= published
    assert report.counts == {"ips": 9, "ips-csv": 9, "doms": 1}
    assert report.home_hits == (
        ("45.9.0.0/16", "b"),
        ("45.9.20.3", "a,b"),
        ("a.home.example.com", "d"),
        ("example.com", "d"),
    )
    assert report.home_hit_count == 4


def test_home_hits_are_recorded_on_the_run(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    add_home(conn, "45.9.20.3", now=now)
    compile_outputs(conn, tmp_path / "out", now=now)
    run = last_run(conn, "compile")
    assert run is not None
    assert run.counts["home_hits"] == 2
    assert run.home_hits == (("45.9.0.0/16", "b"), ("45.9.20.3", "a,b"))


def test_allowlist_exclusions_are_not_home_hits(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    add_entry(conn, "45.9.20.4", "partner", now=now)
    report = compile_outputs(conn, tmp_path / "out", now=now)
    assert report.home_hits == ()
    assert report.home_hit_count == 0
    run = last_run(conn, "compile")
    assert run is not None
    assert "home_hits" not in run.counts
    assert run.home_hits == ()


def test_home_hits_are_capped(conn: sqlite3.Connection, now: datetime, tmp_path: Path) -> None:
    _setup(conn, now)
    many = {Indicator(f"45.9.{i // 200}.{i % 200 + 1}", "ip") for i in range(150)}
    record_fetch_success(conn, "a", many, now=now, etag=None, last_modified=None)
    add_home(conn, "45.9.0.0/16", now=now)
    report = compile_outputs(conn, tmp_path / "out", now=now)
    assert report.home_hit_count == 152  # 150 IPs, the /16 itself and 45.9.20.3 from b
    assert len(report.home_hits) == HOME_HITS_CAP == 100
    run = last_run(conn, "compile")
    assert run is not None
    assert run.counts["home_hits"] == 152
    assert len(run.home_hits) == 100


def test_lookup_names_the_home_network(conn: sqlite3.Connection, now: datetime) -> None:
    _setup(conn, now)
    add_entry(conn, "45.9.20.0/24", "partner", now=now)
    add_home(conn, "45.9.20.3", "office", now=now)
    result = lookup(conn, "45.9.20.3", now=now)
    assert result is not None
    assert result.allowlisted_by is not None
    assert result.allowlisted_by.note == "Home Network: office"
    assert result.eligible_outputs == ()
