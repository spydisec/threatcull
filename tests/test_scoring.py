# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime, timedelta

import pytest

from tests.factories import make_entry
from threatcull.indicators import Indicator
from threatcull.policy.scoring import scored_indicators, tier_for
from threatcull.store.settings import Settings
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import set_enabled, sync_catalog

IP = Indicator("1.2.3.4", "ip")
DOMAIN = Indicator("example.com", "domain")


def _seed(conn: sqlite3.Connection, now: datetime) -> None:
    sync_catalog(
        conn,
        [
            make_entry(id="a", url="https://a.example/1", default_enabled=True, category="c2"),
            make_entry(id="b1", url="https://b.example/1", family="bee", default_enabled=True),
            make_entry(id="b2", url="https://b.example/2", family="bee", default_enabled=True),
            make_entry(id="c", url="https://c.example/1", default_enabled=True),
            make_entry(
                id="d-domains", url="https://d.example/1", kind="domain", default_enabled=True
            ),
            make_entry(
                id="e-domains",
                url="https://e.example/1",
                kind="domain",
                default_enabled=True,
                category="phishing",
            ),
            make_entry(
                id="cdn",
                url="https://cdn.example/1",
                role="allowlist",
                category="infrastructure",
                business_use="unknown",
                default_enabled=True,
            ),
        ],
    )
    for source_id in ("a", "b1", "b2", "c", "cdn"):
        record_fetch_success(conn, source_id, {IP}, now=now, etag=None, last_modified=None)
    for source_id in ("d-domains", "e-domains"):
        record_fetch_success(conn, source_id, {DOMAIN}, now=now, etag=None, last_modified=None)


def _by_value(
    conn: sqlite3.Connection, now: datetime, settings: Settings | None = None
) -> dict[str, int]:
    scored = scored_indicators(conn, now=now, settings=settings or Settings())
    return {s.value: s.score for s in scored}


def test_score_counts_distinct_families_not_sources(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _seed(conn, now)
    scored = scored_indicators(conn, now=now, settings=Settings())
    (ip,) = [s for s in scored if s.kind == "ip"]
    assert ip.score == 3  # a, bee (b1+b2), c; the allowlist Source never scores
    assert ip.tier == "high"
    assert ip.source_ids == ("a", "b1", "b2", "c")
    assert ip.categories == frozenset({"c2", "malicious"})


def test_same_domain_from_two_sources_scores_two(conn: sqlite3.Connection, now: datetime) -> None:
    _seed(conn, now)
    assert _by_value(conn, now)["example.com"] == 2


def test_disabled_sources_do_not_count(conn: sqlite3.Connection, now: datetime) -> None:
    _seed(conn, now)
    set_enabled(conn, "a", False)
    assert _by_value(conn, now)["1.2.3.4"] == 2


def test_stale_sources_do_not_count(conn: sqlite3.Connection, now: datetime) -> None:
    _seed(conn, now)
    assert _by_value(conn, now + timedelta(hours=73)) == {}


def test_sightings_outside_active_window_do_not_count(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _seed(conn, now)
    record_fetch_success(
        conn,
        "c",
        {Indicator("5.6.7.8", "ip")},
        now=now + timedelta(days=8),
        etag=None,
        last_modified=None,
    )
    later = now + timedelta(days=8)
    settings = Settings(stale_after_hours=24 * 30)
    assert _by_value(conn, later, settings) == {"5.6.7.8": 1}


def test_value_filter(conn: sqlite3.Connection, now: datetime) -> None:
    _seed(conn, now)
    (only,) = scored_indicators(conn, now=now, settings=Settings(), value="example.com")
    assert only.value == "example.com"


@pytest.mark.parametrize(
    ("score", "tier"), [(0, None), (1, "low"), (2, "medium"), (3, "high"), (9, "high")]
)
def test_tier_for(score: int, tier: str | None) -> None:
    assert tier_for(score, Settings()) == tier
