# SPDX-License-Identifier: AGPL-3.0-only
from threatcull.outputs.select import select
from threatcull.policy.scoring import ScoredIndicator
from threatcull.store.outputs import OutputSpec


def _s(
    value: str,
    score: int,
    tier: str,
    *,
    kind: str = "ip",
    cats: str = "malicious",
    last_seen: str = "2026-09-24T00:00:00+00:00",
) -> ScoredIndicator:
    return ScoredIndicator(
        value,
        kind,  # type: ignore[arg-type]
        score,
        tier,  # type: ignore[arg-type]
        ("x",),
        frozenset(cats.split(",")),
        "2026-09-01T00:00:00+00:00",
        last_seen,
    )


ITEMS = [
    _s("1.1.1.1", 1, "low"),
    _s("2.2.2.2", 3, "high", last_seen="2026-09-20T00:00:00+00:00"),
    _s("3.3.3.3", 3, "high"),
    _s("4.4.4.0/24", 2, "medium", kind="cidr"),
    _s("5.5.5.5", 5, "high", cats="spam"),
    _s("evil.example.com", 3, "high", kind="domain"),
]


def test_filters_by_kind_tier_and_category_and_ranks() -> None:
    spec = OutputSpec("ip-medium", "ip", frozenset({"malicious", "c2"}), "medium", None, "plain")
    # 4.4.4.0/24 qualifies by Tier and category, but ranges never reach an Output.
    assert [s.value for s in select(ITEMS, spec)] == ["3.3.3.3", "2.2.2.2"]


def test_cap_keeps_the_strongest() -> None:
    spec = OutputSpec("ip-top", "ip", frozenset({"malicious"}), "low", 2, "plain")
    assert [s.value for s in select(ITEMS, spec)] == ["3.3.3.3", "2.2.2.2"]


def test_domain_outputs_take_domains_only() -> None:
    spec = OutputSpec("d", "domain", frozenset({"malicious"}), "low", None, "hosts")
    assert [s.value for s in select(ITEMS, spec)] == ["evil.example.com"]


def test_ties_are_broken_by_value_for_determinism() -> None:
    same = [_s("9.9.9.9", 1, "low"), _s("8.8.8.8", 1, "low")]
    spec = OutputSpec("t", "ip", frozenset({"malicious"}), "low", None, "plain")
    assert [s.value for s in select(same, spec)] == ["8.8.8.8", "9.9.9.9"]
