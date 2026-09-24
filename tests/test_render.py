# SPDX-License-Identifier: AGPL-3.0-only
import csv
import io
import json
from dataclasses import replace

import pytest

from threatcull.outputs.render import Attribution, RenderContext, render
from threatcull.policy.scoring import ScoredIndicator

ITEMS = [
    ScoredIndicator(
        "evil.example.com",
        "domain",
        3,
        "high",
        ("src-a", "src-b", "src-c"),
        frozenset({"malicious"}),
        "2026-09-20T00:00:00+00:00",
        "2026-09-24T11:00:00+00:00",
    ),
    ScoredIndicator(
        "bad.example.net",
        "domain",
        1,
        "low",
        ("src-a",),
        frozenset({"phishing"}),
        "2026-09-23T00:00:00+00:00",
        "2026-09-24T10:00:00+00:00",
    ),
]
CTX = RenderContext(
    output_name="demo",
    generated_at="2026-09-24T12:00:00+00:00",
    attributions=(
        Attribution("Source A", "CC0", "https://a.example/licence"),
        Attribution("Source B", "MIT", "https://b.example/licence"),
    ),
    source_names={"src-a": "Source A", "src-b": "Source B", "src-c": "Source C"},
)


def _header(prefix: str) -> str:
    return (
        f"{prefix} ThreatCull output: demo\n"
        f"{prefix} Generated: 2026-09-24T12:00:00+00:00\n"
        f"{prefix} Entries: 2\n"
        f"{prefix} Sources (each under its own terms):\n"
        f"{prefix}   - Source A | CC0 | https://a.example/licence\n"
        f"{prefix}   - Source B | MIT | https://b.example/licence\n"
    )


def test_plain() -> None:
    assert render("plain", ITEMS, CTX) == _header("#") + "evil.example.com\nbad.example.net\n"


def test_hosts() -> None:
    expected = _header("#") + "0.0.0.0 evil.example.com\n0.0.0.0 bad.example.net\n"
    assert render("hosts", ITEMS, CTX) == expected


def test_adguard() -> None:
    expected = _header("!") + "||evil.example.com^\n||bad.example.net^\n"
    assert render("adguard", ITEMS, CTX) == expected


def test_rpz() -> None:
    expected = _header(";") + (
        "$TTL 300\n"
        "@ IN SOA localhost. hostmaster.localhost. 1790251200 3600 600 86400 300\n"
        "@ IN NS localhost.\n"
        "evil.example.com CNAME .\n"
        "*.evil.example.com CNAME .\n"
        "bad.example.net CNAME .\n"
        "*.bad.example.net CNAME .\n"
    )
    assert render("rpz", ITEMS, CTX) == expected


def test_csv() -> None:
    rows = list(csv.reader(io.StringIO(render("csv", ITEMS, CTX))))
    assert rows[0] == ["indicator", "kind", "score", "tier", "sources", "first_seen", "last_seen"]
    assert rows[1] == [
        "evil.example.com",
        "domain",
        "3",
        "high",
        "Source A;Source B;Source C",
        "2026-09-20T00:00:00+00:00",
        "2026-09-24T11:00:00+00:00",
    ]
    assert len(rows) == 3


def test_json() -> None:
    doc = json.loads(render("json", ITEMS, CTX))
    assert (doc["output"], doc["generated_at"], doc["count"]) == ("demo", CTX.generated_at, 2)
    assert doc["attribution"][0] == {
        "name": "Source A",
        "licence": "CC0",
        "licence_url": "https://a.example/licence",
    }
    assert doc["indicators"][1] == {
        "indicator": "bad.example.net",
        "kind": "domain",
        "score": 1,
        "tier": "low",
        "sources": ["Source A"],
        "first_seen": "2026-09-23T00:00:00+00:00",
        "last_seen": "2026-09-24T10:00:00+00:00",
    }


def test_empty_plain_output_is_just_the_header() -> None:
    assert render("plain", [], CTX).splitlines()[2] == "# Entries: 0"


@pytest.mark.parametrize("items", [ITEMS, ITEMS[:1], []])
def test_json_is_byte_identical_to_one_json_dumps(items: list[ScoredIndicator]) -> None:
    doc = json.loads(render("json", items, CTX))
    assert render("json", items, CTX) == json.dumps(doc, indent=2) + "\n"


def test_csv_quotes_like_the_csv_module() -> None:
    odd = replace(ITEMS[1], source_ids=("src-x",))
    ctx = replace(CTX, source_names={"src-x": 'Quoted, "odd" name'})
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerow(
        [
            odd.value,
            odd.kind,
            odd.score,
            odd.tier,
            'Quoted, "odd" name',
            odd.first_seen,
            odd.last_seen,
        ]
    )
    assert render("csv", [odd], ctx).splitlines(keepends=True)[1] == buffer.getvalue()
