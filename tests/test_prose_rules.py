# SPDX-License-Identifier: AGPL-3.0-only
"""The repo's Vale rules catch AI-slop patterns and leave plain technical prose alone."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytestmark = [
    pytest.mark.skipif(shutil.which("uvx") is None, reason="needs uvx to run Vale"),
    pytest.mark.skipif(
        not (ROOT / ".vale" / "styles" / "write-good").is_dir(),
        reason="Vale packages not synced; run `uvx vale sync` (CI does)",
    ),
]


def _alerts(tmp_path: Path, text: str) -> set[str]:
    doc = tmp_path / "sample.md"
    doc.write_text(text, encoding="utf-8")
    result = subprocess.run(  # noqa: S603 - fixed argv, test-only
        ["uvx", "vale", "--config", str(ROOT / ".vale.ini"), "--output", "JSON", str(doc)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    data = json.loads(result.stdout or "{}")
    return {alert["Check"] for alerts in data.values() for alert in alerts}


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("Here's the thing: blocklists overlap.\n", "ThreatCull.Slop"),
        ("Let that sink in.\n", "ThreatCull.Slop"),
        ("The implications are significant.\n", "ThreatCull.Slop"),
        ("We did a deep dive into feeds.\n", "ThreatCull.Jargon"),
        ("Moving forward, we fetch hourly.\n", "ThreatCull.Jargon"),
        ("It really works.\n", "ThreatCull.Adverbs"),
        ("Scoring is fast — very fast.\n", "ThreatCull.EmDash"),
        ("The problem isn't volume. It's noise.\n", "ThreatCull.Contrast"),
        ("Not because feeds are bad, but because they overlap.\n", "ThreatCull.Contrast"),
    ],
)
def test_rule_fires(tmp_path: Path, text: str, rule: str) -> None:
    assert rule in _alerts(tmp_path, text)


def test_plain_technical_prose_passes(tmp_path: Path) -> None:
    text = (
        "ThreatCull fetches each Source on its own schedule and never redistributes the data.\n"
        "An Output is published only when the Shrink Guard passes.\n"
    )
    checks = _alerts(tmp_path, text)
    assert not {c for c in checks if c.startswith("ThreatCull.")}
