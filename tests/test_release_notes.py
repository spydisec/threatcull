# SPDX-License-Identifier: AGPL-3.0-only
"""scripts/release_notes.py: a changelog section as GitHub release notes."""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.release_notes import main, release_notes

from threatcull import __version__

CHANGELOG = """\
# Changelog

## [Unreleased]

## [9.9.9] - 2030-01-01

A summary that the changelog wraps
over two lines with `a command
split` across them.

### Upgrading

1. First step, which is long enough
   to wrap.
2. Second step.

### Added

- **One entry.** Its text wraps
  onto a second line.
- **Another entry.**

```bash
docker compose pull
docker compose up -d
```

| Column | Other |
|---|---|
| a | b |

> A quoted note.

## [9.9.8] - 2029-12-01

An older release.

[9.9.9]: https://example.test/compare
"""


def test_wrapped_paragraphs_and_list_items_become_one_line() -> None:
    assert release_notes(CHANGELOG, "9.9.9") == (
        "A summary that the changelog wraps over two lines with `a command split` across them.\n"
        "\n"
        "### Upgrading\n"
        "\n"
        "1. First step, which is long enough to wrap.\n"
        "2. Second step.\n"
        "\n"
        "### Added\n"
        "\n"
        "- **One entry.** Its text wraps onto a second line.\n"
        "- **Another entry.**\n"
        "\n"
        "```bash\n"
        "docker compose pull\n"
        "docker compose up -d\n"
        "```\n"
        "\n"
        "| Column | Other |\n"
        "|---|---|\n"
        "| a | b |\n"
        "\n"
        "> A quoted note."
    )


def test_a_section_stops_at_the_next_version() -> None:
    assert release_notes(CHANGELOG, "9.9.8") == "An older release."


def test_a_missing_version_gives_no_notes() -> None:
    assert not release_notes(CHANGELOG, "1.2.3")
    # "9.9" must not match "9.9.9".
    assert not release_notes(CHANGELOG, "9.9")


def test_the_command_prints_the_notes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(CHANGELOG, encoding="utf-8")

    assert main(["9.9.8", str(path)]) == 0
    assert capsys.readouterr().out == "An older release.\n"
    assert main(["1.2.3", str(path)]) == 0
    assert not capsys.readouterr().out


def test_the_real_changelog_has_notes_for_the_current_version() -> None:
    notes = release_notes(Path("CHANGELOG.md").read_text(encoding="utf-8"), __version__)

    assert notes
    # No list entry or paragraph is left wrapped: a continuation line would start with spaces.
    assert not [line for line in notes.splitlines() if line.startswith("  ")]
