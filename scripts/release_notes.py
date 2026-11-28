# SPDX-License-Identifier: AGPL-3.0-only
"""Print one version's section of CHANGELOG.md as GitHub release notes.

Usage:
    python scripts/release_notes.py X.Y.Z [CHANGELOG.md]

CHANGELOG.md wraps its lines, and GitHub shows every line break in a release's notes
as a real line break. This joins each wrapped paragraph and list item into one line,
so the release page reads like the changelog does. Headings, blank lines, tables,
block quotes and fenced code blocks pass through unchanged.

Prints nothing when the changelog has no ``## [X.Y.Z]`` section: the Release workflow
then keeps the notes written in the GitHub Release UI. Standard library only, so the
workflow can run it before installing anything.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_LIST_ITEM = re.compile(r"\s*([-*+]|\d+[.)])\s")
_STANDALONE = ("#", "|", ">")
_LINK_REFERENCE = re.compile(r"\[[^\]]+\]: ")
_FENCE = "```"


def section(changelog: str, version: str) -> list[str]:
    """The lines under ``## [version]``, up to the next version's heading."""
    lines: list[str] = []
    found = False
    for line in changelog.splitlines():
        if line.startswith(f"## [{version}]"):
            found = True
        elif found and (line.startswith("## [") or _LINK_REFERENCE.match(line)):
            break  # the next version, or the compare links at the end of the file
        elif found:
            lines.append(line)
    return lines


def unwrap(lines: list[str]) -> str:
    """Join wrapped paragraphs and list items; keep everything else as written."""
    out: list[str] = []
    current: str | None = None
    fenced = False

    def flush() -> None:
        nonlocal current
        if current is not None:
            out.append(current)
            current = None

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(_FENCE):
            flush()
            fenced = not fenced
            out.append(line)
        elif fenced:
            out.append(line)
        elif not stripped:
            flush()
            out.append("")
        elif stripped.startswith(_STANDALONE):
            flush()
            out.append(line)
        elif _LIST_ITEM.match(line):
            flush()
            current = line.rstrip()
        elif current is None:
            current = stripped
        else:
            current = f"{current} {stripped}"
    flush()
    text = "\n".join(out).strip("\n")
    return re.sub(r"\n{3,}", "\n\n", text)


def release_notes(changelog: str, version: str) -> str:
    return unwrap(section(changelog, version))


def main(argv: list[str]) -> int:
    if len(argv) not in {1, 2}:
        print(__doc__, file=sys.stderr)
        return 2
    path = Path(argv[1]) if len(argv) == 2 else Path("CHANGELOG.md")  # noqa: PLR2004
    notes = release_notes(path.read_text(encoding="utf-8"), argv[0])
    if notes:
        print(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
