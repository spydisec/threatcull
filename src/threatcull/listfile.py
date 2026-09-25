# SPDX-License-Identifier: AGPL-3.0-only
"""Uploaded list files (txt or csv) for bulk-adding Allowlist and Home Network entries.

A line is either ``value`` with an optional ``# note``, or csv ``value,note``. Blank
lines and lines starting with ``#`` are skipped, and so is a first ``value`` header row.
"""

from __future__ import annotations

import csv
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from threatcull.indicators import Indicator

MAX_BYTES = 1024 * 1024
MAX_ENTRIES = 10_000


@dataclass(frozen=True, slots=True)
class ListLine:
    line: int
    value: str
    note: str


@dataclass(frozen=True, slots=True)
class InvalidLine:
    line: int
    value: str
    reason: str


@dataclass(slots=True)
class ImportReport:
    added: int = 0
    existing: int = 0
    invalid: list[InvalidLine] = field(default_factory=list)


def parse_list_file(data: bytes) -> list[ListLine]:
    """Split an uploaded file into values; raises ``ValueError`` for a file we refuse."""
    if len(data) > MAX_BYTES:
        raise ValueError(f"the file is larger than {MAX_BYTES // 1024} KiB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("the file is not UTF-8 text") from exc

    lines: list[ListLine] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "," in stripped:
            cells = [cell.strip() for cell in next(csv.reader([stripped]))]
            value, note = cells[0], (cells[1] if len(cells) > 1 else "")
        else:
            value, _, note = (part.strip() for part in stripped.partition("#"))
        if not lines and value.lower() == "value":
            continue
        lines.append(ListLine(number, value, note))
        if len(lines) > MAX_ENTRIES:
            raise ValueError(f"the file has more than {MAX_ENTRIES:,} entries")
    return lines


def apply_lines(
    lines: Iterable[ListLine],
    *,
    normalize: Callable[[str], Indicator],
    existing: set[str],
    insert: Callable[[str, str], object],
) -> ImportReport:
    """Insert each new value, leave values already present untouched (their notes too),
    and collect the lines ``normalize`` rejects."""
    report = ImportReport()
    for item in lines:
        try:
            value = normalize(item.value).value
        except ValueError as exc:
            report.invalid.append(InvalidLine(item.line, item.value, str(exc)))
            continue
        if value in existing:
            report.existing += 1
            continue
        insert(item.value, item.note)
        existing.add(value)
        report.added += 1
    return report


def _entries(count: int) -> str:
    return f"{count:,} new {'entry' if count == 1 else 'entries'}"


def summary(report: ImportReport, *, shown: int = 5) -> str:
    """One-paragraph result for the web UI, naming the first ``shown`` skipped lines."""
    text = f"Imported {_entries(report.added)}, {report.existing:,} already present."
    if report.invalid:
        count = len(report.invalid)
        skipped = "; ".join(f"line {bad.line} ({bad.value[:60]})" for bad in report.invalid[:shown])
        more = f"; and {count - shown:,} more" if count > shown else ""
        text += f" {count:,} line{'' if count == 1 else 's'} skipped: {skipped}{more}."
    return text


def report_lines(report: ImportReport) -> list[str]:
    """The CLI's result: a count line, then one line per skipped value with its reason."""
    head = f"imported {_entries(report.added)}, {report.existing:,} already present"
    return [head] + [f"line {bad.line}: {bad.value!r}: {bad.reason}" for bad in report.invalid]
