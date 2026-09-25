# SPDX-License-Identifier: AGPL-3.0-only
"""Parsing an uploaded txt/csv list and importing it into the Allowlist or Home Network."""

import sqlite3
from datetime import datetime

import pytest

from threatcull.listfile import MAX_BYTES, MAX_ENTRIES, ListLine, parse_list_file
from threatcull.store.allowlist import add_entry, import_entries, operator_entries
from threatcull.store.home import home_entries, import_home


def test_plain_text_one_value_per_line_with_comments_and_notes() -> None:
    data = b"# my list\n\n1.2.3.4\nexample.com  # payment provider\n   \n"
    assert parse_list_file(data) == [
        ListLine(3, "1.2.3.4", ""),
        ListLine(4, "example.com", "payment provider"),
    ]


def test_csv_value_and_note_columns_with_header_and_quotes() -> None:
    data = b'value,note\n8.8.8.8,dns\n"cdn.example.com","our CDN, eu"\n10.0.0.0/8\n'
    assert parse_list_file(data) == [
        ListLine(2, "8.8.8.8", "dns"),
        ListLine(3, "cdn.example.com", "our CDN, eu"),
        ListLine(4, "10.0.0.0/8", ""),
    ]


def test_utf8_bom_and_windows_line_endings_are_accepted() -> None:
    assert parse_list_file("﻿1.2.3.4\r\nexample.com\r\n".encode()) == [
        ListLine(1, "1.2.3.4", ""),
        ListLine(2, "example.com", ""),
    ]


def test_non_utf8_file_is_refused() -> None:
    with pytest.raises(ValueError, match="UTF-8"):
        parse_list_file(b"\xff\xfe1\x002\x00")


def test_file_over_the_size_limit_is_refused() -> None:
    with pytest.raises(ValueError, match="larger than"):
        parse_list_file(b"a" * (MAX_BYTES + 1))


def test_file_with_too_many_entries_is_refused() -> None:
    data = "".join(f"host{i}.example.com\n" for i in range(MAX_ENTRIES + 1)).encode()
    with pytest.raises(ValueError, match="more than"):
        parse_list_file(data)


def test_import_adds_new_values_keeps_existing_and_reports_invalid_lines(
    conn: sqlite3.Connection, now: datetime
) -> None:
    add_entry(conn, "8.8.8.8", "keep this note", now=now)
    lines = parse_list_file(b"8.8.8.8\npay.example.com,payments\nnot a value\n10.0.0.1\n")

    report = import_entries(conn, lines, now=now)

    assert report.added == 1
    assert report.existing == 1
    assert [(bad.line, bad.value) for bad in report.invalid] == [
        (3, "not a value"),
        (4, "10.0.0.1"),
    ]
    assert {(e.value, e.note) for e in operator_entries(conn)} == {
        ("8.8.8.8", "keep this note"),
        ("pay.example.com", "payments"),
    }


def test_import_counts_a_value_repeated_in_the_file_once(
    conn: sqlite3.Connection, now: datetime
) -> None:
    report = import_entries(conn, parse_list_file(b"1.1.1.1\n1.1.1.1\n"), now=now)
    assert (report.added, report.existing) == (1, 1)
    assert len(operator_entries(conn)) == 1


def test_home_import_explains_private_addresses(conn: sqlite3.Connection, now: datetime) -> None:
    report = import_home(conn, parse_list_file(b"45.9.20.1\n192.168.1.10\n"), now=now)
    assert report.added == 1
    assert [bad.value for bad in report.invalid] == ["192.168.1.10"]
    assert "no Home Network entry is needed" in report.invalid[0].reason
    assert all(entry.origin == "manual" for entry in home_entries(conn))
