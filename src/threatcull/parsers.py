# SPDX-License-Identifier: AGPL-3.0-only
"""Parsers: turn a Source's raw text into candidate indicator strings.

The text is a ``str`` or a text stream (a download spooled to disk). Both are
read one line at a time, so a Source of millions of lines never sits in memory
as a list.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterator
from typing import Literal, TextIO

SourceFormat = Literal["plain", "hosts", "adblock", "csv", "json"]

_COMMENT_PREFIXES = ("#", ";", "//", "!")
_HOSTS_SKIP = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "0.0.0.0",  # noqa: S104 - hosts-file sink address, not a bind address
    }
)


# Runs of characters that are not line boundaries in the sense of str.splitlines().
_LINE = re.compile("[^\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]+")


class ParseError(ValueError):
    """The Source's content cannot be parsed at all (e.g. invalid JSON)."""


def parse(
    fmt: SourceFormat,
    text: str | TextIO,
    *,
    csv_column: int = 0,
    json_keys: tuple[str, ...] = (),
) -> Iterator[str]:
    """Yield candidate indicator strings from ``text`` in format ``fmt``."""
    if fmt == "plain":
        yield from _plain(text)
    elif fmt == "hosts":
        yield from _hosts(text)
    elif fmt == "adblock":
        yield from _adblock(text)
    elif fmt == "csv":
        yield from _csv(text, csv_column)
    else:
        yield from _json(text, json_keys)


def _stream(text: str | TextIO) -> TextIO:
    """A text stream over ``text``; newline="" keeps line endings for the splitting below."""
    return io.StringIO(text, newline="") if isinstance(text, str) else text


def _content_lines(text: str | TextIO) -> Iterator[str]:
    # Lazy equivalent of text.splitlines() (minus empty lines, which are skipped anyway):
    # a list of every line of a 70 MB Source would cost hundreds of MB. The stream
    # splits at \n, \r and \r\n; _LINE also splits the rarer boundaries splitlines() knows.
    for raw in _stream(text):
        for match in _LINE.finditer(raw):
            line = match.group().split("#", 1)[0].strip()
            if line and not line.startswith(_COMMENT_PREFIXES):
                yield line


def _plain(text: str | TextIO) -> Iterator[str]:
    for line in _content_lines(text):
        yield line.split()[0]


def _hosts(text: str | TextIO) -> Iterator[str]:
    for line in _content_lines(text):
        tokens = line.split()
        names = tokens[1:] if len(tokens) > 1 else tokens
        yield from (name for name in names if name.lower() not in _HOSTS_SKIP)


def _adblock(text: str | TextIO) -> Iterator[str]:
    for line in _content_lines(text):
        if not line.startswith("||"):
            continue
        rule = line[2:]
        caret = rule.find("^")
        host = rule[:caret] if caret != -1 else rule.split("$", 1)[0]
        if host and "/" not in host and "*" not in host:
            yield host


def _csv(text: str | TextIO, column: int) -> Iterator[str]:
    rows = csv.reader(_stream(text))
    while True:
        try:
            row = next(rows)
        except StopIteration:
            return
        except csv.Error as exc:
            raise ParseError(f"invalid CSV: {exc}") from exc
        if not row or row[0].lstrip().startswith("#"):
            continue
        if column < len(row):
            yield row[column].strip()


def _json(text: str | TextIO, keys: tuple[str, ...]) -> Iterator[str]:
    try:
        data = json.load(_stream(text))
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc
    except RecursionError as exc:
        raise ParseError("invalid JSON: nested too deeply") from exc
    if not isinstance(data, dict):
        raise ParseError("expected a JSON object at the top level")
    for key in keys:
        values = data.get(key, [])
        if not isinstance(values, list):
            raise ParseError(f"JSON key {key!r} does not hold a list")
        yield from (str(value) for value in values)
