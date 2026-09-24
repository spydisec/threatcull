# SPDX-License-Identifier: AGPL-3.0-only
"""Parsers: turn a Source's raw text into candidate indicator strings."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from typing import Literal

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
        "0.0.0.0",  # noqa: S104  # nosec B104 - hosts-file sink address, not a bind address
    }
)


class ParseError(ValueError):
    """The Source's content cannot be parsed at all (e.g. invalid JSON)."""


def parse(
    fmt: SourceFormat,
    text: str,
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


def _content_lines(text: str) -> Iterator[str]:
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line and not line.startswith(_COMMENT_PREFIXES):
            yield line


def _plain(text: str) -> Iterator[str]:
    for line in _content_lines(text):
        yield line.split()[0]


def _hosts(text: str) -> Iterator[str]:
    for line in _content_lines(text):
        tokens = line.split()
        names = tokens[1:] if len(tokens) > 1 else tokens
        yield from (name for name in names if name.lower() not in _HOSTS_SKIP)


def _adblock(text: str) -> Iterator[str]:
    for line in _content_lines(text):
        if not line.startswith("||"):
            continue
        rule = line[2:]
        caret = rule.find("^")
        host = rule[:caret] if caret != -1 else rule.split("$", 1)[0]
        if host and "/" not in host and "*" not in host:
            yield host


def _csv(text: str, column: int) -> Iterator[str]:
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].lstrip().startswith("#"):
            continue
        if column < len(row):
            yield row[column].strip()


def _json(text: str, keys: tuple[str, ...]) -> Iterator[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError("expected a JSON object at the top level")
    for key in keys:
        values = data.get(key, [])
        if not isinstance(values, list):
            raise ParseError(f"JSON key {key!r} does not hold a list")
        yield from (str(value) for value in values)
