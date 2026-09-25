# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime

import pytest

from threatcull.clock import ts
from threatcull.store.errors import NotFoundError
from threatcull.store.outputs import (
    DEFAULT_OUTPUTS,
    OutputSpec,
    create_output,
    ensure_default_outputs,
    get_output,
    list_outputs,
    record_published,
    rotate_token,
    verify_token,
)


def test_default_outputs_are_created_once(conn: sqlite3.Connection) -> None:
    tokens = ensure_default_outputs(conn)
    assert set(tokens) == {spec.name for spec in DEFAULT_OUTPUTS}
    assert ensure_default_outputs(conn) == {}
    assert [o.name for o in list_outputs(conn)] == sorted(tokens)


def test_feed_tokens_are_stored_hashed_and_verified(conn: sqlite3.Connection) -> None:
    spec = OutputSpec("demo", "ip", frozenset({"malicious"}), "high", None, "plain")
    token = create_output(conn, spec)
    stored = conn.execute("SELECT feed_token_hash FROM outputs").fetchone()[0]
    assert token not in stored
    assert verify_token(conn, "demo", token)
    assert not verify_token(conn, "demo", "wrong")
    assert not verify_token(conn, "missing", token)


def test_rotate_token_invalidates_old_one(conn: sqlite3.Connection) -> None:
    old = create_output(conn, OutputSpec("demo", "ip", frozenset({"c2"}), "low", 10, "csv"))
    new = rotate_token(conn, "demo")
    assert verify_token(conn, "demo", new)
    assert not verify_token(conn, "demo", old)


def test_record_published(conn: sqlite3.Connection, now: datetime) -> None:
    create_output(conn, OutputSpec("demo", "domain", frozenset({"spam"}), "low", None, "rpz"))
    record_published(conn, "demo", 42, now=now)
    spec = get_output(conn, "demo")
    assert (spec.last_count, spec.last_published_at, spec.format) == (42, ts(now), "rpz")


def test_unknown_output(conn: sqlite3.Connection) -> None:
    with pytest.raises(NotFoundError):
        get_output(conn, "nope")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "Bad Name"},
        {"kind": "ip", "format": "hosts"},
        {"kind": "ip", "format": "rpz"},
        {"categories": frozenset()},
        {"max_entries": 0},
    ],
)
def test_output_spec_validation(kwargs: dict[str, object]) -> None:
    base: dict[str, object] = {
        "name": "ok",
        "kind": "domain",
        "categories": frozenset({"spam"}),
        "min_tier": "low",
        "max_entries": None,
        "format": "plain",
    }
    with pytest.raises(ValueError, match="Output"):
        OutputSpec(**{**base, **kwargs})  # type: ignore[arg-type]
