# SPDX-License-Identifier: AGPL-3.0-only
"""Review Focus 4: a Fetch that is still parsing must not hold the main write lock.

Real separate connections to the same database file: one thread runs a Fetch
whose parser blocks mid-stream; meanwhile an operator's Allowlist save on a
second connection must go through straight away.
"""

import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.factories import make_entry
from threatcull import fetching
from threatcull.clock import utcnow
from threatcull.fetcher import FetchResult
from threatcull.fetching import FetchOutcome, fetch_source
from threatcull.store.allowlist import add_entry, operator_entries
from threatcull.store.db import connect
from threatcull.store.sources import get_source, sync_catalog

WAIT = 10.0  # seconds; every wait is bounded
URL = "https://a.example/list.txt"


def _fetcher(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
    return FetchResult("ok", "unused: the parser is replaced\n")


def test_allowlist_save_succeeds_while_a_fetch_is_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "threatcull.db"
    setup = connect(db_path)
    sync_catalog(setup, [make_entry(id="a", url=URL, default_enabled=True)])
    setup.close()

    mid_stream = threading.Event()
    release = threading.Event()

    def blocking_parse(*args: object, **kwargs: object) -> Iterator[str]:
        yield "45.9.20.1"
        mid_stream.set()
        release.wait(WAIT)
        yield "45.9.20.2"

    monkeypatch.setattr(fetching, "parse", blocking_parse)
    outcome: list[FetchOutcome] = []

    def run_fetch() -> None:
        conn = connect(db_path)
        try:
            source = get_source(conn, "a")
            outcome.append(fetch_source(conn, source, _fetcher, now=utcnow()))
        finally:
            conn.close()

    thread = threading.Thread(target=run_fetch, daemon=True)
    thread.start()
    operator = connect(db_path)
    try:
        assert mid_stream.wait(WAIT)
        operator.execute("PRAGMA busy_timeout = 1000")
        started = time.monotonic()
        add_entry(operator, "45.9.21.7", "partner", now=utcnow())
        assert time.monotonic() - started < 1.0
        assert [entry.value for entry in operator_entries(operator)] == ["45.9.21.7"]
    finally:
        release.set()
        thread.join(WAIT)
        operator.close()
    assert not thread.is_alive()
    assert len(outcome) == 1
    assert outcome[0].status == "ok"
    assert outcome[0].valid == 2
