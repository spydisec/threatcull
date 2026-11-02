# SPDX-License-Identifier: AGPL-3.0-only
"""Check every Catalog Source once and keep a rolling health record (ADR-0010).

    catalog_health.py --state STATE.json --report REPORT.md [--run-url URL]
        Prints ``problems=<n>`` and ``skipped=<n>`` for the workflow; exit 0 when the
        check ran.

Each Source is downloaded once with ThreatCull's own fetcher and parser. A Source is
dead after FAILURES_TO_REPORT failing runs in a row (download error, parse error, HTML
page or no valid entries), counting at most one failure per FAILURE_SPACING_DAYS so a
re-run or an extra manual run in the same week does not count twice. A blocklist is
frozen when its entry set has not changed for FROZEN_AFTER_DAYS. The state between runs
lives in STATE.json.

Each download gets at most SOURCE_SECONDS, and the run stops starting new downloads
after RUN_SECONDS: Sources it did not reach keep their previous record and are named in
the report, so a slow feed never costs the whole run its saved state.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, fields, replace
from datetime import date, timedelta
from pathlib import Path

import httpx

from threatcull.catalog import CatalogEntry, load_catalog
from threatcull.clock import utcnow
from threatcull.feedcheck import FeedProbe, probe_feed
from threatcull.fetcher import USER_AGENT, Fetcher, HttpFetcher

FAILURES_TO_REPORT = 2
# A failure counts only this many days after the last counted one: a weekly schedule
# counts every run, a re-run or an extra manual run in the same week does not.
FAILURE_SPACING_DAYS = 6
FROZEN_AFTER_DAYS = 30
# One download, redirects included in each request's own budget; the job's
# timeout-minutes (20) must stay above RUN_SECONDS plus one SOURCE_SECONDS plus setup.
SOURCE_SECONDS = 120
RUN_SECONDS = 12 * 60
_DETAIL_MAX = 120

__all__ = ["DeadlineTransport", "FeedProbe", "HttpFetcher", "probe_feed"]


@dataclass
class Record:
    set_sha256: str = ""
    valid: int = 0
    last_changed: str | None = None
    last_ok: str | None = None
    failures: int = 0
    failing_since: str | None = None
    last_error: str | None = None
    last_failure_counted: str | None = None


@dataclass(frozen=True)
class Problem:
    source_id: str
    name: str
    url: str
    problem: str  # "dead" or "frozen"
    since: str
    detail: str


class _DeadlineStream(httpx.SyncByteStream):
    def __init__(
        self,
        inner: httpx.SyncByteStream,
        deadline: float,
        seconds: float,
        request: httpx.Request,
        clock: Callable[[], float],
    ) -> None:
        self._inner = inner
        self._deadline = deadline
        self._seconds = seconds
        self._request = request
        self._clock = clock

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._inner:
            if self._clock() > self._deadline:
                raise httpx.ReadTimeout(
                    f"download took longer than {self._seconds:g} s", request=self._request
                )
            yield chunk

    def close(self) -> None:
        self._inner.close()


class DeadlineTransport(httpx.BaseTransport):
    """Fail a response whose body takes longer than ``seconds`` in total.

    httpx's own timeouts limit each read, so a server sending a byte every few
    seconds never trips them. The overrun surfaces as ``httpx.ReadTimeout``, which
    ``HttpFetcher`` reports as a ``FetchError`` like any other transport failure.
    """

    def __init__(
        self,
        inner: httpx.BaseTransport,
        seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._inner = inner
        self._seconds = seconds
        self._clock = clock

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        deadline = self._clock() + self._seconds
        response = self._inner.handle_request(request)
        stream = response.stream
        if isinstance(stream, httpx.SyncByteStream):
            response.stream = _DeadlineStream(stream, deadline, self._seconds, request, self._clock)
        return response

    def close(self) -> None:
        self._inner.close()


def _next(previous: Record | None, probe: FeedProbe, today: str) -> Record:
    prev = previous or Record()
    found = probe.problem
    if found is not None:
        counted = prev.last_failure_counted
        counts = counted is None or date.fromisoformat(today) >= date.fromisoformat(
            counted
        ) + timedelta(days=FAILURE_SPACING_DAYS)
        # replace() keeps every other field, including any added later.
        return replace(
            prev,
            failures=prev.failures + 1 if counts else prev.failures,
            failing_since=prev.failing_since if prev.failures else today,
            last_error=found[1],
            last_failure_counted=today if counts else counted,
        )
    changed = prev.set_sha256 != probe.set_sha256 or not prev.last_changed
    return Record(
        set_sha256=probe.set_sha256,
        valid=probe.valid,
        last_changed=today if changed else prev.last_changed,
        last_ok=today,
    )


def _problem(entry: CatalogEntry, record: Record, today: date) -> Problem | None:
    if record.failures >= FAILURES_TO_REPORT:
        return Problem(
            entry.id,
            entry.name,
            entry.url,
            "dead",
            record.failing_since or today.isoformat(),
            record.last_error or "",
        )
    # Not dead (checked above): a frozen blocklist stays listed through a single failed
    # run, so the issue doesn't close and reopen when a frozen feed has one bad week.
    if (
        entry.role == "blocklist"
        and record.last_changed is not None
        and date.fromisoformat(record.last_changed) <= today - timedelta(days=FROZEN_AFTER_DAYS)
    ):
        return Problem(
            entry.id,
            entry.name,
            entry.url,
            "frozen",
            record.last_changed,
            f"{record.valid} valid entries, unchanged",
        )
    return None


def check(
    entries: Sequence[CatalogEntry],
    state: Mapping[str, Record],
    fetch: Fetcher,
    today: date,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Record], list[Problem], list[str]]:
    """Probe every entry once.

    Returns the new state (Catalog Sources only), the problems, and the ids of the
    Sources not probed because ``clock()`` passed ``deadline``: those keep their
    previous record, and a problem it already shows is still reported.
    """
    stamp = today.isoformat()
    new_state: dict[str, Record] = {}
    problems: list[Problem] = []
    skipped: list[str] = []
    for entry in entries:
        previous = state.get(entry.id)
        if deadline is not None and clock() > deadline:
            skipped.append(entry.id)
            if previous is None:
                continue
            record = previous
        else:
            try:
                probe = probe_feed(entry, fetch)
            except Exception as exc:
                # One broken Source must not stop the check or the state of all the others.
                probe = FeedProbe(0, 0, f"{type(exc).__name__}: {exc}")
            record = _next(previous, probe, stamp)
        new_state[entry.id] = record
        if (problem := _problem(entry, record, today)) is not None:
            problems.append(problem)
    return new_state, problems, skipped


def load_state(path: Path) -> dict[str, Record]:
    if not path.exists():
        return {}
    known = {f.name for f in fields(Record)}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {
        source_id: Record(**{k: v for k, v in values.items() if k in known})
        for source_id, values in raw.items()
    }


def save_state(path: Path, state: Mapping[str, Record]) -> None:
    data = {source_id: asdict(state[source_id]) for source_id in sorted(state)}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _cell(text: str) -> str:
    """One Markdown table cell: no line breaks, pipes or backticks from remote text."""
    flat = " ".join(text.split()).replace("|", "/").replace("`", "'")
    return flat if len(flat) <= _DETAIL_MAX else flat[: _DETAIL_MAX - 3] + "..."


def render(
    problems: Sequence[Problem], today: date, run_url: str, *, skipped: Sequence[str] = ()
) -> str:
    lines = [
        "The Catalog health check of every Source in `src/threatcull/catalog.yaml` found",
        "Sources that need attention. Dead: a download or parse error, an HTML page or no",
        f"valid entries for {FAILURES_TO_REPORT} runs in a row. Frozen: a blocklist whose",
        f"entries have not changed for {FROZEN_AFTER_DAYS} days or more.",
        "",
        "| Source | Problem | Since | Detail | Feed |",
        "| --- | --- | --- | --- | --- |",
    ]
    for p in sorted(problems, key=lambda p: (p.problem, p.source_id)):
        detail = f"`{_cell(p.detail)}`" if p.detail else ""
        lines.append(
            f"| {_cell(p.name)}<br>`{p.source_id}` | {p.problem} | {p.since} | {detail} "
            f"| {_cell(p.url)} |"
        )
    if skipped:
        names = ", ".join(f"`{source_id}`" for source_id in skipped)
        lines += ["", f"Not checked this run (out of time), previous result kept: {names}."]
    checked = f"Checked {today.isoformat()}"
    lines += ["", f"{checked} by [this run]({run_url})." if run_url else f"{checked}."]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--run-url", default="")
    args = parser.parse_args(argv)
    today = utcnow().date()
    deadline = time.monotonic() + RUN_SECONDS
    transport = DeadlineTransport(httpx.HTTPTransport(), SOURCE_SECONDS)
    with httpx.Client(
        timeout=20, follow_redirects=True, headers={"User-Agent": USER_AGENT}, transport=transport
    ) as client:
        # spool=True: big lists go to a temporary file and parse line by line.
        fetch = HttpFetcher(client, retry_delays=(), spool=True)
        state, problems, skipped = check(
            load_catalog(), load_state(args.state), fetch, today, deadline=deadline
        )
    save_state(args.state, state)
    args.report.write_text(render(problems, today, args.run_url, skipped=skipped), encoding="utf-8")
    print(f"problems={len(problems)}")
    print(f"skipped={len(skipped)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
