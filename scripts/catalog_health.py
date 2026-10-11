# SPDX-License-Identifier: AGPL-3.0-only
"""Check every Catalog Source once and keep a rolling health record (ADR-0010).

    catalog_health.py --state STATE.json --report REPORT.md [--run-url URL]
        Prints one line, ``problems=<n>``, for the workflow; exit 0 when the check ran.

Each Source is downloaded once with ThreatCull's own fetcher and parser. A Source is
dead after FAILURES_TO_REPORT failing runs in a row (download error, HTML page or no
valid entries), and a blocklist is frozen when its entry set has not changed for
FROZEN_AFTER_DAYS. The state between runs lives in STATE.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, fields
from datetime import date, timedelta
from pathlib import Path

import httpx

from threatcull.catalog import CatalogEntry, load_catalog
from threatcull.clock import utcnow
from threatcull.feedcheck import FeedProbe, probe_feed
from threatcull.fetcher import USER_AGENT, Fetcher, HttpFetcher

FAILURES_TO_REPORT = 2
FROZEN_AFTER_DAYS = 30
_DETAIL_MAX = 120


@dataclass
class Record:
    set_sha256: str = ""
    valid: int = 0
    last_changed: str | None = None
    last_ok: str | None = None
    failures: int = 0
    failing_since: str | None = None
    last_error: str | None = None


@dataclass(frozen=True)
class Problem:
    source_id: str
    name: str
    url: str
    problem: str  # "dead" or "frozen"
    since: str
    detail: str


def _failure(probe: FeedProbe) -> str | None:
    """Why ``probe`` counts as a failed run, or None when the feed is usable."""
    if probe.error:
        return probe.error
    if probe.html:
        return "HTML page, not a list"
    if probe.valid == 0:
        return f"0 valid entries ({probe.rejected} lines rejected)"
    return None


def _next(previous: Record | None, probe: FeedProbe, today: str) -> Record:
    prev = previous or Record()
    error = _failure(probe)
    if error is not None:
        return Record(
            set_sha256=prev.set_sha256,
            valid=prev.valid,
            last_changed=prev.last_changed,
            last_ok=prev.last_ok,
            failures=prev.failures + 1,
            failing_since=prev.failing_since if prev.failures else today,
            last_error=error,
        )
    changed = previous is None or prev.set_sha256 != probe.set_sha256 or not prev.last_changed
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
    if (
        entry.role == "blocklist"
        and record.failures == 0
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
    entries: Sequence[CatalogEntry], state: Mapping[str, Record], fetch: Fetcher, today: date
) -> tuple[dict[str, Record], list[Problem]]:
    """Probe every entry once; return the new state (Catalog Sources only) and the problems."""
    stamp = today.isoformat()
    new_state: dict[str, Record] = {}
    problems: list[Problem] = []
    for entry in entries:
        record = _next(state.get(entry.id), probe_feed(entry, fetch), stamp)
        new_state[entry.id] = record
        if (problem := _problem(entry, record, today)) is not None:
            problems.append(problem)
    return new_state, problems


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


def render(problems: Sequence[Problem], today: date, run_url: str) -> str:
    lines = [
        "The weekly check of every Source in `src/threatcull/catalog.yaml` found Sources",
        "that need attention. Dead: failing, an HTML page or no valid entries for",
        f"{FAILURES_TO_REPORT} runs in a row. Frozen: a blocklist whose entries have not",
        f"changed for {FROZEN_AFTER_DAYS} days or more.",
        "",
        "| Source | Problem | Since | Detail | Feed |",
        "| --- | --- | --- | --- | --- |",
    ]
    for p in sorted(problems, key=lambda p: (p.problem, p.source_id)):
        lines.append(
            f"| `{p.source_id}` | {p.problem} | {p.since} | {_cell(p.detail)} | {_cell(p.url)} |"
        )
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
    with httpx.Client(
        timeout=20, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    ) as client:
        state, problems = check(
            load_catalog(), load_state(args.state), HttpFetcher(client, retry_delays=()), today
        )
    save_state(args.state, state)
    args.report.write_text(render(problems, today, args.run_url), encoding="utf-8")
    print(f"problems={len(problems)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
