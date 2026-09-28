# SPDX-License-Identifier: AGPL-3.0-only
"""Check a Catalog suggestion from the issue form, and apply an approved one.

    catalog_request.py validate --body-file BODY --report REPORT.md
        Exit 0 when the suggestion is usable, 2 when it needs changes.
    catalog_request.py apply --body-file BODY --issue N
        Add the entry to catalog.yaml, raise the revision, add a CHANGELOG line.

The issue body is untrusted input: it is parsed as data, validated against the
Catalog schema, and only written to catalog.yaml through yaml.safe_dump.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml
from pydantic import ValidationError

from threatcull.catalog import Catalog, CatalogEntry, shipped_catalog
from threatcull.fetcher import USER_AGENT, Fetcher, FetchError, HttpFetcher
from threatcull.indicators import SourceKind, normalize
from threatcull.parsers import SourceFormat, parse
from threatcull.web.dashboard import CATEGORY_LABELS

ROOT = Path(__file__).resolve().parent.parent
CATALOG_YAML = ROOT / "src" / "threatcull" / "catalog.yaml"
CHANGELOG = ROOT / "CHANGELOG.md"
MARKER = "<!-- catalog-request-bot -->"
MAX_FEED_BYTES = 8 * 1024 * 1024
ALLOWLIST_BLOCK = "  # -------------------------------------------- Built-in Allowlist"

_ROLES = {"Blocklist": "blocklist", "Allowlist": "allowlist"}
_KINDS = {"IPs and CIDRs": "ip", "Domains": "domain"}
_CATEGORIES = {label: slug for slug, label in CATEGORY_LABELS.items()}
_REFRESH = {"Hourly": 60, "Daily": 1440, "Weekly": 10080}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class Feed:
    """What probe_feed needs: enough to download and parse a list."""

    url: str
    format: SourceFormat
    kind: SourceKind
    csv_column: int = 0
    json_keys: tuple[str, ...] = ()


@dataclass
class Request:
    fields: dict[str, str]
    entry: CatalogEntry | None = None
    feed: Feed | None = None  # set whenever the feed itself can be checked
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FeedProbe:
    valid: int
    rejected: int
    error: str | None


@dataclass(frozen=True)
class Report:
    valid: bool
    markdown: str


def parse_form(body: str) -> dict[str, str]:
    """Issue-form markdown (``### Label`` then the answer) to {label: answer}."""
    fields: dict[str, str] = {}
    label: str | None = None
    lines: list[str] = []
    for line in [*body.replace("\r\n", "\n").split("\n"), "### "]:
        if line.startswith("### "):
            if label is not None:
                value = "\n".join(lines).strip()
                fields[label] = "" if value == "_No response_" else value
            label, lines = line[4:].strip(), []
        elif label is not None:
            lines.append(line)
    return fields


def build_request(fields: dict[str, str], catalog: Catalog) -> Request:
    request = Request(fields)
    get = fields.get
    name, url = get("Source name", ""), get("Feed URL", "")
    for label in ("Source name", "Feed URL"):
        if _CONTROL.search(get(label, "")):
            request.problems.append(f"{label} contains control characters.")
    if not url.startswith("https://"):
        request.problems.append("Feed URL must start with https://.")
    choices: dict[str, dict[str, Any]] = {
        "List type": _ROLES,
        "Contains": _KINDS,
        "Category": _CATEGORIES,
        "Update frequency": _REFRESH,
        "Format": {f: f for f in ("plain", "hosts", "adblock", "csv", "json")},
    }
    picked: dict[str, Any] = {}
    for label, options in choices.items():
        value = get(label, "")
        if value not in options:
            request.problems.append(f"{label}: '{value}' is not one of {', '.join(options)}.")
        picked[label] = options.get(value)
    source_id = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60].strip("-")
    host = urlparse(url).hostname
    for listed in catalog.entries:
        if listed.url == url or listed.id == source_id:
            request.problems.append(f"This Source is already in the Catalog as `{listed.id}`.")
        elif host and urlparse(listed.url).hostname == host:
            request.notes.append(
                f"Same publisher as `{listed.id}`: if the lists overlap, give this one "
                f"`family: {listed.family}` so they count once in the score."
            )
    if (
        url.startswith("https://")
        and not _CONTROL.search(url)
        and picked["Format"]
        and picked["Contains"]
    ):
        request.feed = Feed(url, picked["Format"], picked["Contains"])
    if request.problems:
        return request
    try:
        request.entry = CatalogEntry.model_validate(
            {
                "id": source_id,
                "name": name,
                "url": url,
                "format": picked["Format"],
                "kind": picked["Contains"],
                "role": picked["List type"],
                "category": picked["Category"],
                "refresh_minutes": picked["Update frequency"],
            }
        )
    except ValidationError as exc:
        for error in exc.errors():
            where = ".".join(str(part) for part in error["loc"])
            request.problems.append(f"{where}: {error['msg']}.")
    return request


def probe_feed(entry: Feed | CatalogEntry, fetch: Fetcher) -> FeedProbe:
    """Download the feed once and count what ThreatCull would keep from it."""
    try:
        result = fetch(entry.url, etag=None, last_modified=None)
    except FetchError as exc:
        return FeedProbe(0, 0, str(exc))
    valid = rejected = 0
    for raw in parse(
        entry.format, result.text, csv_column=entry.csv_column, json_keys=entry.json_keys
    ):
        if normalize(raw, entry.kind) is None:
            rejected += 1
        else:
            valid += 1
    return FeedProbe(valid, rejected, None)


def entry_yaml(entry: CatalogEntry) -> str:
    data = entry.model_dump(mode="json", exclude={"notes", "json_keys", "csv_column"})
    if entry.json_keys:
        data["json_keys"] = list(entry.json_keys)
    if entry.format == "csv":
        data["csv_column"] = entry.csv_column
    if data.get("family") == data["id"]:
        del data["family"]
    text = yaml.safe_dump([data], sort_keys=False, allow_unicode=True, width=100)
    return "".join(f"  {line}" if line.strip() else line for line in text.splitlines(True))


def report(request: Request, probe: FeedProbe | None) -> Report:
    lines = [MARKER, "### Catalog check", ""]
    problems = list(request.problems)
    if probe is not None:
        if probe.error:
            problems.append(f"The feed could not be downloaded: `{_code(probe.error)}`.")
        elif probe.valid == 0:
            problems.append(
                f"The feed has no usable entries ({probe.rejected} lines rejected). "
                "Check the URL points at the raw list and the Format and Contains fields."
            )
        else:
            lines.append(
                f"- ✅ Feed downloaded: **{probe.valid} entries ThreatCull would keep**, "
                f"{probe.rejected} lines rejected (comments, private or invalid values)."
            )
    lines += [f"- ❌ {problem}" for problem in problems]
    lines += [f"- 💡 {note}" for note in dict.fromkeys(request.notes)]
    valid = not problems and request.entry is not None
    if valid and request.entry is not None:
        lines += [
            "",
            "Looks usable. A maintainer reviews the list and adds the `approved` label; a pull",
            "request with this entry follows.",
            "",
            "```yaml",
            entry_yaml(request.entry).rstrip(),
            "```",
        ]
    else:
        lines += ["", "Edit the issue to fix the points above; this check runs again."]
    return Report(valid, "\n".join(lines) + "\n")


def apply(entry: CatalogEntry, catalog_yaml: Path, changelog: Path, *, issue: int) -> None:
    """Add ``entry`` to catalog.yaml, raise the revision, and note it in CHANGELOG.md."""
    text = catalog_yaml.read_text(encoding="utf-8")
    block = entry_yaml(entry)
    if entry.role == "blocklist" and ALLOWLIST_BLOCK in text:
        text = text.replace(ALLOWLIST_BLOCK, block + "\n" + ALLOWLIST_BLOCK, 1)
    else:
        text = text.rstrip("\n") + "\n\n" + block
    text, count = re.subn(
        r"^revision: (\d+)$",
        lambda m: f"revision: {int(m.group(1)) + 1}",
        text,
        count=1,
        flags=re.M,
    )
    if count != 1:
        raise SystemExit("catalog.yaml has no 'revision:' line")
    catalog_yaml.write_text(text, encoding="utf-8")

    note = (
        f"- 🆕 **New Catalog Source: {entry.name}.** "
        f"{'An IP' if entry.kind == 'ip' else 'A domain'} {entry.role} "
        f"(`{entry.id}`), disabled until you enable it. "
        f"[#{issue}](https://github.com/spydisec/threatcull/issues/{issue})\n"
    )
    log = changelog.read_text(encoding="utf-8")
    head, marker, rest = log.partition("## [Unreleased]\n")
    if not marker:
        raise SystemExit("CHANGELOG.md has no '## [Unreleased]' section")
    section, next_release, tail = rest.partition("\n## [")
    if "### Added\n" in section:
        section = section.replace("### Added\n\n", "### Added\n\n" + note, 1)
    else:
        section = "\n### Added\n\n" + note + section
    changelog.write_text(head + marker + section + next_release + tail, encoding="utf-8")


def _code(value: str) -> str:
    return value.replace("`", "'")[:300]


def _fetcher(client: httpx.Client) -> Fetcher:
    return HttpFetcher(client, max_bytes=MAX_FEED_BYTES, retry_delays=())


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["validate", "apply"])
    parser.add_argument("--body-file", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--issue", type=int, default=0)
    args = parser.parse_args(argv)
    request = build_request(
        parse_form(args.body_file.read_text(encoding="utf-8")), shipped_catalog()
    )
    if args.action == "apply":
        if request.entry is None:
            print("\n".join(request.problems), file=sys.stderr)
            return 2
        apply(request.entry, CATALOG_YAML, CHANGELOG, issue=args.issue)
        print(json.dumps({"id": request.entry.id, "name": request.entry.name}))
        return 0
    with httpx.Client(
        timeout=20, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    ) as client:
        probe = probe_feed(request.feed, _fetcher(client)) if request.feed else None
        result = report(request, probe)
    if args.report:
        args.report.write_text(result.markdown, encoding="utf-8")
    print(result.markdown)
    return 0 if result.valid else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
