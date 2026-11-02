# SPDX-License-Identifier: AGPL-3.0-only
"""scripts/catalog_request.py: Catalog suggestions from the issue form."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from threatcull.catalog import parse_catalog, shipped_catalog
from threatcull.fetcher import FetchError, FetchResult

ROOT = Path(__file__).resolve().parent.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "catalog_request", ROOT / "scripts" / "catalog_request.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["catalog_request"] = module
    spec.loader.exec_module(module)
    return module


cr = _load()

BODY = """### Source name

Example Security bad IPs (30 days)

### Feed URL

https://feeds.example/bad-ips.txt

### List type

Blocklist

### Contains

IPs and CIDRs

### Format

plain

### Category

Scanners

### Update frequency

Daily

### Notes

_No response_
"""


def _fetch(text: str = "45.9.20.1\n45.9.20.2\nnot-an-ip\n192.168.1.1\n") -> object:
    def fetch(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        return FetchResult("ok", text)

    return fetch


def test_parse_form_reads_every_field_and_drops_no_response() -> None:
    fields = cr.parse_form(BODY)
    assert fields["Source name"] == "Example Security bad IPs (30 days)"
    assert fields["Update frequency"] == "Daily"
    assert fields["Notes"] == ""


def test_build_entry_maps_the_form_to_a_disabled_catalog_entry() -> None:
    request = cr.build_request(cr.parse_form(BODY), shipped_catalog())
    assert request.problems == []
    entry = request.entry
    assert entry is not None
    assert (entry.id, entry.role, entry.kind, entry.category) == (
        "example-security-bad-ips-30-days",
        "blocklist",
        "ip",
        "scanner",
    )
    assert (entry.refresh_minutes, entry.default_enabled) == (1440, False)


@pytest.mark.parametrize(
    ("heading", "value", "problem"),
    [
        ("Feed URL", "http://feeds.example/x.txt", "Feed URL must start with https://"),
        ("Source name", "Bad\u0007name", "control characters"),
        ("Format", "xml", "Format"),
    ],
)
def test_build_entry_reports_bad_fields(heading: str, value: str, problem: str) -> None:
    fields = cr.parse_form(BODY)
    fields[heading] = value
    request = cr.build_request(fields, shipped_catalog())
    assert request.entry is None
    assert any(problem in p for p in request.problems), request.problems


def test_duplicates_of_listed_sources_are_refused() -> None:
    listed = shipped_catalog().entries[0]
    fields = cr.parse_form(BODY)
    fields["Feed URL"] = listed.url
    request = cr.build_request(fields, shipped_catalog())
    assert any("already in the Catalog" in p for p in request.problems)


def test_probe_feed_counts_what_threatcull_would_keep() -> None:
    entry = cr.build_request(cr.parse_form(BODY), shipped_catalog()).entry
    probe = cr.probe_feed(entry, _fetch())
    assert (probe.valid, probe.rejected, probe.error) == (2, 2, None)
    empty = cr.probe_feed(entry, _fetch("<html>not a list</html>\n"))
    assert empty.valid == 0

    def down(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        raise FetchError("ConnectError")

    assert cr.probe_feed(entry, down).error == "ConnectError"


def test_report_marks_a_usable_request_valid() -> None:
    request = cr.build_request(cr.parse_form(BODY), shipped_catalog())
    probe = cr.probe_feed(request.entry, _fetch())
    report = cr.report(request, probe)
    assert report.valid
    assert "2 entries ThreatCull would keep" in report.markdown
    assert "id: example-security-bad-ips-30-days" in report.markdown
    assert cr.MARKER in report.markdown
    broken = cr.report(request, cr.FeedProbe(0, 5, None))
    assert not broken.valid
    assert "no usable entries" in broken.markdown


def test_apply_adds_the_entry_and_raises_the_revision(tmp_path: Path) -> None:
    catalog_yaml = tmp_path / "catalog.yaml"
    catalog_yaml.write_text(
        (ROOT / "src" / "threatcull" / "catalog.yaml").read_text(encoding="utf-8")
    )
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## [Unreleased]\n\n## [1.0.0] - 2026-01-01\n")
    request = cr.build_request(cr.parse_form(BODY), shipped_catalog())

    cr.apply(request.entry, catalog_yaml, changelog, issue=42)

    updated = parse_catalog(catalog_yaml.read_text(encoding="utf-8"))
    assert updated.revision == shipped_catalog().revision + 1
    assert updated.entries[-1].role == "allowlist"  # blocklists go before the allowlist block
    added = next(e for e in updated.entries if e.id == "example-security-bad-ips-30-days")
    assert added == request.entry
    text = changelog.read_text(encoding="utf-8")
    assert "### Added" in text
    assert "Example Security bad IPs (30 days).** An IP blocklist" in text
    assert "[#42](https://github.com/spydisec/threatcull/issues/42)" in text


def test_same_publisher_is_noted_for_the_family() -> None:
    listed = next(e for e in shipped_catalog().entries if e.id == "blocklist-de-all")
    fields = cr.parse_form(BODY)
    fields["Feed URL"] = "https://lists.blocklist.de/lists/ssh.txt"
    request = cr.build_request(fields, shipped_catalog())
    assert request.problems == []
    assert request.notes == [
        f"Same publisher as `blocklist-de-all`: if the lists overlap, give this one "
        f"`family: {listed.family}` so they count once in the score."
    ]
    probe = cr.probe_feed(request.entry, _fetch())
    assert "Same publisher as `blocklist-de-all`" in cr.report(request, probe).markdown


def test_the_feed_is_probed_even_when_other_fields_need_fixing() -> None:
    fields = cr.parse_form(BODY)
    fields["Category"] = "Everything"
    request = cr.build_request(fields, shipped_catalog())
    assert request.entry is None
    assert request.feed is not None  # URL, format and contents were fine
    probe = cr.probe_feed(request.feed, _fetch())
    markdown = cr.report(request, probe).markdown
    assert "2 entries ThreatCull would keep" in markdown
    assert "Category: 'Everything' is not one of" in markdown


def test_licence_fields_from_old_forms_are_ignored() -> None:
    body = BODY + "\n### Licence\n\nnull\n\n### Licence link\n\nnull\n"
    request = cr.build_request(cr.parse_form(body), shipped_catalog())
    assert request.problems == []
    assert request.entry is not None


def test_report_explains_an_html_page() -> None:
    request = cr.build_request(cr.parse_form(BODY), shipped_catalog())
    probe = cr.probe_feed(request.entry, _fetch("<html>not a list</html>\n"))
    assert probe.html is True
    report = cr.report(request, probe)
    assert report.valid is False
    assert "HTML page" in report.markdown


def test_report_says_a_feed_that_downloaded_but_did_not_parse() -> None:
    request = cr.build_request(cr.parse_form(BODY), shipped_catalog())
    probe = cr.FeedProbe(0, 0, None, parse_error="invalid JSON: Expecting value")
    report = cr.report(request, probe)
    assert report.valid is False
    assert "downloaded but could not be read as" in report.markdown
    assert "could not be downloaded" not in report.markdown
