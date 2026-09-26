# SPDX-License-Identifier: AGPL-3.0-only
"""Catalog updates between releases: download or upload a newer Catalog and apply it.

The update is saved as ``<data dir>/catalog.yaml``. Every start uses whichever
Catalog has the higher revision: the saved one or the one shipped with this
release, so a restart never falls back to an older Catalog and an upgrade to a
release with a newer Catalog takes over from the saved one.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import httpx

from threatcull.catalog import Catalog, CatalogError, parse_catalog, shipped_catalog
from threatcull.fetcher import DEFAULT_TIMEOUT, USER_AGENT, Fetcher, HttpFetcher
from threatcull.store.db import transaction
from threatcull.store.sources import sync_catalog

CATALOG_FILE = "catalog.yaml"
DEFAULT_CATALOG_URL = (
    "https://raw.githubusercontent.com/spydisec/threatcull/main/src/threatcull/catalog.yaml"
)
MAX_CATALOG_BYTES = 1024 * 1024  # the shipped Catalog is about 15 KiB

CatalogOrigin = Literal["shipped", "updated"]
_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ActiveCatalog:
    catalog: Catalog
    origin: CatalogOrigin


@dataclass(frozen=True, slots=True)
class UpdateReport:
    previous_revision: int
    revision: int
    added: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()

    @property
    def up_to_date(self) -> bool:
        return self.revision == self.previous_revision

    def summary(self) -> str:
        if self.up_to_date:
            return f"The Catalog is up to date (revision {self.revision})."
        parts = [
            f"{len(self.added)} new Source{'s' if len(self.added) != 1 else ''} (disabled)",
            f"{len(self.changed)} updated",
            f"{len(self.removed)} removed",
        ]
        return (
            f"Catalog updated from revision {self.previous_revision} to {self.revision}: "
            + ", ".join(parts)
            + "."
        )


def active_catalog(data_dir: Path) -> ActiveCatalog:
    """The Catalog to use: the saved update when its revision beats the shipped one."""
    shipped = shipped_catalog()
    saved = _saved_catalog(data_dir)
    if saved is not None and saved.revision > shipped.revision:
        return ActiveCatalog(saved, "updated")
    return ActiveCatalog(shipped, "shipped")


def apply_update(conn: sqlite3.Connection, data_dir: Path, text: str) -> UpdateReport:
    """Validate ``text`` as a Catalog update, save it and sync its Sources.

    Raises ``CatalogError`` (or pydantic's ``ValidationError``, also a ``ValueError``)
    for a malformed Catalog, one older than the Catalog in use, one that needs a
    newer ThreatCull or one with ``file://`` Sources. New Sources arrive disabled.
    """
    if len(text.encode("utf-8")) > MAX_CATALOG_BYTES:
        raise CatalogError(f"a Catalog update must be at most {MAX_CATALOG_BYTES} bytes")
    update = parse_catalog(text, allow_file_urls=False)
    current = active_catalog(data_dir).catalog
    if update.revision < current.revision:
        raise CatalogError(
            f"this Catalog (revision {update.revision}) is older than the one in use "
            f"(revision {current.revision})"
        )
    if update.revision == current.revision:
        return UpdateReport(current.revision, current.revision)
    old = {entry.id: entry for entry in current.entries}
    new = {entry.id: entry for entry in update.entries}
    report = UpdateReport(
        previous_revision=current.revision,
        revision=update.revision,
        added=tuple(sorted(new.keys() - old.keys())),
        changed=tuple(sorted(i for i in new.keys() & old.keys() if new[i] != old[i])),
        removed=tuple(sorted(old.keys() - new.keys())),
    )
    # Save first: if the sync fails, the next start syncs the saved file anyway.
    _save(data_dir, text)
    with transaction(conn):
        sync_catalog(conn, update.entries, enable_new=False)
    return report


def download_catalog(url: str = DEFAULT_CATALOG_URL, *, fetcher: Fetcher | None = None) -> str:
    """Download Catalog YAML over https (no retries, at most ``MAX_CATALOG_BYTES``)."""
    if not url.startswith("https://"):
        raise CatalogError("Catalog updates download over https:// only")
    if fetcher is not None:
        return _download(fetcher, url)
    with httpx.Client(
        timeout=DEFAULT_TIMEOUT, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    ) as client:
        return _download(HttpFetcher(client, max_bytes=MAX_CATALOG_BYTES, retry_delays=()), url)


def _download(fetcher: Fetcher, url: str) -> str:
    result = fetcher(url, etag=None, last_modified=None)
    if result.status != "ok":
        raise CatalogError(f"{url} returned no Catalog")
    return result.text


def _saved_catalog(data_dir: Path) -> Catalog | None:
    path = data_dir / CATALOG_FILE
    try:
        return parse_catalog(path.read_text(encoding="utf-8"), allow_file_urls=False)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:  # ValueError covers CatalogError and pydantic
        _log.warning("ignoring the saved Catalog %s: %s", path, exc)
        return None


def _save(data_dir: Path, text: str) -> None:
    """Write ``catalog.yaml`` atomically: a crash leaves the old file or the new one."""
    fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".catalog.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
        Path(tmp).replace(data_dir / CATALOG_FILE)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
