# SPDX-License-Identifier: AGPL-3.0-only
"""The Catalog: curated Source definitions with licence evidence."""

from __future__ import annotations

from collections import Counter
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from threatcull.indicators import SourceKind
from threatcull.parsers import SourceFormat

Category = Literal[
    "malicious", "c2", "scanner", "phishing", "spam", "ads_tracking", "infrastructure"
]
SourceRole = Literal["blocklist", "allowlist"]
SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}$"


class LicenceClass(StrEnum):
    """What a Source's terms allow for redistribution."""

    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    NONCOMMERCIAL = "noncommercial"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class BusinessUse(StrEnum):
    """Whether a business may use a Source to protect its own network."""

    ALLOWED = "allowed"
    FORBIDDEN = "forbidden"
    UNKNOWN = "unknown"


class CatalogError(ValueError):
    """The Catalog file is malformed."""


class CatalogEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=SLUG_PATTERN)
    name: str = Field(min_length=1)
    family: str = Field(pattern=SLUG_PATTERN)
    url: str = Field(pattern=r"^(https?://|file://)")
    format: SourceFormat
    kind: SourceKind
    role: SourceRole = "blocklist"
    category: Category
    licence_class: LicenceClass
    business_use: BusinessUse
    licence: str = Field(min_length=1)
    licence_url: str = Field(pattern=r"^https?://")
    refresh_minutes: int = Field(ge=15, le=10080)
    default_enabled: bool = False
    csv_column: int = Field(default=0, ge=0)
    json_keys: tuple[str, ...] = ()
    notes: str = ""

    @model_validator(mode="before")
    @classmethod
    def _default_family(cls, data: Any) -> Any:
        if isinstance(data, dict) and not data.get("family"):
            return {**data, "family": data.get("id", "")}
        return data

    @model_validator(mode="after")
    def _check_consistency(self) -> CatalogEntry:
        if self.format == "json" and not self.json_keys:
            raise ValueError("json Sources need json_keys")
        if self.default_enabled and not business_use_permitted(self.role, self.business_use):
            raise ValueError("only Sources cleared for business use may be enabled by default")
        if self.default_enabled and self.licence_class is LicenceClass.RESTRICTED:
            raise ValueError("restricted Sources need acknowledgement, so no default enablement")
        return self


def business_use_permitted(role: SourceRole, business_use: BusinessUse) -> bool:
    """Business Mode rule: blocklist Sources need business use allowed; allowlist is exempt."""
    return role == "allowlist" or business_use is BusinessUse.ALLOWED


def load_catalog(path: Path | None = None) -> list[CatalogEntry]:
    """Load and validate the Catalog (the shipped one when ``path`` is None)."""
    if path is None:
        text = resources.files("threatcull").joinpath("catalog.yaml").read_text(encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict) or not isinstance(raw.get("sources"), list):
        raise CatalogError("the Catalog must be a mapping with a 'sources' list")
    entries = [CatalogEntry.model_validate(item) for item in raw["sources"]]
    counts = Counter(entry.id for entry in entries)
    duplicates = sorted(source_id for source_id, n in counts.items() if n > 1)
    if duplicates:
        raise CatalogError(f"duplicate Source ids: {', '.join(duplicates)}")
    return entries
