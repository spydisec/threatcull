# SPDX-License-Identifier: AGPL-3.0-only
"""Pydantic request bodies for Sources/Settings write endpoints.

Plan 1's ``store.sources`` functions take ``category``/``format``/``kind`` as
plain ``Literal`` types with no runtime check of their own (the Plan 1 final
review flagged this for custom Sources); these models are what actually
enforces the allow-listed values, for both the HTML form handlers in
``routes/pages.py`` and the JSON API in ``routes/api.py``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threatcull.catalog import BusinessUse, Category
from threatcull.indicators import SourceKind
from threatcull.parsers import SourceFormat
from threatcull.policy.scoring import Tier
from threatcull.store.home import HomeOrigin
from threatcull.store.outputs import OutputFormat

# Mirrors threatcull.store.sources._CUSTOM_ID (kept in sync by
# tests/web/test_sources_actions.py exercising add_custom_source's own check).
_CUSTOM_ID_PATTERN = r"^custom-[a-z0-9][a-z0-9-]{0,54}$"


class SourceEnableIn(BaseModel):
    """Body of ``POST /api/v1/sources/{id}``."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    acknowledge_restricted: bool = False


class CustomSourceIn(BaseModel):
    """A custom Source as submitted through the Sources page form."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=_CUSTOM_ID_PATTERN)
    name: str = Field(min_length=1)
    url: str
    format: SourceFormat
    kind: SourceKind
    category: Category
    csv_column: int = Field(default=0, ge=0)
    json_keys: tuple[str, ...] = ()
    business_use: BusinessUse = BusinessUse.UNKNOWN


class AllowlistEntryIn(BaseModel):
    """Body of ``POST /allowlist`` and ``POST /api/v1/allowlist``.

    ``value`` is only checked for non-emptiness here; ``store.allowlist.add_entry``
    is what actually normalises it into an IP/CIDR/domain ``Indicator`` and
    raises ``ValueError`` (shown inline) if it isn't one.
    """

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)
    note: str = ""


class OutputCreateIn(BaseModel):
    """An Output as submitted through the Outputs page create form.

    Only enforces the fields Plan 1's ``OutputSpec`` dataclass does not check
    at runtime (``kind``/``format``/``min_tier`` are plain ``Literal`` types,
    and ``categories`` items aren't checked against the Catalog's ``Category``
    at all): a bogus value for any of those gets a ``422``-shaped ``400`` here
    instead of a silent bad row. The name pattern, kind/format compatibility,
    non-empty-categories and positive-``max_entries`` checks stay with
    ``OutputSpec.__post_init__`` itself, so its own message is what the
    operator sees for those.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    kind: SourceKind
    categories: tuple[Category, ...] = Field(min_length=1)
    min_tier: Tier
    max_entries: int | None = Field(default=None, ge=1)
    format: OutputFormat


class HomeEntryIn(BaseModel):
    """Body of ``POST /home`` and ``POST /api/v1/home``.

    ``origin`` is ``auto`` only for a detected candidate's Add button; the store
    normalises ``value`` and explains why a private address needs no entry.
    """

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)
    note: str = ""
    origin: HomeOrigin = "manual"
