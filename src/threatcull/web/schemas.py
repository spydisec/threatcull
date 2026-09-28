# SPDX-License-Identifier: AGPL-3.0-only
"""Pydantic request bodies for Sources/Settings write endpoints.

Plan 1's ``store.sources`` functions take ``category``/``format``/``kind`` as
plain ``Literal`` types with no runtime check of their own (the Plan 1 final
review flagged this for custom Sources); these models are what actually
enforces the allow-listed values, for both the HTML form handlers in
``routes/pages.py`` and the JSON API in ``routes/api.py``.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threatcull.catalog import Category, SourceRole
from threatcull.indicators import SourceKind
from threatcull.parsers import SourceFormat
from threatcull.policy.scoring import Tier
from threatcull.store.outputs import OutputFormat

# Mirrors threatcull.store.sources._CUSTOM_ID (kept in sync by
# tests/web/test_sources_actions.py exercising add_custom_source's own check).
_CUSTOM_ID_PATTERN = r"^custom-[a-z0-9][a-z0-9-]{0,54}$"


class SourceEnableIn(BaseModel):
    """Body of ``POST /api/v1/sources/{id}``."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool


class CustomSourceIn(BaseModel):
    """A custom Source as submitted through the Sources page form.

    An empty ``id`` means "make one from the name"; the route picks a free one.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = ""
    name: str = Field(min_length=1)
    url: str = Field(min_length=1)
    role: SourceRole = "blocklist"
    format: SourceFormat = "plain"
    kind: SourceKind
    category: Category = "malicious"
    csv_column: int = Field(default=0, ge=0)
    json_keys: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def _id_shape(cls, value: str) -> str:
        value = value.strip()
        if value and not re.fullmatch(_CUSTOM_ID_PATTERN, value):
            raise ValueError(
                "ids look like custom-my-feed: lowercase letters, digits and dashes. "
                "Leave it empty to make one from the name"
            )
        return value


class AllowlistEntryIn(BaseModel):
    """Body of ``POST /allowlist`` and ``POST /api/v1/allowlist``.

    ``value`` is only checked for non-emptiness here; ``store.allowlist.add_entry``
    is what actually normalises it into an IP/CIDR/domain ``Indicator`` and
    raises ``ValueError`` (shown inline) if it isn't one.
    """

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)
    note: str = ""
    mine: bool = False  # the operator's own network: flagged when a Source lists it


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
