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
