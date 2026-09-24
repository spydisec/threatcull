# SPDX-License-Identifier: AGPL-3.0-only
"""Jinja2 templates (always auto-escaped) and a page-render helper."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jinja2
from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from threatcull.web.deps import session_user
from threatcull.web.security import ensure_csrf_token

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(WEB_DIR / "templates"),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
)
templates = Jinja2Templates(env=_env)


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """Render ``name`` with the logged-in ``user`` and the session ``csrf`` token."""
    page: dict[str, Any] = {
        "user": session_user(request),
        "csrf": ensure_csrf_token(request.session),
    }
    page.update(context or {})
    return templates.TemplateResponse(request, name, page, status_code=status_code, headers=headers)
