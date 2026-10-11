# SPDX-License-Identifier: AGPL-3.0-only
"""Jinja2 templates (always auto-escaped) and a page-render helper."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jinja2
from fastapi import Request
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from starlette.responses import HTMLResponse, Response

from threatcull.catalog import feed_label
from threatcull.clock import local, utcnow
from threatcull.web.dashboard import CATEGORY_LABELS
from threatcull.web.deps import session_user
from threatcull.web.security import ensure_csrf_token

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(WEB_DIR / "templates"),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
)


def _when(value: str | None, missing: str = "never") -> Markup:
    """Show a stored ISO-8601 UTC timestamp in the ``TZ`` zone, as
    ``2026-09-25 07:53 AEST``; the stored UTC value stays in the tooltip."""
    if not value:
        return Markup("{}").format(missing)
    try:
        moment = local(value)
    except ValueError:
        return Markup("{}").format(value)
    return Markup('<time datetime="{}" title="{}">{}</time>').format(
        value, value, moment.strftime("%Y-%m-%d %H:%M %Z")
    )


_DAYS_AS_DAYS = 14
_DAYS_AS_WEEKS = 60
_DAYS_AS_MONTHS = 730


def age_label(then: datetime, now: datetime) -> str:
    """``3 days``, ``5 weeks``, ``4 months``, ``2 years``: how long ago ``then`` was."""
    days = (now - then).days
    if days < 1:
        return "less than a day"
    if days < _DAYS_AS_DAYS:
        return f"{days} day" if days == 1 else f"{days} days"
    if days < _DAYS_AS_WEEKS:
        return f"{days // 7} weeks"
    if days < _DAYS_AS_MONTHS:
        return f"{days // 30} months"
    return f"{days // 365} years"


def _age(value: str | None) -> Markup:
    """How long ago a stored timestamp was; the exact UTC time in the tooltip."""
    if not value:
        return Markup("never")
    try:
        then = datetime.fromisoformat(value)
    except ValueError:
        return Markup("{}").format(value)
    if then.tzinfo is None:  # stored times are UTC; a hand-edited one may lack the zone
        then = then.replace(tzinfo=UTC)
    return Markup('<time datetime="{}" title="{}">{}</time>').format(
        value, value, age_label(then, utcnow())
    )


_PER_UNIT = 60  # seconds per minute, minutes per hour


def _duration(value: float | None) -> str:
    """``45 s``, ``3 min 20 s``, ``1 h 5 min``: a run's length, for people."""
    if value is None:
        return ""
    if 0 < value < 1:
        return "<1 s"
    seconds = round(value)
    if seconds < _PER_UNIT:
        return f"{seconds} s"
    minutes, secs = divmod(seconds, _PER_UNIT)
    if minutes < _PER_UNIT:
        return f"{minutes} min {secs} s" if secs else f"{minutes} min"
    hours, minutes = divmod(minutes, _PER_UNIT)
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


_BYTE_UNITS = ("B", "KB", "MB", "GB", "TB")
_KILO = 1024


def _size(value: int | None) -> str:
    """``950 B``, ``95.7 MB``, ``1.5 GB``: a file or database size, for people."""
    if value is None:
        return ""
    size = float(value)
    for unit in _BYTE_UNITS[:-1]:
        if size < _KILO:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= _KILO
    return f"{size:.1f} {_BYTE_UNITS[-1]}"


_env.filters["when"] = _when
_env.filters["age"] = _age
_env.filters["size"] = _size
_env.filters["duration"] = _duration
_env.filters["feed_label"] = feed_label
_env.globals["category_labels"] = CATEGORY_LABELS  # readable category names
templates = Jinja2Templates(env=_env)

FLASH_KEY = "flash"


def flash(request: Request, message: str) -> None:
    """Queue a one-shot message for the next rendered page (Post/Redirect/Get).

    Stored in the signed session cookie; only our own fixed strings go here.
    """
    request.session[FLASH_KEY] = message


def _pop_flash(request: Request) -> str | None:
    message = request.session.pop(FLASH_KEY, None)
    return message if isinstance(message, str) else None


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """Render ``name`` with the logged-in ``user``, the session ``csrf`` token and
    any pending flash message (shown once, then gone)."""
    page: dict[str, Any] = {
        "user": session_user(request),
        "csrf": ensure_csrf_token(request.session),
        "flash": _pop_flash(request),
    }
    page.update(context or {})
    return templates.TemplateResponse(request, name, page, status_code=status_code, headers=headers)


def render_fragment(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
) -> Response:
    """Render an htmx-swap fragment: just the piece, no ``base.html`` layout.

    Still carries the session ``csrf`` token, since a fragment usually
    contains its own form.
    """
    page: dict[str, Any] = {"csrf": ensure_csrf_token(request.session)}
    page.update(context or {})
    return HTMLResponse(_env.get_template(name).render(**page), status_code=status_code)
