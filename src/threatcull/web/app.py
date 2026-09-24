# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application factory."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import FastAPI

from threatcull.store.db import connect
from threatcull.web.routes import health
from threatcull.web.security import (
    SecurityHeadersMiddleware,
    load_or_create_secret,
    unhandled_exception_response,
)

DB_NAME = "threatcull.db"


def open_db(data_dir: Path) -> sqlite3.Connection:
    """Open (and migrate) the database in ``data_dir``.

    Catalog sync and default Outputs are NOT done here: the CLI (``init``,
    ``serve``) does that once at start-up, not on every request.
    """
    return connect(data_dir / DB_NAME)


def create_app(data_dir: Path, *, start_scheduler: bool = True) -> FastAPI:
    """Build the ThreatCull web application rooted at ``data_dir``.

    ``start_scheduler`` is accepted for forward compatibility; scheduler
    wiring arrives in a later task.
    """
    app = FastAPI(title="ThreatCull", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.data_dir = data_dir
    app.state.start_scheduler = start_scheduler
    app.state.secret_key = load_or_create_secret(data_dir)
    # Covers the one response SecurityHeadersMiddleware can't reach: Starlette's
    # own fallback 500 for a truly unhandled exception (see security.py).
    app.add_exception_handler(Exception, unhandled_exception_response)
    app.add_middleware(SecurityHeadersMiddleware)
    app.include_router(health.router)
    return app
