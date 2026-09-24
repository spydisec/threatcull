# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI dependencies shared across routes."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

from fastapi import Request

from threatcull.web.app import open_db


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    """Open one database connection for this request, closed after the response."""
    conn = open_db(request.app.state.data_dir)
    try:
        yield conn
    finally:
        conn.close()
