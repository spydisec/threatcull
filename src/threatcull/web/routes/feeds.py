# SPDX-License-Identifier: AGPL-3.0-only
"""Serve published Outputs to devices, authenticated by a per-Output Feed Token.

Unauthenticated by design (Feed Tokens are the credential): no session is
read or written here, so these responses never carry ``Set-Cookie``.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from starlette.responses import FileResponse, PlainTextResponse, Response

from threatcull.outputs.files import output_path
from threatcull.store.errors import NotFoundError
from threatcull.store.outputs import OutputFormat, OutputSpec, get_output, verify_token
from threatcull.web.deps import get_conn

router = APIRouter()

# Same shape as OutputSpec's own name pattern (store/outputs.py): checked here
# too, before any path is built from the URL's ``name``, so a path-traversal-
# shaped name never reaches the filesystem or even the database.
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

_CONTENT_TYPES: dict[OutputFormat, str] = {
    "plain": "text/plain; charset=utf-8",
    "hosts": "text/plain; charset=utf-8",
    "adguard": "text/plain; charset=utf-8",
    "rpz": "text/plain; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
}


def _not_found() -> Response:
    # Identical body for a wrong token, an unknown Output and a never-published
    # one: none of the three should be distinguishable from the outside.
    return PlainTextResponse("not found", status_code=404, headers={"Cache-Control": "no-cache"})


def _not_modified(etag: str | None, last_modified: str | None) -> Response:
    response = Response(status_code=304, headers={"Cache-Control": "no-cache"})
    if etag is not None:
        response.headers["etag"] = etag
    if last_modified is not None:
        response.headers["last-modified"] = last_modified
    return response


def _lookup_spec(conn: sqlite3.Connection, name: str) -> OutputSpec | None:
    """The named Output's spec, or ``None`` if ``name`` is invalid or unknown.

    Checked against the Output-name pattern before ever touching the
    database, so a path-traversal-shaped name is rejected without building
    any path or query from it.
    """
    if not _NAME.fullmatch(name):
        return None
    try:
        return get_output(conn, name)
    except NotFoundError:
        return None


def _conditional(request: Request, response: Response) -> Response:
    """Apply ``If-None-Match``/``If-Modified-Since`` against ``response``'s headers."""
    etag = response.headers.get("etag")
    last_modified = response.headers.get("last-modified")

    if_none_match = request.headers.get("if-none-match")
    if if_none_match is not None:
        if etag is not None and if_none_match == etag:
            return _not_modified(etag, last_modified)
        return response

    if_modified_since = request.headers.get("if-modified-since")
    fresh = if_modified_since is not None and if_modified_since == last_modified
    if fresh:
        return _not_modified(etag, last_modified)
    return response


def _serve(request: Request, conn: sqlite3.Connection, name: str, token: str) -> Response:
    spec = _lookup_spec(conn, name)
    if spec is None or not verify_token(conn, name, token):
        return _not_found()

    path = output_path(request.app.state.data_dir / "outputs", spec)
    if not path.is_file():
        return _not_found()

    stat_result = path.stat()
    response = FileResponse(path, media_type=_CONTENT_TYPES[spec.format], stat_result=stat_result)
    response.headers["cache-control"] = "no-cache"
    return _conditional(request, response)


@router.get("/o/{name}")
def serve_by_query_token(
    request: Request,
    name: str,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    token: str = "",
) -> Response:
    return _serve(request, conn, name, token)


@router.get("/o/{name}/{token}")
def serve_by_path_token(
    request: Request,
    name: str,
    token: str,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
) -> Response:
    return _serve(request, conn, name, token)
