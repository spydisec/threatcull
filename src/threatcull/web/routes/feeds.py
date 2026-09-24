# SPDX-License-Identifier: AGPL-3.0-only
"""Serve published Outputs to devices, authenticated by a per-Output Feed Token.

Unauthenticated by design (Feed Tokens are the credential): no session is
read or written here, so these responses never carry ``Set-Cookie``.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from starlette.responses import FileResponse, PlainTextResponse, Response

from threatcull.outputs.files import output_path
from threatcull.store.errors import NotFoundError
from threatcull.store.outputs import (
    NAME_PATTERN,
    OutputFormat,
    OutputSpec,
    get_output,
    verify_token,
)
from threatcull.web.deps import get_conn

router = APIRouter()

# Longer than any real Output name can ever be (NAME_PATTERN caps it at 63
# chars), so this can never collide with a real row. Used so an invalid-shaped
# name still runs one verify_token() lookup, the same as a valid-but-unknown
# name or a valid name with the wrong token — see _verify().
_DUMMY_NAME = "x" * 200

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
    if not NAME_PATTERN.fullmatch(name):
        return None
    try:
        return get_output(conn, name)
    except NotFoundError:
        return None


def _verify(conn: sqlite3.Connection, name: str, token: str) -> bool:
    """Run ``verify_token`` exactly once per request, whatever ``name`` is.

    An invalid-shaped name, a valid-but-unknown name, and a valid known name
    all reach one ``verify_token`` call here (against ``name`` itself, or
    against the never-real ``_DUMMY_NAME`` for an invalid shape). Without
    this, ``_serve`` would short-circuit past ``verify_token`` entirely for
    an invalid or unknown name, making "no token check ran at all" an
    observable (faster) signal that the name doesn't exist.
    """
    lookup_name = name if NAME_PATTERN.fullmatch(name) else _DUMMY_NAME
    return verify_token(conn, lookup_name, token)


def _etag_matches(if_none_match: str, etag: str) -> bool:
    """``If-None-Match`` semantics: ``*``, a comma list, weak (``W/``) compare."""
    if if_none_match.strip() == "*":
        return True

    def opaque(value: str) -> str:
        value = value.strip()
        return value[2:] if value.startswith("W/") else value

    wanted = opaque(etag)
    return any(opaque(candidate) == wanted for candidate in if_none_match.split(","))


def _conditional(request: Request, response: Response) -> Response:
    """Apply ``If-None-Match``/``If-Modified-Since`` against ``response``'s headers."""
    etag = response.headers.get("etag")
    last_modified = response.headers.get("last-modified")

    if_none_match = request.headers.get("if-none-match")
    if if_none_match is not None:
        if etag is not None and _etag_matches(if_none_match, etag):
            return _not_modified(etag, last_modified)
        return response

    if_modified_since = request.headers.get("if-modified-since")
    fresh = if_modified_since is not None and if_modified_since == last_modified
    if fresh:
        return _not_modified(etag, last_modified)
    return response


def _serve(request: Request, conn: sqlite3.Connection, name: str, token: str) -> Response:
    spec = _lookup_spec(conn, name)
    token_ok = _verify(conn, name, token)
    if spec is None or not token_ok:
        return _not_found()

    path = output_path(request.app.state.data_dir / "outputs", spec)
    if not path.is_file():
        return _not_found()
    try:
        stat_result = path.stat()
    except FileNotFoundError:
        # Republished/rotated between is_file() and stat(): same 404 as never published.
        return _not_found()

    response = FileResponse(path, media_type=_CONTENT_TYPES[spec.format], stat_result=stat_result)
    response.headers["cache-control"] = "no-cache"
    return _conditional(request, response)


@router.get("/o/{name}")
def serve_by_query_token(
    request: Request,
    name: str,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    token: str = "",  # nosec B107 - empty default for a query field, not a credential
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


# --- Feed Token redaction in uvicorn's access log --------------------------------

# uvicorn logs each request via the "uvicorn.access" logger as
# '%s - "%s %s HTTP/%s" %d' with args (client_addr, method, path, http_version,
# status); `path` is where a Feed Token appears, in either URL style:
#   /o/<name>?token=<token>   (query string)
#   /o/<name>/<token>         (path segment)
_QUERY_TOKEN = re.compile(r"([?&]token=)[^&\s]*")
_PATH_TOKEN = re.compile(r"^(/o/[^/?\s]+/)[^/?\s]+")
# uvicorn's access args tuple is (client_addr, method, path, http_version, status).
_ACCESS_PATH_ARG_INDEX = 2
_MIN_ACCESS_ARGS = 3


def _redact_feed_token(path: str) -> str:
    redacted = _QUERY_TOKEN.sub(r"\1<redacted>", path)
    return _PATH_TOKEN.sub(r"\1<redacted>", redacted)


class FeedTokenAccessFilter(logging.Filter):
    """Redacts Feed Tokens from uvicorn's access log, in both URL styles.

    Rewrites the request-path argument of each ``uvicorn.access`` record in
    place before it is formatted, so the token never reaches a handler
    (file, syslog, console, ...) in plain text.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if not isinstance(args, tuple) or len(args) < _MIN_ACCESS_ARGS:
            return True
        path = args[_ACCESS_PATH_ARG_INDEX]
        if isinstance(path, str) and path.startswith("/o/"):
            redacted = _redact_feed_token(path)
            record.args = (
                *args[:_ACCESS_PATH_ARG_INDEX],
                redacted,
                *args[_ACCESS_PATH_ARG_INDEX + 1 :],
            )
        return True


def install_feed_token_redaction() -> None:
    """Attach :class:`FeedTokenAccessFilter` to uvicorn's access logger, once."""
    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(existing, FeedTokenAccessFilter) for existing in logger.filters):
        logger.addFilter(FeedTokenAccessFilter())
