# SPDX-License-Identifier: AGPL-3.0-only
"""Security headers middleware and the per-install session secret."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

KEY_FILE_NAME = "secret.key"
SECRET_LENGTH = 32

# Homelab / air-gapped first: no Host/Origin/Referer checks, plain HTTP by
# default. These four headers apply to every response (see global constraints).
_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


class SecurityHeadersMiddleware:
    """Attach the standard security headers to every HTTP response.

    A plain ASGI middleware (not ``BaseHTTPMiddleware``): it wraps ``send`` and
    injects the headers into the ``http.response.start`` message, which covers
    normal and streamed responses, including ones built by exception handlers
    registered on the app. It does NOT cover the response Starlette's own
    ``ServerErrorMiddleware`` sends for a truly unhandled exception when no
    ``Exception`` handler is registered: that middleware always wraps outside
    every user middleware (by ASGI/Starlette design) and sends its fallback
    500 straight to the raw ASGI ``send``, bypassing this middleware entirely.
    ``create_app`` closes that gap by registering
    :func:`unhandled_exception_response` as the handler for the base
    ``Exception`` class, which sets these same headers directly on the
    response object it returns.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _SECURITY_HEADERS.items():
                    headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


async def unhandled_exception_response(request: Request, exc: Exception) -> Response:
    """The security-headers equivalent of Starlette's default 500 response.

    Registered for the base ``Exception`` class, this becomes the ``handler``
    ``ServerErrorMiddleware`` calls for an exception no other handler caught.
    ServerErrorMiddleware sends whatever response object this returns via the
    raw ASGI ``send`` (bypassing ``SecurityHeadersMiddleware``), so the headers
    are set here directly instead of relying on that middleware.
    """
    del request, exc  # Nothing route/exception-specific belongs in the response.
    response = PlainTextResponse("Internal Server Error", status_code=500)
    for name, value in _SECURITY_HEADERS.items():
        response.headers[name] = value
    return response


def _read_key(path: Path) -> bytes | None:
    """Read an existing secret file, or ``None`` if it does not exist.

    A file that exists but isn't exactly ``SECRET_LENGTH`` bytes is never a
    partially-written or corrupted key silently accepted: it's a clear error.
    """
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    if len(data) != SECRET_LENGTH:
        raise ValueError(
            f"{path} is {len(data)} bytes, not the expected {SECRET_LENGTH}-byte secret "
            "(partially written or corrupted); delete it to regenerate, or restore a backup"
        )
    return data


def load_or_create_secret(data_dir: Path) -> bytes:
    """Return the per-install session secret, creating it (mode 0600) if missing.

    Safe under concurrent callers (threads or processes): the key is written in
    full to a uniquely-named temp file in ``data_dir`` (mode 0600 from creation,
    fsynced before anyone can see it), then published under its final name with
    ``os.link``, which fails rather than truncating/overwriting if another
    caller already published one. No reader can ever observe a file that
    exists but is only partially written.
    """
    path = data_dir / KEY_FILE_NAME
    existing = _read_key(path)
    if existing is not None:
        return existing

    data_dir.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(SECRET_LENGTH)
    tmp_path = data_dir / f".{KEY_FILE_NAME}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, secret)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        try:
            os.link(tmp_path, path)
        except FileExistsError:
            # Another caller published a key first; use theirs, not ours.
            published = _read_key(path)
            if published is None:  # pragma: no cover - only if it vanished again
                raise
            return published
    finally:
        tmp_path.unlink(missing_ok=True)
    return secret
