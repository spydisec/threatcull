# SPDX-License-Identifier: AGPL-3.0-only
"""Security headers middleware and the per-install session secret."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach the standard security headers to every response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response


def load_or_create_secret(data_dir: Path) -> bytes:
    """Return the per-install session secret, creating it (mode 0600) if missing."""
    path = data_dir / KEY_FILE_NAME
    try:
        return path.read_bytes()
    except FileNotFoundError:
        pass
    data_dir.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(SECRET_LENGTH)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Lost a race with another process creating the file; use its secret.
        return path.read_bytes()
    try:
        os.write(fd, secret)
    finally:
        os.close(fd)
    return secret
