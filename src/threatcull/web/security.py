# SPDX-License-Identifier: AGPL-3.0-only
"""Security headers, session secret, CSRF tokens and the login rate limiter."""

from __future__ import annotations

import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, MutableMapping
from pathlib import Path
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
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


# --- CSRF: session-bound synchronizer token (no Origin/Referer checks) -----------

CSRF_SESSION_KEY = "csrf"
CSRF_FORM_FIELD = "csrf"
CSRF_HEADER = "X-CSRF-Token"


def ensure_csrf_token(session: MutableMapping[str, Any]) -> str:
    """Return the session's CSRF token, creating one on first use."""
    token = session.get(CSRF_SESSION_KEY)
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def rotate_csrf_token(session: MutableMapping[str, Any]) -> str:
    """Replace the session's CSRF token (done on login)."""
    token = secrets.token_urlsafe(32)
    session[CSRF_SESSION_KEY] = token
    return token


def csrf_token_matches(session: MutableMapping[str, Any], submitted: str | None) -> bool:
    """Constant-time check of a submitted token against the session's one."""
    expected = session.get(CSRF_SESSION_KEY)
    if not isinstance(expected, str) or not expected or not submitted:
        return False
    return secrets.compare_digest(expected.encode(), submitted.encode())


# --- Login rate limiting --------------------------------------------------------


def client_ip(request: Request) -> str:
    """The address login attempts are counted against.

    The direct peer only; ``X-Forwarded-For`` is never trusted here (opt-in
    trusted-proxy handling belongs in this one function).
    """
    return request.client.host if request.client is not None else "unknown"


class LoginRateLimiter:
    """In-memory, per-IP sliding window of login attempts; thread-safe.

    :meth:`try_begin` reserves an attempt atomically *before* the password is
    checked, so parallel requests can't slip past the limit: at most
    ``max_failures`` attempts per IP start within ``window_seconds``. A
    successful login clears the IP (:meth:`succeeded`); a failed one keeps its
    reservation. Refused attempts are not recorded, so a block lifts once the
    oldest attempt leaves the window.

    Memory is bounded: at most ``max_tracked`` IPs (least recently seen are
    evicted first), and expired IPs are swept at most once per
    ``sweep_interval`` seconds.
    """

    def __init__(
        self,
        *,
        max_failures: int = 5,
        window_seconds: float = 300.0,
        max_tracked: int = 10_000,
        sweep_interval: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_tracked = max_tracked
        self.sweep_interval = sweep_interval
        self._clock = clock
        self._lock = threading.Lock()
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()
        self._last_sweep = clock()

    def _expire(self, ip: str, now: float) -> int:
        """Drop ``ip``'s attempts outside the window; returns what is left.

        Caller holds the lock.
        """
        stamps = self._attempts.get(ip)
        if stamps is None:
            return 0
        while stamps and stamps[0] <= now - self.window_seconds:
            stamps.popleft()
        if not stamps:
            del self._attempts[ip]
        return len(stamps)

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep < self.sweep_interval:
            return
        self._last_sweep = now
        for ip in list(self._attempts):
            self._expire(ip, now)

    def try_begin(self, ip: str) -> bool:
        """Reserve one login attempt for ``ip``; ``False`` if it is blocked."""
        with self._lock:
            now = self._clock()
            self._maybe_sweep(now)
            if self._expire(ip, now) >= self.max_failures:
                return False
            self._attempts.setdefault(ip, deque()).append(now)
            self._attempts.move_to_end(ip)
            while len(self._attempts) > self.max_tracked:
                self._attempts.popitem(last=False)
            return True

    def succeeded(self, ip: str) -> None:
        """A login from ``ip`` worked: forget its attempts."""
        with self._lock:
            self._attempts.pop(ip, None)

    def attempts(self, ip: str) -> int:
        with self._lock:
            return self._expire(ip, self._clock())

    def tracked(self) -> int:
        with self._lock:
            return len(self._attempts)


# --- Login redirect for HTML pages ----------------------------------------------


class LoginRequiredError(Exception):
    """Raised by ``require_user``; turned into a ``303`` to ``/login``."""


async def login_required_response(request: Request, exc: Exception) -> Response:
    del request, exc
    return RedirectResponse("/login", status_code=303)
