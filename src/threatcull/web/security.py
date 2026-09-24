# SPDX-License-Identifier: AGPL-3.0-only
"""Security headers, session secret, CSRF tokens and the login rate limiter."""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, MutableMapping
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


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
TrustedProxies = tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]

# A trusted-proxy range this wide would trust (nearly) every client, which
# makes X-Forwarded-For forgeable by anyone; refuse it outright.
MIN_TRUSTED_PREFIX = {4: 8, 6: 16}
# client_ip() reads at most this many X-Forwarded-For hops from the right.
MAX_FORWARDED_HOPS = 20


def parse_trusted_proxies(values: Iterable[str]) -> TrustedProxies:
    """Parse ``--trusted-proxy`` values (IP addresses or CIDRs); ``ValueError`` if bad.

    Ranges wider than /8 (IPv4) or /16 (IPv6), such as ``0.0.0.0/0``, are
    refused: they would let any client forge its address.
    """
    networks = []
    for value in values:
        try:
            network = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"not a valid trusted proxy IP or CIDR: {value!r}") from exc
        minimum = MIN_TRUSTED_PREFIX[network.version]
        if network.prefixlen < minimum:
            raise ValueError(
                f"trusted proxy range {value!r} is too wide (use /{minimum} or narrower): "
                "it would let any client forge its address"
            )
        networks.append(network)
    return tuple(networks)


def _normalise(address: IPAddress) -> IPAddress:
    """``::ffff:10.0.0.1`` is ``10.0.0.1`` (dual-stack sockets report the former)."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _parse_ip(value: str) -> IPAddress | None:
    try:
        return _normalise(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _parse_hop(value: str) -> IPAddress | None:
    """One ``X-Forwarded-For`` hop: ``ip``, ``ip:port`` (IPv4) or ``[ipv6]`` / ``[ipv6]:port``."""
    hop = value.strip()
    if hop.startswith("["):
        end = hop.find("]")
        rest = hop[end + 1 :]
        if end < 0 or (rest and not (rest.startswith(":") and rest[1:].isdigit())):
            return None
        return _parse_ip(hop[1:end])
    host, colon, port = hop.partition(":")
    if colon and "." in host and ":" not in port and port.isdigit():
        return _parse_ip(host)
    return _parse_ip(hop)


def _is_trusted(address: IPAddress, trusted: TrustedProxies) -> bool:
    return any(address in network for network in trusted)


def _trusted_peer(client: tuple[str, int] | None, trusted: TrustedProxies) -> bool:
    if not trusted or client is None:
        return False
    peer = _parse_ip(client[0])
    return peer is not None and _is_trusted(peer, trusted)


def client_ip(request: Request) -> str:
    """The address login attempts are counted against.

    By default the direct peer, with ``X-Forwarded-For`` ignored. Only when the
    peer is one of the app's trusted proxies (``serve --trusted-proxy``) is the
    header used: walking it from the right, skipping trusted hops, the first
    untrusted address is the client. The left-most entries are whatever the
    client sent, so they are never taken on trust.

    Fallbacks (all to the direct peer, the conservative choice): a hop that
    isn't an address (garbage, or the empty hop a trailing comma leaves), or
    ``MAX_FORWARDED_HOPS`` trusted hops in a row without reaching an untrusted
    one. If every hop of a shorter chain is trusted, the left-most is used.
    """
    if request.client is None:
        return "unknown"
    peer = request.client.host
    trusted: TrustedProxies = getattr(request.app.state, "trusted_proxies", ())
    if not _trusted_peer((request.client.host, request.client.port), trusted):
        return peer
    hops = [
        hop for header in request.headers.getlist("x-forwarded-for") for hop in header.split(",")
    ]
    forwarded = _forwarded_client(hops, trusted)
    return str(forwarded) if forwarded is not None else peer


def _forwarded_client(hops: list[str], trusted: TrustedProxies) -> IPAddress | None:
    """The right-most untrusted hop; ``None`` means "use the peer" (see ``client_ip``)."""
    parsed: IPAddress | None = None
    for hop in hops[::-1][:MAX_FORWARDED_HOPS]:
        parsed = _parse_hop(hop)
        if parsed is None or not _is_trusted(parsed, trusted):
            return parsed
    if len(hops) > MAX_FORWARDED_HOPS:
        return None
    return parsed  # every hop is a trusted proxy: the left-most one (None if no hops)


# Syntax only (never an allowlist: homelab rule): host or IP, optional port.
_FORWARDED_HOST = re.compile(r"[A-Za-z0-9.\-:\[\]]{1,255}")


def _last_header_value(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    """The right-most comma-separated value across every ``name`` header."""
    values = [value for key, value in headers if key.lower() == name]
    if not values:
        return None
    try:
        joined = b",".join(values).decode("latin-1")
    except UnicodeDecodeError:  # pragma: no cover - latin-1 decodes any byte
        return None
    return joined.rsplit(",", 1)[-1].strip()


class ForwardedHeadersMiddleware:
    """Believe ``X-Forwarded-Proto`` / ``X-Forwarded-Host`` from trusted proxies only.

    Installed only with ``serve --trusted-proxy``. When the direct peer is a
    trusted proxy: the right-most ``X-Forwarded-Proto`` sets the scheme if it
    is exactly ``http`` or ``https``; the right-most ``X-Forwarded-Host``
    replaces ``Host`` if it is syntactically ``host[:port]``. Anything else,
    or any other peer, leaves the request untouched. Feed URLs then show the
    address clients actually use (``https://`` behind a TLS proxy).
    """

    def __init__(self, app: ASGIApp, trusted: TrustedProxies) -> None:
        self.app = app
        self.trusted = trusted

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket") and _trusted_peer(
            scope.get("client"), self.trusted
        ):
            scope = self._apply(scope)
        await self.app(scope, receive, send)

    @staticmethod
    def _apply(scope: Scope) -> Scope:
        headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
        scope = dict(scope)
        proto = _last_header_value(headers, b"x-forwarded-proto")
        if proto is not None and proto.lower() in ("http", "https"):
            scope["scheme"] = proto.lower()
        host = _last_header_value(headers, b"x-forwarded-host")
        if host is not None and _FORWARDED_HOST.fullmatch(host):
            headers = [(k, v) for k, v in headers if k.lower() != b"host"]
            headers.append((b"host", host.encode("latin-1")))
            scope["headers"] = headers
        return scope


IPV6_CLIENT_PREFIX = 64


def rate_limit_key(ip: str) -> str:
    """The bucket a client address is counted in.

    IPv4: the address itself. IPv6: its /64, since one host usually holds a
    whole /64 and could otherwise rotate addresses to reset its budget.
    Anything that isn't an address (e.g. ``"unknown"``) is used as-is.
    """
    address = _parse_ip(ip)
    if isinstance(address, ipaddress.IPv6Address):
        network = ipaddress.IPv6Network((address, IPV6_CLIENT_PREFIX), strict=False)
        return str(network)
    return str(address) if address is not None else ip


class LoginRateLimiter:
    """In-memory, per-IP sliding window of login attempts; thread-safe.

    IPv6 clients are counted per /64 (see :func:`rate_limit_key`).

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
        ip = rate_limit_key(ip)
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
        """A login from ``ip`` worked: forget its attempts (its whole /64 for IPv6)."""
        ip = rate_limit_key(ip)
        with self._lock:
            self._attempts.pop(ip, None)

    def attempts(self, ip: str) -> int:
        ip = rate_limit_key(ip)
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


# --- CSRF failure on an HTML form post -------------------------------------------


class CsrfError(Exception):
    """Raised by ``check_csrf`` for a non-``/api/`` request; turned into a 403 page.

    A bearer-authenticated or other ``/api/`` request never raises this: those
    stay a plain ``HTTPException(403)`` (JSON), since CSRF only applies to
    cookie sessions in the first place.
    """
