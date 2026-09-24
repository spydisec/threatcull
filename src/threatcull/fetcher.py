# SPDX-License-Identifier: AGPL-3.0-only
"""Fetcher: retrieve a Source over HTTP(S) or from a local file (the air-gap seam)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import unquote, urlparse

import httpx

from threatcull import __version__

USER_AGENT = f"ThreatCull/{__version__} (+https://github.com/spydisec/threatcull)"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
RETRY_DELAYS = (1.0, 2.0, 4.0)
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class FetchError(Exception):
    """A Source could not be retrieved."""


class _RetryableError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class FetchResult:
    status: Literal["ok", "not_modified"]
    text: str = ""
    etag: str | None = None
    last_modified: str | None = None


class Fetcher(Protocol):
    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult: ...


class HttpFetcher:
    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        retry_delays: tuple[float, ...] = RETRY_DELAYS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client or httpx.Client(
            timeout=DEFAULT_TIMEOUT, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        )
        self._max_bytes = max_bytes
        self._retry_delays = retry_delays
        self._sleep = sleep

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        if url.startswith("file://"):
            return _read_file(url, self._max_bytes)
        headers: dict[str, str] = {}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        for delay in self._retry_delays:
            try:
                return self._get(url, headers)
            except _RetryableError:
                self._sleep(delay)
        try:
            return self._get(url, headers)
        except _RetryableError as exc:
            raise FetchError(str(exc)) from exc

    def _get(self, url: str, headers: dict[str, str]) -> FetchResult:
        try:
            with self._client.stream("GET", url, headers=headers) as response:
                return self._read(url, response)
        except httpx.TransportError as exc:
            raise _RetryableError(f"{type(exc).__name__} fetching {url}: {exc}") from exc
        except httpx.RequestError as exc:
            # Non-transport request errors (e.g. DecodingError, TooManyRedirects) are
            # not transient, so fail immediately instead of retrying.
            raise FetchError(f"{type(exc).__name__} fetching {url}: {exc}") from exc

    def _read(self, url: str, response: httpx.Response) -> FetchResult:
        etag = response.headers.get("ETag")
        last_modified = response.headers.get("Last-Modified")
        if response.status_code == httpx.codes.NOT_MODIFIED:
            return FetchResult("not_modified", etag=etag, last_modified=last_modified)
        if response.status_code in _RETRY_STATUSES:
            raise _RetryableError(f"HTTP {response.status_code} from {url}")
        if response.status_code != httpx.codes.OK:
            raise FetchError(f"HTTP {response.status_code} from {url}")
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > self._max_bytes:
                raise FetchError(f"{url} exceeds {self._max_bytes} bytes")
        text = body.decode("utf-8", errors="replace")
        return FetchResult("ok", text, etag, last_modified)


def _read_file(url: str, max_bytes: int) -> FetchResult:
    path = Path(unquote(urlparse(url).path))
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FetchError(f"cannot read {path}: {exc}") from exc
    if size > max_bytes:
        raise FetchError(f"{path} exceeds {max_bytes} bytes")
    return FetchResult("ok", path.read_text(encoding="utf-8", errors="replace"))
