# SPDX-License-Identifier: AGPL-3.0-only
"""Fetcher: retrieve a Source over HTTP(S) or from a local file (the air-gap seam)."""

from __future__ import annotations

import hashlib
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Literal, Protocol
from urllib.parse import unquote, urlparse

import httpx

from threatcull import __version__

USER_AGENT = f"ThreatCull/{__version__} (+https://github.com/spydisec/threatcull)"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
RETRY_DELAYS = (1.0, 2.0, 4.0)
_FILE_CHUNK = 1024 * 1024
# A spooled download stays in memory up to this size, then moves to a temporary
# file (in TMPDIR: /data in the image), so a 100 MB list never sits in RAM.
SPOOL_IN_MEMORY = 8 * 1024 * 1024
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class FetchError(Exception):
    """A Source could not be retrieved."""


class _RetryableError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class FetchResult:
    """A download. Small bodies arrive as ``text``; a spooled one as ``body``.

    ``body`` is a binary file positioned at the start, and ``sha256`` the hex
    digest of its bytes, computed while downloading. Whoever receives a result
    with a ``body`` calls :meth:`close` when done.
    """

    status: Literal["ok", "not_modified"]
    text: str = ""
    etag: str | None = None
    last_modified: str | None = None
    content_type: str | None = None
    body: IO[bytes] | None = None
    sha256: str | None = None

    def close(self) -> None:
        if self.body is not None:
            self.body.close()


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
        spool: bool = False,
    ) -> None:
        self._client = client or httpx.Client(
            timeout=DEFAULT_TIMEOUT, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        )
        self._max_bytes = max_bytes
        self._retry_delays = retry_delays
        self._sleep = sleep
        # spool=True (Source Fetches): return the body as a spooled file plus its
        # SHA-256 instead of one decoded string. Small fetches (the Catalog,
        # the public-IP lookup) keep spool=False and read ``text``.
        self._spool = spool

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        if url.startswith("file://"):
            return _read_file(url, self._max_bytes, spool=self._spool)
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
        content_type = response.headers.get("Content-Type")
        if self._spool:
            body, digest = _spool(response.iter_bytes(), self._max_bytes, url)
            return FetchResult(
                "ok", "", etag, last_modified, content_type, body=body, sha256=digest
            )
        data = bytearray()
        for chunk in response.iter_bytes():
            data.extend(chunk)
            if len(data) > self._max_bytes:
                raise FetchError(f"{url} exceeds {self._max_bytes} bytes")
        text = data.decode("utf-8", errors="replace")
        return FetchResult("ok", text, etag, last_modified, content_type)


def _spool(chunks: Iterable[bytes], max_bytes: int, label: object) -> tuple[IO[bytes], str]:
    """Copy ``chunks`` into a spooled temporary file, hashing them on the way."""
    body: IO[bytes] = tempfile.SpooledTemporaryFile(max_size=SPOOL_IN_MEMORY)  # noqa: SIM115
    try:
        digest = _copy_hashed(chunks, body, max_bytes, label)
        body.seek(0)
    except BaseException:
        body.close()  # the temporary file goes with it
        raise
    return body, digest


def _copy_hashed(chunks: Iterable[bytes], body: IO[bytes], max_bytes: int, label: object) -> str:
    digest = hashlib.sha256()
    size = 0
    for chunk in chunks:
        size += len(chunk)
        if size > max_bytes:
            raise FetchError(f"{label} exceeds {max_bytes} bytes")
        digest.update(chunk)
        body.write(chunk)
    return digest.hexdigest()


def _read_file(url: str, max_bytes: int, *, spool: bool = False) -> FetchResult:
    parsed = urlparse(url)
    if parsed.netloc not in ("", "localhost"):
        raise FetchError(f"file:// URLs cannot name a host ({parsed.netloc!r}): {url}")
    path = Path(unquote(parsed.path))
    if spool:
        try:
            with path.open("rb") as handle:
                body, digest = _spool(iter(lambda: handle.read(_FILE_CHUNK), b""), max_bytes, path)
        except OSError as exc:
            raise FetchError(f"cannot read {path}: {exc}") from exc
        return FetchResult("ok", body=body, sha256=digest)
    data = bytearray()
    try:
        # Read in bounded chunks rather than stat-then-read: no race with the file
        # changing in between, and /dev/zero-style paths stop at the cap.
        with path.open("rb") as handle:
            while chunk := handle.read(_FILE_CHUNK):
                data.extend(chunk)
                if len(data) > max_bytes:
                    raise FetchError(f"{path} exceeds {max_bytes} bytes")
    except OSError as exc:
        raise FetchError(f"cannot read {path}: {exc}") from exc
    return FetchResult("ok", data.decode("utf-8", errors="replace"))
