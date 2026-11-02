# SPDX-License-Identifier: AGPL-3.0-only
"""A local HTTP server so no test needs the internet."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

Response = tuple[int, bytes, dict[str, str]]


@dataclass
class Route:
    responses: list[Response]
    calls: int = 0
    request_headers: list[dict[str, str]] = field(default_factory=list)


class FixtureServer:
    def __init__(self) -> None:
        self.routes: dict[str, Route] = {}
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                route = routes.get(self.path)
                if route is None:
                    self.send_error(404)
                    return
                route.request_headers.append(dict(self.headers.items()))
                status, body, headers = route.responses[min(route.calls, len(route.responses) - 1)]
                route.calls += 1
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def add(self, path: str, *responses: Response) -> None:
        self.routes[path] = Route(list(responses))

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"
