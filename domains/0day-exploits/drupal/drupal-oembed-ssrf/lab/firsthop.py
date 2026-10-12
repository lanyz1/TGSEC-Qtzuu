#!/usr/bin/env python3
"""Allowlisted first-hop HTML with an oEmbed link href to loopback."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import urlparse

BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.environ.get("BIND_PORT", "8080"))
SECOND_HOP_URL = os.environ.get("SECOND_HOP_URL", "http://127.0.0.1:18080/oembed")
WITNESS = os.environ.get("WITNESS", "DRUPAL-OEMBED-SSRF-WITNESS")

_lock = Lock()
_hits: list[dict[str, str]] = []


def _html() -> bytes:
    page = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "  <title>lab first hop</title>\n"
        f'  <link rel="alternate" type="application/json+oembed" href="{SECOND_HOP_URL}">\n'
        "</head>\n"
        "<body>oembed discovery page</body>\n"
        "</html>\n"
    )
    return page.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"firsthop {self.address_string()} {fmt % args}", flush=True)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/video.html"):
            rec = {
                "path": path,
                "client": self.client_address[0],
                "ua": self.headers.get("User-Agent", ""),
            }
            with _lock:
                _hits.append(rec)
            self._send(200, _html(), "text/html; charset=utf-8")
            return
        if path == "/hits":
            with _lock:
                hits = list(_hits)
            payload = json.dumps({"hits": hits, "count": len(hits)}, indent=2).encode(
                "utf-8"
            )
            self._send(200, payload, "application/json")
            return
        if path == "/health":
            self._send(200, b"ok\n", "text/plain; charset=utf-8")
            return
        self._send(404, b"not found\n", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/reset":
            with _lock:
                _hits.clear()
            self._send(200, b"reset\n", "text/plain; charset=utf-8")
            return
        self._send(404, b"not found\n", "text/plain; charset=utf-8")


def main() -> int:
    print(
        f"firsthop bind={BIND_HOST}:{BIND_PORT} href={SECOND_HOP_URL} witness={WITNESS}",
        flush=True,
    )
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
