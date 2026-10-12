#!/usr/bin/env python3
"""Loopback second-hop oEmbed oracle inside the gadget netns."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import urlparse

BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("BIND_PORT", "18080"))
WITNESS = os.environ.get("WITNESS", "DRUPAL-OEMBED-SSRF-WITNESS")

_lock = Lock()
_hits: list[dict[str, str]] = []


def _resource() -> bytes:
    body = {
        "version": "1.0",
        "type": "link",
        "title": WITNESS,
        "provider_name": None,
    }
    return json.dumps(body).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"oracle {self.address_string()} {fmt % args}", flush=True)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Lab-Witness", WITNESS)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/oembed"):
            rec = {
                "path": path,
                "client": self.client_address[0],
                "ua": self.headers.get("User-Agent", ""),
            }
            with _lock:
                _hits.append(rec)
            self._send(200, _resource(), "application/json+oembed")
            return
        if path == "/hits":
            with _lock:
                hits = list(_hits)
            payload = json.dumps(
                {"hits": hits, "witness": WITNESS, "count": len(hits)},
                indent=2,
            ).encode("utf-8")
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
    print(f"oracle bind={BIND_HOST}:{BIND_PORT} witness={WITNESS}", flush=True)
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
