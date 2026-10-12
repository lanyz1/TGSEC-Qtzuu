#!/usr/bin/env python3
"""Loopback Databricks HTTP mock. Logs every request path; secrets/get returns the witness."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

WITNESS = "N8N-DBX-SECRET-WITNESS"
SECRET_PATH = "/api/2.0/secrets/get"
HOST = "0.0.0.0"
PORT = 8080


class AccessLog:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._lines: list[str] = []

    def record(self, line: str) -> None:
        with self._lock:
            self._lines.append(line)
            print(line, flush=True)

    def dump(self) -> bytes:
        with self._lock:
            if not self._lines:
                return b""
            return ("\n".join(self._lines) + "\n").encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    access_log = AccessLog()

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: object) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send(code, raw, "application/json")

    def _read_body(self) -> None:
        raw_len = self.headers.get("Content-Length") or "0"
        try:
            length = int(raw_len)
        except ValueError:
            length = 0
        if length > 0:
            self.rfile.read(length)

    def _handle(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parsed.query
        line = f"{self.command} {self.path}"
        if path not in ("/health", "/__logs"):
            self.access_log.record(line)

        if path in ("/health", "/healthz"):
            self._send(200, b"ok", "text/plain")
            return

        if path == "/__logs":
            self._send(200, self.access_log.dump(), "text/plain; charset=utf-8")
            return

        if self.command == "GET" and path.rstrip("/") == SECRET_PATH:
            self._json(200, {"value": WITNESS, "scope": "s", "key": "k", "query": qs})
            return

        self._json(
            404,
            {
                "error_code": "NOT_FOUND",
                "message": f"no mock handler for {self.command} {path}",
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._read_body()
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._read_body()
        self._handle()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle()


def main() -> int:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
