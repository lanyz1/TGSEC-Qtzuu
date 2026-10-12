#!/usr/bin/env python3
"""Loopback readiness listener for the sqlite-session-ncol lab."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "0.0.0.0"
PORT = 18900
BODY = b"ok SQLITE-SESSION-NCOL-WITNESS\n"


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> int:
    HTTPServer((HOST, PORT), HealthHandler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
