#!/usr/bin/env python3
"""Same-netns HTTP oracle. Witness proves Gitea dialed this listener."""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

WITNESS = b"GITEA-0000-SSRF"
BIND_HOST = "0.0.0.0"
BIND_PORT = 8080


class Handler(BaseHTTPRequestHandler):
    def _reply(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(WITNESS)))
        self.end_headers()
        self.wfile.write(WITNESS)

    def do_GET(self) -> None:  # noqa: N802
        self._reply()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._reply()

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"oracle {fmt % args}\n")


def main() -> int:
    # 0.0.0.0 so Linux 0.0.0.1 this-host dials land here in the shared netns.
    HTTPServer((BIND_HOST, BIND_PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
