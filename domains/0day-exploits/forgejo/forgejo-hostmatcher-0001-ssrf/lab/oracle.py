#!/usr/bin/env python3
"""Same-netns HTTP oracle. Witness proves Forgejo dialed this listener."""

from __future__ import annotations

import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

WITNESS = os.environ.get("WITNESS", "FORGEJO-HOSTMATCHER-0001-WITNESS").encode()
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.environ.get("BIND_PORT", "8080"))


def ensure_this_network() -> None:
    """Linux 0.0.0.0/8 is this-host once 0.0.0.1 is on lo."""
    subprocess.run(
        ["ip", "addr", "add", "0.0.0.1/8", "dev", "lo"],
        check=False,
        capture_output=True,
    )


class Handler(BaseHTTPRequestHandler):
    def _reply(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
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
        sys.stderr.write("oracle " + (fmt % args) + "\n")


def main() -> int:
    ensure_this_network()
    sys.stderr.write(f"oracle listening {BIND_HOST}:{BIND_PORT}\n")
    HTTPServer((BIND_HOST, BIND_PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
