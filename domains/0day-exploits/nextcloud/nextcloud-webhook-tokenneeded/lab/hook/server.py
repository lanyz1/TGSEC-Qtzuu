#!/usr/bin/env python3
"""Loopback webhook catcher. Writes POST bodies and always returns 200."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEFAULT_DATA = Path("/data")
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
HEALTH_PATHS = ("/health", "/", "/ready")
LAST_PATHS = ("/last", "/hook")


@dataclass(frozen=True)
class CatcherPaths:
    data: Path
    last: Path
    all_log: Path

    @classmethod
    def from_env(cls) -> CatcherPaths:
        data = Path(os.environ.get("CATCHER_DATA", str(DEFAULT_DATA)))
        return cls(data=data, last=data / "last.json", all_log=data / "all.jsonl")


class Handler(BaseHTTPRequestHandler):
    paths: CatcherPaths

    def _send(self, code: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in HEALTH_PATHS:
            self._send(200, b'{"ok":true}')
            return
        if path in LAST_PATHS:
            if self.paths.last.is_file():
                self._send(200, self.paths.last.read_bytes())
            else:
                self._send(200, b"{}")
            return
        self._send(404, b'{"error":"not found"}')

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        self.paths.last.write_bytes(raw or b"{}")
        with self.paths.all_log.open("ab") as fh:
            fh.write(raw.replace(b"\n", b" ") + b"\n")
        self._send(200, b'{"ok":true}')

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("hook " + (fmt % args) + "\n")


def main() -> int:
    paths = CatcherPaths.from_env()
    paths.data.mkdir(parents=True, exist_ok=True)
    Handler.paths = paths
    host = os.environ.get("CATCHER_HOST", DEFAULT_HOST)
    port = int(os.environ.get("CATCHER_PORT", str(DEFAULT_PORT)))
    print(f"hook listening {host}:{port}", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
