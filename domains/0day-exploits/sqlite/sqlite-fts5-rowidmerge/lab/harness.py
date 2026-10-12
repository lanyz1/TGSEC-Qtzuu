#!/usr/bin/env python3
"""Loopback SQL runner for ASan sqlite3. Keeps the CLI out of the HTTP process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BIND_HOST = "0.0.0.0"
BIND_PORT = 8080
SQLITE_BIN = Path(os.environ.get("SQLITE_BIN", "/usr/local/bin/sqlite3"))
SQL_TIMEOUT_S = 25.0
BODY_LIMIT = 64 * 1024
ASAN_OPTIONS = os.environ.get(
    "ASAN_OPTIONS",
    "detect_leaks=0:abort_on_error=1:halt_on_error=1:allocator_may_return_null=1",
)


def _run_sql(sql: str) -> dict[str, object]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = ASAN_OPTIONS
    try:
        proc = subprocess.run(
            [str(SQLITE_BIN), ":memory:"],
            input=sql,
            text=True,
            capture_output=True,
            timeout=SQL_TIMEOUT_S,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {
            "ok": False,
            "timeout": True,
            "rc": -1,
            "stdout": stdout or "",
            "stderr": (stderr or "") + "\nTIMEOUT",
        }
    except OSError as exc:
        return {
            "ok": False,
            "timeout": False,
            "rc": -1,
            "stdout": "",
            "stderr": str(exc),
        }
    return {
        "ok": proc.returncode == 0,
        "timeout": False,
        "rc": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def _version_probe() -> dict[str, object]:
    result = _run_sql("SELECT sqlite_version();\nSELECT sqlite_source_id();\n")
    stdout = str(result.get("stdout") or "")
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    version = lines[0] if lines else ""
    source_id = lines[1] if len(lines) > 1 else ""
    fts5 = _run_sql("CREATE VIRTUAL TABLE t USING fts5(a);\nSELECT 'fts5-ok';\n")
    return {
        "ok": bool(result.get("ok")) and bool(fts5.get("ok")),
        "sqlite_version": version,
        "source_id": source_id,
        "fts5": "fts5-ok" in str(fts5.get("stdout") or ""),
        "sqlite_bin": str(SQLITE_BIN),
        "rc": result.get("rc"),
        "fts5_rc": fts5.get("rc"),
        "stderr": str(result.get("stderr") or "") + str(fts5.get("stderr") or ""),
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"harness {self.address_string()} {fmt % args}", file=sys.stderr, flush=True)

    def _send_json(self, code: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8") + b"\n"
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/health":
            self._send_json(404, {"ok": False, "error": "not-found"})
            return
        self._send_json(200, _version_probe())

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/sql":
            self._send_json(404, {"ok": False, "error": "not-found"})
            return
        length_s = self.headers.get("Content-Length", "0")
        try:
            length = int(length_s)
        except ValueError:
            self._send_json(400, {"ok": False, "error": "bad-content-length"})
            return
        if length < 0 or length > BODY_LIMIT:
            self._send_json(413, {"ok": False, "error": "body-too-large"})
            return
        raw = self.rfile.read(length) if length else b""
        sql = raw.decode("utf-8", errors="replace")
        if not sql.strip():
            self._send_json(400, {"ok": False, "error": "empty-sql"})
            return
        self._send_json(200, _run_sql(sql))


def main() -> int:
    httpd = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    print(f"harness listen {BIND_HOST}:{BIND_PORT}", flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
