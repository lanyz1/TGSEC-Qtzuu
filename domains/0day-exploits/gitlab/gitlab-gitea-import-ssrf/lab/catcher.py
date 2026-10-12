#!/usr/bin/env python3
"""HTTPS Gitea-shaped oracle on GitLab loopback."""

from __future__ import annotations

import json
import os
import ssl
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WITNESS = os.environ.get("WITNESS", "GITLAB-GITEA-IMPORT-SSRF-WITNESS")
RATE_LIMIT_RESET = 2147483647
BIND_HOST = "127.0.0.1"


@dataclass(frozen=True)
class CatcherConfig:
    tls_cert: Path
    tls_key: Path
    https_port: int
    https_port_alt: int

    @classmethod
    def from_env(cls) -> CatcherConfig:
        cert = Path(os.environ.get("TLS_CERT", "/certs/gitea.crt"))
        key_raw = os.environ.get("CATCHER_TLS_KEY") or os.environ.get("TLS_KEY", "/certs/gitea.key")
        return cls(
            tls_cert=cert,
            tls_key=Path(key_raw),
            https_port=int(os.environ.get("HTTPS_PORT", "443")),
            https_port_alt=int(os.environ.get("HTTPS_PORT_ALT", "8443")),
        )


def log(msg: str) -> None:
    print(msg, flush=True)


def json_bytes(payload: object, status: int = 200) -> tuple[int, bytes, str]:
    body = json.dumps(payload).encode("utf-8")
    return status, body, "application/json"


def _gitea_user() -> dict[str, object]:
    return {
        "id": 1,
        "login": "lab",
        "username": "lab",
        "email": "lab@localhost.invalid",
    }


def _gitea_repo() -> dict[str, object]:
    return {
        "id": 1,
        "name": WITNESS,
        "full_name": f"lab/{WITNESS}",
        "description": WITNESS,
        "clone_url": "https://gitea.lab/lab/witness.git",
        "html_url": "https://gitea.lab/lab/witness",
        "private": False,
        "owner": {"login": "lab"},
    }


def gitea_payload(path: str) -> tuple[int, bytes, str]:
    user = _gitea_user()
    repo = _gitea_repo()
    if path.endswith("/rate_limit") or path.endswith("/rate_limit/"):
        payload = {
            "resources": {
                "core": {"limit": 5000, "remaining": 4999, "reset": RATE_LIMIT_RESET, "used": 1},
                "search": {"limit": 30, "remaining": 30, "reset": RATE_LIMIT_RESET, "used": 0},
                "graphql": {"limit": 5000, "remaining": 5000, "reset": RATE_LIMIT_RESET, "used": 0},
            },
            "rate": {"limit": 5000, "remaining": 4999, "reset": RATE_LIMIT_RESET, "used": 1},
        }
        return json_bytes(payload)
    if path.rstrip("/").endswith("/user"):
        return json_bytes(user)
    if "/user/repos" in path or path.rstrip("/").endswith("/repos"):
        return json_bytes([repo])
    if path in ("/", "/health", "/healthz"):
        return 200, WITNESS.encode("utf-8"), "text/plain; charset=utf-8"
    return json_bytes([repo])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self) -> None:
        path = self.path.split("?", 1)[0]
        peer = self.client_address[0] if self.client_address else "?"
        host = self.headers.get("Host", "")
        status, body, ctype = gitea_payload(path)
        log(
            f"catcher {self.command} {path} peer={peer} host={host} "
            f"status={status} witness={WITNESS in body.decode('utf-8', 'replace')}"
        )
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.send_header("X-RateLimit-Limit", "5000")
        self.send_header("X-RateLimit-Remaining", "4999")
        self.send_header("X-RateLimit-Reset", str(RATE_LIMIT_RESET))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._reply()

    def do_HEAD(self) -> None:
        self._reply()

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length:
            self.rfile.read(length)
        self._reply()

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("catcher-http " + (fmt % args) + "\n")
        sys.stderr.flush()


def serve(cfg: CatcherConfig, port: int) -> None:
    httpd = ThreadingHTTPServer((BIND_HOST, port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cfg.tls_cert), str(cfg.tls_key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log(f"catcher-listen {BIND_HOST}:{port} witness={WITNESS}")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


def main() -> int:
    cfg = CatcherConfig.from_env()
    if not cfg.tls_cert.is_file() or not cfg.tls_key.is_file():
        log("catcher-fatal missing TLS cert/key")
        return 1
    threads = [
        threading.Thread(target=serve, args=(cfg, cfg.https_port), daemon=False),
        threading.Thread(target=serve, args=(cfg, cfg.https_port_alt), daemon=True),
    ]
    threads[0].start()
    threads[1].start()
    threads[0].join()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as exc:
        log(f"catcher-fatal {exc}")
        raise SystemExit(1)
