#!/usr/bin/env python3
"""HTTP oracle inside the GitLab netns, bound to 0.0.0.1 (not 127.0.0.1)."""

from __future__ import annotations

import http.server
import os
import socket
import subprocess
import sys
from dataclasses import dataclass

DEFAULT_WITNESS = "GITLAB-WEBHOOK-0NET-SSRF-WITNESS"
DEFAULT_HOST = "0.0.0.1"
DEFAULT_PORT = 18080
# linux/in.h IP_FREEBIND
IP_FREEBIND = 15


@dataclass(frozen=True)
class CatcherConfig:
    host: str
    port: int
    witness: str

    @classmethod
    def from_env(cls) -> CatcherConfig:
        return cls(
            host=os.environ.get("BIND_HOST", DEFAULT_HOST),
            port=int(os.environ.get("BIND_PORT", str(DEFAULT_PORT))),
            witness=os.environ.get("WITNESS", DEFAULT_WITNESS),
        )


def log(msg: str) -> None:
    print(msg, flush=True)


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def try_bind(host: str, port: int, *, use_freebind: bool) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if use_freebind:
            sock.setsockopt(socket.SOL_IP, IP_FREEBIND, 1)
        sock.bind((host, port))


def ensure_listen_target(cfg: CatcherConfig) -> str:
    """Deliver 0.0.0.1 locally without putting it on an interface.

    UrlBlocker.validate_localhost unions Socket.ip_address_list. Assigning
    0.0.0.1 to lo would make the denylist treat it as localhost. A local
    fib route keeps the address off ip addr while the kernel still delivers.
    """
    route = _run(["ip", "route", "add", "local", f"{cfg.host}/32", "dev", "lo"])
    log(
        f"catcher-local-route rc={route.returncode} "
        f"{route.stdout.strip()}{route.stderr.strip()}"
    )
    got = _run(["ip", "route", "get", cfg.host])
    log(f"catcher-route-get {got.stdout.strip() or got.stderr.strip()}")

    try:
        try_bind(cfg.host, cfg.port, use_freebind=True)
        log("catcher-bind method=local-route+freebind")
        return "local-route+freebind"
    except OSError as exc:
        log(f"catcher-bind freebind failed: {exc}")

    try:
        try_bind(cfg.host, cfg.port, use_freebind=False)
        log("catcher-bind method=local-route+direct")
        return "local-route+direct"
    except OSError as exc:
        log(f"catcher-bind direct failed: {exc}")

    sysctl = _run(["sysctl", "-w", "net.ipv4.ip_nonlocal_bind=1"])
    log(
        f"catcher-sysctl rc={sysctl.returncode} "
        f"{sysctl.stdout.strip()} {sysctl.stderr.strip()}"
    )
    try:
        try_bind(cfg.host, cfg.port, use_freebind=True)
        log("catcher-bind method=nonlocal+freebind")
        return "nonlocal+freebind"
    except OSError as exc:
        log(f"catcher-bind after sysctl failed: {exc}")

    added = _run(["ip", "addr", "add", f"{cfg.host}/32", "dev", "lo"])
    log(
        f"catcher-ip-addr-add rc={added.returncode} "
        f"{added.stdout.strip()} {added.stderr.strip()}"
    )
    try_bind(cfg.host, cfg.port, use_freebind=True)
    log("catcher-bind method=ip-addr-add")
    return "ip-addr-add"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    witness: str = DEFAULT_WITNESS

    def _read_body(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self.rfile.read(length)

    def _reply(self, write_body: bool) -> None:
        body = self.witness.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if write_body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._reply(True)

    def do_HEAD(self) -> None:
        self._reply(False)

    def do_POST(self) -> None:
        self._read_body()
        self._reply(True)

    def do_PUT(self) -> None:
        self._read_body()
        self._reply(True)

    def do_PATCH(self) -> None:
        self._read_body()
        self._reply(True)

    def do_DELETE(self) -> None:
        self._reply(True)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("catcher " + (fmt % args) + "\n")
        sys.stderr.flush()


class CatcherServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.setsockopt(socket.SOL_IP, IP_FREEBIND, 1)
        except OSError as exc:
            log(f"catcher IP_FREEBIND setsockopt: {exc}")
        super().server_bind()


def main() -> int:
    cfg = CatcherConfig.from_env()
    method = ensure_listen_target(cfg)
    addr = _run(["ip", "-4", "addr", "show", "dev", "lo"])
    log(f"catcher-lo {addr.stdout.strip() or addr.stderr.strip()}")
    log(f"catcher-listen {cfg.host}:{cfg.port} method={method} witness={cfg.witness}")
    Handler.witness = cfg.witness
    httpd = CatcherServer((cfg.host, cfg.port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as exc:
        log(f"catcher-fatal {exc}")
        raise SystemExit(1)
