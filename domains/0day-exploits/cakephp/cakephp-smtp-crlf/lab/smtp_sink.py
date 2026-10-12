#!/usr/bin/env python3
"""Loopback SMTP sink. Captures DATA for the CakePHP 5.4.2 header-injection lab."""

from __future__ import annotations

import socket
from pathlib import Path

HOST = "0.0.0.0"
PORT = 2525
ORACLE = Path("/oracle")
TIMEOUT_S = 20.0


def log(msg: str) -> None:
    print(msg, flush=True)


def send_line(sock: socket.socket, code: int, text: str) -> None:
    sock.sendall(f"{code} {text}\r\n".encode("ascii"))


def strip_dot_terminator(blob: bytes) -> bytes:
    for marker in (b"\r\n.\r\n", b"\n.\r\n", b"\n.\n"):
        idx = blob.find(marker)
        if idx != -1:
            return blob[:idx]
    return blob.rstrip(b".\r\n")


def recv_until(sock: socket.socket, buf: bytearray, marker: bytes) -> bytes:
    while marker not in buf:
        piece = sock.recv(4096)
        if not piece:
            raise ConnectionResetError("eof")
        buf.extend(piece)
    idx = buf.find(marker)
    taken = bytes(buf[: idx + len(marker)])
    del buf[: idx + len(marker)]
    return taken


def data_complete(buf: bytes) -> bool:
    return b"\r\n.\r\n" in buf or b"\n.\r\n" in buf or buf.endswith(b"\n.\n")


def handle(conn: socket.socket, addr: tuple[str, int]) -> None:
    log(f"conn {addr[0]}:{addr[1]}")
    conn.settimeout(TIMEOUT_S)
    send_line(conn, 220, "lab.local SMTP")
    buf = bytearray()
    while True:
        line = recv_until(conn, buf, b"\n")
        cmd = line.decode("utf-8", errors="replace").strip()
        upper = cmd.upper()
        log(f"cmd {cmd[:120]!r}")
        if upper.startswith("HELO") or upper.startswith("EHLO"):
            send_line(conn, 250, "lab.local")
        elif upper.startswith(("MAIL", "RCPT", "RSET", "NOOP", "VRFY")):
            send_line(conn, 250, "OK")
        elif upper == "DATA":
            send_line(conn, 354, "start mail")
            while not data_complete(bytes(buf)):
                piece = conn.recv(4096)
                if not piece:
                    break
                buf.extend(piece)
            payload = strip_dot_terminator(bytes(buf))
            buf.clear()
            ORACLE.mkdir(parents=True, exist_ok=True)
            (ORACLE / "last.eml").write_bytes(payload)
            (ORACLE / "last.hexlen").write_text(f"{len(payload)}\n", encoding="utf-8")
            log(f"data-bytes={len(payload)}")
            send_line(conn, 250, "OK")
        elif upper == "QUIT":
            send_line(conn, 221, "bye")
            return
        else:
            send_line(conn, 250, "OK")


def main() -> int:
    ORACLE.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(8)
        log(f"listen {HOST}:{PORT}")
        while True:
            conn, addr = server.accept()
            with conn:
                try:
                    handle(conn, addr)
                except (OSError, ConnectionResetError, TimeoutError) as exc:
                    log(f"conn-end {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
