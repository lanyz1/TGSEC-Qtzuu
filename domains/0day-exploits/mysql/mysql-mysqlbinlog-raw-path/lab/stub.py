#!/usr/bin/env python3
"""Hostile MySQL protocol stub for mysqlbinlog --raw -R ident leftover."""

from __future__ import annotations

import os
import re
import socket
import struct
import threading
import traceback
from dataclasses import dataclass
from typing import Pattern

WITNESS = os.environ.get("WITNESS", "MYSQL-BINLOG-RAW-WITNESS")
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "3306"))
TRAVERSAL_PORT = int(os.environ.get("TRAVERSAL_PORT", "3307"))
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
SERVER_VERSION = "26.7.0"
CONTROL_IDENT = os.environ.get("CONTROL_IDENT", "mysql-bin.000001")
TRAVERSAL_IDENT = os.environ.get("TRAVERSAL_IDENT", f"/work/oracle/{WITNESS}")
REQUESTED_LOG = os.environ.get("REQUESTED_LOG", "mysql-bin.000001")

CLIENT_LONG_PASSWORD = 1
CLIENT_FOUND_ROWS = 2
CLIENT_LONG_FLAG = 4
CLIENT_CONNECT_WITH_DB = 8
CLIENT_PROTOCOL_41 = 512
CLIENT_TRANSACTIONS = 8192
CLIENT_SECURE_CONNECTION = 32768
CLIENT_MULTI_RESULTS = 1 << 17
CLIENT_PS_MULTI_RESULTS = 1 << 18
CLIENT_PLUGIN_AUTH = 1 << 19
CLIENT_CONNECT_ATTRS = 1 << 20
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1 << 21
CLIENT_DEPRECATE_EOF = 1 << 24

SERVER_STATUS_AUTOCOMMIT = 0x0002

COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_FIELD_LIST = 0x04
COM_STATISTICS = 0x09
COM_PING = 0x0E
COM_BINLOG_DUMP = 0x12
COM_REGISTER_SLAVE = 0x15
COM_SET_OPTION = 0x1B
COM_RESET_CONNECTION = 0x1F

PROTOCOL_VERSION = 10
PACKET_HEADER_LEN = 4
OK_HEADER = 0x00
EOF_HEADER = 0xFE
AUTH_SWITCH_HEADER = 0xFE
NULL_CELL = 0xFB
LENENC_MARK_2B = 0xFC
LENENC_MARK_3B = 0xFD
LENENC_MARK_8B = 0xFE
LENENC_1B_LIMIT = 251
COLUMN_LENGTH_CODE = 0x0C
COLUMN_MAX_OCTETS = 16 * 1024 * 1024
AUTH_PLUGIN_DATA_LEN = 21
RESERVED_FILLER_LEN = 10
# HandshakeResponse41: capability(4) max_packet(4) charset(1) reserved(23)
HANDSHAKE_RESPONSE_SKIP = 4 + 4 + 1 + 23
SCRAMBLE_LEN = 20
AUTH_PLUGIN = "mysql_native_password"
MYSQL_TYPE_VAR_STRING = 0xFD
CHARSET_UTF8MB4 = 45
CLIENT_TIMEOUT_S = 30.0
LISTEN_BACKLOG = 16
COMMAND_SEQ = 1
HANDSHAKE_SEQ = 0
AUTH_RESPONSE_SEQ = 2

ROTATE_EVENT = 4
FORMAT_DESCRIPTION_EVENT = 15
LOG_EVENT_HEADER_LEN = 19
LOG_EVENT_ARTIFICIAL_F = 0x20
BINLOG_VERSION = 4
ST_SERVER_VER_LEN = 50
LOG_EVENT_TYPES = 42
SERVER_ID = 1
BINLOG_FIRST_POS = 4
BINLOG_DUMP_MIN_LEN = 10
CHECKSUM_ALG_OFF = 0
FD_CRC32_PLACEHOLDER = b"\x00\x00\x00\x00"
FAKE_ROTATE_TS = 0
REAL_ROTATE_TS = 1
FD_EVENT_TS = 1

# post_header_len[event_type - 1] matching Format_description_event v4 / 26.7.0
POST_HEADER_LENS = bytes(
    [
        0,
        13,
        0,
        8,
        0,
        0,
        0,
        0,
        4,
        0,
        4,
        0,
        0,
        0,
        99,
        0,
        4,
        26,
        8,
        0,
        0,
        0,
        0,
        0,
        0,
        2,
        0,
        0,
        0,
        10,
        10,
        10,
        42,
        42,
        0,
        18,
        52,
        0,
        10,
        40,
        0,
        0,
    ]
)
assert len(POST_HEADER_LENS) == LOG_EVENT_TYPES

SERVER_CAPS = (
    CLIENT_LONG_PASSWORD
    | CLIENT_FOUND_ROWS
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_RESULTS
    | CLIENT_PS_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH
    | CLIENT_CONNECT_ATTRS
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | CLIENT_DEPRECATE_EOF
)

SCRAMBLE = b"a" * SCRAMBLE_LEN
Cell = bytes | str | None
Row = list[Cell]
PeerAddr = tuple[str, int] | tuple[str, int, int, int]

RE_SET = re.compile(r"\bset\b")
RE_SELECT = re.compile(r"\bselect\b")
RE_SHOW = re.compile(r"\bshow\b")
RE_USE = re.compile(r"^\s*use\s+")
RE_VERSION = re.compile(r"version")

_thread_ids = 0
_tid_lock = threading.Lock()


@dataclass(frozen=True)
class StubConfig:
    bind_host: str
    control_port: int
    traversal_port: int
    witness: str
    control_ident: str
    traversal_ident: str
    requested_log: str
    server_version: str


@dataclass(frozen=True)
class BinlogDumpRequest:
    pos: int
    flags: int
    server_id: int
    filename: str


@dataclass
class ClientSession:
    sock: socket.socket
    peer: str
    label: str
    deprecate_eof: bool


def load_config() -> StubConfig:
    return StubConfig(
        bind_host=BIND_HOST,
        control_port=CONTROL_PORT,
        traversal_port=TRAVERSAL_PORT,
        witness=WITNESS,
        control_ident=CONTROL_IDENT,
        traversal_ident=TRAVERSAL_IDENT,
        requested_log=REQUESTED_LOG,
        server_version=SERVER_VERSION,
    )


def log(msg: str) -> None:
    print(msg, flush=True)


def next_thread_id() -> int:
    global _thread_ids
    with _tid_lock:
        _thread_ids += 1
        return _thread_ids


def pack_u24(n: int) -> bytes:
    return bytes((n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF))


def unpack_u24(raw: bytes) -> int:
    return raw[0] | (raw[1] << 8) | (raw[2] << 16)


def lenenc_int(n: int) -> bytes:
    if n < LENENC_1B_LIMIT:
        return bytes([n])
    if n < 2**16:
        return bytes([LENENC_MARK_2B]) + struct.pack("<H", n)
    if n < 2**24:
        return bytes([LENENC_MARK_3B]) + struct.pack("<I", n)[:3]
    return bytes([LENENC_MARK_8B]) + struct.pack("<Q", n)


def lenenc_str(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return lenenc_int(len(data)) + data


def recvall(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_packet(sock: socket.socket) -> tuple[int, bytes] | None:
    hdr = recvall(sock, PACKET_HEADER_LEN)
    if not hdr:
        return None
    length = unpack_u24(hdr)
    seq = hdr[3]
    payload = recvall(sock, length) if length else b""
    if payload is None:
        return None
    return seq, payload


def send_packet(sock: socket.socket, seq: int, payload: bytes) -> int:
    sock.sendall(pack_u24(len(payload)) + bytes([seq & 0xFF]) + payload)
    return seq + 1


def ok_payload(header: int = OK_HEADER) -> bytes:
    return (
        bytes([header, 0x00, 0x00])
        + struct.pack("<H", SERVER_STATUS_AUTOCOMMIT)
        + struct.pack("<H", 0)
    )


def handshake_payload(thread_id: int) -> bytes:
    caps_low = SERVER_CAPS & 0xFFFF
    caps_high = (SERVER_CAPS >> 16) & 0xFFFF
    payload = bytearray()
    payload.append(PROTOCOL_VERSION)
    payload.extend(SERVER_VERSION.encode("ascii") + b"\x00")
    payload.extend(struct.pack("<I", thread_id))
    payload.extend(SCRAMBLE[:8])
    payload.append(0)
    payload.extend(struct.pack("<H", caps_low))
    payload.append(CHARSET_UTF8MB4)
    payload.extend(struct.pack("<H", SERVER_STATUS_AUTOCOMMIT))
    payload.extend(struct.pack("<H", caps_high))
    payload.append(AUTH_PLUGIN_DATA_LEN)
    payload.extend(b"\x00" * RESERVED_FILLER_LEN)
    payload.extend(SCRAMBLE[8:] + b"\x00")
    payload.extend(AUTH_PLUGIN.encode("ascii") + b"\x00")
    return bytes(payload)


def _skip_lenenc_auth(payload: bytes, pos: int) -> int | None:
    if pos >= len(payload):
        return None
    first = payload[pos]
    if first < LENENC_1B_LIMIT:
        return pos + 1 + first
    if first == LENENC_MARK_2B and pos + 3 <= len(payload):
        alen = struct.unpack_from("<H", payload, pos + 1)[0]
        return pos + 3 + alen
    return None


def parse_handshake_response(payload: bytes) -> tuple[int, str]:
    if len(payload) < HANDSHAKE_RESPONSE_SKIP:
        return 0, ""
    caps = struct.unpack_from("<I", payload, 0)[0]
    pos = HANDSHAKE_RESPONSE_SKIP
    z = payload.find(b"\x00", pos)
    if z < 0:
        return caps, ""
    pos = z + 1
    if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        nxt = _skip_lenenc_auth(payload, pos)
        if nxt is None:
            return caps, ""
        pos = nxt
    elif caps & CLIENT_SECURE_CONNECTION:
        if pos >= len(payload):
            return caps, ""
        pos += 1 + payload[pos]
    else:
        z = payload.find(b"\x00", pos)
        pos = len(payload) if z < 0 else z + 1
    if caps & CLIENT_CONNECT_WITH_DB:
        z = payload.find(b"\x00", pos)
        if z < 0:
            return caps, ""
        pos = z + 1
    plugin = ""
    if caps & CLIENT_PLUGIN_AUTH:
        z = payload.find(b"\x00", pos)
        if z >= 0:
            plugin = payload[pos:z].decode("ascii", "replace")
    return caps, plugin


def auth_switch_payload() -> bytes:
    return bytes([AUTH_SWITCH_HEADER]) + AUTH_PLUGIN.encode("ascii") + b"\x00" + SCRAMBLE + b"\x00"


def column_def(name: str) -> bytes:
    nb = name.encode("utf-8")
    payload = bytearray()
    payload.extend(lenenc_str(b"def"))
    payload.extend(lenenc_str(b""))
    payload.extend(lenenc_str(b""))
    payload.extend(lenenc_str(b""))
    payload.extend(lenenc_str(nb))
    payload.extend(lenenc_str(nb))
    payload.append(COLUMN_LENGTH_CODE)
    payload.extend(struct.pack("<H", CHARSET_UTF8MB4))
    payload.extend(struct.pack("<I", COLUMN_MAX_OCTETS))
    payload.append(MYSQL_TYPE_VAR_STRING)
    payload.extend(struct.pack("<H", 0))
    payload.append(0)
    payload.extend(b"\x00\x00")
    return bytes(payload)


def encode_cell(cell: Cell) -> bytes:
    if cell is None:
        return bytes([NULL_CELL])
    return lenenc_str(cell)


def send_result(
    sock: socket.socket,
    seq: int,
    columns: list[str],
    rows: list[Row],
    deprecate_eof: bool,
) -> None:
    seq = send_packet(sock, seq, lenenc_int(len(columns)))
    for col in columns:
        seq = send_packet(sock, seq, column_def(col))
    if not deprecate_eof:
        seq = send_packet(sock, seq, ok_payload(EOF_HEADER))
    for row in rows:
        seq = send_packet(sock, seq, b"".join(encode_cell(cell) for cell in row))
    # Always EOF-shaped 0xFE. mysqlbinlog accepts this terminator whether or
    # not CLIENT_DEPRECATE_EOF is set.
    send_packet(sock, seq, ok_payload(EOF_HEADER))


def send_ok(sock: socket.socket, seq: int) -> None:
    send_packet(sock, seq, ok_payload())


def event_header(
    timestamp: int,
    event_type: int,
    event_size: int,
    log_pos: int,
    flags: int = 0,
    server_id: int = SERVER_ID,
) -> bytes:
    return (
        struct.pack("<I", timestamp)
        + bytes([event_type])
        + struct.pack("<I", server_id)
        + struct.pack("<I", event_size)
        + struct.pack("<I", log_pos)
        + struct.pack("<H", flags)
    )


def rotate_event(
    ident: str,
    timestamp: int,
    next_pos: int = BINLOG_FIRST_POS,
    flags: int = 0,
) -> bytes:
    ident_b = ident.encode("utf-8")
    post = struct.pack("<Q", next_pos) + ident_b
    event_size = LOG_EVENT_HEADER_LEN + len(post)
    return event_header(timestamp, ROTATE_EVENT, event_size, 0, flags) + post


def format_description_event() -> bytes:
    ver = SERVER_VERSION.encode("ascii")[: ST_SERVER_VER_LEN - 1]
    ver = ver + b"\x00" * (ST_SERVER_VER_LEN - len(ver))
    body = (
        struct.pack("<H", BINLOG_VERSION)
        + ver
        + struct.pack("<I", 1)
        + bytes([LOG_EVENT_HEADER_LEN])
        + POST_HEADER_LENS
        + bytes([CHECKSUM_ALG_OFF])
        + FD_CRC32_PLACEHOLDER  # CRC room (FD still carries (V) even when OFF)
    )
    event_size = LOG_EVENT_HEADER_LEN + len(body)
    return event_header(FD_EVENT_TS, FORMAT_DESCRIPTION_EVENT, event_size, BINLOG_FIRST_POS, 0) + body


def dump_event_packets(cfg: StubConfig, label: str) -> list[bytes]:
    fake = rotate_event(
        cfg.requested_log,
        timestamp=FAKE_ROTATE_TS,
        next_pos=BINLOG_FIRST_POS,
        flags=LOG_EVENT_ARTIFICIAL_F,
    )
    fd = format_description_event()
    if label == "control":
        log(
            f"dump-plan label={label} events=fake-rotate({cfg.requested_log!r},ts={FAKE_ROTATE_TS}),"
            f"fd size_fake={len(fake)} size_fd={len(fd)}"
        )
        return [fake, fd]
    real = rotate_event(
        cfg.traversal_ident,
        timestamp=REAL_ROTATE_TS,
        next_pos=BINLOG_FIRST_POS,
        flags=0,
    )
    log(
        f"dump-plan label={label} events=fake-rotate({cfg.requested_log!r},ts={FAKE_ROTATE_TS}),"
        f"real-rotate({cfg.traversal_ident!r},ts={REAL_ROTATE_TS}),fd "
        f"size_fake={len(fake)} size_real={len(real)} size_fd={len(fd)}"
    )
    return [fake, real, fd]


def _hit(pattern: Pattern[str], q: str) -> bool:
    return pattern.search(q) is not None


def handle_query(session: ClientSession, seq: int, query: str) -> None:
    q = query.strip().strip(";").lower()
    log(f"query label={session.label} peer={session.peer} sql={query!r}")

    if _hit(RE_SET, q) and not _hit(RE_SELECT, q) and not _hit(RE_SHOW, q):
        send_ok(session.sock, seq)
        return

    if _hit(RE_USE, q):
        send_ok(session.sock, seq)
        return

    if _hit(RE_SELECT, q) and _hit(RE_VERSION, q):
        send_result(session.sock, seq, ["VERSION()"], [[SERVER_VERSION]], session.deprecate_eof)
        return

    if _hit(RE_SELECT, q) or _hit(RE_SHOW, q):
        send_result(session.sock, seq, ["Value"], [], session.deprecate_eof)
        return

    send_ok(session.sock, seq)


def parse_binlog_dump(body: bytes) -> BinlogDumpRequest:
    if len(body) < BINLOG_DUMP_MIN_LEN:
        return BinlogDumpRequest(0, 0, 0, "")
    pos, flags, server_id = struct.unpack_from("<IHI", body, 0)
    filename = body[BINLOG_DUMP_MIN_LEN:].decode("utf-8", "replace")
    return BinlogDumpRequest(pos, flags, server_id, filename)


def handle_binlog_dump(cfg: StubConfig, session: ClientSession, body: bytes) -> None:
    req = parse_binlog_dump(body)
    log(
        f"binlog-dump label={session.label} peer={session.peer} pos={req.pos} "
        f"flags=0x{req.flags:04x} server_id={req.server_id} filename={req.filename!r}"
    )
    seq = COMMAND_SEQ
    for ev in dump_event_packets(cfg, session.label):
        etype = ev[4] if len(ev) > 4 else -1
        ts = struct.unpack_from("<I", ev, 0)[0] if len(ev) >= 4 else -1
        log(
            f"binlog-event label={session.label} type={etype} ts={ts} size={len(ev)} "
            f"hex={ev[:32].hex()}"
        )
        seq = send_packet(session.sock, seq, bytes([OK_HEADER]) + ev)
    send_packet(session.sock, seq, bytes([EOF_HEADER]))
    log(f"binlog-dump-eof label={session.label} peer={session.peer}")


def peer_name(addr: PeerAddr) -> str:
    return f"{addr[0]}:{addr[1]}"


def handle_client(
    cfg: StubConfig,
    conn: socket.socket,
    addr: PeerAddr,
    label: str,
) -> None:
    peer = peer_name(addr)
    log(f"accept label={label} peer={peer}")
    conn.settimeout(CLIENT_TIMEOUT_S)
    try:
        tid = next_thread_id()
        send_packet(conn, HANDSHAKE_SEQ, handshake_payload(tid))
        pkt = read_packet(conn)
        if pkt is None:
            return
        _seq, payload = pkt
        caps, plugin = parse_handshake_response(payload)
        log(f"handshake label={label} peer={peer} caps=0x{caps:08x} plugin={plugin!r}")
        seq = AUTH_RESPONSE_SEQ
        if plugin and plugin not in (AUTH_PLUGIN, ""):
            seq = send_packet(conn, seq, auth_switch_payload())
            nxt = read_packet(conn)
            if nxt is None:
                return
            seq = nxt[0] + 1
        send_ok(conn, seq)
        session = ClientSession(
            sock=conn,
            peer=peer,
            label=label,
            deprecate_eof=bool(caps & CLIENT_DEPRECATE_EOF),
        )
        while True:
            pkt = read_packet(conn)
            if pkt is None:
                return
            _cseq, command = pkt
            if not command:
                continue
            cmd = command[0]
            body = command[1:]
            if cmd == COM_QUIT:
                log(f"quit label={label} peer={peer}")
                return
            if cmd in (COM_PING, COM_RESET_CONNECTION, COM_STATISTICS, COM_SET_OPTION):
                send_ok(conn, COMMAND_SEQ)
                continue
            if cmd == COM_INIT_DB:
                db = body.split(b"\x00", 1)[0].decode("utf-8", "replace")
                log(f"init_db label={label} peer={peer} db={db!r}")
                send_ok(conn, COMMAND_SEQ)
                continue
            if cmd == COM_FIELD_LIST:
                send_result(conn, COMMAND_SEQ, ["Field"], [], session.deprecate_eof)
                continue
            if cmd == COM_REGISTER_SLAVE:
                log(f"register-slave label={label} peer={peer} len={len(body)}")
                send_ok(conn, COMMAND_SEQ)
                continue
            if cmd == COM_QUERY:
                handle_query(session, COMMAND_SEQ, body.decode("utf-8", "replace"))
                continue
            if cmd == COM_BINLOG_DUMP:
                handle_binlog_dump(cfg, session, body)
                continue
            log(f"unknown-cmd label={label} peer={peer} cmd=0x{cmd:02x} len={len(body)}")
            send_ok(conn, COMMAND_SEQ)
    except (TimeoutError, socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as exc:
        log(f"disconnect label={label} peer={peer} err={exc}")
    except Exception:
        log(f"stub-error label={label} peer={peer}\n{traceback.format_exc()}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(cfg: StubConfig, port: int, ident: str, label: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((cfg.bind_host, port))
    sock.listen(LISTEN_BACKLOG)
    log(f"listen label={label} bind={cfg.bind_host}:{port} ident={ident!r}")
    while True:
        conn, addr = sock.accept()
        threading.Thread(
            target=handle_client,
            args=(cfg, conn, addr, label),
            daemon=True,
        ).start()


def main() -> None:
    cfg = load_config()
    log(
        f"stub start control={cfg.bind_host}:{cfg.control_port} "
        f"traversal={cfg.bind_host}:{cfg.traversal_port} "
        f"control_ident={cfg.control_ident!r} traversal_ident={cfg.traversal_ident!r} "
        f"witness={cfg.witness}"
    )
    threading.Thread(
        target=serve,
        args=(cfg, cfg.control_port, cfg.control_ident, "control"),
        daemon=True,
    ).start()
    serve(cfg, cfg.traversal_port, cfg.traversal_ident, "traversal")


if __name__ == "__main__":
    main()
