#!/usr/bin/env python3
"""Hostile MySQL protocol stub for mysqldump --tab client-path leftover."""

from __future__ import annotations

import os
import re
import socket
import struct
import threading
import traceback
from dataclasses import dataclass

# mysqldump dump_all_tables_in_db uses hash_key[NAME_LEN]. Keep SHOW TABLES
# names under 192 so this leftover is a client path write, not the G1 overflow.
NAME_LEN = 192

WITNESS = os.environ.get("WITNESS", "MYSQL-DUMP-TAB-TRAVERSAL-WITNESS")
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "3306"))
TRAVERSAL_PORT = int(os.environ.get("TRAVERSAL_PORT", "3307"))
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
SERVER_VERSION = "26.7.0"
CONTROL_TABLE = os.environ.get("CONTROL_TABLE", "t")
TRAVERSAL_TABLE = os.environ.get(
    "TRAVERSAL_TABLE", "/work/oracle/MYSQL-DUMP-TAB-TRAVERSAL-WITNESS"
)

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

PROTOCOL_VERSION = 10
PACKET_HEADER_LEN = 4
OK_HEADER = 0x00
EOF_HEADER = 0xFE
ERR_HEADER = 0xFF
NULL_CELL = 0xFB
AUTH_SWITCH_HEADER = 0xFE
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
COLLATION_UTF8MB4 = "utf8mb4_0900_ai_ci"
ERRNO_NO_SUCH_TABLE = 1146
SQLSTATE_NO_SUCH_TABLE = "42S02"
CLIENT_TIMEOUT_S = 30.0
LISTEN_BACKLOG = 16
COMMAND_SEQ = 1

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
SHOW_TABLES_COLS = ["Tables_in_testdb"]
SHOW_CREATE_COLS = ["Table", "Create Table"]
SHOW_TRIGGERS_COLS = ["Trigger", "Event", "Table", "Statement", "Timing"]
ENGINE_INNODB = "InnoDB"
Cell = bytes | str | None
Row = list[Cell]
PeerAddr = tuple[str, int] | tuple[str, int, int, int]

STATUS_COLS = [
    "Name",
    "Engine",
    "Version",
    "Row_format",
    "Rows",
    "Avg_row_length",
    "Data_length",
    "Max_data_length",
    "Index_length",
    "Data_free",
    "Auto_increment",
    "Create_time",
    "Update_time",
    "Check_time",
    "Collation",
    "Checksum",
    "Create_options",
    "Comment",
]

RE_SHOW_TABLES = re.compile(r"\bshow\s+tables\b")
RE_SHOW_TABLE_STATUS = re.compile(r"\bshow\s+table\s+status\b")
RE_SHOW_CREATE_TABLE = re.compile(r"\bshow\s+create\s+table\b")
RE_SHOW_TRIGGERS = re.compile(r"\bshow\s+triggers\b")
RE_SET = re.compile(r"\bset\b")
RE_SELECT = re.compile(r"\bselect\b")
RE_SHOW = re.compile(r"\bshow\b")
RE_USE = re.compile(r"^\s*use\s+")
RE_LOCK_TABLES = re.compile(r"\b(un)?lock\s+tables\b")
RE_VERSION = re.compile(r"version")
RE_COLLATION = re.compile(r"collation_database")
RE_SHOW_VARIABLES = re.compile(r"\bshow\s+variables\b")
RE_SCHEMA_SELECT = re.compile(
    r"information_schema|performance_schema|column_masking_policy"
)

_thread_ids = 0
_tid_lock = threading.Lock()


@dataclass(frozen=True)
class StubConfig:
    bind_host: str
    control_port: int
    traversal_port: int
    witness: str
    control_table: str
    traversal_table: str
    server_version: str


@dataclass
class ClientSession:
    sock: socket.socket
    peer: str
    table_name: str
    label: str
    deprecate_eof: bool


def load_config() -> StubConfig:
    return StubConfig(
        bind_host=BIND_HOST,
        control_port=CONTROL_PORT,
        traversal_port=TRAVERSAL_PORT,
        witness=WITNESS,
        control_table=CONTROL_TABLE,
        traversal_table=TRAVERSAL_TABLE,
        server_version=SERVER_VERSION,
    )


def log(msg: str) -> None:
    print(msg, flush=True)


def require_name_len(table: str, label: str) -> None:
    encoded = table.encode("utf-8")
    if len(encoded) >= NAME_LEN:
        raise SystemExit(
            f"table name exceeds NAME_LEN={NAME_LEN} label={label} bytes={len(encoded)}"
        )


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
    # Always EOF-shaped 0xFE. The proven dump client accepts this terminator
    # whether or not CLIENT_DEPRECATE_EOF is set.
    send_packet(sock, seq, ok_payload(EOF_HEADER))


def send_ok(sock: socket.socket, seq: int) -> None:
    send_packet(sock, seq, ok_payload())


def send_no_such_table(sock: socket.socket, seq: int) -> None:
    send_packet(
        sock,
        seq,
        err_payload(ERRNO_NO_SUCH_TABLE, SQLSTATE_NO_SUCH_TABLE, "Table 'testdb.t' doesn't exist"),
    )


def status_row(table_name: str) -> Row:
    return [
        table_name,
        ENGINE_INNODB,
        "10",
        "Dynamic",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        None,
        "2026-01-01 00:00:00",
        None,
        None,
        COLLATION_UTF8MB4,
        None,
        "",
        WITNESS,
    ]


def create_table_sql(table_name: str) -> str:
    quoted = "`" + table_name.replace("`", "``") + "`"
    return (
        f"CREATE TABLE {quoted} (\n"
        f"  `id` int NOT NULL\n"
        f") ENGINE={ENGINE_INNODB} DEFAULT CHARSET=utf8mb4 "
        f"COMMENT='{WITNESS}'"
    )


def _norm_sql(query: str) -> str:
    return query.strip().strip(";").lower()


def _hit(pattern: re.Pattern[str], q: str) -> bool:
    return pattern.search(q) is not None


def handle_query(session: ClientSession, seq: int, query: str) -> None:
    sock = session.sock
    table_name = session.table_name
    deprecate_eof = session.deprecate_eof
    q = _norm_sql(query)
    log(f"query peer={session.peer} sql={query!r}")

    if _hit(RE_SHOW_TABLES, q):
        send_result(sock, seq, SHOW_TABLES_COLS, [[table_name]], deprecate_eof)
        return

    if _hit(RE_SHOW_TABLE_STATUS, q):
        send_result(sock, seq, STATUS_COLS, [status_row(table_name)], deprecate_eof)
        return

    # First column name must be Table; mysqldump reads field names here.
    if _hit(RE_SHOW_CREATE_TABLE, q):
        send_result(
            sock,
            seq,
            SHOW_CREATE_COLS,
            [[table_name, create_table_sql(table_name)]],
            deprecate_eof,
        )
        return

    if _hit(RE_SHOW_TRIGGERS, q):
        send_result(sock, seq, SHOW_TRIGGERS_COLS, [], deprecate_eof)
        return

    # SET SQL_QUOTE_SHOW_CREATE and character_set_results (binary, then utf8mb4).
    if _hit(RE_SET, q) and not _hit(RE_SELECT, q) and not _hit(RE_SHOW, q):
        send_ok(sock, seq)
        return

    if _hit(RE_USE, q) or _hit(RE_LOCK_TABLES, q):
        send_ok(sock, seq)
        return

    if _hit(RE_SELECT, q) and _hit(RE_VERSION, q):
        send_result(sock, seq, ["version()"], [[SERVER_VERSION]], deprecate_eof)
        return

    if _hit(RE_SELECT, q) and _hit(RE_COLLATION, q):
        send_result(
            sock,
            seq,
            ["@@collation_database"],
            [[COLLATION_UTF8MB4]],
            deprecate_eof,
        )
        return

    if _hit(RE_SHOW_VARIABLES, q) or (_hit(RE_SELECT, q) and _hit(RE_SCHEMA_SELECT, q)):
        send_result(sock, seq, ["Value"], [], deprecate_eof)
        return

    # SHOW FIELDS after the client .sql write may 1146; dump still keeps the file.
    if _hit(RE_SELECT, q) or _hit(RE_SHOW, q):
        send_no_such_table(sock, seq)
        return

    send_ok(sock, seq)


def peer_name(addr: PeerAddr) -> str:
    return f"{addr[0]}:{addr[1]}"


def handle_client(
    conn: socket.socket,
    addr: PeerAddr,
    table_name: str,
    label: str,
) -> None:
    peer = peer_name(addr)
    log(f"accept label={label} peer={peer}")
    conn.settimeout(CLIENT_TIMEOUT_S)
    try:
        tid = next_thread_id()
        send_packet(conn, 0, handshake_payload(tid))
        pkt = read_packet(conn)
        if pkt is None:
            return
        _seq, payload = pkt
        caps, plugin = parse_handshake_response(payload)
        log(f"handshake label={label} peer={peer} caps=0x{caps:08x} plugin={plugin!r}")
        seq = 2
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
            table_name=table_name,
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
            if cmd in (COM_PING, COM_RESET_CONNECTION, COM_STATISTICS):
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
            if cmd == COM_QUERY:
                handle_query(session, COMMAND_SEQ, body.decode("utf-8", "replace"))
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


def serve(cfg: StubConfig, port: int, table_name: str, label: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((cfg.bind_host, port))
    sock.listen(LISTEN_BACKLOG)
    log(f"listen label={label} bind={cfg.bind_host}:{port} table={table_name!r}")
    while True:
        conn, addr = sock.accept()
        threading.Thread(
            target=handle_client,
            args=(conn, addr, table_name, label),
            daemon=True,
        ).start()


def main() -> None:
    cfg = load_config()
    require_name_len(cfg.control_table, "control")
    require_name_len(cfg.traversal_table, "traversal")
    log(
        f"stub start control={cfg.bind_host}:{cfg.control_port} "
        f"traversal={cfg.bind_host}:{cfg.traversal_port} "
        f"control_table={cfg.control_table!r} traversal_table={cfg.traversal_table!r} "
        f"witness={cfg.witness}"
    )
    threading.Thread(
        target=serve,
        args=(cfg, cfg.control_port, cfg.control_table, "control"),
        daemon=True,
    ).start()
    serve(cfg, cfg.traversal_port, cfg.traversal_table, "traversal")


if __name__ == "__main__":
    main()
