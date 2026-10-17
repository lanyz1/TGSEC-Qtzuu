#!/usr/bin/env python3
"""Minimal MySQL client for lab SQL from the OM container (no mysql CLI)."""


import hashlib
import socket
import struct
import sys


def _scramble_native(password: bytes, salt: bytes) -> bytes:
    stage1 = hashlib.sha1(password).digest()
    stage2 = hashlib.sha1(stage1).digest()
    mix = hashlib.sha1(salt[:20] + stage2).digest()
    return bytes(a ^ b for a, b in zip(mix, stage1))


class Mysql:
    def __init__(self, host: str, port: int, user: str, password: str, database: str) -> None:
        self.sock = socket.create_connection((host, port), 20)
        self.sock.settimeout(20)
        greeting = self._read()
        self._handshake(greeting, user, password, database)

    def _recvall(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise OSError("mysql eof")
            buf += chunk
        return bytes(buf)

    def _read(self) -> bytes:
        hdr = self._recvall(4)
        n = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
        return self._recvall(n)

    def _send(self, seq: int, payload: bytes) -> None:
        n = len(payload)
        self.sock.sendall(bytes((n & 255, (n >> 8) & 255, (n >> 16) & 255, seq & 255)) + payload)

    def _handshake(self, g: bytes, user: str, password: str, database: str) -> None:
        i = 1
        i = g.index(b"\x00", i) + 1
        i += 4
        salt = g[i : i + 8]
        i += 9
        i += 2  # caps low
        charset = g[i]
        i += 1
        i += 2  # status
        i += 2  # caps high
        auth_len = g[i]
        i += 1
        i += 10
        rest_len = max(13, auth_len - 8)
        salt += g[i : i + rest_len]
        salt = salt.split(b"\x00")[0]
        i += rest_len
        plugin = b"mysql_native_password"
        if i < len(g):
            plugin = g[i:].split(b"\x00")[0] or plugin

        caps = 0x00000200 | 0x00008000 | 0x00080000 | 0x00000008 | 0x00200000
        scrambled = _scramble_native(password.encode(), salt)
        payload = struct.pack("<I", caps)
        payload += struct.pack("<I", 0xFFFFFF)
        payload += bytes([charset]) + b"\x00" * 23
        payload += user.encode() + b"\x00"
        payload += bytes([len(scrambled)]) + scrambled
        payload += database.encode() + b"\x00"
        payload += plugin + b"\x00"
        self._send(1, payload)
        self._finish(self._read(), password.encode(), salt)

    def _finish(self, resp: bytes, password: bytes, salt: bytes) -> None:
        if resp[0] == 0x00:
            return
        if resp[0] == 0xFF:
            msg = resp[9:].split(b"\x00")[0].decode("utf-8", "replace")
            raise RuntimeError(f"mysql err {msg}")
        if resp[0] == 0xFE:
            rest = resp[1:]
            plugin = b"mysql_native_password"
            if b"\x00" in rest:
                plugin, salt_part = rest.split(b"\x00", 1)
                salt = salt_part.split(b"\x00")[0]
            if plugin not in (b"mysql_native_password", b""):
                raise RuntimeError(f"mysql plugin {plugin!r} unsupported")
            self._send(3, _scramble_native(password, salt))
            self._finish(self._read(), password, salt)
            return
        raise RuntimeError(f"mysql unexpected auth {resp[:24]!r}")

    def query(self, sql: str) -> bytes:
        self._send(0, b"\x03" + sql.encode())
        resp = self._read()
        if resp[0] == 0xFF:
            msg = resp[9:].split(b"\x00")[0].decode("utf-8", "replace")
            raise RuntimeError(f"mysql query {msg}")
        return resp


def main() -> int:
    if len(sys.argv) < 7:
        print("usage: mysql_lab.py host port user password database sql [sql...]", file=sys.stderr)
        return 2
    host, port_s, user, password, database, *sqls = sys.argv[1:]
    conn = Mysql(host, int(port_s), user, password, database)
    for sql in sqls:
        conn.query(sql)
        print(f"IOC mysql-ok {sql[:96]}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
