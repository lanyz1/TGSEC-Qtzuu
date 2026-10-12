#!/usr/bin/env python3
"""Rebind DNS for ghe.lab: public A until flip file exists, then loopback."""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_HTTPS = 65
QCLASS_IN = 1
DNS_HEADER_LEN = 12

LogFn = Callable[[str], None]


@dataclass(frozen=True)
class DnsConfig:
    ghe_name: str
    public_ip: str
    rebind_ip: str
    shared_dir: Path
    log_dir: Path
    bind: str
    port: int
    forwarder: str

    @classmethod
    def from_env(cls) -> DnsConfig:
        return cls(
            ghe_name=os.environ.get("GHE_NAME", "ghe.lab").rstrip(".").lower(),
            public_ip=os.environ.get("PUBLIC_IP", "1.1.1.1"),
            rebind_ip=os.environ.get("REBIND_IP", "127.0.0.1"),
            shared_dir=Path(os.environ.get("SHARED_DIR", "/shared")),
            log_dir=Path(os.environ.get("LOG_DIR", "/logs")),
            bind=os.environ.get("DNS_BIND", "0.0.0.0"),
            port=int(os.environ.get("DNS_PORT", "53")),
            forwarder=os.environ.get("FORWARDER", "8.8.8.8"),
        )

    @property
    def flip_path(self) -> Path:
        return self.shared_dir / "rebind_flip"

    @property
    def log_path(self) -> Path:
        return self.log_dir / "dns.log"


def make_logger(cfg: DnsConfig) -> LogFn:
    def log(msg: str) -> None:
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}"
        print(line, flush=True)
        cfg.log_dir.mkdir(parents=True, exist_ok=True)
        with cfg.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    return log


def flipped(cfg: DnsConfig) -> bool:
    return cfg.flip_path.exists()


def ghe_ip(cfg: DnsConfig) -> str:
    return cfg.rebind_ip if flipped(cfg) else cfg.public_ip


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    orig = offset
    seen: set[int] = set()
    while True:
        if offset >= len(data):
            raise ValueError("name overflow")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("ptr overflow")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in seen:
                raise ValueError("ptr loop")
            seen.add(ptr)
            if not jumped:
                orig = offset + 2
                jumped = True
            offset = ptr
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels).rstrip(".").lower(), (orig if jumped else offset)


def encode_name(name: str) -> bytes:
    out = bytearray()
    cleaned = name.rstrip(".")
    if cleaned:
        for label in cleaned.split("."):
            raw = label.encode("ascii")
            out.append(len(raw))
            out.extend(raw)
    out.append(0)
    return bytes(out)


def parse_query(data: bytes) -> tuple[int, str, int, int] | None:
    if len(data) < DNS_HEADER_LEN:
        return None
    txid, flags, qdcount, *_rest = struct.unpack("!HHHHHH", data[:DNS_HEADER_LEN])
    if qdcount < 1:
        return None
    name, offset = decode_name(data, DNS_HEADER_LEN)
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return txid, name, qtype, qclass


def build_response(
    query: bytes,
    txid: int,
    qname: str,
    qtype: int,
    answers: list[tuple[int, int, bytes]],
) -> bytes:
    flags = 0x8400  # QR, AA
    if query[2] & 0x01:
        flags |= 0x0100  # RD
    flags |= 0x0080  # RA
    header = struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0)
    question = encode_name(qname) + struct.pack("!HH", qtype, QCLASS_IN)
    body = bytearray()
    for atype, ttl, rdata in answers:
        body.extend(b"\xc0\x0c")
        body.extend(struct.pack("!HHIH", atype, QCLASS_IN, ttl, len(rdata)))
        body.extend(rdata)
    return header + question + bytes(body)


def is_ghe(cfg: DnsConfig, qname: str) -> bool:
    return qname == cfg.ghe_name or qname.endswith("." + cfg.ghe_name)


def handle_ghe(
    cfg: DnsConfig,
    log: LogFn,
    query: bytes,
    txid: int,
    qname: str,
    qtype: int,
) -> bytes:
    ip = ghe_ip(cfg)
    if qtype == QTYPE_A:
        rdata = socket.inet_aton(ip)
        log(f"A {qname} -> {ip} flip={int(flipped(cfg))}")
        return build_response(query, txid, qname, qtype, [(QTYPE_A, 0, rdata)])
    log(f"NODATA {qname} qtype={qtype} flip={int(flipped(cfg))}")
    return build_response(query, txid, qname, qtype, [])


def forward(cfg: DnsConfig, log: LogFn, query: bytes) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        try:
            sock.sendto(query, (cfg.forwarder, 53))
            data, _addr = sock.recvfrom(4096)
            return data
        except OSError as exc:
            log(f"forward-error {exc}")
            return None


def nxdomain(query: bytes, txid: int, qname: str, qtype: int) -> bytes:
    flags = 0x8403
    if query[2] & 0x01:
        flags |= 0x0100
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_name(qname) + struct.pack("!HH", qtype, QCLASS_IN)
    return header + question


def serve_one(
    cfg: DnsConfig,
    log: LogFn,
    data: bytes,
    addr: tuple[str, int],
    sock: socket.socket,
) -> None:
    try:
        parsed = parse_query(data)
        if not parsed:
            return
        txid, qname, qtype, qclass = parsed
        if qclass != QCLASS_IN:
            return
        if is_ghe(cfg, qname):
            resp = handle_ghe(cfg, log, data, txid, qname, qtype)
        else:
            resp = forward(cfg, log, data)
            if resp is None:
                resp = nxdomain(data, txid, qname, qtype)
                log(f"nxdomain {qname} qtype={qtype}")
            else:
                log(f"forward {qname} qtype={qtype} bytes={len(resp)}")
        sock.sendto(resp, addr)
    except (OSError, ValueError, struct.error) as exc:
        log(f"handler-error {exc}")
    except Exception as exc:
        log(f"handler-error {exc}")


def main() -> int:
    cfg = DnsConfig.from_env()
    log = make_logger(cfg)
    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((cfg.bind, cfg.port))
        log(
            f"dns-listen {cfg.bind}:{cfg.port} ghe={cfg.ghe_name} "
            f"public={cfg.public_ip} rebind={cfg.rebind_ip}"
        )
        while True:
            data, addr = sock.recvfrom(4096)
            threading.Thread(
                target=serve_one,
                args=(cfg, log, data, addr, sock),
                daemon=True,
            ).start()
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
