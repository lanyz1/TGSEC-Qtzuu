#!/usr/bin/env python3
"""Local oracle for unpublished SONiC gNMI empty UserAuth fail-open.

ToR plaintext :18080 and DPU insecure TLS :18081 both skip authenticate()
when UserAuth is empty after setupFlags unsets cert mode with no ca_crt.
Writes stay compiled in (ENABLE_NATIVE_WRITE). Negative: password UserAuth
with no creds is Unauthenticated. Loopback only. No shells.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import NoReturn

LABEL = "SONIC-GNMI-NOAUTH"
WITNESS = "SONIC-GNMI-NOAUTH-WITNESS"
DEFAULT_TOR = "127.0.0.1:18080"
DEFAULT_DPU = "127.0.0.1:18081"
CHECK_METHOD = "/probe.Probe/Check"
TLS_OVERRIDE = "localhost"
GRPC_TIMEOUT_S = 8.0
WIRE_VARINT = 0
WIRE_LEN = 2
FIELD_WITNESS = 1
FIELD_AUTH_ENABLED = 2
FIELD_ENABLE_NATIVE_WRITE = 3
FIELD_ENABLE_TRANSLIB_WRITE = 4
FIELD_USER_AUTH_ANY = 5
FIELD_MODE = 6


@dataclass(frozen=True)
class LabConfig:
    tor: str
    dpu: str
    cert: Path
    timeout_s: float = GRPC_TIMEOUT_S


@dataclass(frozen=True)
class CheckReply:
    witness: str
    auth_enabled: bool
    enable_native_write: bool
    enable_translib_write: bool
    user_auth_any: bool
    mode: str


def load_config() -> LabConfig:
    here = Path(__file__).resolve().parent
    return LabConfig(
        tor=os.environ.get("TOR_ADDR", DEFAULT_TOR),
        dpu=os.environ.get("DPU_ADDR", DEFAULT_DPU),
        cert=here / "certs" / "server.crt",
    )


def fail(reason: str) -> NoReturn:
    print(f"FAIL {LABEL} {reason}", flush=True)
    raise SystemExit(1)


def load_grpc() -> ModuleType:
    try:
        import grpc
    except ImportError:
        fail("grpcio not installed")
    return grpc


def encode_varint(n: int) -> bytes:
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def decode_varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = 0
    n = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if b < 0x80:
            return n, i
        shift += 7


def encode_check_request(require_password: bool = False) -> bytes:
    if not require_password:
        return b""
    return bytes([(1 << 3) | WIRE_VARINT]) + encode_varint(1)


def _as_str(val: object) -> str:
    if isinstance(val, (bytes, bytearray)):
        return val.decode()
    return ""


def decode_check_reply(buf: bytes) -> CheckReply:
    fields: dict[int, object] = {}
    i = 0
    while i < len(buf):
        key, i = decode_varint(buf, i)
        field, wire_type = key >> 3, key & 7
        if wire_type == WIRE_VARINT:
            value, i = decode_varint(buf, i)
            fields[field] = value
        elif wire_type == WIRE_LEN:
            length, i = decode_varint(buf, i)
            fields[field] = buf[i : i + length]
            i += length
        else:
            fail(f"unexpected protobuf wire type {wire_type}")
    return CheckReply(
        witness=_as_str(fields.get(FIELD_WITNESS, b"")),
        auth_enabled=bool(fields.get(FIELD_AUTH_ENABLED, 0)),
        enable_native_write=bool(fields.get(FIELD_ENABLE_NATIVE_WRITE, 0)),
        enable_translib_write=bool(fields.get(FIELD_ENABLE_TRANSLIB_WRITE, 0)),
        user_auth_any=bool(fields.get(FIELD_USER_AUTH_ANY, 0)),
        mode=_as_str(fields.get(FIELD_MODE, b"")),
    )


def call_check(
    cfg: LabConfig,
    target: str,
    tls: bool,
    require_password: bool = False,
) -> CheckReply:
    grpc = load_grpc()
    proxy_off = ("grpc.enable_http_proxy", 0)
    if tls:
        creds = grpc.ssl_channel_credentials(root_certificates=cfg.cert.read_bytes())
        options = (proxy_off, ("grpc.ssl_target_name_override", TLS_OVERRIDE))
        channel = grpc.secure_channel(target, creds, options=options)
    else:
        channel = grpc.insecure_channel(target, options=(proxy_off,))
    try:
        grpc.channel_ready_future(channel).result(timeout=cfg.timeout_s)
        method = channel.unary_unary(
            CHECK_METHOD,
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        raw = method(
            encode_check_request(require_password),
            timeout=cfg.timeout_s,
            metadata=(),
        )
        return decode_check_reply(raw)
    finally:
        channel.close()


def expect_open(cfg: LabConfig, label: str, target: str, tls: bool, mode: str) -> None:
    try:
        reply = call_check(cfg, target, tls=tls, require_password=False)
    except Exception as exc:
        fail(f"{label} check error {type(exc).__name__}: {exc}")
    print(
        f"IOC {label}-check witness={reply.witness} "
        f"auth_enabled={str(reply.auth_enabled).lower()} "
        f"enable_native_write={str(reply.enable_native_write).lower()} "
        f"user_auth_any={str(reply.user_auth_any).lower()} mode={reply.mode}",
        flush=True,
    )
    if reply.witness != WITNESS:
        fail(f"{label} missing witness got={reply.witness!r}")
    if reply.auth_enabled:
        fail(f"{label} auth_enabled true")
    if not reply.enable_native_write:
        fail(f"{label} enable_native_write false")
    if not reply.enable_translib_write:
        fail(f"{label} enable_translib_write false")
    if reply.user_auth_any:
        fail(f"{label} user_auth_any true")
    if reply.mode != mode:
        fail(f"{label} mode={reply.mode!r} expected={mode!r}")


def expect_closed(cfg: LabConfig, label: str, target: str, tls: bool) -> None:
    grpc = load_grpc()
    try:
        reply = call_check(cfg, target, tls=tls, require_password=True)
    except grpc.RpcError as exc:
        code = exc.code().name if hasattr(exc, "code") else "RPC"
        print(f"IOC {label}-negative status={code}", flush=True)
        if exc.code() == grpc.StatusCode.OK:
            fail(f"{label} password mode returned OK")
        return
    except Exception as exc:
        fail(f"{label} negative unexpected {type(exc).__name__}: {exc}")
    fail(f"{label} password mode succeeded reply={reply}")


def main() -> int:
    cfg = load_config()
    load_grpc()
    if not cfg.cert.is_file():
        fail(f"missing lab TLS cert {cfg.cert}")

    print(f"IOC tor-connect {cfg.tor} plaintext no-metadata", flush=True)
    expect_open(cfg, "tor", cfg.tor, tls=False, mode="tor")
    print(
        f"IOC dpu-connect {cfg.dpu} tls-insecure no-client-cert no-metadata",
        flush=True,
    )
    expect_open(cfg, "dpu", cfg.dpu, tls=True, mode="dpu")
    expect_closed(cfg, "tor", cfg.tor, tls=False)
    expect_closed(cfg, "dpu", cfg.dpu, tls=True)
    print(
        f"SUCCESS {LABEL} who=unauth tor=18080 dpu=18081 {WITNESS}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
