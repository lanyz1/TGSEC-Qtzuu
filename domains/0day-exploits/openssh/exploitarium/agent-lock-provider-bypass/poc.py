import argparse
import os
import socket
import struct
import time


LOCK = 22
UNLOCK = 23
ADD_SMARTCARD_KEY = 20
SUCCESS = b"\x06"


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


def recv_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("agent closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def request(sock, body):
    sock.sendall(struct.pack(">I", len(body)) + body)
    length = struct.unpack(">I", recv_exact(sock, 4))[0]
    return recv_exact(sock, length)


def connect(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    return sock


def control(args):
    request_type = LOCK if args.action == "lock" else UNLOCK
    body = bytes([request_type]) + ssh_string(args.password.encode())
    with connect(args.socket) as sock:
        reply = request(sock, body)
    value = reply[0] if reply else -1
    print(f"{args.action}_reply_type={value}", flush=True)
    return 0 if reply == SUCCESS else 1


def probe(args):
    with connect(os.environ["SSH_AUTH_SOCK"]) as sock:
        print("forwarded_socket_connected=true", flush=True)
        time.sleep(args.hold)
        body = bytes([ADD_SMARTCARD_KEY])
        body += ssh_string(args.provider.encode())
        body += ssh_string(b"")
        reply = request(sock, body)
    value = reply[0] if reply else -1
    print(f"provider_reply_type={value}", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    control_parser = commands.add_parser("control")
    control_parser.add_argument("action", choices=("lock", "unlock"))
    control_parser.add_argument("--socket", required=True)
    control_parser.add_argument("--password", default="agent-lock-proof")
    control_parser.set_defaults(handler=control)

    probe_parser = commands.add_parser("probe")
    probe_parser.add_argument("--provider", required=True)
    probe_parser.add_argument("--hold", type=float, default=3.0)
    probe_parser.set_defaults(handler=probe)

    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
