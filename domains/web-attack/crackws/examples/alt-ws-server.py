#!/usr/bin/env python3
"""A second, deliberately different WebSocket service, used to show that
crackws is not tied to the reference lab's protocol shape.

Differences from the reference lab:

  * the wire format is plain text, not JSON -- ``LOGIN <user> <pass>``
  * there is no ``type`` discriminator field at all, so differential type
    enumeration has nothing to find
  * tokens are space separated, so payloads travel inside a positional
    argument
  * the backend is injectable

Everything crackws does to it comes from a profile, not from hard-coded
knowledge of the target.

    python3 examples/alt-ws-server.py       # ws://127.0.0.1:9200/
"""

import argparse
import asyncio
import sqlite3

try:
    import websockets
except ImportError:  # pragma: no cover
    raise SystemExit("pip install websockets")

DDL = """
CREATE TABLE accounts (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
INSERT INTO accounts VALUES (1, 'root', 't0p-Secret', 'admin');
INSERT INTO accounts VALUES (2, 'carol', 'carolpw', 'user');
"""

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript(DDL)

BANNER = "crackws-alt-lab/1.0"


async def handler(ws):
    await ws.send(f"{BANNER} ready")
    async for raw in ws:
        line = raw.strip()
        if not line:
            await ws.send("ERR empty command")
            continue

        # command + up to two positional arguments; the third keeps its spaces
        parts = line.split(" ", 2)
        cmd = parts[0].upper()

        if cmd == "LOGIN":
            if len(parts) < 3:
                await ws.send("ERR usage: LOGIN <user> <pass>")
                continue
            user, password = parts[1], parts[2]
            # Deliberately vulnerable: string concatenation.
            sql = (
                "SELECT username, role FROM accounts "
                f"WHERE username='{user}' AND password='{password}'"
            )
            try:
                row = DB.execute(sql).fetchone()
            except Exception as exc:
                await ws.send(f"ERR sql: {exc}")
                continue
            if row:
                await ws.send(f"OK role={row[1]} user={row[0]}")
            else:
                await ws.send("ERR bad credentials")
        elif cmd == "ECHO":
            await ws.send("OK " + line[5:])
        elif cmd == "PING":
            await ws.send("PONG")
        else:
            await ws.send(f"ERR unknown command: {cmd}")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9200)
    args = ap.parse_args()
    async with websockets.serve(handler, args.host, args.port):
        print(f"alt protocol lab on ws://{args.host}:{args.port}/  (plain text, no JSON)")
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
