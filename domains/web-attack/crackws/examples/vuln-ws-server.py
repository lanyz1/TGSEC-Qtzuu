#!/usr/bin/env python3
"""A deliberately vulnerable WebSocket service for demonstrating crackws.

It speaks the same JSON envelope as the reference lab ({"type":"login", ...})
but builds its SQLite query by string concatenation, so it is genuinely
injectable. Point a crackws bridge at it and sqlmap can dump the users table
through plain HTTP.

    python3 examples/vuln-ws-server.py            # listens on 127.0.0.1:9100

Do not run this anywhere reachable from an untrusted network.
"""

import argparse
import asyncio
import json
import sqlite3

try:
    import websockets
except ImportError:  # pragma: no cover
    raise SystemExit("pip install websockets")

DDL = """
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, note TEXT);
INSERT INTO users VALUES (1, 'admin', 'S3cr3t-Adm1n!', 'admin', 'flag{ws_bridge_sqli_works}');
INSERT INTO users VALUES (2, 'alice', 'alicepw', 'user',  'alice-note');
INSERT INTO users VALUES (3, 'bob',   'bobpw',   'user',  'bob-note');
"""

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript(DDL)


async def handler(ws):
    async for raw in ws:
        try:
            msg = json.loads(raw)
        except Exception:
            await ws.send(json.dumps({"type": "error", "message": "invalid JSON"}, ensure_ascii=False))
            continue

        kind = msg.get("type")
        if kind == "login":
            user = str(msg.get("username", ""))
            password = str(msg.get("password", ""))
            if not user:
                await ws.send(json.dumps({"type": "error", "message": "username is required"}))
                continue
            # Deliberately vulnerable: string concatenation, not a parameterised query.
            sql = (
                "SELECT username, role FROM users "
                f"WHERE username='{user}' AND password='{password}'"
            )
            try:
                row = DB.execute(sql).fetchone()
            except Exception as exc:
                await ws.send(json.dumps({"type": "error", "message": f"SQL error: {exc}"}))
                continue
            if row:
                await ws.send(json.dumps({"type": "system", "message": "welcome", "role": row[1]}))
            else:
                await ws.send(json.dumps({"type": "error", "message": "bad credentials"}))
        elif kind == "chat":
            content = str(msg.get("content", ""))
            await ws.send(json.dumps({"type": "chat", "from": "admin", "content": content}, ensure_ascii=False))
        else:
            await ws.send(json.dumps({"type": "error", "message": "unknown message type"}))


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9100)
    args = ap.parse_args()

    async with websockets.serve(handler, args.host, args.port):
        print(f"vulnerable WebSocket lab on ws://{args.host}:{args.port}/")
        print("bridge it with:  crackws bridge --profile examples/vuln-sqli.yaml --listen 127.0.0.1:8899")
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
