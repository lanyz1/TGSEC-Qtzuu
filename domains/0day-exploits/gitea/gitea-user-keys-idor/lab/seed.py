#!/usr/bin/env python3
"""Plant victim witness SSH key and attacker own key via the Gitea API."""
from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE = "http://127.0.0.1:18101"
PASSWORD = "LabPass123!"
WITNESS = "GHSA-GITEA-KEY-IDOR-WITNESS"
ATTACKER_TITLE = "attacker-own-key"
USER_AGENT = "gitea-key-idor-lab"
HTTP_TIMEOUT_S = 30
SSL_CONTEXT = ssl._create_unverified_context()


def request(
    method: str,
    path: str,
    data: dict[str, Any] | None = None,
    user: str | None = None,
) -> tuple[int, str]:
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if user is not None:
        token = base64.b64encode(f"{user}:{PASSWORD}".encode()).decode()
        headers["Authorization"] = "Basic " + token
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S, context=SSL_CONTEXT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def add_key(user: str, title: str, pub: str) -> None:
    status, body = request("GET", "/api/v1/user/keys", user=user)
    if status == 200 and title in body:
        print(f"IOC key-exists user={user}")
        return
    payload = {"title": title, "key": pub.strip()}
    status, body = request("POST", "/api/v1/user/keys", data=payload, user=user)
    print(f"IOC add-key user={user} status={status} snippet={body[:160]!r}")
    if status not in (200, 201):
        raise SystemExit(f"FAIL add key {user}")


def main() -> int:
    workdir = Path(sys.argv[1])
    victim_pub = (workdir / "victim.pub").read_text(encoding="utf-8")
    attacker_pub = (workdir / "attacker.pub").read_text(encoding="utf-8")
    add_key("victim", WITNESS, victim_pub)
    add_key("attacker", ATTACKER_TITLE, attacker_pub)
    print("IOC seed-done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
