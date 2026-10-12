#!/usr/bin/env python3
"""Local oracle: public-only PAT still creates a private org.

POST /api/v1/orgs has no rejectPublicOnly(); POST /api/v1/user/repos does.
Witness is visibility=private on the created org. Loopback only.
"""
from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

LABEL = "GITEA-PUBLIC-ONLY-PAT"
DEFAULT_BASE = "http://127.0.0.1:18132"
DEFAULT_USER = "labuser"
DEFAULT_PASSWORD = "LabPass123!"
USER_AGENT = "gitea-public-only-pat-org-lab"
HTTP_TIMEOUT_S = 30
ORG_FULL_NAME = "private-org-lab"
CREATED_OK = frozenset({200, 201})
# write:user is required to reach POST /user/repos (outer /user group); then
# rejectPublicOnly() is the intended deny for a private repo.
SCOPES: tuple[str, ...] = (
    "public-only",
    "write:organization",
    "write:repository",
    "write:user",
)
SSL_CTX = ssl._create_unverified_context()


@dataclass(frozen=True)
class LabConfig:
    base: str
    user: str
    password: str
    org: str
    repo: str
    token_name: str


def fail(reason: str) -> int:
    print(f"FAIL {reason}")
    return 1


def parse_args(argv: list[str]) -> LabConfig:
    suffix = uuid.uuid4().hex[:8]
    base = (argv[1] if len(argv) > 1 else DEFAULT_BASE).rstrip("/")
    user = argv[2] if len(argv) > 2 else DEFAULT_USER
    password = argv[3] if len(argv) > 3 else DEFAULT_PASSWORD
    return LabConfig(
        base=base,
        user=user,
        password=password,
        org=f"privorg{suffix}",
        repo=f"privrepo{suffix}",
        token_name=f"public-only-{suffix}",
    )


def req(
    cfg: LabConfig,
    method: str,
    path: str,
    data: dict[str, Any] | None = None,
    *,
    basic: tuple[str, str] | None = None,
    token: str | None = None,
) -> tuple[int, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if basic is not None:
        raw = f"{basic[0]}:{basic[1]}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    if token is not None:
        headers["Authorization"] = "token " + token
    body = None if data is None else json.dumps(data).encode("utf-8")
    request = urllib.request.Request(
        cfg.base + path,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(
            request, timeout=HTTP_TIMEOUT_S, context=SSL_CTX
        ) as resp:
            return int(resp.status), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return 0, str(exc.reason)


def parse_json_object(body: str) -> dict[str, Any]:
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


def is_private_org(obj: dict[str, Any]) -> bool:
    vis = str(obj.get("visibility") or "").lower()
    if vis == "private":
        return True
    return obj.get("private") is True


def scope_blob(scopes: Any) -> str:
    if isinstance(scopes, list):
        return ",".join(str(item) for item in scopes)
    return str(scopes)


def main() -> int:
    cfg = parse_args(sys.argv)
    print(f"IOC base={cfg.base} user={cfg.user} org={cfg.org} repo={cfg.repo}")

    status, body = req(cfg, "GET", "/api/v1/version")
    print(f"IOC version status={status} snippet={body[:120]!r}")
    if status != 200:
        return fail("version")

    status, body = req(
        cfg,
        "POST",
        f"/api/v1/users/{cfg.user}/tokens",
        {"name": cfg.token_name, "scopes": list(SCOPES)},
        basic=(cfg.user, cfg.password),
    )
    print(f"IOC token-create status={status} snippet={body[:240]!r}")
    tok = parse_json_object(body)
    sha = str(tok.get("sha1") or "")
    scopes = tok.get("scopes") or []
    if status not in CREATED_OK or not sha:
        return fail("token create")
    blob = scope_blob(scopes)
    if "public-only" not in blob:
        return fail(f"token missing public-only scopes={blob!r}")
    print(f"IOC token-scopes={blob}")

    org_status, org_body = req(
        cfg,
        "POST",
        "/api/v1/orgs",
        {
            "username": cfg.org,
            "visibility": "private",
            "full_name": ORG_FULL_NAME,
        },
        token=sha,
    )
    print(f"IOC org-create status={org_status} snippet={org_body[:280]!r}")
    if org_status == 403 and "public-only" in org_body.lower():
        return fail("org create rejected by public-only")
    created = parse_json_object(org_body)
    if org_status not in CREATED_OK or not is_private_org(created):
        return fail("org create did not yield a private org")

    get_status, get_body = req(
        cfg,
        "GET",
        f"/api/v1/orgs/{cfg.org}",
        basic=(cfg.user, cfg.password),
    )
    print(f"IOC org-get status={get_status} snippet={get_body[:280]!r}")
    got = parse_json_object(get_body)
    if get_status != 200 or not is_private_org(got):
        return fail("GET as user did not show visibility=private")
    print(
        f"IOC org-visibility={got.get('visibility')!r} private={got.get('private')!r}"
    )

    repo_status, repo_body = req(
        cfg,
        "POST",
        "/api/v1/user/repos",
        {"name": cfg.repo, "private": True},
        token=sha,
    )
    print(f"IOC user-repo-create status={repo_status} snippet={repo_body[:280]!r}")
    if repo_status in CREATED_OK:
        return fail("public-only token created a private user repo (negative failed)")
    if repo_status != 403 or "public-only" not in repo_body.lower():
        return fail("expected public-only 403 on private user repo create")
    print(f"SUCCESS {LABEL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
