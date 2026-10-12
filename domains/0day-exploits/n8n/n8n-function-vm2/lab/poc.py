#!/usr/bin/env python3
"""Local oracle for unpublished n8n Function/vm2 in-process JS (n8n 2.42.0).

Hidden n8n-nodes-base.function is still loaded (palette hidden is not an ACL).
Default NODES_EXCLUDE is only executeCommand + localFileTrigger. Function
runs JS in the n8n main process via leftover vm2 NodeVM. Code v2 uses the
JS task runner child. Oracle is process.pid vs docker pgrep, not a shell.
Loopback only.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import parse_qs, urlparse

LABEL = "N8N-FUNCTION-VM2"
WITNESS = "N8N-FUNCTION-VM2-WITNESS"
DEFAULT_BASE = "http://127.0.0.1:18201"
DEFAULT_PROJECT = "n8n-function-vm2"
EXPECTED_VERSION = "2.42.0"
OWNER_EMAIL = "labadmin@localhost.invalid"
MEMBER_EMAIL = "labmember@localhost.invalid"
PASSWORD = "LabPass123!"
BROWSER_ID = "n8n-function-vm2-browser"
USER_AGENT = "n8n-function-vm2-lab"
AUTH_COOKIE = "n8n-auth"
COMPOSE_SERVICE = "n8n"
CANARY_PATH = "/tmp/N8N-FUNCTION-VM2-CANARY"
HTTP_OK = (200, 201)
HIDDEN_REJECT_STATUS = (400, 404)
READY_ATTEMPTS = 90
READY_SLEEP_S = 2
EXEC_POLL_ATTEMPTS = 40
RUN_TIMEOUT_S = 90
TERMINAL_EXEC_STATUS = ("success", "error", "crashed", "canceled", "failed")
RUNNER_TOKENS = (
    "task-runner",
    "task_runner",
    "javascript-task-runner",
    "@n8n/task-runner",
)

FUNCTION_JS = (
    "var pid = process.pid; "
    f'return [{{ json: {{ pid: pid, pidMark: "N8NPID-" + pid, witness: "{WITNESS}" }} }}];'
)
CODE_JS = (
    "var pid = (typeof process !== 'undefined' ? process.pid : null); "
    "var mark = (pid === null || pid === undefined) ? 'N8NPID-none' : ('N8NPID-' + pid); "
    f'return [{{ json: {{ pid: pid, pidMark: mark, hasProcess: typeof process !== "undefined", witness: "{WITNESS}" }} }}];'
)
PROC_SCRIPT = (
    "for d in /proc/[0-9]*; do "
    'pid=${d#/proc/}; [ -r "$d/cmdline" ] || continue; '
    'cmd=$(tr "\\0" " " < "$d/cmdline"); '
    'printf "%s %s\\n" "$pid" "$cmd"; '
    "done; echo '---ps---'; ps -o pid,ppid,args || true"
)


@dataclass(frozen=True)
class LabConfig:
    label: str
    witness: str
    base: str
    compose_project: str
    lab_dir: Path
    owner_email: str
    member_email: str
    password: str
    browser_id: str

    @classmethod
    def from_argv(cls, argv: list[str]) -> LabConfig:
        base = (argv[1] if len(argv) > 1 else DEFAULT_BASE).rstrip("/")
        return cls(
            label=LABEL,
            witness=WITNESS,
            base=base,
            compose_project=os.environ.get("COMPOSE_PROJECT_NAME", DEFAULT_PROJECT),
            lab_dir=Path(__file__).resolve().parent,
            owner_email=OWNER_EMAIL,
            member_email=MEMBER_EMAIL,
            password=PASSWORD,
            browser_id=BROWSER_ID,
        )


def log(msg: str) -> None:
    print(msg, flush=True)


def fail(reason: str) -> NoReturn:
    log(f"FAIL {LABEL} {reason}")
    raise SystemExit(1)


def snippet(text: str, n: int = 240) -> str:
    return re.sub(r"\s+", " ", text)[:n]


def invite_token_from_url(url: str) -> str | None:
    if "token=" not in url:
        return None
    values = parse_qs(urlparse(url).query).get("token")
    if not values:
        return None
    return values[0]


class Session:
    def __init__(self, cfg: LabConfig, browser_id: str) -> None:
        self.cfg = cfg
        self.browser_id = browser_id
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def request(
        self,
        method: str,
        path: str,
        data: object | None = None,
        timeout: int = 60,
    ) -> tuple[int, str, dict[str, str]]:
        url = path if path.startswith("http") else self.cfg.base + path
        headers = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": USER_AGENT,
            "browser-id": self.browser_id,
        }
        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, raw, hdrs
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            return exc.code, raw, hdrs

    def has_auth_cookie(self) -> bool:
        return any(cookie.name == AUTH_COOKIE for cookie in self.jar)


def unwrap(body: str) -> Any:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return body
    if isinstance(parsed, dict) and "data" in parsed:
        return parsed["data"]
    return parsed


def compose(
    cfg: LabConfig, *args: str, timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-p", cfg.compose_project, *args],
        cwd=cfg.lab_dir,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def wait_ready(cfg: LabConfig) -> None:
    probe = Session(cfg, cfg.browser_id)
    for i in range(READY_ATTEMPTS):
        live, live_b, _ = probe.request("GET", "/healthz", timeout=8)
        ready, _, _ = probe.request("GET", "/healthz/readiness", timeout=8)
        settings, _, _ = probe.request("GET", "/rest/settings", timeout=8)
        if live == 200:
            log(f"IOC healthz http={live} body={snippet(live_b, 80)!r}")
        if ready == 200 and settings == 200:
            log(f"IOC rest-ready readiness={ready} settings={settings}")
            return
        log(
            f"IOC wait-ready i={i} healthz={live} readiness={ready} settings={settings}"
        )
        time.sleep(READY_SLEEP_S)
    fail("n8n REST never became ready")


def confirm_version(cfg: LabConfig, sess: Session) -> None:
    status, body, _ = sess.request("GET", "/rest/settings")
    data = unwrap(body)
    version = ""
    if isinstance(data, dict):
        version = str(data.get("versionCli") or data.get("version") or "")
    log(f"IOC version-settings http={status} versionCli={version!r}")
    if EXPECTED_VERSION not in version and EXPECTED_VERSION not in body:
        img = compose(cfg, "exec", "-T", COMPOSE_SERVICE, "n8n", "--version")
        ver_out = (img.stdout or "") + (img.stderr or "")
        log(f"IOC n8n-version-cli rc={img.returncode} out={snippet(ver_out)!r}")
        if EXPECTED_VERSION not in ver_out:
            fail(f"not stock n8n {EXPECTED_VERSION} settings={snippet(body)}")
    else:
        log(f"IOC stock-n8n={EXPECTED_VERSION}")


def owner_setup(cfg: LabConfig, sess: Session) -> dict[str, Any]:
    payload = {
        "email": cfg.owner_email,
        "firstName": "Lab",
        "lastName": "Admin",
        "password": cfg.password,
    }
    status, body, _ = sess.request("POST", "/rest/owner/setup", payload)
    log(f"IOC owner-setup http={status} snippet={snippet(body)!r}")
    if status not in HTTP_OK:
        login_status, login_body, _ = sess.request(
            "POST",
            "/rest/login",
            {"emailOrLdapLoginId": cfg.owner_email, "password": cfg.password},
        )
        log(f"IOC owner-login http={login_status} snippet={snippet(login_body)!r}")
        if login_status not in HTTP_OK or not sess.has_auth_cookie():
            fail(f"owner setup/login failed setup={status} login={login_status}")
        data = unwrap(login_body)
        return data if isinstance(data, dict) else {}
    data = unwrap(body)
    if not sess.has_auth_cookie():
        fail("owner setup did not set n8n-auth cookie")
    return data if isinstance(data, dict) else {}


def try_member(cfg: LabConfig, owner: Session) -> Session | None:
    status, body, _ = owner.request(
        "POST",
        "/rest/invitations",
        [{"email": cfg.member_email, "role": "global:member"}],
    )
    log(f"IOC invite http={status} snippet={snippet(body)!r}")
    if status not in HTTP_OK:
        log(f"IOC member-invite-blocked http={status}")
        return None
    data = unwrap(body)
    token: str | None = None
    user_id: Any = None
    if isinstance(data, list) and data:
        user = data[0].get("user") if isinstance(data[0], dict) else None
        if isinstance(user, dict):
            user_id = user.get("id")
            token = invite_token_from_url(str(user.get("inviteAcceptUrl") or ""))
    if not token and user_id:
        link_status, link_body, _ = owner.request(
            "POST", f"/rest/users/{user_id}/invite-link", {}
        )
        log(f"IOC invite-link http={link_status} snippet={snippet(link_body)!r}")
        link_data = unwrap(link_body)
        link = ""
        if isinstance(link_data, dict):
            link = str(link_data.get("link") or "")
        elif isinstance(link_data, str):
            link = link_data
        token = invite_token_from_url(link)
    if not token:
        log("IOC member-invite-no-token")
        return None
    member = Session(cfg, cfg.browser_id + "-member")
    accept_status, accept_body, _ = member.request(
        "POST",
        "/rest/invitations/accept",
        {
            "token": token,
            "firstName": "Lab",
            "lastName": "Member",
            "password": cfg.password,
        },
    )
    log(f"IOC invite-accept http={accept_status} snippet={snippet(accept_body)!r}")
    if accept_status not in HTTP_OK or not member.has_auth_cookie():
        log("IOC member-accept-failed")
        return None
    who = unwrap(accept_body)
    role = who.get("role") if isinstance(who, dict) else None
    log(f"IOC member-session role={role!r} email={cfg.member_email}")
    return member


def workflow_payload(name: str, node: dict[str, Any]) -> dict[str, Any]:
    trigger = {
        "id": "manual-1",
        "name": "Manual Trigger",
        "type": "n8n-nodes-base.manualTrigger",
        "typeVersion": 1,
        "position": [0, 0],
        "parameters": {},
    }
    return {
        "name": name,
        "nodes": [trigger, node],
        "connections": {
            "Manual Trigger": {
                "main": [[{"node": node["name"], "type": "main", "index": 0}]]
            }
        },
        "settings": {
            "executionOrder": "v1",
            "saveDataErrorExecution": "all",
            "saveDataSuccessExecution": "all",
            "saveManualExecutions": True,
            "saveExecutionProgress": True,
        },
    }


def create_and_run(
    sess: Session, name: str, node: dict[str, Any]
) -> tuple[int, str, Any]:
    payload = workflow_payload(name, node)
    status, body, _ = sess.request("POST", "/rest/workflows", payload)
    log(
        f"IOC workflow-create name={name} type={node['type']} http={status} "
        f"snippet={snippet(body)!r}"
    )
    if status not in HTTP_OK:
        return status, body, None
    data = unwrap(body)
    if not isinstance(data, dict) or not data.get("id"):
        return status, body, None
    wf_id = str(data["id"])
    run_body = {"triggerToStartFrom": {"name": "Manual Trigger"}}
    run_status, run_raw, _ = sess.request(
        "POST", f"/rest/workflows/{wf_id}/run", run_body, timeout=RUN_TIMEOUT_S
    )
    log(f"IOC workflow-run name={name} http={run_status} snippet={snippet(run_raw)!r}")
    run = unwrap(run_raw)
    if not isinstance(run, dict):
        return run_status, run_raw, None
    if run.get("waitingForWebhook"):
        return run_status, run_raw, run
    exec_id = run.get("executionId")
    if not exec_id:
        return run_status, run_raw, run
    last_body = run_raw
    last_data: Any = run
    for i in range(EXEC_POLL_ATTEMPTS):
        poll_status, poll_body, _ = sess.request(
            "GET", f"/rest/executions/{exec_id}?redactExecutionData=false"
        )
        last_body = poll_body
        last_data = unwrap(poll_body)
        exec_status = last_data.get("status") if isinstance(last_data, dict) else None
        log(f"IOC exec-poll name={name} i={i} http={poll_status} status={exec_status!r}")
        if exec_status in TERMINAL_EXEC_STATUS:
            return poll_status, last_body, last_data
        time.sleep(1)
    return run_status, last_body, last_data


def _walk_json(obj: Any, found: list[dict[str, Any]]) -> None:
    if isinstance(obj, dict):
        if "pidMark" in obj or obj.get("witness") == WITNESS:
            found.append(obj)
        for value in obj.values():
            _walk_json(value, found)
    elif isinstance(obj, list):
        for value in obj:
            _walk_json(value, found)


def extract_json_fields(blob: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    marks = re.findall(r"N8NPID-(\d+|none)", blob)
    runtime_marks = [
        mark
        for mark in marks
        if f"N8NPID-{mark}" not in FUNCTION_JS and f"N8NPID-{mark}" not in CODE_JS
    ]
    if runtime_marks:
        chosen = next((mark for mark in runtime_marks if mark != "none"), runtime_marks[0])
        out["pidMark"] = f"N8NPID-{chosen}"
        out["pid"] = int(chosen) if chosen.isdigit() else None
    if WITNESS in blob:
        out["witness"] = WITNESS
    has_process = re.search(r'"hasProcess"\s*:\s*(true|false)', blob)
    if has_process:
        out["hasProcess"] = has_process.group(1) == "true"
    err = ""
    for key in ("error", "message"):
        match = re.search(rf'"{key}"\s*:\s*"([^"]{{0,200}})"', blob)
        if match:
            err = match.group(1)
            break
    if err:
        out["error"] = err
    # Walk flattened execution payload for runData json objects.
    try:
        parsed = json.loads(blob)
        inner = parsed.get("data", parsed) if isinstance(parsed, dict) else parsed
        if isinstance(inner, dict) and isinstance(inner.get("data"), str):
            try:
                inner = json.loads(inner["data"])
            except json.JSONDecodeError:
                pass
        found: list[dict[str, Any]] = []
        _walk_json(inner, found)
        if found and "pid" not in out:
            item = found[0]
            mark = str(item.get("pidMark") or "")
            pid_match = re.search(r"N8NPID-(\d+)", mark)
            if pid_match:
                out["pid"] = int(pid_match.group(1))
            elif isinstance(item.get("pid"), int):
                out["pid"] = item["pid"]
            out["runDataItem"] = {
                key: item.get(key) for key in ("pid", "pidMark", "witness", "hasProcess")
            }
    except (json.JSONDecodeError, TypeError, AttributeError, ValueError, RecursionError) as exc:
        out["parseError"] = str(exc)
    return out


def container_node_pids(cfg: LabConfig) -> tuple[int | None, int | None, str]:
    proc = compose(cfg, "exec", "-T", COMPOSE_SERVICE, "sh", "-c", PROC_SCRIPT)
    raw = (proc.stdout or "") + "\n" + (proc.stderr or "")
    log(f"IOC proc-cmdlines rc={proc.returncode} out={snippet(raw, 800)!r}")
    main_pid: int | None = None
    runner_pid: int | None = None
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("---"):
            continue
        match = re.match(r"^(\d+)\s+(.*)$", line)
        if not match:
            continue
        pid = int(match.group(1))
        args = match.group(2)
        low = args.lower()
        if "tini" in low:
            continue
        if any(token in low for token in RUNNER_TOKENS):
            runner_pid = pid
            continue
        if "bin/n8n" in low or re.search(r"(^|\s)n8n(\s|$)", low):
            if main_pid is None:
                main_pid = pid
    return main_pid, runner_pid, raw


def plant_canary(cfg: LabConfig) -> str:
    proc = compose(
        cfg,
        "exec",
        "-T",
        COMPOSE_SERVICE,
        "sh",
        "-c",
        f"printf '%s\\n' '{WITNESS}' > {CANARY_PATH} && chmod 600 {CANARY_PATH} && echo planted",
    )
    planted = snippet((proc.stdout or "") + (proc.stderr or ""))
    log(f"IOC canary-plant rc={proc.returncode} out={planted!r}")
    return CANARY_PATH


def function_node() -> dict[str, Any]:
    return {
        "id": "function-1",
        "name": "Function",
        "type": "n8n-nodes-base.function",
        "typeVersion": 1,
        "position": [220, 0],
        "parameters": {"functionCode": FUNCTION_JS},
    }


def code_node() -> dict[str, Any]:
    return {
        "id": "code-1",
        "name": "Code",
        "type": "n8n-nodes-base.code",
        "typeVersion": 2,
        "position": [220, 0],
        "parameters": {
            "mode": "runOnceForAllItems",
            "language": "javaScript",
            "jsCode": CODE_JS,
        },
    }


def maybe_owner_fetch(
    owner: Session,
    actor: Session,
    fn_fields: dict[str, Any],
    fn_body: str,
    fn_data: Any,
) -> tuple[dict[str, Any], str]:
    if fn_fields.get("pid") is not None or actor is owner:
        return fn_fields, fn_body
    exec_id = None
    if isinstance(fn_data, dict):
        exec_id = fn_data.get("id") or fn_data.get("executionId")
    if not exec_id:
        return fn_fields, fn_body
    status, body, _ = owner.request(
        "GET", f"/rest/executions/{exec_id}?redactExecutionData=false"
    )
    log(f"IOC function-owner-fetch http={status} snippet={snippet(body)!r}")
    owned = extract_json_fields(body)
    log(f"IOC function-owner-fields={owned}")
    if owned.get("pid") is not None:
        return owned, body
    return fn_fields, fn_body


def prove_function_isolation(
    fn_pid: object,
    code_pid: object,
    main_pid: int,
    runner_pid: int | None,
) -> None:
    if int(fn_pid) != int(main_pid):
        # PID 1 may be tini; Function should still match the main n8n node, not the runner.
        if runner_pid is not None and int(fn_pid) == int(runner_pid):
            fail(f"function ran in task-runner child pid={fn_pid}")
        if main_pid != 1 and int(fn_pid) != 1:
            fail(f"function pid {fn_pid} != n8n main pid {main_pid}")

    same_as_code = code_pid is not None and int(code_pid) == int(fn_pid)
    if same_as_code and (runner_pid is None or int(fn_pid) == int(runner_pid)):
        fail(f"function isolation matches code runner pid={fn_pid}")
    if same_as_code and int(fn_pid) != int(main_pid):
        fail(f"function pid equals code pid {fn_pid} and is not main {main_pid}")

    negative_ok = False
    if code_pid is None:
        log("IOC code-negative=process-blocked-or-error")
        negative_ok = True
    elif int(code_pid) != int(fn_pid):
        log(f"IOC code-negative=different-pid code={code_pid} function={fn_pid}")
        negative_ok = True
    elif (
        runner_pid is not None
        and int(code_pid) == int(runner_pid)
        and int(fn_pid) != int(runner_pid)
    ):
        negative_ok = True
    if not negative_ok:
        fail(
            f"code node did not prove runner isolation "
            f"code_pid={code_pid} function_pid={fn_pid}"
        )


def main(argv: list[str] | None = None) -> int:
    cfg = LabConfig.from_argv(sys.argv if argv is None else argv)
    log(f"IOC base={cfg.base}")
    wait_ready(cfg)
    owner = Session(cfg, cfg.browser_id)
    confirm_version(cfg, owner)
    owner_user = owner_setup(cfg, owner)
    owner_role = owner_user.get("role") if isinstance(owner_user, dict) else None
    log(f"IOC owner-role={owner_role!r} email={cfg.owner_email}")

    actor = try_member(cfg, owner)
    if actor is None:
        actor = owner
        who = "owner"
        log("IOC authenticated-as=owner (member invite blocked or unused)")
    else:
        who = "member"
        log("IOC authenticated-as=member")

    plant_canary(cfg)
    main_pid, runner_pid, pgrep_raw = container_node_pids(cfg)
    log(f"IOC container-main-pid={main_pid} container-runner-pid={runner_pid}")
    if main_pid is None:
        fail(
            f"could not resolve n8n main node pid from pgrep/ps out={snippet(pgrep_raw)}"
        )

    fn_http, fn_body, fn_data = create_and_run(actor, "function-vm2-oracle", function_node())
    fn_fields = extract_json_fields(
        fn_body if isinstance(fn_body, str) else json.dumps(fn_data)
    )
    mark_at = fn_body.find("N8NPID-") if isinstance(fn_body, str) else -1
    rundata_at = fn_body.find("runData") if isinstance(fn_body, str) else -1
    log(f"IOC function-fields={fn_fields}")
    if mark_at >= 0:
        log(
            "IOC function-pidmark-context="
            f"{snippet(fn_body[max(0, mark_at - 80): mark_at + 80], 200)!r}"
        )
    elif rundata_at >= 0:
        log(
            "IOC function-rundata-context="
            f"{snippet(fn_body[rundata_at: rundata_at + 400], 400)!r}"
        )
    else:
        tail = fn_body[-600:] if isinstance(fn_body, str) else ""
        log(f"IOC function-body-tail={snippet(tail, 400)!r}")
    fn_fields, fn_body = maybe_owner_fetch(owner, actor, fn_fields, fn_body, fn_data)
    lowered = fn_body.lower()
    if fn_http in HIDDEN_REJECT_STATUS and (
        "unknown" in lowered or "hidden" in lowered or "not found" in lowered
    ):
        fail(
            f"function type rejected as hidden/unknown http={fn_http} "
            f"body={snippet(fn_body)}"
        )
    fn_status = fn_data.get("status") if isinstance(fn_data, dict) else None
    fn_pid = fn_fields.get("pid")
    if fn_status not in (None, "success") and fn_pid is None:
        fail(f"function execution status={fn_status!r} error={fn_fields.get('error')!r}")
    if fn_pid is None:
        fail(f"function node did not return process.pid body={snippet(fn_body)}")
    if WITNESS not in fn_body:
        fail("function execution missing witness")

    code_http, code_body, code_data = create_and_run(
        actor, "code-runner-negative", code_node()
    )
    code_fields = extract_json_fields(
        code_body if isinstance(code_body, str) else json.dumps(code_data)
    )
    log(f"IOC code-fields={code_fields}")
    code_status = code_data.get("status") if isinstance(code_data, dict) else None
    code_pid = code_fields.get("pid")

    log(
        f"IOC compare function_pid={fn_pid} code_pid={code_pid} "
        f"main_pid={main_pid} runner_pid={runner_pid} who={who}"
    )
    prove_function_isolation(fn_pid, code_pid, main_pid, runner_pid)

    log(f"IOC pgrep-snippet={snippet(pgrep_raw, 200)!r}")
    log(
        f"IOC function-http={fn_http} code-http={code_http} "
        f"function-status={fn_status} code-status={code_status}"
    )
    log(f"IOC authenticated-as={who}")
    log(WITNESS)
    log(
        f"SUCCESS {LABEL} who={who} function_pid={fn_pid} "
        f"code_pid={code_pid} main_pid={main_pid} runner_pid={runner_pid} {WITNESS}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"exception={type(exc).__name__}:{exc}")
