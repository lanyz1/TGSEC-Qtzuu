#!/usr/bin/env python3
"""Local oracle: restore-repo release asset OpenWithClient file:// -> os.Open.

Operator restore of an untrusted dump. DownloadURL is an absolute path;
restore rewrites it to file:// and the uploader opens it because DownloadFunc
is nil. Witness is GITEA-FILE-OPEN-WITNESS in the restored attachment bytes.
Not a shell. Loopback only.
"""

from __future__ import annotations

import base64
import json
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

LABEL = "GITEA-RESTORE-FILE-OPEN"
WITNESS = "GITEA-FILE-OPEN-WITNESS"
HOST = "127.0.0.1"
PORT = 18137
DEFAULT_BASE = f"http://{HOST}:{PORT}"
COMPOSE_SERVICE = "gitea"
USER_AGENT = "gitea-restore-file-open-lab"
HTTP_TIMEOUT = 60
VERSION_PATH = "/api/v1/version"
ATTACH_FIND = "find /data/gitea/attachments -type f 2>/dev/null | head -20"
LAB_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class LabConfig:
    base: str
    username: str
    password: str
    owner: str
    repo: str
    timeout: int
    ssl_context: ssl.SSLContext


def _config(argv: list[str]) -> LabConfig:
    base = (argv[1] if len(argv) > 1 else DEFAULT_BASE).rstrip("/")
    return LabConfig(
        base=base,
        username="labadmin",
        password="LabPass123!",
        owner="labadmin",
        repo="restored",
        timeout=HTTP_TIMEOUT,
        ssl_context=ssl._create_unverified_context(),
    )


def log(msg: str) -> None:
    print(msg, flush=True)


def fail(reason: str) -> int:
    log(f"FAIL {reason}")
    return 1


def req(
    cfg: LabConfig,
    method: str,
    path: str,
    data: dict[str, object] | None = None,
    url: str | None = None,
) -> tuple[int, bytes]:
    token = base64.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()
    headers = {
        "User-Agent": USER_AGENT,
        "Authorization": f"Basic {token}",
    }
    body: bytes | None = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode()
    target = url if url is not None else f"{cfg.base}{path}"
    request = urllib.request.Request(target, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(
            request, timeout=cfg.timeout, context=cfg.ssl_context
        ) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def docker_exec(*args: str) -> str:
    cmd = ["docker", "compose", "exec", "-T", COMPOSE_SERVICE, *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=LAB_DIR)
    return (proc.stdout or "") + (proc.stderr or "")


def _decode(body: bytes) -> str:
    return body.decode("utf-8", "replace")


def _release_assets(releases: object) -> list[object]:
    assets: list[object] = []
    if not isinstance(releases, list):
        return assets
    for rel in releases:
        extra = rel.get("assets") if isinstance(rel, dict) else None
        assets.extend(extra or [])
    return assets


def _attachment_from_disk() -> tuple[bytes, str]:
    disk = docker_exec("sh", "-c", ATTACH_FIND)
    log(f"IOC disk-attachments {disk.strip()[:400]!r}")
    paths = [ln.strip() for ln in disk.splitlines() if ln.strip().startswith("/data/")]
    for pth in paths:
        raw = docker_exec("cat", pth)
        log(f"IOC disk-cat path={pth} snippet={raw[:80]!r}")
        if WITNESS in raw:
            return raw.encode(), "disk"
    return b"", ""


def main() -> int:
    cfg = _config(sys.argv)
    log(f"IOC base={cfg.base}")

    status, body = req(cfg, "GET", VERSION_PATH)
    log(f"IOC version status={status} snippet={body[:80]!r}")
    if status != 200:
        return fail("gitea version")

    status, body = req(cfg, "GET", f"/api/v1/repos/{cfg.owner}/{cfg.repo}/releases")
    text = _decode(body)
    log(f"IOC releases status={status} snippet={text[:280]!r}")
    if status != 200:
        return fail("list releases")
    try:
        releases: object = json.loads(text)
    except json.JSONDecodeError:
        return fail("releases json")
    if not isinstance(releases, list) or not releases:
        return fail("no restored releases")

    assets = _release_assets(releases)
    if not assets:
        return fail("no restored release assets")

    raw_asset = assets[0]
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    download_url = str(asset.get("browser_download_url") or "")
    uuid = str(asset.get("uuid") or "")
    log(
        f"IOC asset name={asset.get('name')!r} size={asset.get('size')} "
        f"uuid={uuid} url={download_url}"
    )

    attachment = b""
    src = ""
    if download_url:
        status, attachment = req(cfg, "GET", "", url=download_url)
        log(
            f"IOC download status={status} bytes={len(attachment)} "
            f"snippet={attachment[:80]!r}"
        )
        if status == 200 and attachment:
            src = "api"

    if WITNESS not in _decode(attachment):
        disk_body, disk_src = _attachment_from_disk()
        if disk_src:
            attachment, src = disk_body, disk_src

    snippet = _decode(attachment)[:80]
    if WITNESS not in snippet and WITNESS not in _decode(attachment):
        return fail("attachment empty/missing witness")
    log(f"IOC attachment-src={src} snippet={snippet!r}")
    log(f"SUCCESS {LABEL}")
    log(
        "oracle: restore-repo release asset OpenWithClient file:// os.Open; "
        "attachment bytes == GITEA-FILE-OPEN-WITNESS"
    )
    log("product: Gitea 1.27.3")
    log("sink: modules/uri/uri.go OpenWithClient case file -> os.Open")
    log(f"lab: {DEFAULT_BASE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
