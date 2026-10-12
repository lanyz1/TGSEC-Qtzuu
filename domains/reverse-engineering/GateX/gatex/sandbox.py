"""Docker cage for the untrusted 7350FH ELF.

The binary is a Linux x86-64 Nuitka onefile. It is never exec'd on the host.
Each live attempt runs inside a long-lived container with:

* --platform linux/amd64 (qemu/Rosetta on Apple Silicon)
* --network none
* --read-only root + tmpfs for HOME/TMP
* --cap-drop ALL, no-new-privileges
* memory / pids / cpu limits
* non-root user
* password passed only as FH_PASS (never argv)

/bypass re-keys the inner ELF and execs it here. The host never runs the payload.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

IMAGE = "gatex-cage:noble"
DOCKERFILE = Path(__file__).resolve().parent.parent / "sandbox" / "Dockerfile"
CONTAINER_PREFIX = "gatex-cage"
INNER_PATH = "/tmp/7350FH"
PAYLOAD_PATH = "/in/payload"
PATCHED_BIN = "/opt/fh/7350FH.bin"

HARDENED_RUN: tuple[str, ...] = (
    "--platform",
    "linux/amd64",
    "--network",
    "none",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--memory",
    "2g",
    "--memory-swap",
    "2g",
    "--cpus",
    "1",
    "--pids-limit",
    "256",
    "--user",
    "65532:65532",
    "--tmpfs",
    "/tmp:rw,exec,nosuid,nodev,size=1024m",
)

LogFn = Callable[[str, str], None]


@dataclass
class CageResult:
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    error: str = ""


class CageError(Exception):
    pass


def docker_bin() -> str:
    return shutil.which("docker") or "/usr/local/bin/docker"


def docker_cmd(
    *args: str,
    timeout: float = 30,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    exe = docker_bin()
    if not Path(exe).exists() and shutil.which("docker") is None:
        raise CageError("docker CLI not found")
    try:
        proc = subprocess.run(
            [exe, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise CageError("docker CLI not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise CageError(f"docker {' '.join(args[:3])} timed out") from exc
    if check and proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise CageError(err or f"docker exit {proc.returncode}")
    return proc


def docker_running() -> bool:
    try:
        proc = docker_cmd("info", timeout=8)
        return proc.returncode == 0
    except CageError:
        return False


def start_docker_desktop(wait_seconds: float = 90) -> None:
    if docker_running():
        return
    if platform.system() == "Darwin" and Path("/Applications/Docker.app").exists():
        subprocess.Popen(
            ["open", "-a", "Docker"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if docker_running():
            return
        time.sleep(2)
    raise CageError("Docker daemon is not running (tried to launch Docker Desktop)")


def image_exists() -> bool:
    proc = docker_cmd("image", "inspect", IMAGE, timeout=15)
    return proc.returncode == 0


def build_image() -> None:
    if not DOCKERFILE.is_file():
        raise CageError(f"missing Dockerfile at {DOCKERFILE}")
    context = str(DOCKERFILE.parent)
    proc = docker_cmd(
        "build",
        "--platform",
        "linux/amd64",
        "-t",
        IMAGE,
        "-f",
        str(DOCKERFILE),
        context,
        timeout=300,
    )
    if proc.returncode != 0:
        raise CageError((proc.stderr or proc.stdout or "build failed").strip())


def container_name(session: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in session)[:40]
    return f"{CONTAINER_PREFIX}-{safe or 'default'}"


def container_running(name: str) -> bool:
    proc = docker_cmd("inspect", "-f", "{{.State.Running}}", name, timeout=10)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def destroy(name: str) -> None:
    docker_cmd("rm", "-f", name, timeout=20)


def _mounted_source(name: str) -> str:
    proc = docker_cmd(
        "inspect",
        "-f",
        '{{range .Mounts}}{{if eq .Destination "/in/payload"}}{{.Source}}{{end}}{{end}}',
        name,
        timeout=10,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def spawn(name: str, target: Path, extra_binds: list[tuple[Path, str]] | None = None) -> None:
    destroy(name)
    target = target.expanduser().resolve()
    vols = ["-v", f"{target}:{PAYLOAD_PATH}:ro"]
    for src, dst in extra_binds or []:
        vols += ["-v", f"{src.resolve()}:{dst}:ro"]
    proc = docker_cmd(
        "run",
        "-d",
        "--name",
        name,
        *vols,
        *HARDENED_RUN,
        IMAGE,
        "sleep",
        "infinity",
        timeout=60,
    )
    if proc.returncode != 0:
        raise CageError((proc.stderr or proc.stdout or "docker run failed").strip())


def stage_binary(name: str) -> None:
    """Unpack the bind-mounted zip/ELF onto tmpfs. No host exec, no docker cp."""
    script = (
        "set -e; "
        "if unzip -l /in/payload >/dev/null 2>&1; then "
        "  mkdir -p /tmp/unpack; unzip -o -qq /in/payload -d /tmp/unpack; "
        "  find /tmp/unpack -type f ! -name '*.md' ! -name '*.txt' -exec cp {} /tmp/7350FH \\; ; "
        "else "
        "  cp /in/payload /tmp/7350FH; "
        "fi; "
        "chmod 0700 /tmp/7350FH; "
        "test -x /tmp/7350FH"
    )
    proc = docker_cmd("exec", name, "sh", "-c", script, timeout=90)
    if proc.returncode != 0:
        raise CageError((proc.stderr or proc.stdout or "stage inside cage failed").strip())


def ensure_cage(session: str, target: Path, log: LogFn | None = None) -> str:
    name = container_name(session)
    target = target.expanduser().resolve()
    if not target.is_file():
        raise CageError(f"target not a file: {target}")
    if log:
        log("sys", "waiting for docker…")
    start_docker_desktop()
    if not image_exists():
        if log:
            log("sys", f"building {IMAGE} (linux/amd64, first time)")
        build_image()
    running = container_running(name)
    mounted = _mounted_source(name) if running else ""
    if running and mounted == str(target):
        # Binary already staged on tmpfs from a previous exec in this cage.
        probe = docker_cmd("exec", name, "test", "-x", INNER_PATH, timeout=10)
        if probe.returncode == 0:
            return name
        if log:
            log("sys", "restaging binary on cage tmpfs")
        stage_binary(name)
        return name
    if log:
        log("sys", f"spawning cage {name}  net=none cap-drop=ALL read-only  bind={target.name}")
    spawn(name, target)
    stage_binary(name)
    return name


def _env_args(*pairs: str) -> list[str]:
    args: list[str] = []
    for pair in pairs:
        args.extend(("-e", pair))
    return args


def _captured_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _run_inner(
    name: str,
    password: str,
    binary: str,
    extra: Sequence[str],
    timeout: float,
    extra_env: Sequence[str],
    host_slack: float,
) -> CageResult:
    cmd = [
        docker_bin(),
        "exec",
        *_env_args(f"FH_PASS={password}", *extra_env),
        name,
        "timeout",
        "--signal=KILL",
        f"{max(1, int(timeout))}s",
        binary,
        *extra,
    ]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + host_slack,
        )
        duration = time.perf_counter() - t0
        return CageResult(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=duration,
            timed_out=proc.returncode in (124, 137),
        )
    except subprocess.TimeoutExpired as exc:
        return CageResult(
            returncode=137,
            stdout=_captured_text(exc.stdout),
            stderr=_captured_text(exc.stderr),
            duration=time.perf_counter() - t0,
            timed_out=True,
            error="host-side timeout",
        )
    except FileNotFoundError as exc:
        raise CageError("docker CLI not found") from exc


def try_password(
    name: str,
    password: str,
    argv: list[str] | None = None,
    timeout: float = 45.0,
) -> CageResult:
    extra = list(argv or [])
    # coreutils timeout: 124 on timeout. KILL after grace.
    return _run_inner(
        name,
        password,
        INNER_PATH,
        extra,
        timeout,
        extra_env=(
            "HOME=/tmp",
            "TMPDIR=/tmp",
            "TEMP=/tmp",
            "NUITKA_ONEFILE_PARENT=",
            "PYTHONIOENCODING=utf-8",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
        ),
        host_slack=10.0,
    )


def bypass_container_name(session: str) -> str:
    return container_name(session) + "-bp"


def ensure_bypass_cage(
    session: str,
    target: Path,
    payload_dir: Path,
    log: LogFn | None = None,
) -> str:
    """Cage with the re-keyed inner tree bind-mounted at /opt/fh (read-only)."""
    name = bypass_container_name(session)
    target = target.expanduser().resolve()
    payload_dir = payload_dir.expanduser().resolve()
    inner = payload_dir / "7350FH.bin"
    if not inner.is_file():
        raise CageError(f"patched inner missing: {inner}")
    if log:
        log("sys", "waiting for docker…")
    start_docker_desktop()
    if not image_exists():
        if log:
            log("sys", f"building {IMAGE} (linux/amd64, first time)")
        build_image()
    running = container_running(name)
    if running:
        probe = docker_cmd("exec", name, "test", "-x", PATCHED_BIN, timeout=10)
        if probe.returncode == 0:
            return name
        destroy(name)
    if log:
        log("sys", f"spawning bypass cage {name}  bind={payload_dir.name} → /opt/fh")
    spawn(name, target, extra_binds=[(payload_dir, "/opt/fh")])
    return name


def try_patched(
    name: str,
    password: str,
    argv: list[str] | None = None,
    timeout: float = 180.0,
) -> CageResult:
    extra = list(argv if argv is not None else ["list"])
    return _run_inner(
        name,
        password,
        PATCHED_BIN,
        extra,
        timeout,
        extra_env=(
            "HOME=/tmp",
            "TMPDIR=/tmp",
            "TEMP=/tmp",
            "LD_LIBRARY_PATH=/opt/fh",
            "PYTHONIOENCODING=utf-8",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
        ),
        host_slack=15.0,
    )
