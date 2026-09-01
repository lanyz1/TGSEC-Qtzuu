"""C2 框架 — Go 守护进程适配器 + Payload 生成

架构：
    高性能数据面 = c2d（Go，本仓库 c2d/ 目录）：TCP 反向 / HTTP Beacon / WebSocket
                  监听器与加解密，单进程数万并发连接
    控制面       = Python (FastAPI)：REST API / SQLite 会话与任务状态 / Payload 生成
    bridge       = c2d 通过内部接口回调 Python 注册会话、拉取任务、回写结果

适配逻辑：
    1. 优先使用 Go 守护进程（c2d/c2d.exe，或本机 Go 工具链现场编译）
    2. 守护进程不可用时自动回退 legacy 纯 Python 实现（c2_service_legacy.py）
    3. 对 routes/c2.py 暴露与旧版完全一致的接口：start/stop/gen_payload/get_status
"""
import asyncio
import base64
import os
import secrets
import subprocess
import sys
import threading
from pathlib import Path

import httpx

from app_config.logging_config import get_logger
from app_config.settings import BASE_DIR
from services.c2_service_legacy import C2Encryption  # noqa: F401  (payload 模板沿用)
from services.db_service import db

log = get_logger(__name__)

C2D_DIR = BASE_DIR.parent / "c2d"
C2D_PORT = int(os.environ.get("STOPEN_C2D_PORT", "8477"))
BACKEND_PORT = int(os.environ.get("STOPEN_PORT", "8080"))


def _auth_token() -> str:
    from app_config.auth import _load_or_create_secret
    return _load_or_create_secret()

_IS_WINDOWS = sys.platform == "win32"
_BIN_NAME = "c2d.exe" if _IS_WINDOWS else "c2d"


def _daemon_binary() -> Path | None:
    p = C2D_DIR / _BIN_NAME
    return p if p.is_file() else None


class C2Daemon:
    """c2d 守护进程生命周期管理（线程安全，惰性启动）"""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._ctl_token = ""

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{C2D_PORT}"

    def _headers(self) -> dict:
        return {"X-CTL-Token": self._ctl_token}

    def binary_available(self) -> bool:
        return _daemon_binary() is not None

    def _try_build(self) -> bool:
        """本机有 Go 工具链时现场编译"""
        import shutil
        if not shutil.which("go"):
            return False
        out = C2D_DIR / _BIN_NAME
        cmd = ["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", str(out), "."]
        try:
            r = subprocess.run(cmd, cwd=str(C2D_DIR), capture_output=True, text=True, timeout=300)
            if r.returncode == 0:
                log.info(f"c2d 现场编译完成: {out}")
                return True
            log.warning(f"c2d 编译失败: {r.stderr[-300:]}")
        except Exception as e:
            log.warning(f"c2d 编译异常: {e}")
        return False

    def _spawn(self) -> bool:
        bin_path = _daemon_binary()
        if not bin_path and not self._try_build():
            return False
        bin_path = _daemon_binary()
        self._ctl_token = secrets.token_hex(16)
        kwargs = {}
        if _IS_WINDOWS:
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            self._proc = subprocess.Popen(
                [str(bin_path), "--addr", f"127.0.0.1:{C2D_PORT}",
                 "--ctl-token", self._ctl_token,
                 "--backend-url", f"http://127.0.0.1:{BACKEND_PORT}",
                 "--backend-token", _auth_token()],
                cwd=str(C2D_DIR), **kwargs)
        except Exception as e:
            log.error(f"c2d 启动失败: {e}")
            self._proc = None
            return False
        log.info(f"c2d 守护进程已启动 pid={self._proc.pid} ctl={self.base_url}")
        return True

    def _port_occupied(self) -> bool:
        """端口上有 c2d 实例（无论 token 是否匹配）"""
        try:
            r = httpx.get(f"{self.base_url}/ctl/health",
                          headers={"X-CTL-Token": "probe"}, timeout=2)
            return r.status_code in (200, 403)
        except Exception:
            return False

    def _kill_orphans(self):
        """清理孤儿 c2d（后端重启后遗留、token 不匹配无法控制）"""
        import shutil
        try:
            if _IS_WINDOWS and shutil.which("taskkill"):
                subprocess.run(["taskkill", "/F", "/IM", _BIN_NAME],
                               capture_output=True, timeout=10)
            elif shutil.which("pkill"):
                subprocess.run(["pkill", "-f", _BIN_NAME], capture_output=True, timeout=10)
        except Exception as e:
            log.warning(f"清理孤儿 c2d 失败: {e}")

    def ensure_running(self) -> bool:
        """确保守护进程存活（孤儿自动清理 + 一次重试）"""
        with self._lock:
            if self._health_ok():
                return True
            self._cleanup_proc()
            for attempt in range(2):
                if self._spawn():
                    for _ in range(20):
                        if self._health_ok():
                            return True
                        time_sleep(0.25)
                    log.warning("c2d 健康检查超时")
                    self._cleanup_proc()
                if attempt == 0 and self._port_occupied():
                    log.warning("c2d 端口被孤儿实例占用，清理后重试")
                    self._kill_orphans()
                    time_sleep(1.5)
                    continue
                break
            log.error("c2d 启动失败，将回退 legacy")
            return False

    def _health_ok(self) -> bool:
        if not self._proc and not self._ctl_token:
            return False
        try:
            r = httpx.get(f"{self.base_url}/ctl/health", headers=self._headers(), timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    def _cleanup_proc(self):
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
            self._proc = None


def time_sleep(sec: float):
    import time
    time.sleep(sec)


class C2Service:
    """对外接口与旧版一致；Go 优先，失败回退 legacy"""

    def __init__(self):
        self.daemon = C2Daemon()
        self._legacy_backend: dict[str, str] = {}  # lid -> "go" | "legacy"

    # ── 监听器管理 ──

    async def start_listener(self, lid: str, name: str, listener_type: str,
                             host: str, port: int) -> dict:
        info = next((l for l in db.list_listeners() if l["id"] == lid), None)
        if not info:
            return {"error": "监听器不存在"}
        secret = info.get("secret", "")
        if not secret:
            secret = C2Encryption.generate_key()
            db.update_listener(lid, secret=secret)

        if self.daemon.ensure_running():
            try:
                r = await asyncio.to_thread(
                    httpx.post, f"{self.daemon.base_url}/ctl/listeners",
                    headers=self.daemon._headers(), timeout=10,
                    json={"id": lid, "type": listener_type, "host": host,
                          "port": port, "secret": secret,
                          "encryption": info.get("encryption_type", "aes-256-ctr")})
                if r.status_code == 200:
                    db.update_listener(lid, status="running")
                    self._legacy_backend[lid] = "go"
                    log.info(f"C2 监听器已启动 (Go): {name} ({listener_type}://{host}:{port})")
                    return {"status": "running", "lid": lid, "host": host, "port": port, "engine": "go"}
                log.warning(f"c2d 启动监听器失败 HTTP {r.status_code}: {r.text[:200]}")
            except Exception as e:
                log.warning(f"c2d 通信异常: {e}")
        else:
            log.warning("c2d 不可用，回退 legacy Python 监听器")

        # legacy 回退
        from services.c2_service_legacy import c2_service as legacy
        result = await legacy.start_listener(lid, name, listener_type, host, port)
        if "error" not in result:
            self._legacy_backend[lid] = "legacy"
        return result

    async def stop_listener(self, lid: str) -> dict:
        backend = self._legacy_backend.pop(lid, "go")
        if backend == "go" and self.daemon._health_ok():
            try:
                r = await asyncio.to_thread(
                    httpx.delete,
                    f"{self.daemon.base_url}/ctl/listeners/{lid}",
                    headers=self.daemon._headers(), timeout=10)
                if r.status_code == 200:
                    db.update_listener(lid, status="stopped")
                    return {"status": "stopped", "engine": "go"}
            except Exception as e:
                log.warning(f"c2d 停止监听器异常: {e}")
        from services.c2_service_legacy import c2_service as legacy
        return await legacy.stop_listener(lid)

    def get_status(self) -> dict:
        # 有 Go 二进制（或守护进程已运行）即视为 Go 引擎；否则 legacy 回退
        go_ready = self.daemon._health_ok() or self.daemon.binary_available()
        return {
            "running_listeners": len(db.list_listeners()),
            "total_sessions": len(db.list_sessions()),
            "engine": "go" if go_ready else "legacy",
        }

    # ── Payload 生成（纯字符串模板，无性能诉求，保留 Python 实现）──

    def gen_payload(self, payload_type: str = "python", host: str = "127.0.0.1",
                    port: int = 4444, secret: str = "", template_id: str = "") -> dict:
        from services.c2_service_legacy import c2_service as legacy
        return legacy.gen_payload(payload_type, host, port, secret=secret, template_id=template_id)


c2_service = C2Service()
