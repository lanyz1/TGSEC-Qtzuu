"""简单认证中间件 — Bearer Token"""
import json
import secrets
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

AUTH_FILE = Path(__file__).resolve().parent.parent / "storage" / ".auth_secret"

# /api/auth/config 仅允许本机读取 token（前端/CLI 本地无缝登录）
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _load_or_create_secret() -> str:
    if AUTH_FILE.exists():
        return AUTH_FILE.read_text().strip()
    token = secrets.token_hex(32)
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(token)
    Path(AUTH_FILE.parent / "auth_config.json").write_text(json.dumps({"token": token}))
    return token


class AuthMiddleware(BaseHTTPMiddleware):
    """所有 /api/* 路由需要 Bearer Token 认证，静态文件和前端页面放行

    例外：
    - /api/health 无需认证（探活）
    - /api/auth/config 仅本机(127.0.0.1)可读 token；局域网客户端必须手动输入 token
    """

    def __init__(self, app):
        super().__init__(app)
        self._token = _load_or_create_secret()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # 放行前端资源（.html, .js, .css, 图片等）
        if not path.startswith("/api/"):
            return await call_next(request)

        # /api/health 放行
        if path == "/api/health":
            return await call_next(request)

        # /api/auth/config 仅本机可读（远程客户端拿不到 token，须手动输入）
        if path.startswith("/api/auth/"):
            client_host = request.client.host if request.client else ""
            if client_host in LOOPBACK_HOSTS:
                return await call_next(request)
            return JSONResponse(status_code=401, content={"detail": "远程访问请手动输入 Token 认证"})

        # 其他 /api/* 需要 Bearer Token
        auth = request.headers.get("Authorization", "")
        provided = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        # encode 防御非 ASCII 头导致的 TypeError，compare_digest 防时序侧信道
        if not secrets.compare_digest(provided.encode(), self._token.encode()):
            return JSONResponse(status_code=401, content={"detail": "未认证：需要有效的 Bearer Token"})

        return await call_next(request)
