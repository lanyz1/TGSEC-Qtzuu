"""认证中间件测试：token 校验 + /api/auth/config 仅本机可读"""
import httpx
import pytest
from fastapi import FastAPI

from app_config import auth as auth_module
from app_config.auth import AuthMiddleware


@pytest.fixture
def secret_file(tmp_path, monkeypatch):
    f = tmp_path / ".auth_secret"
    monkeypatch.setattr(auth_module, "AUTH_FILE", f)
    return f


def _build_app(secret_file):
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/api/tools")
    async def tools():
        return {"tools": []}

    @app.get("/api/auth/config")
    async def auth_config():
        return {"token": auth_module._load_or_create_secret()}

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    return app


async def _request(app, path, host, headers=None):
    transport = httpx.ASGITransport(app=app, client=(host, 51234))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        return await c.get(path, headers=headers or {})


@pytest.mark.asyncio
async def test_health_no_auth_required(secret_file):
    app = _build_app(secret_file)
    r = await _request(app, "/api/health", "192.168.1.50")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_api_requires_token(secret_file):
    app = _build_app(secret_file)
    r = await _request(app, "/api/tools", "192.168.1.50")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_api_wrong_token_rejected(secret_file):
    app = _build_app(secret_file)
    r = await _request(app, "/api/tools", "127.0.0.1", {"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_api_valid_token_accepted(secret_file):
    app = _build_app(secret_file)
    token = auth_module._load_or_create_secret()
    r = await _request(app, "/api/tools", "192.168.1.50", {"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_auth_config_loopback_allowed(secret_file):
    app = _build_app(secret_file)
    r = await _request(app, "/api/auth/config", "127.0.0.1")
    assert r.status_code == 200
    assert r.json()["token"] == secret_file.read_text().strip()


@pytest.mark.asyncio
async def test_auth_config_remote_denied(secret_file):
    """核心安全回归：远程客户端不能匿名拿到 token"""
    app = _build_app(secret_file)
    r = await _request(app, "/api/auth/config", "192.168.1.50")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_non_ascii_token_header_no_500(secret_file):
    """非 ASCII Authorization 头应返回 401 而非 500（绕过 httpx 客户端编码限制，直接走 ASGI）"""
    app = _build_app(secret_file)
    token = auth_module._load_or_create_secret()
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "method": "GET",
        "path": "/api/tools", "query_string": b"", "headers": [
            (b"authorization", f"Bearer caf\xe9-{token[:5]}".encode("latin-1")),
        ],
        "client": ("127.0.0.1", 51234), "server": ("testserver", 80),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    status_holder = {}

    async def send(message):
        if message["type"] == "http.response.start":
            status_holder["status"] = message["status"]

    await app(scope, receive, send)
    assert status_holder["status"] == 401
