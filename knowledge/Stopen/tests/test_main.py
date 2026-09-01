"""整应用集成测试：导入 main、认证行为、stats/skills 接口"""
import httpx
import pytest
from fastapi.testclient import TestClient

from app_config import auth as auth_module
from services.db_service import Database

TEST_TOKEN = "test-token-123"


@pytest.fixture(scope="module", autouse=True)
def _patch_auth_file():
    """token 文件指向测试隔离目录（模块级手动 patch，避免作用域冲突）"""
    import conftest
    storage = conftest.TEST_STORAGE
    storage.mkdir(parents=True, exist_ok=True)
    (storage / ".auth_secret").write_text(TEST_TOKEN)
    original = auth_module.AUTH_FILE
    auth_module.AUTH_FILE = storage / ".auth_secret"
    yield
    auth_module.AUTH_FILE = original


@pytest.fixture(scope="module")
def client():
    import main as main_module
    with TestClient(main_module.app) as c:
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_api_blocked_without_token(client):
    assert client.get("/api/tools").status_code == 401


def test_api_accessible_with_token(client):
    r = client.get("/api/tools", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert r.status_code == 200
    assert "tools" in r.json()


def test_stats_endpoint(client):
    r = client.get("/api/stats", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert r.status_code == 200
    data = r.json()
    for key in ("listeners", "sessions", "webshells", "vulnerabilities", "tasks",
                "conversations", "skills", "tools"):
        assert key in data


def test_skills_endpoints(client):
    r = client.get("/api/skills", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert r.status_code == 200
    skills = r.json()["skills"]
    assert skills, "技能列表不应为空"
    name = skills[0]["name"]
    r2 = client.get(f"/api/skills/{name}", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert r2.status_code == 200 and r2.json()["content"]
    r3 = client.get("/api/skills/__nope__", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert r3.status_code == 404


def test_webshell_list_masks_password(client):
    """API 列表必须脱敏，不能回传明文密码"""
    h = {"Authorization": f"Bearer {TEST_TOKEN}"}
    client.post("/api/webshell", json={"name": "t", "url": "http://x/s.php",
                                       "password": "secret123", "shell_type": "php"}, headers=h)
    rows = client.get("/api/webshell", headers=h).json()["webshells"]
    target = [w for w in rows if w["name"] == "t"][0]
    assert target["password"] == "****"


def test_auth_config_remote_via_asgi():
    """模拟局域网客户端：/api/auth/config 必须拒绝"""
    import asyncio
    import main as main_module

    async def _run():
        transport = httpx.ASGITransport(app=main_module.app, client=("192.168.1.88", 5000))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return await c.get("/api/auth/config")

    r = asyncio.run(_run())
    assert r.status_code == 401


def test_db_singleton_uses_isolated_path():
    import conftest
    from services.db_service import db
    assert db.db_path == conftest.TEST_STORAGE / "test.db"
    assert isinstance(db, Database)
