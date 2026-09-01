"""C2 Go 守护进程集成测试

真实拉起 c2d.exe + 内部 bridge API（uvicorn 线程），
用 Python 按线上协议模拟被控端 payload，验证三种监听器全链路：
    payload ↔ Go 监听器 ↔ bridge ↔ SQLite
"""
import base64
import json
import socket
import threading
import time

import httpx
import pytest

from services.c2_service_legacy import C2Encryption
from services.db_service import db as global_db

CTL_TOKEN = "test-ctl-token"
KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def backend_server():
    """内部 bridge API（复用 c2 路由，挂临时 DB，无认证中间件）"""
    import uvicorn
    from fastapi import FastAPI
    from routes.c2 import router as c2_router

    app = FastAPI()
    app.include_router(c2_router)
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(50):
        try:
            httpx.get(f"http://127.0.0.1:{port}/docs", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(timeout=5)


@pytest.fixture(scope="module")
def daemon(backend_server):
    """拉起真实 c2d.exe 并下发 backend 配置"""
    from pathlib import Path
    import subprocess
    import sys

    repo = Path(__file__).resolve().parent.parent
    exe = repo / "c2d" / ("c2d.exe" if sys.platform == "win32" else "c2d")
    if not exe.is_file():
        pytest.skip("c2d 二进制未构建")
    ctl_port = _free_port()
    ctl_token = CTL_TOKEN
    proc = subprocess.Popen(
        [str(exe), "--addr", f"127.0.0.1:{ctl_port}", "--ctl-token", ctl_token],
        cwd=str(exe.parent),
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    base = f"http://127.0.0.1:{ctl_port}"
    for _ in range(50):
        try:
            if httpx.get(f"{base}/ctl/health", headers={"X-CTL-Token": ctl_token}, timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("c2d 健康检查超时")
    r = httpx.post(f"{base}/ctl/config", headers={"X-CTL-Token": ctl_token},
                   json={"backend_url": backend_server, "backend_token": "test-token"}, timeout=5)
    assert r.status_code == 200
    yield {"base": base, "headers": {"X-CTL-Token": ctl_token}}
    proc.terminate()
    proc.wait(timeout=5)


def _start_listener(daemon, ltype: str, host="127.0.0.1") -> tuple[str, int]:
    port = _free_port()
    lid = f"l-{ltype}-{port}"
    global_db.create_listener(name=lid, listener_type=ltype, host=host, port=port)
    r = httpx.post(f"{daemon['base']}/ctl/listeners", headers=daemon["headers"], timeout=10,
                   json={"id": lid, "type": ltype, "host": host, "port": port,
                         "secret": KEY, "encryption": "aes-256-ctr"})
    assert r.status_code == 200, r.text
    time.sleep(0.3)
    return lid, port


def _wait_task_result(task_id: str, timeout=15) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        import sqlite3
        conn = sqlite3.connect(str(global_db.db_path))
        row = conn.execute("SELECT result, status FROM c2_tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
        if row and row[1] == "done" and row[0]:
            return row[0]
        time.sleep(0.3)
    return None


def test_health_and_ctl_auth(daemon):
    r = httpx.get(f"{daemon['base']}/ctl/health", headers=daemon["headers"], timeout=5)
    assert r.status_code == 200 and r.json()["status"] == "ok"
    # health 免认证（仅本机绑定）；管理接口必须鉴权
    r2 = httpx.post(f"{daemon['base']}/ctl/listeners", headers={"X-CTL-Token": "wrong"}, timeout=5,
                    json={"id": "x", "type": "tcp", "host": "127.0.0.1", "port": 1, "secret": KEY})
    assert r2.status_code == 403
    r3 = httpx.post(f"{daemon['base']}/ctl/listeners", timeout=5,
                    json={"id": "x", "type": "tcp", "host": "127.0.0.1", "port": 1, "secret": KEY})
    assert r3.status_code == 403


def test_tcp_full_flow(daemon):
    """TCP 反向连接：注册 → 心跳 → 下发命令 → 回传结果 → 落库"""
    lid, port = _start_listener(daemon, "tcp")

    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    # 1. 握手：加密注册信息
    reg = C2Encryption.encrypt(json.dumps(
        {"hostname": "go-test-host", "username": "tester", "os": "python"}), KEY)
    s.sendall((reg + "\n").encode())
    time.sleep(1.0)

    # 会话已注册
    sessions = [x for x in global_db.list_sessions() if x["listener_id"] == lid]
    assert sessions, "会话未注册"
    sid = sessions[0]["id"]
    assert sessions[0]["hostname"] == "go-test-host"

    # 2. 收心跳
    s.settimeout(10)
    buf = b""
    while not buf.endswith(b"\n"):
        buf += s.recv(4096)
    msg = json.loads(C2Encryption.decrypt(buf.decode().strip(), KEY))
    assert msg["type"] == "heartbeat"

    # 3. 下发任务
    task = global_db.create_c2_task(sid, "whoami")
    deadline = time.time() + 15
    cmd_msg = None
    while time.time() < deadline:
        buf = b""
        try:
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            break
        if not buf:
            break
        msg = json.loads(C2Encryption.decrypt(buf.decode().strip(), KEY))
        if msg["type"] == "exec":
            cmd_msg = msg
            break
    assert cmd_msg and cmd_msg["command"] == "whoami"

    # 4. 回传结果
    result = C2Encryption.encrypt(json.dumps(
        {"type": "result", "output": "go-test-user"}), KEY)
    s.sendall((result + "\n").encode())

    got = _wait_task_result(task["id"])
    assert got == "go-test-user", f"任务结果未落库: {got}"
    s.close()


def test_http_beacon_full_flow(daemon):
    """HTTP Beacon：注册 → 心跳 → 下发命令 → result 回传（写入最近 sent 任务）"""
    import sqlite3
    lid, port = _start_listener(daemon, "http")
    url = f"http://127.0.0.1:{port}/beacon"

    def beacon(payload_plain: str) -> dict:
        enc = C2Encryption.encrypt(payload_plain, KEY)
        r = httpx.post(url, content=enc.encode(), timeout=10)
        assert r.status_code == 200
        return json.loads(C2Encryption.decrypt(r.text, KEY))

    # 1. 注册 beacon
    msg = beacon(json.dumps({"hostname": "http-host", "username": "u1", "os": "python"}))
    assert msg["type"] == "heartbeat"

    sessions = [x for x in global_db.list_sessions() if x["listener_id"] == lid]
    assert sessions and sessions[0]["hostname"] == "http-host"
    sid = sessions[0]["id"]

    # 2. 复用会话（同 IP 再次 beacon 不新建）
    beacon(json.dumps({"hostname": "http-host", "username": "u1", "os": "python"}))
    assert len([x for x in global_db.list_sessions() if x["listener_id"] == lid]) == 1

    # 3. 下发任务
    task = global_db.create_c2_task(sid, "id")
    msg = beacon(json.dumps({"hostname": "http-host", "username": "u1", "os": "python"}))
    assert msg["type"] == "exec" and msg["command"] == "id"

    # 4. result 回传（无 task_id，Go 端写入最近 sent 任务 —— 修复 Python 版缺陷）
    beacon(json.dumps({"type": "result", "output": "uid=0(root)"}))
    conn = sqlite3.connect(str(global_db.db_path))
    row = conn.execute("SELECT result, status FROM c2_tasks WHERE id=?", (task["id"],)).fetchone()
    conn.close()
    assert row and row[0] == "uid=0(root)", f"HTTP 结果未落库: {row}"


def test_ws_full_flow(daemon):
    """WebSocket：register → 心跳 → exec(带 task_id) → result(带 task_id)"""
    import asyncio

    async def run():
        import aiohttp
        lid, port = _start_listener(daemon, "ws")
        sid_holder = {}

        async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)) as sess:
            ws = await sess.ws_connect(f"ws://127.0.0.1:{port}/beacon")

            # register
            await ws.send_str(C2Encryption.encrypt(json.dumps(
                {"type": "register", "hostname": "ws-host", "username": "u2", "os": "python"}), KEY))
            rmsg = await asyncio.wait_for(ws.receive(), timeout=10)
            msg = json.loads(C2Encryption.decrypt(rmsg.data, KEY))
            assert msg["type"] == "heartbeat"

            # register 的 Meta 更新是异步的，轮询等待
            sid, hostname_ok = None, False
            for _ in range(20):
                sessions = [x for x in global_db.list_sessions() if x["listener_id"] == lid]
                if sessions:
                    sid = sessions[0]["id"]
                    if sessions[0]["hostname"] == "ws-host":
                        hostname_ok = True
                        break
                await asyncio.sleep(0.25)
            assert sid and hostname_ok, f"WS 会话注册/主机名未落库: {sessions}"

            task = global_db.create_c2_task(sid, "uname -a")
            rmsg2 = await asyncio.wait_for(ws.receive(), timeout=15)
            msg = json.loads(C2Encryption.decrypt(rmsg2.data, KEY))
            assert msg["type"] == "exec" and msg["command"] == "uname -a"
            assert msg.get("task_id") == task["id"]

            await ws.send_str(C2Encryption.encrypt(json.dumps(
                {"type": "result", "task_id": task["id"], "output": "Linux ws-host"}), KEY))
            await asyncio.sleep(1.0)
            await ws.close()
            sid_holder["task"] = task["id"]

        return sid_holder["task"]

    task_id = asyncio.run(run())
    got = _wait_task_result(task_id)
    assert got == "Linux ws-host", f"WS 结果未落库: {got}"


def test_stop_listener(daemon):
    lid, port = _start_listener(daemon, "tcp")
    r = httpx.delete(f"{daemon['base']}/ctl/listeners/{lid}", headers=daemon["headers"], timeout=10)
    assert r.status_code == 200
    # 端口已释放：新连接应被拒绝
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.close()
        pytest.fail("监听器停止后端口仍可连接")
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass
