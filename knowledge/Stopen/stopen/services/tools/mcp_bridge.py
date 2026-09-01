"""MCP 工具桥接器 —— 支持 HTTP + stdio 模式的动态 MCP 服务管理"""
import asyncio
import json
import httpx

from services.db_service import db
from app_config.logging_config import get_logger

log = get_logger(__name__)


class MCPServer:
    """单个 HTTP MCP 服务器连接"""

    def __init__(self, server_id: str, name: str, base_url: str, api_key: str = ""):
        self.id = server_id
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._http = httpx.AsyncClient(timeout=60, verify=False)

    async def call(self, tool_name: str, **params) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "method": tool_name,
            "params": params,
            "id": 1,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            resp = await self._http.post(
                f"{self.base_url}/mcp" if "mcp" in self.base_url else self.base_url,
                json=payload,
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    return {"success": True, "data": data["result"]}
                return {"success": True, "data": data}
            return {"success": False, "error": f"HTTP {resp.status_code}", "body": resp.text[:500]}
        except httpx.ConnectError:
            return {"success": False, "error": "连接失败"}
        except httpx.TimeoutException:
            return {"success": False, "error": "超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def health(self) -> str:
        try:
            r = await self._http.get(f"{self.base_url}/health", timeout=3)
            return "connected" if r.is_success else "error"
        except Exception:
            return "disconnected"

    async def close(self):
        await self._http.aclose()

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "base_url": self.base_url}


class MCPServerStdio:
    """stdio 模式 MCP 服务器 —— 通过子进程 stdin/stdout JSON-RPC 通信"""

    def __init__(self, server_id: str, name: str, command: str, args: list = None):
        self.id = server_id
        self.name = name
        self.command = command
        self.args = args or []
        self._process: asyncio.subprocess.Process | None = None

    async def _ensure_running(self):
        if self._process and self._process.returncode is None:
            return
        self._process = await asyncio.create_subprocess_exec(
            self.command, *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def call(self, tool_name: str, **params) -> dict:
        await self._ensure_running()
        payload = {
            "jsonrpc": "2.0",
            "method": tool_name,
            "params": params,
            "id": 1,
        }
        try:
            line = json.dumps(payload) + "\n"
            self._process.stdin.write(line.encode())
            await self._process.stdin.drain()
            resp_line = await asyncio.wait_for(self._process.stdout.readline(), timeout=30)
            data = json.loads(resp_line.decode().strip())
            if "result" in data:
                return {"success": True, "data": data["result"]}
            return {"success": True, "data": data}
        except asyncio.TimeoutError:
            return {"success": False, "error": "stdio 调用超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def health(self) -> str:
        try:
            await self._ensure_running()
            if self._process and self._process.returncode is None:
                return "connected"
            return "disconnected"
        except Exception:
            return "disconnected"

    async def close(self):
        if self._process and self._process.returncode is None:
            self._process.kill()
            await self._process.wait()
            self._process = None

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "type": "stdio", "command": self.command}


class MCPBridge:
    """统一 MCP 桥接器 —— 从数据库动态加载 MCP 服务器配置"""

    def __init__(self):
        self._servers: dict[str, MCPServer | MCPServerStdio] = {}
        self._default_loaded = False

    def _load_servers(self):
        rows = db.list_mcp_servers()
        current_ids = set(self._servers.keys())
        db_ids = set()
        for r in rows:
            db_ids.add(r["id"])
            if r["id"] not in self._servers and r.get("enabled", 1):
                srv_type = r.get("server_type", "mcp")
                if srv_type == "stdio":
                    command = r.get("command", "")
                    args_str = r.get("args", "")
                    args = json.loads(args_str) if args_str else []
                    self._servers[r["id"]] = MCPServerStdio(
                        r["id"], r["name"], command, args)
                else:
                    self._servers[r["id"]] = MCPServer(
                        r["id"], r["name"], r["base_url"], r.get("api_key", ""))
        for sid in current_ids - db_ids:
            self._servers.pop(sid, None)

    async def reload(self):
        self._load_servers()

    async def call(self, server_id: str, tool_name: str, **params) -> dict:
        self._load_servers()
        server = self._servers.get(server_id)
        if not server:
            return {"success": False, "error": f"MCP 服务器 '{server_id}' 不存在或已禁用"}
        return await server.call(tool_name, **params)

    async def call_by_name(self, name: str, tool_name: str, **params) -> dict:
        self._load_servers()
        for s in self._servers.values():
            if s.name == name:
                return await s.call(tool_name, **params)
        return {"success": False, "error": f"未找到名为 '{name}' 的 MCP 服务器"}

    async def get_status(self) -> dict:
        self._load_servers()
        status = {}
        for sid, server in self._servers.items():
            status[server.name] = await server.health()
        return status

    def list_servers(self) -> list[dict]:
        self._load_servers()
        return [s.to_dict() for s in self._servers.values()]

    async def close(self):
        for s in self._servers.values():
            await s.close()
        self._servers.clear()


mcp_bridge = MCPBridge()
