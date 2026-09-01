"""YAML 工具加载器 —— 从数据库加载用户自定义工具到 ToolRegistry"""
import asyncio
import json
import shlex

import httpx

from services.tool_base import BaseTool, ToolResult
from services.tool_registry import tool_registry
from services.db_service import db
from app_config.logging_config import get_logger

log = get_logger(__name__)


class YamlToolInstance(BaseTool):
    """从 YAML 定义动态生成的 BaseTool 实例"""

    def __init__(self, yid: str, name: str, description: str, category: str,
                 tool_type: str, command: str, parameters: dict, timeout: int):
        super().__init__()
        self.yid = yid
        self.name = name
        self.description = description
        self.category = category
        self.tool_type = tool_type  # subprocess | api
        self.command_str = command
        self.parameters = {
            "type": "object",
            "properties": {k: {"type": v.get("type", "string"),
                               "description": v.get("description", "")}
                           for k, v in parameters.items()},
            "required": [k for k, v in parameters.items() if v.get("required")],
        }
        self._timeout = timeout

    def _build_command(self, args: dict) -> list[str]:
        """用自定义参数替换命令模板中的占位符"""
        cmd = self.command_str
        for k, v in args.items():
            cmd = cmd.replace("{" + k + "}", str(v))
        # 移除未替换的占位符
        import re
        cmd = re.sub(r'\{[^}]+\}', '', cmd)
        return shlex.split(cmd)

    async def execute(self, args: dict) -> ToolResult:
        try:
            if self.tool_type == "api":
                url = args.pop("_url", self.command_str)
                method = args.pop("_method", "GET")
                async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
                    resp = await client.request(method, url, params=args)
                    text = resp.text[:3000]
                    return ToolResult.ok(
                        output=f"[API] {method} {url}\nHTTP {resp.status_code}\n{text}",
                        data={"status": resp.status_code, "body": text},
                    )
            else:
                cmd_parts = self._build_command(args)
                proc = await asyncio.create_subprocess_exec(
                    *cmd_parts,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout)
                output = stdout.decode("utf-8", errors="replace")[:3000]
                error = stderr.decode("utf-8", errors="replace")[:500]
                if proc.returncode != 0:
                    return ToolResult.fail(f"退出码 {proc.returncode}: {error}")
                return ToolResult.ok(
                    output=f"$ {' '.join(cmd_parts)}\n{output}",
                    data={"stdout": output, "stderr": error},
                )
        except FileNotFoundError:
            return ToolResult.fail(f"命令未找到: {self.command_str}")
        except asyncio.TimeoutError:
            return ToolResult.fail(f"命令超时 ({self._timeout}s)")
        except Exception as e:
            return ToolResult.fail(str(e))


def load_from_db():
    """从数据库加载所有启用的 YAML 工具并注册到 registry"""
    tools = db.list_yaml_tools()
    count = 0
    for t in tools:
        if not t.get("enabled", 1):
            continue
        try:
            params = json.loads(t.get("parameters", "{}"))
        except (json.JSONDecodeError, TypeError):
            params = {}
        instance = YamlToolInstance(
            yid=t["id"],
            name=t["name"],
            description=t.get("description", ""),
            category=t.get("category", "custom"),
            tool_type=t.get("tool_type", "subprocess"),
            command=t.get("command", ""),
            parameters=params,
            timeout=t.get("timeout", 60),
        )
        tool_registry.register(instance)
        count += 1
    log.info(f"已从 DB 加载 {count} 个自定义工具")
    return count


def reload_all():
    """卸载旧工具并从 DB 重新加载"""
    # 移除所有已注册的自定义工具
    specs = tool_registry.list_specs()
    for s in specs:
        inst = tool_registry.get(s["name"])
        if inst and hasattr(inst, "yid"):
            tool_registry.unregister(s["name"])
    return load_from_db()
