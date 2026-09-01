"""网络空间搜索引擎工具 —— FOFA/Hunter/Shodan"""
import json

import httpx

from services.tool_base import BaseTool, ToolResult
from services.tools.mcp_bridge import mcp_bridge
from app_config.logging_config import get_logger

log = get_logger(__name__)


class FOFASearchTool(BaseTool):
    """FOFA 搜索引擎"""
    name = "fofa_search"
    description = "FOFA 网络空间搜索引擎：搜索目标相关资产（IP、域名、端口、服务）"
    category = "scanner"
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "FOFA 搜索语法，如 'domain=example.com' 或 'ip=\"1.1.1.1\"'"},
            "limit": {"type": "integer", "description": "返回结果数量，默认 10"},
        },
        "required": ["query"],
    }

    async def execute(self, args: dict) -> ToolResult:
        query = args.get("query", "")
        limit = min(args.get("limit", 10), 100)

        # 尝试 Yakit MCP FOFA
        result = await mcp_bridge.call_yakit("fofa_search", query=query, limit=limit)
        if result.get("success"):
            return ToolResult.ok(
                output=f"FOFA 搜索结果:\n{json.dumps(result['data'], indent=2, ensure_ascii=False)[:2000]}",
                data=result["data"],
            )

        return ToolResult.ok(output="FOFA 搜索不可用：未配置 Yakit MCP 或 FOFA API Key", data={"results": []})


class HunterSearchTool(BaseTool):
    """鹰图 (Hunter) 搜索引擎"""
    name = "hunter_search"
    description = "鹰图网络资产搜索引擎：搜索目标资产信息"
    category = "scanner"
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "搜索语法，如 'domain=example.com'"},
            "limit": {"type": "integer", "description": "返回结果数量，默认 10"},
        },
        "required": ["query"],
    }

    async def execute(self, args: dict) -> ToolResult:
        query = args.get("query", "")
        limit = min(args.get("limit", 10), 100)
        result = await mcp_bridge.call_yakit("zoomeye_search", query=query, limit=limit)
        if result.get("success"):
            return ToolResult.ok(
                output=f"鹰图搜索结果:\n{json.dumps(result['data'], indent=2, ensure_ascii=False)[:2000]}",
                data=result["data"],
            )
        return ToolResult.ok(output="鹰图搜索不可用：未配置 Yakit MCP", data={"results": []})


class ShodanSearchTool(BaseTool):
    """Shodan 搜索引擎"""
    name = "shodan_search"
    description = "Shodan 网络设备搜索引擎：搜索开放端口和服务的设备"
    category = "scanner"
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Shodan 搜索语法，如 'apache country:CN'"},
            "limit": {"type": "integer", "description": "返回结果数量，默认 10"},
        },
        "required": ["query"],
    }

    async def execute(self, args: dict) -> ToolResult:
        query = args.get("query", "")
        limit = min(args.get("limit", 10), 100)
        result = await mcp_bridge.call_yakit("zoomeye_search", query=query, limit=limit)
        if result.get("success"):
            return ToolResult.ok(
                output=f"Shodan 搜索结果:\n{json.dumps(result['data'], indent=2, ensure_ascii=False)[:2000]}",
                data=result["data"],
            )
        return ToolResult.ok(output="Shodan 搜索不可用", data={"results": []})
