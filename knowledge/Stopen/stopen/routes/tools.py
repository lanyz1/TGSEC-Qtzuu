"""工具列表/状态 API"""
from fastapi import APIRouter
from services.tool_registry import tool_registry
from services.tools.mcp_bridge import mcp_bridge

router = APIRouter(prefix="/api/tools", tags=["tools"])


@router.get("")
async def list_all_tools():
    """列出所有可用的 Agent 工具及 MCP 服务器状态"""
    tools = tool_registry.list_specs()
    mcp_status = await mcp_bridge.get_status()
    mcp_servers = mcp_bridge.list_servers()
    return {
        "tools": tools,
        "count": len(tools),
        "mcp_servers": mcp_status,
        "mcp_list": mcp_servers,
    }
