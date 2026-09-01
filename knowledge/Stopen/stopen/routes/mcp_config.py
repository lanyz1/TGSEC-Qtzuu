"""MCP 服务器配置 API"""
from fastapi import APIRouter, Request, HTTPException
from services.db_service import db
from services.tools.mcp_bridge import mcp_bridge
from app_config.logging_config import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/api/mcp", tags=["mcp"])


@router.get("/servers")
async def list_mcp_servers():
    return {"servers": db.list_mcp_servers()}


@router.post("/servers")
async def create_mcp_server(req: Request):
    body = await req.json()
    name = body.get("name", "")
    base_url = body.get("base_url", "")
    server_type = body.get("server_type", "mcp")
    api_key = body.get("api_key", "")
    description = body.get("description", "")
    command = body.get("command", "")
    args = body.get("args", "")
    if server_type == "stdio":
        if not command:
            raise HTTPException(400, "stdio 模式需要 command")
        base_url = f"stdio://{command}"
    if not name or not base_url:
        raise HTTPException(400, "name 和 base_url 不能为空")
    result = db.create_mcp_server(
        name=name, base_url=base_url, server_type=server_type,
        api_key=api_key, description=description,
        command=command, args=args,
    )
    await mcp_bridge.reload()
    return result


@router.put("/servers/{sid}")
async def update_mcp_server(sid: str, req: Request):
    body = await req.json()
    existing = db.get_mcp_server(sid)
    if not existing:
        raise HTTPException(404, "MCP 服务器不存在")
    if body.get("api_key") and body["api_key"] == "****":
        body.pop("api_key")
    db.update_mcp_server(sid, **body)
    await mcp_bridge.reload()
    return {"ok": True}


@router.delete("/servers/{sid}")
async def delete_mcp_server(sid: str):
    db.delete_mcp_server(sid)
    await mcp_bridge.reload()
    return {"ok": True}


@router.post("/servers/{sid}/test")
async def test_mcp_server(sid: str):
    """测试 MCP 服务器连接"""
    info = db.get_mcp_server(sid)
    if not info:
        raise HTTPException(404, "MCP 服务器不存在")
    srv_type = info.get("server_type", "mcp")
    if srv_type == "stdio":
        from services.tools.mcp_bridge import MCPServerStdio
        command = info.get("command", "")
        import json as _json
        args = _json.loads(info.get("args", "[]")) if info.get("args") else []
        if not command:
            return {"status": "error", "error": "未配置 command"}
        server = MCPServerStdio(info["id"], info["name"], command, args)
        status = await server.health()
        await server.close()
        return {"status": status, "name": info["name"], "command": command}
    else:
        from services.tools.mcp_bridge import MCPServer
        server = MCPServer(info["id"], info["name"], info["base_url"], info.get("api_key", ""))
        status = await server.health()
        await server.close()
        return {"status": status, "name": info["name"], "base_url": info["base_url"]}


@router.post("/call")
async def call_mcp_tool(req: Request):
    """调用指定 MCP 服务器的工具"""
    body = await req.json()
    server_id = body.get("server_id", "")
    tool_name = body.get("tool_name", "")
    params = body.get("params", {})
    result = await mcp_bridge.call(server_id, tool_name, **params)
    return result
