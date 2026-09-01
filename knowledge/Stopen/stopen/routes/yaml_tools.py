"""自定义 YAML 工具管理 API"""
from fastapi import APIRouter, Request, HTTPException
from services.db_service import db
from services.tools import yaml_loader
from app_config.logging_config import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/api/yaml-tools", tags=["yaml-tools"])


@router.get("")
async def list_yaml_tools():
    tools = db.list_yaml_tools()
    # 增强显示是否已加载到 registry
    from services.tool_registry import tool_registry
    loaded_names = {s["name"] for s in tool_registry.list_specs()}
    for t in tools:
        t["loaded"] = t["name"] in loaded_names
    return {"tools": tools}


@router.post("")
async def create_yaml_tool(req: Request):
    body = await req.json()
    name = body.get("name", "")
    description = body.get("description", "")
    category = body.get("category", "custom")
    tool_type = body.get("tool_type", "subprocess")
    command = body.get("command", "")
    parameters = body.get("parameters", "{}")
    timeout = body.get("timeout", 60)
    if not name or not command:
        raise HTTPException(400, "name 和 command 不能为空")
    import json as _json
    if isinstance(parameters, dict):
        parameters = _json.dumps(parameters, ensure_ascii=False)
    result = db.create_yaml_tool(name, description, category, tool_type, command, parameters, timeout)
    return result


@router.put("/{tid}")
async def update_yaml_tool(tid: str, req: Request):
    body = await req.json()
    existing = db.get_yaml_tool(tid)
    if not existing:
        raise HTTPException(404, "工具不存在")
    allowed = {"name", "description", "category", "tool_type", "command", "parameters", "timeout", "enabled"}
    import json as _json
    if "parameters" in body and isinstance(body["parameters"], dict):
        body["parameters"] = _json.dumps(body["parameters"], ensure_ascii=False)
    updates = {k: v for k, v in body.items() if k in allowed and v is not None}
    if updates:
        db.update_yaml_tool(tid, **updates)
    return {"ok": True}


@router.delete("/{tid}")
async def delete_yaml_tool(tid: str):
    db.delete_yaml_tool(tid)
    return {"ok": True}


@router.post("/reload")
async def reload_tools():
    """重新加载所有自定义工具到 ToolRegistry"""
    count = yaml_loader.reload_all()
    return {"ok": True, "count": count}


@router.post("/{tid}/test")
async def test_yaml_tool(tid: str, req: Request):
    """测试工具运行"""
    body = await req.json()
    tool_def = db.get_yaml_tool(tid)
    if not tool_def:
        raise HTTPException(404, "工具不存在")
    from services.tools.yaml_loader import YamlToolInstance
    import json as _json
    params = {}
    try:
        params = _json.loads(tool_def.get("parameters", "{}"))
    except (json.JSONDecodeError, TypeError):
        params = {}
    instance = YamlToolInstance(
        yid=tool_def["id"],
        name=tool_def["name"],
        description=tool_def.get("description", ""),
        category=tool_def.get("category", "custom"),
        tool_type=tool_def.get("tool_type", "subprocess"),
        command=tool_def.get("command", ""),
        parameters=params,
        timeout=tool_def.get("timeout", 60),
    )
    result = await instance.execute(body.get("args", {}))
    return {"success": result.success, "output": result.output[:2000], "error": result.error}
