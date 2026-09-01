"""Agent 执行 API（SSE 流式）"""
import json, asyncio
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from services.agent_loop_ooda import ooda_loop_stream
from services.llm_service import _get_model_string
from services.blackboard import Blackboard
from app_config.encryption import ConfigEncryption
from app_config.providers import PROVIDERS, PROVIDER_ORDER
from app_config.settings import CONFIG_DIR
from app_config.logging_config import get_logger
from services.db_service import db

log = get_logger(__name__)
router = APIRouter(prefix="/api/agent", tags=["agent"])

# 每个任务的取消事件和黑板实例
_cancel_events: dict[str, asyncio.Event] = {}
_blackboards: dict[str, Blackboard] = {}


@router.post("/run")
async def run_agent(req: Request):
    """运行 OODA Agent 循环，返回 SSE 流"""
    body = await req.json()
    target = body.get("target", "")
    goal = body.get("goal", "")
    task_type = body.get("task_type", "pentest")
    model = body.get("model", "")
    task_id = body.get("task_id", "")
    custom_prompt = body.get("system_prompt", "")
    role_id = body.get("role_id", "")
    skills_override = body.get("skills", "")
    persistent_mode = body.get("persistent_mode", False)

    # 如果指定了角色，从角色获取 system_prompt 和 skills
    role_prompt = ""
    if role_id:
        role = db.get_role(role_id)
        if role:
            role_prompt = role.get("system_prompt", "")
            if not skills_override and role.get("skills"):
                skills_override = role["skills"]
            custom_prompt = role_prompt or custom_prompt

    if not target:
        raise HTTPException(400, "target 不能为空")

    # 解析模型
    provider_key = "openai"
    model_str = model
    if model_str:
        for pk in PROVIDER_ORDER:
            if model_str.startswith(pk + "/"):
                provider_key = pk
                break
    else:
        enc = ConfigEncryption(CONFIG_DIR)
        cfg = enc.load_config()
        for pk in PROVIDER_ORDER:
            saved = cfg.get(pk, {})
            if saved.get("enabled") and saved.get("api_key"):
                models = saved.get("models", PROVIDERS[pk].get("models", []))
                if models:
                    model_str = _get_model_string(pk, models[0])
                    provider_key = pk
                    break
        if not model_str:
            model_str = "openai/gpt-4o-mini"
            provider_key = "openai"

    if not task_id:
        import uuid
        task_id = str(uuid.uuid4())[:8]
        db.create_task(name=f"Task-{task_id}", target=target, task_type=task_type, goal=goal)

    # 黑板
    blackboard = Blackboard(goal=goal or f"对 {target} 进行渗透测试")
    _blackboards[task_id] = blackboard
    cancel_event = asyncio.Event()
    _cancel_events[task_id] = cancel_event

    async def generate():
        try:
            async for chunk in ooda_loop_stream(
                target=target,
                goal=goal or f"对 {target} 进行渗透测试",
                task_type=task_type,
                model=model_str,
                provider_key=provider_key,
                blackboard=blackboard,
                cancel_event=cancel_event,
                custom_prompt=custom_prompt,
                skills_override=skills_override,
                persistent_mode=persistent_mode,
            ):
                yield f"data: {json.dumps({'token': chunk})}\n\n"
        except Exception as e:
            log.error(f"Agent error: {e}")
            yield f"data: {json.dumps({'token': f'[错误: {str(e)}]'})}\n\n"
        yield "data: [DONE]\n\n"
        db.update_task(task_id, status="completed" if blackboard.goal_achieved else "failed")

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@router.post("/cancel/{task_id}")
async def cancel_agent(task_id: str):
    event = _cancel_events.get(task_id)
    if event:
        event.set()
        return {"ok": True}
    return {"ok": False, "message": "没有运行中的 Agent"}


@router.get("/blackboard/{task_id}")
async def get_blackboard(task_id: str):
    bb = _blackboards.get(task_id)
    if not bb:
        raise HTTPException(404, "黑板不存在")
    return bb.to_dict()
