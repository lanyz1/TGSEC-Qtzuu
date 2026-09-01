"""对话/聊天 API"""
import json
import uuid
from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import StreamingResponse
from services.db_service import db

router = APIRouter(prefix="/api/chat", tags=["chat"])


def _msg_to_llm(m: dict) -> dict:
    """DB 消息 → LLM 上下文；助手消息兼容 JSON 信封格式"""
    if m["role"] != "assistant":
        return {"role": m["role"], "content": m["content"]}
    try:
        obj = json.loads(m["content"])
        if isinstance(obj, dict) and "content" in obj:
            return {"role": "assistant", "content": obj.get("content") or ""}
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return {"role": "assistant", "content": m["content"]}


def _resolve_chat_model() -> str:
    """从已启用的提供商中选第一个可用的模型"""
    from app_config.encryption import ConfigEncryption
    from app_config.providers import PROVIDERS, PROVIDER_ORDER
    from app_config.settings import CONFIG_DIR
    from services.llm_service import _get_model_string

    enc = ConfigEncryption(CONFIG_DIR)
    cfg = enc.load_config()
    for pk in PROVIDER_ORDER:
        saved = cfg.get(pk, {})
        if saved.get("enabled") and saved.get("api_key"):
            models = saved.get("models") or PROVIDERS[pk].get("models", [])
            if models:
                return _get_model_string(pk, models[0])
    return "openai/gpt-4o-mini"


@router.get("/conversations")
async def list_conversations():
    return {"conversations": db.list_conversations()}


@router.post("/conversations")
async def create_conversation(req: Request):
    body = await req.json()
    title = body.get("title", "新对话")
    model = body.get("model", "")
    system_prompt = body.get("system_prompt", "")
    task_type = body.get("task_type", "pentest")
    conv = db.create_conversation(title=title, model=model,
                                   system_prompt=system_prompt, task_type=task_type)
    return conv


@router.get("/conversations/{cid}")
async def get_conversation(cid: str):
    conv = db.get_conversation(cid)
    if not conv:
        raise HTTPException(404, "对话不存在")
    messages = db.get_messages(cid)
    return {"conversation": conv, "messages": messages}


@router.delete("/conversations/{cid}")
async def delete_conversation(cid: str):
    conn = db._get_conn()
    conn.execute("DELETE FROM messages WHERE conversation_id=?", (cid,))
    conn.execute("DELETE FROM conversations WHERE id=?", (cid,))
    conn.commit()
    return {"ok": True}


@router.post("/conversations/{cid}/messages")
async def send_message(cid: str, req: Request):
    body = await req.json()
    content = body.get("content", "")
    role = body.get("role", "user")
    if not content:
        raise HTTPException(400, "内容不能为空")
    db.add_message(cid, role, content)
    conv = db.get_conversation(cid)
    if not conv:
        raise HTTPException(404, "对话不存在")

    use_agent = body.get("use_agent", False)
    # 支持前端传递模型选择
    model_str = body.get("model", "") or conv.get("model", "")
    if not model_str:
        model_str = _resolve_chat_model()

    if not use_agent:
        return {"ok": True, "message": "消息已记录"}

    # 直接 LLM 对话（不走 OODA 循环）
    from services.llm_client import acompletion
    history = db.get_messages(cid, limit=20)
    msgs = [{"role": "system", "content": "你是 Stopen AI 助手，帮助用户进行渗透测试和网络安全分析。回复简洁专业。"}]
    for m in history:
        msgs.append({"role": m["role"], "content": m["content"]})

    try:
        # 获取 API key
        from app_config.encryption import ConfigEncryption
        from app_config.settings import CONFIG_DIR
        enc = ConfigEncryption(CONFIG_DIR)
        cfg = enc.load_config()
        provider_key = model_str.split("/")[0] if "/" in model_str else "openai"
        saved = cfg.get(provider_key, {})
        api_key = saved.get("api_key", "")
        if not api_key:
            return {"assistant": "[错误] 未配置 API Key，请在「配置」页面设置", "use_agent": True}

        llm_kwargs = {"api_key": api_key}
        from app_config.providers import PROVIDERS
        info = PROVIDERS.get(provider_key, {})
        if info.get("base_url") and not info.get("is_native", True):
            llm_kwargs["api_base"] = saved.get("base_url") or info["base_url"]

        resp = await acompletion(model=model_str, messages=msgs, **llm_kwargs)
        reply = resp.choices[0].message.content or ""
        db.add_message(cid, "assistant", reply[:5000])
        return {"assistant": reply[:5000], "use_agent": True}
    except Exception as e:
        error_msg = f"[错误] {e}"
        return {"assistant": error_msg, "use_agent": True, "error": str(e)}


@router.post("/conversations/{cid}/stream")
async def stream_message(cid: str, req: Request):
    """流式对话（SSE）：透传思考过程、工具调用与正文增量

    事件格式: data: {"type": "reasoning|token|tool_call|tool_result|error|done", ...}
    """
    body = await req.json()
    content = body.get("content", "")
    if not content:
        raise HTTPException(400, "内容不能为空")
    conv = db.get_conversation(cid)
    if not conv:
        raise HTTPException(404, "对话不存在")
    db.add_message(cid, "user", content)

    from app_config.encryption import ConfigEncryption
    from app_config.providers import PROVIDERS
    from app_config.settings import CONFIG_DIR
    from services.chat_engine import chat_agent_stream, CHAT_SYSTEM_PROMPT

    model_str = body.get("model", "") or conv.get("model", "") or _resolve_chat_model()
    provider_key = model_str.split("/")[0] if "/" in model_str else "openai"
    enc = ConfigEncryption(CONFIG_DIR)
    cfg = enc.load_config()
    saved = cfg.get(provider_key, {})
    api_key = saved.get("api_key", "")
    info = PROVIDERS.get(provider_key, {})
    api_base = None
    if info.get("base_url") and not info.get("is_native", True):
        api_base = saved.get("base_url") or info["base_url"]

    history = db.get_messages(cid, limit=20)
    msgs = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]
    msgs += [_msg_to_llm(m) for m in history]
    use_tools = body.get("use_tools", True)

    async def generate():
        final_content = ""
        final_reasoning = ""
        tool_trace = []

        async def run_engine():
            nonlocal final_content, final_reasoning, tool_trace
            if not api_key:
                yield {"type": "error", "text": "未配置 API Key，请在「配置」页面设置"}
                yield {"type": "done", "content": "", "reasoning": ""}
                return
            async for ev in chat_agent_stream(
                messages=msgs, model=model_str, api_key=api_key,
                api_base=api_base, use_tools=use_tools,
            ):
                yield ev

        async for ev in run_engine():
            if ev["type"] == "tool_call":
                tool_trace.append({"name": ev["name"], "arguments": ev.get("arguments", {}),
                                   "output": "", "success": None})
            elif ev["type"] == "tool_result" and tool_trace:
                tool_trace[-1]["output"] = ev.get("output", "")
                tool_trace[-1]["success"] = ev.get("success")
            elif ev["type"] == "done":
                final_content = ev.get("content", "") or final_content
                final_reasoning = ev.get("reasoning", "") or final_reasoning
            yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

        yield "data: [DONE]\n\n"

        # 持久化：有思考/工具轨迹时存 JSON 信封，便于回放
        if final_content or final_reasoning or tool_trace:
            if final_reasoning or tool_trace:
                payload = json.dumps({
                    "content": final_content, "reasoning": final_reasoning,
                    "tool_calls": tool_trace,
                }, ensure_ascii=False)
            else:
                payload = final_content
            db.add_message(cid, "assistant", payload[:20000])

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )
