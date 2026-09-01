"""C2 API"""
from fastapi import APIRouter, Request, HTTPException
from models.c2 import ListenerCreate
from services.db_service import db
from services.c2_service import c2_service
from app_config.logging_config import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/api/c2", tags=["c2"])


@router.post("/listeners")
async def create_listener(data: ListenerCreate):
    encryption_type = getattr(data, "encryption_type", "aes-256-ctr")
    return db.create_listener(name=data.name, listener_type=data.listener_type,
                              host=data.host, port=data.port,
                              encryption_type=encryption_type)


@router.put("/listeners/{lid}")
async def update_listener(lid: str, req: Request):
    body = await req.json()
    existing = None
    for l in db.list_listeners():
        if l["id"] == lid:
            existing = l
            break
    if not existing:
        raise HTTPException(404, "监听器不存在")
    allowed = {"encryption_type", "secret", "name", "host", "port"}
    updates = {k: v for k, v in body.items() if k in allowed and v is not None}
    if updates:
        db.update_listener(lid, **updates)
    return {"ok": True, "updated": updates}


@router.get("/listeners")
async def list_listeners():
    """列监听器（mask secret）"""
    raw = db.list_listeners()
    for l in raw:
        if l.get("secret"):
            l["secret"] = "****"
    return {"listeners": raw}


@router.post("/listeners/{lid}/start")
async def start_listener(lid: str):
    info = next((l for l in db.list_listeners() if l["id"] == lid), None)
    if not info:
        return {"error": "监听器不存在"}
    result = await c2_service.start_listener(
        lid, info["name"], info["listener_type"], info["host"], info["port"])
    return result


@router.post("/listeners/{lid}/stop")
async def stop_listener(lid: str):
    result = await c2_service.stop_listener(lid)
    return result


@router.get("/sessions")
async def list_sessions():
    return {"sessions": db.list_sessions()}


@router.get("/sessions/{sid}/tasks")
async def list_session_tasks(sid: str):
    return {"tasks": db.list_c2_tasks(sid)}


@router.post("/sessions/{sid}/tasks")
async def create_session_task(sid: str, command: str):
    t = db.create_c2_task(sid, command)
    return t


@router.post("/payload/generate")
async def generate_payload(payload_type: str = "python",
                           host: str = "127.0.0.1", port: int = 4444,
                           listener_id: str = "", template_id: str = ""):
    """生成 Payload，支持传入 listener_id 自动使用监听器密钥"""
    secret = ""
    if listener_id:
        listeners = db.list_listeners()
        li = next((l for l in listeners if l["id"] == listener_id), None)
        if li:
            secret = li.get("secret", "")
    return c2_service.gen_payload(payload_type, host, port, secret=secret, template_id=template_id)


# ── Payload 模板 CRUD ──
@router.get("/payload-templates")
async def list_payload_templates():
    return {"templates": db.list_payload_templates()}


@router.post("/payload-templates")
async def create_payload_template(req: Request):
    body = await req.json()
    name = body.get("name", "")
    payload_type = body.get("payload_type", "python")
    content = body.get("content", "")
    if not name:
        raise HTTPException(400, "name 不能为空")
    return db.create_payload_template(name, payload_type, content)


@router.put("/payload-templates/{tid}")
async def update_payload_template(tid: str, req: Request):
    body = await req.json()
    existing = db.get_payload_template(tid)
    if not existing:
        raise HTTPException(404, "模板不存在")
    allowed = {"name", "payload_type", "content"}
    updates = {k: v for k, v in body.items() if k in allowed and v is not None}
    if updates:
        db.update_payload_template(tid, **updates)
    return {"ok": True}


@router.delete("/payload-templates/{tid}")
async def delete_payload_template(tid: str):
    db.delete_payload_template(tid)
    return {"ok": True}


# ── 内部 bridge 接口（c2d Go 守护进程回调；受全局 Bearer Token 中间件保护）──

@router.post("/internal/sessions/checkin")
async def internal_session_checkin(req: Request):
    """注册或复用会话。reuse=true 时同 listener+IP 的活跃会话复用（HTTP beacon），否则新建"""
    body = await req.json()
    listener_id = body.get("listener_id", "")
    remote = body.get("remote_addr", "")
    reuse = body.get("reuse", False)
    hostname = body.get("hostname", "")
    username = body.get("username", "")
    os_info = body.get("os_info", "")

    if reuse:
        existing = [s for s in db.list_sessions()
                    if s["remote_addr"] == remote and s["listener_id"] == listener_id
                    and s["status"] == "active"]
        if existing:
            sid = existing[0]["id"]
            db.update_session(sid, hostname=hostname, username=username, os_info=os_info)
            return {"session_id": sid}

    session = db.create_session(listener_id=listener_id, remote_addr=remote,
                                hostname=hostname, username=username, os_info=os_info)
    return {"session_id": session["id"]}


@router.post("/internal/sessions/{sid}/meta")
async def internal_session_meta(sid: str, req: Request):
    body = await req.json()
    db.update_session(sid,
                      hostname=body.get("hostname", ""),
                      username=body.get("username", ""),
                      os_info=body.get("os_info", ""))
    return {"ok": True}


@router.post("/internal/sessions/{sid}/poll")
async def internal_session_poll(sid: str):
    """弹出一条待执行任务（标记 sent），并刷新会话活跃状态"""
    tasks = db.list_c2_tasks(sid)
    for t in tasks:
        if t["status"] == "pending":
            db.update_c2_task(t["id"], status="sent")
            db.update_session(sid, status="active")
            return {"task_id": t["id"], "command": t["command"]}
    db.update_session(sid, status="active")
    return {"task_id": "", "command": ""}


@router.post("/internal/sessions/{sid}/result")
async def internal_session_result(sid: str, req: Request):
    """回写任务结果；task_id 为空时写入该会话最近一条 sent 任务（HTTP beacon 无 id 的场景）"""
    body = await req.json()
    task_id = body.get("task_id", "")
    output = (body.get("output", "") or "")[:5000]
    if task_id:
        db.update_c2_task(task_id, result=output)
        return {"ok": True, "matched": "id"}
    for t in db.list_c2_tasks(sid):
        if t["status"] == "sent":
            db.update_c2_task(t["id"], result=output)
            return {"ok": True, "matched": "latest_sent"}
    return {"ok": False, "matched": "none"}


@router.post("/internal/sessions/{sid}/dead")
async def internal_session_dead(sid: str):
    db.update_session(sid, status="dead")
    return {"ok": True}
