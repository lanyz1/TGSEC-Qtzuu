"""WebShell API"""
from fastapi import APIRouter, HTTPException, Request
from models.chat import WebShellCreate
from services.db_service import db

router = APIRouter(prefix="/api/webshell", tags=["webshell"])


@router.post("")
async def create_webshell(data: WebShellCreate):
    protocol = getattr(data, "protocol", "antsword")
    return db.create_webshell(name=data.name, url=data.url,
                               password=data.password, shell_type=data.shell_type,
                               protocol=protocol)


@router.get("")
async def list_webshells():
    rows = db.list_webshells()
    # 密码不回传前端（连接口令在服务端使用）；兼容前端编辑场景留空即可
    for w in rows:
        if w.get("password"):
            w["password"] = "****"
    return {"webshells": rows}


@router.post("/{wid}/exec")
async def exec_command(wid: str, command: str = "whoami"):
    from services.webshell_service import webshell_service
    ws = next((w for w in db.list_webshells() if w["id"] == wid), None)
    if not ws:
        raise HTTPException(404, "WebShell 不存在")
    result = await webshell_service.exec(
        ws["url"], ws["password"], command,
        shell_type=ws.get("shell_type", "php"),
        protocol=ws.get("protocol", "antsword"),
    )
    return result


@router.post("/{wid}/test")
async def test_webshell(wid: str):
    ws = next((w for w in db.list_webshells() if w["id"] == wid), None)
    if not ws:
        raise HTTPException(404, "WebShell 不存在")
    from services.webshell_service import webshell_service
    return await webshell_service.test(ws["url"], ws["password"], protocol=ws.get("protocol", "antsword"))


@router.delete("/{wid}")
async def delete_webshell(wid: str):
    db.update_webshell(wid, status="deleted")
    return {"ok": True}


# ── 文件操作 ──
@router.post("/{wid}/files/list")
async def webshell_list_files(wid: str, path: str = "/"):
    from services.webshell_service import webshell_service
    ws = next((w for w in db.list_webshells() if w["id"] == wid), None)
    if not ws:
        raise HTTPException(404, "WebShell 不存在")
    return await webshell_service.list_files(
        ws["url"], ws["password"], path,
        shell_type=ws.get("shell_type", "php"),
        protocol=ws.get("protocol", "antsword"),
    )


@router.post("/{wid}/files/read")
async def webshell_read_file(wid: str, path: str = ""):
    if not path:
        raise HTTPException(400, "path 不能为空")
    from services.webshell_service import webshell_service
    ws = next((w for w in db.list_webshells() if w["id"] == wid), None)
    if not ws:
        raise HTTPException(404, "WebShell 不存在")
    return await webshell_service.read_file(
        ws["url"], ws["password"], path,
        shell_type=ws.get("shell_type", "php"),
        protocol=ws.get("protocol", "antsword"),
    )


@router.post("/{wid}/files/write")
async def webshell_write_file(wid: str, req: Request):
    body = await req.json()
    path = body.get("path", "")
    content = body.get("content", "")
    if not path:
        raise HTTPException(400, "path 不能为空")
    from services.webshell_service import webshell_service
    ws = next((w for w in db.list_webshells() if w["id"] == wid), None)
    if not ws:
        raise HTTPException(404, "WebShell 不存在")
    return await webshell_service.write_file(
        ws["url"], ws["password"], path, content,
        shell_type=ws.get("shell_type", "php"),
        protocol=ws.get("protocol", "antsword"),
    )


@router.post("/{wid}/files/delete")
async def webshell_delete_file(wid: str, path: str = ""):
    if not path:
        raise HTTPException(400, "path 不能为空")
    from services.webshell_service import webshell_service
    ws = next((w for w in db.list_webshells() if w["id"] == wid), None)
    if not ws:
        raise HTTPException(404, "WebShell 不存在")
    return await webshell_service.delete_file(
        ws["url"], ws["password"], path,
        shell_type=ws.get("shell_type", "php"),
        protocol=ws.get("protocol", "antsword"),
    )


@router.post("/{wid}/files/mkdir")
async def webshell_mkdir(wid: str, path: str = ""):
    if not path:
        raise HTTPException(400, "path 不能为空")
    from services.webshell_service import webshell_service
    ws = next((w for w in db.list_webshells() if w["id"] == wid), None)
    if not ws:
        raise HTTPException(404, "WebShell 不存在")
    return await webshell_service.mkdir(
        ws["url"], ws["password"], path,
        shell_type=ws.get("shell_type", "php"),
        protocol=ws.get("protocol", "antsword"),
    )
