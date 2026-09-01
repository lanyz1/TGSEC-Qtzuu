"""漏洞管理 API"""
from fastapi import APIRouter, Request, HTTPException
from services.db_service import db
from app_config.logging_config import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("/stats")
async def vulnerability_stats():
    return db.vulnerability_stats()


@router.get("")
async def list_vulnerabilities(severity: str = "", status: str = "", vuln_type: str = ""):
    return {"vulnerabilities": db.list_vulnerabilities(severity, status, vuln_type)}


@router.post("")
async def create_vulnerability(req: Request):
    body = await req.json()
    title = body.get("title", "")
    target = body.get("target", "")
    vuln_type = body.get("vuln_type", "")
    severity = body.get("severity", "medium")
    status = body.get("status", "open")
    description = body.get("description", "")
    evidence = body.get("evidence", "")
    source = body.get("source", "")
    if not title:
        raise HTTPException(400, "title 不能为空")
    result = db.create_vulnerability(title, target, vuln_type, severity, status,
                                      description, evidence, source)
    return result


@router.put("/{vid}")
async def update_vulnerability(vid: str, req: Request):
    body = await req.json()
    existing = db.get_vulnerability(vid)
    if not existing:
        raise HTTPException(404, "漏洞不存在")
    allowed = {"title", "target", "vuln_type", "severity", "status",
               "description", "evidence", "source"}
    updates = {k: v for k, v in body.items() if k in allowed and v is not None}
    if updates:
        db.update_vulnerability(vid, **updates)
    return {"ok": True}


@router.delete("/{vid}")
async def delete_vulnerability(vid: str):
    db.delete_vulnerability(vid)
    return {"ok": True}


@router.get("/stats")
async def vulnerability_stats():
    return db.vulnerability_stats()
