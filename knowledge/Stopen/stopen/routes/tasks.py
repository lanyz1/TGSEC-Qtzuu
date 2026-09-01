"""渗透任务 API"""
from fastapi import APIRouter, HTTPException
from services.db_service import db
from models.task import PentestTask

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


@router.get("")
async def list_tasks():
    return {"tasks": db.list_tasks()}


@router.post("")
async def create_task(task: PentestTask):
    t = db.create_task(
        name=task.name, target=task.target,
        task_type=task.task_type, goal=task.goal, model=task.model,
    )
    return t


@router.get("/{task_id}")
async def get_task(task_id: str):
    task = None
    for t in db.list_tasks():
        if t["id"] == task_id:
            task = t
            break
    if not task:
        raise HTTPException(404, "任务不存在")
    return {"task": task}


@router.post("/{task_id}/report")
async def generate_report_endpoint(task_id: str):
    from services.report_service import generate_report, generate_html_report
    from services.db_service import db
    try:
        from routes.agent import _blackboards
        bb = _blackboards.get(task_id)
        if bb:
            findings = [f.to_dict() for f in bb.facts]
        else:
            findings = []
    except Exception:
        findings = []
    task_info = db.get_conversation(task_id) or {"target": "unknown", "task_type": "pentest"}
    report = generate_report(
        task_id=task_id,
        target=task_info.get("target", "unknown"),
        task_type=task_info.get("task_type", "pentest"),
        findings=findings,
    )
    html = generate_html_report(
        task_id=task_id,
        target=task_info.get("target", "unknown"),
        task_type=task_info.get("task_type", "pentest"),
        findings=findings,
    )
    db.update_task(task_id, report_path=report.get("path", ""))
    return {"markdown": report, "html": html}


@router.post("/{task_id}/poc/{vid}")
async def generate_poc_endpoint(task_id: str, vid: str):
    from services.report_service import generate_poc_file
    from services.db_service import db
    vuln = db.get_vulnerability(vid)
    if not vuln:
        from fastapi import HTTPException
        raise HTTPException(404, "漏洞不存在")
    return generate_poc_file(vuln)
