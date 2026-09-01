"""渗透任务模型"""
from pydantic import BaseModel
from typing import Optional


class PentestTask(BaseModel):
    id: str = ""
    name: str
    target: str
    task_type: str = "pentest"  # pentest | ctf
    goal: str = ""
    status: str = "pending"  # pending | running | completed | failed
    model: str = ""
    report_path: str = ""
    created_at: str = ""
    updated_at: str = ""
