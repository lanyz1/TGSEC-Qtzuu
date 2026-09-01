"""报告模型"""
from pydantic import BaseModel
from typing import Optional


class PentestReport(BaseModel):
    task_id: str = ""
    target: str
    task_type: str = "pentest"
    summary: str = ""
    findings: list[dict] = []
    timeline: list[dict] = []
    poc_code: str = ""
    generated_at: str = ""
