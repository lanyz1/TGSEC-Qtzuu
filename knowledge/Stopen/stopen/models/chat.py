"""Pydantic 模型"""
from pydantic import BaseModel
from typing import Optional


class SendMessageRequest(BaseModel):
    conversation_id: str = ""
    content: str = ""
    model: str = ""
    system_prompt: str = ""
    use_agent: bool = True  # 默认走 Agent 模式


class CreateConversationRequest(BaseModel):
    title: str = ""
    model: str = ""
    system_prompt: str = ""


class WebShellCreate(BaseModel):
    name: str = ""
    url: str = ""
    password: str = ""
    shell_type: str = "php"
    protocol: str = "antsword"
