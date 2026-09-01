"""C2 数据模型"""
from pydantic import BaseModel
from typing import Optional


class ListenerCreate(BaseModel):
    name: str = ""
    listener_type: str = "tcp"
    host: str = "0.0.0.0"
    port: int = 4444
    encryption_type: str = "aes-256-ctr"


class Listener(BaseModel):
    id: str = ""
    name: str
    listener_type: str = "tcp"
    host: str = "0.0.0.0"
    port: int = 4444
    status: str = "stopped"  # running | stopped
    secret: str = ""
    encryption_type: str = "aes-256-ctr"
    created_at: str = ""


class Session(BaseModel):
    id: str = ""
    listener_id: str = ""
    remote_addr: str = ""
    hostname: str = ""
    username: str = ""
    os_info: str = ""
    status: str = "active"  # active | dead
    last_seen: str = ""
    created_at: str = ""


class C2Task(BaseModel):
    id: str = ""
    session_id: str = ""
    command: str = ""
    status: str = "pending"  # pending | sent | done | failed
    result: str = ""
    created_at: str = ""
    completed_at: str = ""
