"""黑板（Blackboard）—— Fact-Intent-Goal 状态空间"""

import json
import uuid
from typing import Any


class Fact:
    """已确认的客观发现"""
    def __init__(self, fact_type: str, value: str, source: str = "",
                 evidence: str = "", priority: int = 5):
        self.id = str(uuid.uuid4())[:8]
        self.type = fact_type       # port_open | service | vuln | flag | info
        self.value = value          # "80/tcp" | "Apache 2.4.41" | "SQLi"
        self.source = source        # "nmap" | "burp" | "yakit"
        self.evidence = evidence    # 工具输出原文摘要
        self.priority = priority    # 1-10 重要性
        self.timestamp = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "evidence": self.evidence[:200] if self.evidence else "",
            "priority": self.priority,
        }


class Intent:
    """待探索的方向"""
    def __init__(self, intent_type: str, target: str = "",
                 params: dict = None, priority: int = 5):
        self.id = str(uuid.uuid4())[:8]
        self.type = intent_type     # scan_port | dir_brute | dns_enum | exploit
        self.target = target        # "192.168.1.1" | "http://example.com"
        self.params = params or {}
        self.priority = priority
        self.status = "pending"     # pending | running | done | failed
        self.result = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "target": self.target,
            "params": self.params,
            "priority": self.priority,
            "status": self.status,
            "result": self.result[:200] if self.result else "",
        }


class Blackboard:
    """黑板：追踪渗透测试状态的共享数据结构"""

    def __init__(self, goal: str = ""):
        self.goal = goal
        self.goal_achieved = False
        self.facts: list[Fact] = []
        self.intents: list[Intent] = []
        self.max_intents = 10

    def add_fact(self, fact_type: str, value: str, source: str = "",
                 evidence: str = "", priority: int = 5) -> Fact:
        """添加事实（去重）"""
        # 去重：相同 type+value 不再添加
        for f in self.facts:
            if f.type == fact_type and f.value == value:
                return f
        fact = Fact(fact_type, value, source, evidence, priority)
        import datetime
        fact.timestamp = datetime.datetime.now().isoformat(timespec="seconds")
        self.facts.append(fact)
        return fact

    def add_intent(self, intent_type: str, target: str = "",
                   params: dict = None, priority: int = 5) -> Intent:
        """添加探索意图（去重）"""
        params = params or {}
        for it in self.intents:
            if it.type == intent_type and it.target == target and it.status == "pending":
                return it
        if len(self.intents) >= self.max_intents:
            # 移除最低优先级的已完成/失败 intent
            self.intents.sort(key=lambda x: (0 if x.status == "pending" else 1, x.priority))
            self.intents = self.intents[:self.max_intents]
        intent = Intent(intent_type, target, params, priority)
        self.intents.append(intent)
        return intent

    def get_pending_intents(self) -> list[Intent]:
        """获取待处理的意图，按优先级排序"""
        pending = [i for i in self.intents if i.status == "pending"]
        pending.sort(key=lambda x: x.priority, reverse=True)
        return pending

    def complete_intent(self, intent_id: str, result: str = "",
                        success: bool = True) -> None:
        """标记 intent 完成"""
        for i in self.intents:
            if i.id == intent_id:
                i.status = "done" if success else "failed"
                i.result = result
                break

    def has_fact(self, fact_type: str, value: str = "") -> bool:
        """检查是否存在某个事实"""
        for f in self.facts:
            if f.type == fact_type:
                if value and f.value == value:
                    return True
                if not value:
                    return True
        return False

    def get_facts_by_type(self, fact_type: str) -> list[Fact]:
        return [f for f in self.facts if f.type == fact_type]

    def to_dict(self) -> dict:
        return {
            "goal": self.goal,
            "goal_achieved": self.goal_achieved,
            "facts": [f.to_dict() for f in self.facts],
            "intents": [i.to_dict() for i in self.intents],
            "fact_count": len(self.facts),
            "intent_count": len(self.intents),
        }
