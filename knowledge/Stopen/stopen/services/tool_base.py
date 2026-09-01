"""基础工具抽象"""
from abc import ABC, abstractmethod
from typing import Any
from dataclasses import dataclass, field


@dataclass
class ToolResult:
    success: bool
    output: str = ""
    error: str = ""
    data: dict = field(default_factory=dict)

    @classmethod
    def ok(cls, output: str = "", **data) -> "ToolResult":
        return cls(success=True, output=output, data=data)

    @classmethod
    def fail(cls, error: str) -> "ToolResult":
        return cls(success=False, error=error)


class BaseTool(ABC):
    """工具基类"""
    name: str = ""
    description: str = ""
    parameters: dict = {}
    category: str = "general"  # scanner | mcp | crypto | c2 | webshell | web

    @abstractmethod
    async def execute(self, args: dict) -> ToolResult:
        ...

    def to_openai_tool(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_spec(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "category": self.category,
        }
