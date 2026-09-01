"""工具注册表——管理所有可用工具的注册与查询"""

from services.tool_base import BaseTool, ToolResult

# 给 ToolSpec 一个别名
ToolSpec = dict


class ToolRegistry:
    """单例工具注册表"""

    def __init__(self):
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)

    def get(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def list_specs(self) -> list[dict]:
        return [t.to_spec() for t in self._tools.values()]

    def list_openai_tools(self) -> list[dict]:
        return [t.to_openai_tool() for t in self._tools.values()
                if t.name != "think"]

    async def execute(self, name: str, args: dict) -> ToolResult:
        tool = self.get(name)
        if not tool:
            return ToolResult.fail(f"工具 '{name}' 不存在")
        return await tool.execute(args)

    @property
    def count(self) -> int:
        return len(self._tools)


# 全局单例
tool_registry = ToolRegistry()
