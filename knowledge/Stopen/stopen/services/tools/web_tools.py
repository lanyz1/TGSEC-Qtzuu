"""Web 工具 —— HTTP 请求、爬虫、屏幕截图等"""
import json

from services.tool_base import BaseTool, ToolResult
from services.tools.mcp_bridge import mcp_bridge


class HTTPRequestTool(BaseTool):
    """HTTP 请求工具"""
    name = "http_request"
    description = "HTTP 请求：发送自定义 HTTP 请求（GET/POST），查看响应内容和头信息"
    category = "web"
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "请求 URL"},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD"],
                       "description": "HTTP 方法"},
            "headers": {"type": "object", "description": "自定义请求头"},
            "body": {"type": "string", "description": "请求体（POST/PUT 时使用）"},
        },
        "required": ["url"],
    }

    async def execute(self, args: dict) -> ToolResult:
        url = args["url"]
        method = args.get("method", "GET").upper()
        headers = args.get("headers", {})
        body = args.get("body")

        try:
            import httpx
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.request(method, url, headers=headers, content=body,
                                            follow_redirects=True)
                content = resp.text[:3000]
                if len(resp.text) > 3000:
                    content += "\n... (截断)"
                summary = (
                    f"HTTP {method} {url}\n"
                    f"Status: {resp.status_code}\n"
                    f"Headers: {dict(resp.headers)}\n"
                    f"Content-Length: {len(resp.text)}\n"
                    f"Content-Type: {resp.headers.get('content-type', 'N/A')}\n"
                    f"\n{content}"
                )
                return ToolResult.ok(
                    output=summary,
                    data={
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "body_preview": resp.text[:2000],
                    },
                )
        except Exception as e:
            return ToolResult.fail(f"HTTP 请求失败: {e}")


class BrowserTool(BaseTool):
    """浏览器工具 —— 通过 Kimi WebBridge 控制 Chrome"""
    name = "browser"
    description = "浏览器控制：通过 Chrome 浏览器访问网页（支持截图、查看元素、点击、填表）"
    category = "web"
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["navigate", "snapshot", "screenshot", "click", "fill", "evaluate"],
                "description": "操作类型：navigate=导航, snapshot=页面结构, screenshot=截图, click=点击元素, fill=填表, evaluate=执行JS"
            },
            "url": {"type": "string", "description": "页面 URL（navigate 操作需要）"},
            "selector": {"type": "string", "description": "CSS 选择器（click/fill 操作需要）"},
            "value": {"type": "string", "description": "输入值（fill 操作需要）"},
            "script": {"type": "string", "description": "JS 代码（evaluate 操作需要）"},
            "session": {"type": "string", "description": "浏览器会话名"},
        },
        "required": ["action"],
    }

    async def execute(self, args: dict) -> ToolResult:
        action = args.get("action")
        session = args.get("session", "stopen")

        # 通过 Kimi WebBridge HTTP API 控制 Chrome
        import httpx
        payload = {"action": action, "args": {}, "session": session}
        if args.get("url"):
            payload["args"]["url"] = args["url"]
        if args.get("selector"):
            payload["args"]["selector"] = args["selector"]
        if args.get("value"):
            payload["args"]["value"] = args["value"]
        if args.get("script"):
            payload["args"]["script"] = args["script"]

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    "http://127.0.0.1:10086/command",
                    json=payload,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return ToolResult.ok(
                        output=f"[Browser] {action} 成功\n{json.dumps(data, indent=2, ensure_ascii=False)[:2000]}",
                        data=data,
                    )
                return ToolResult.fail(f"Kimi WebBridge 返回 {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            return ToolResult.fail(f"浏览器操作失败: {e}")


class BurpTool(BaseTool):
    """Burp 工具 —— 通过 Burp MCP 调用"""
    name = "burp"
    description = "Burp Suite 工具：发送请求到 Burp 的代理/扫描器/Repeater 等功能"
    category = "web"
    parameters = {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["send_to_repeater", "send_to_scanner", "send_to_intruder",
                         "activate_scan", "get_scan_status", "get_issues"],
                "description": "Burp 工具操作"
            },
            "url": {"type": "string", "description": "目标 URL"},
            "request": {"type": "string", "description": "原始 HTTP 请求"},
        },
        "required": ["tool"],
    }

    async def execute(self, args: dict) -> ToolResult:
        tool = args.get("tool", "")
        params = {k: v for k, v in args.items() if k != "tool"}
        result = await mcp_bridge.call_burp(tool, **params)
        if result.get("success"):
            return ToolResult.ok(
                output=f"[Burp] {tool} 成功\n{json.dumps(result['data'], indent=2, ensure_ascii=False)[:2000]}",
                data=result["data"],
            )
        return ToolResult.fail(f"Burp 调用失败: {result.get('error', '未知错误')}")
