"""JS 资产发现工具 —— JS 文件分析 + 未授权探测 + 目录枚举"""
import json
import re

import httpx

from services.tool_base import BaseTool, ToolResult
from app_config.logging_config import get_logger

log = get_logger(__name__)


class JSDiscoveryTool(BaseTool):
    """JS 资产发现 —— 提取 API 路径、密钥、子域名，自动未授权探测"""
    name = "js_discovery"
    description = "JS 资产发现：从目标网页提取 JS 文件 → 分析 API 路径/密钥/子域名/实体 → 自动未授权访问探测"
    category = "scanner"
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标 URL，如 https://example.com"},
            "action": {
                "type": "string",
                "enum": ["js_recon", "unauth_test", "dir_enum"],
                "description": "操作类型：js_recon=JS分析, unauth_test=未授权探测, dir_enum=目录枚举",
            },
            "depth": {"type": "integer", "description": "目录枚举深度，默认 2"},
        },
        "required": ["url", "action"],
    }

    async def execute(self, args: dict) -> ToolResult:
        url = args.get("url", "").rstrip("/")
        action = args.get("action", "js_recon")

        if action == "js_recon":
            return await self._js_recon(url)
        elif action == "unauth_test":
            return await self._unauth_test(url)
        elif action == "dir_enum":
            depth = args.get("depth", 2)
            return await self._dir_enum(url, depth)
        return ToolResult.fail(f"未知操作: {action}")

    async def _js_recon(self, url: str) -> ToolResult:
        """JS 资产发现：获取页面 → 提取 JS → 分析 API/密钥/子域名"""
        findings = {"api_paths": set(), "domains": set(), "keys": set(), "entities": set()}

        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(url)
                html = resp.text

                # 提取 JS 文件
                js_urls = set()
                for m in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', html):
                    src = m.group(1)
                    if src.startswith("//"):
                        src = "https:" + src
                    elif src.startswith("/"):
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        src = f"{parsed.scheme}://{parsed.netloc}{src}"
                    elif not src.startswith("http"):
                        src = url.rstrip("/") + "/" + src.lstrip("/")
                    js_urls.add(src)

                # 分析每个 JS 文件
                for js_url in list(js_urls)[:20]:
                    try:
                        js_resp = await client.get(js_url, timeout=10)
                        js_content = js_resp.text

                        # 提取 API 路径
                        for m in re.finditer(r'["\'](/api/[^"\']+)["\']', js_content):
                            findings["api_paths"].add(m.group(1))
                        for m in re.finditer(r'["\'](https?://[^"\']+)["\']', js_content):
                            api_url = m.group(1)
                            if "api" in api_url.lower():
                                findings["api_paths"].add(api_url)

                        # 提取域名
                        for m in re.finditer(r'["\']((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})["\']', js_content):
                            domain = m.group(1)
                            if domain != "localhost" and "." in domain:
                                findings["domains"].add(domain)

                        # 提取疑似密钥 (sk-, AKIA, eyJ 等)
                        for m in re.finditer(r'["\'][A-Za-z0-9+/=]{20,64}["\']', js_content):
                            candidates = m.group(0).strip("\"'")
                            if candidates.startswith(("sk-", "AKIA", "eyJ", "ghp_", "gho_")):
                                findings["keys"].add(candidates[:30])

                        # 提取 PascalCase 实体
                        for m in re.finditer(r'\b[A-Z][a-z]+(?:[A-Z][a-z]+)+\b', js_content):
                            entity = m.group(0)
                            if len(entity) > 3 and entity not in ("JavaScript", "TypeScript", "JsonException"):
                                findings["entities"].add(entity)
                    except Exception:
                        continue

        except Exception as e:
            return ToolResult.fail(f"JS 分析失败: {e}")

        # 格式化输出
        lines = [f"JS 资产分析: {url}", ""]
        lines.append(f"├─ JS 文件数: {len(js_urls)}")
        api_list = list(findings["api_paths"])[:20]
        if api_list:
            lines.append(f"├─ API 路径 ({len(api_list)}):")
            for p in api_list:
                lines.append(f"│  • {p}")
        domain_list = list(findings["domains"])[:20]
        if domain_list:
            lines.append(f"├─ 关联域名 ({len(domain_list)}):")
            for d in domain_list:
                lines.append(f"│  • {d}")
        key_list = list(findings["keys"])[:10]
        if key_list:
            lines.append(f"├─ 疑似密钥 ({len(key_list)}):")
            for k in key_list:
                lines.append(f"│  • {k}")
        entity_list = list(findings["entities"])[:20]
        if entity_list:
            lines.append(f"└─ 实体名 ({len(entity_list)}):")
            for e in entity_list:
                lines.append(f"   • {e}")

        return ToolResult.ok(
            output="\n".join(lines),
            data={k: list(v) for k, v in findings.items()},
        )

    async def _unauth_test(self, url: str) -> ToolResult:
        """未授权测试：批量请求已知路径"""
        common_paths = [
            "/api/admin", "/api/user", "/api/config", "/api/backup",
            "/api/v1/admin", "/api/v1/user", "/api/v1/config",
            "/admin", "/backup", "/config", "/.env", "/.git/config",
        ]
        results = []
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for path in common_paths:
                try:
                    resp = await client.get(url.rstrip("/") + path)
                    if resp.status_code in (200, 201, 204, 301, 302):
                        results.append({
                            "path": path,
                            "status": resp.status_code,
                            "length": len(resp.content),
                        })
                except Exception:
                    continue

        if results:
            lines = [f"未授权探测: {url}",
                     f"发现 {len(results)} 个可访问路径:"]
            for r in results:
                lines.append(f"  {r['status']} {r['length']:>7}b  {r['path']}")
            return ToolResult.ok(output="\n".join(lines), data={"found": results})
        return ToolResult.ok(output=f"未授权探测: {url}\n未发现可访问路径", data={"found": []})

    async def _dir_enum(self, url: str, depth: int = 2) -> ToolResult:
        """简单目录枚举"""
        common = ["admin", "api", "backup", ".git", ".env", "config", "login",
                   "wp-admin", "uploads", "download", "static", "assets", "js", "css",
                   "swagger", "docs", "graphql", "api/v1", "api/v2"]
        found = []
        paths = common[:20 * depth]

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for path in paths:
                full_url = url.rstrip("/") + "/" + path.lstrip("/")
                try:
                    resp = await client.get(full_url)
                    if resp.status_code in (200, 201, 204, 301, 302, 403):
                        found.append({"path": path, "status": resp.status_code,
                                      "length": len(resp.content)})
                except Exception:
                    continue

        if found:
            lines = [f"目录枚举: {url}", f"发现 {len(found)} 个路径:"]
            for f_item in found:
                lines.append(f"  {f_item['status']} {f_item['length']:>7}b  /{f_item['path']}")
            return ToolResult.ok(output="\n".join(lines), data={"found": found})
        return ToolResult.ok(output="目录枚举未发现路径", data={"found": []})
