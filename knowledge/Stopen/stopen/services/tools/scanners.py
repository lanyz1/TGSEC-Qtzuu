"""扫描器工具 —— 端口扫描、目录枚举、子域名枚举"""
import asyncio
import json
import re
import subprocess
from urllib.parse import urlparse

from services.tool_base import BaseTool, ToolResult
from services.tools.mcp_bridge import mcp_bridge


class PortScanTool(BaseTool):
    """端口扫描工具 —— 优先使用 Yakit MCP，回退到 subprocess nmap"""
    name = "port_scan"
    description = "端口扫描：扫描目标主机的开放端口、服务版本、操作系统识别。支持 TCP/UDP"
    category = "scanner"
    parameters = {
        "type": "object",
        "properties": {
            "targets": {
                "type": "string",
                "description": "目标 IP/域名，支持 CIDR 格式和域名"
            },
            "ports": {
                "type": "string",
                "description": "端口范围，默认 '21,22,23,80,443,8080,8443,3306,6379,27017'"
            },
            "proto": {
                "type": "string",
                "enum": ["tcp", "udp"],
                "description": "协议，默认 tcp"
            },
        },
        "required": ["targets"],
    }

    async def execute(self, args: dict) -> ToolResult:
        targets = args.get("targets", "")
        ports = args.get("ports", "21,22,23,80,443,8080,8443,3306,6379,27017")
        proto = args.get("proto", "tcp")

        # 优先走 Yakit MCP
        result = await mcp_bridge.call_yakit("port_scan", targets=targets, ports=ports, proto=proto)
        if result.get("success"):
            return ToolResult.ok(
                output=f"Yakit 端口扫描完成\n{json.dumps(result['data'], indent=2, ensure_ascii=False)}",
                data=result["data"],
            )

        # 回退到 nmap
        try:
            cmd = ["nmap", "-sV", "-p", ports, targets]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode("utf-8", errors="ignore")
            if proc.returncode != 0:
                return ToolResult.fail(f"nmap 失败: {stderr.decode()[:200]}")
            return ToolResult.ok(output=f"nmap 扫描结果:\n{output}", data={"raw": output})
        except FileNotFoundError:
            return ToolResult.fail("未安装 nmap，Yakit MCP 也未连接。请先启动 Yakit")
        except asyncio.TimeoutError:
            return ToolResult.fail("nmap 扫描超时（120s）")


class DirBruteTool(BaseTool):
    """目录枚举工具 —— 基于 Python 字典的 Web 路径枚举"""
    name = "dir_brute"
    description = "目录枚举：对 Web 站点进行目录/文件路径爆破，发现隐藏页面和敏感文件"
    category = "scanner"
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "目标 URL，如 http://example.com"
            },
            "wordlist": {
                "type": "string",
                "description": "字典关键词，默认 'admin,login,api,backup,.git,.env,config,wp-admin'"
            },
            "extensions": {
                "type": "string",
                "description": "扩展名，默认 'php,asp,aspx,jsp,html,txt'"
            },
        },
        "required": ["url"],
    }

    async def execute(self, args: dict) -> ToolResult:
        url = args.get("url", "").rstrip("/")
        wordlist = args.get("wordlist", "admin,login,api,backup,.git,.env,config,wp-admin")
        extensions = args.get("extensions", "php,asp,aspx,jsp,html,txt,tar,zip,sql")

        # 优先走 Yakit MCP
        result = await mcp_bridge.call_yakit("web_crawler", target=url)
        if result.get("success"):
            return ToolResult.ok(
                output=f"Yakit 爬取结果:\n{json.dumps(result['data'], indent=2, ensure_ascii=False)[:2000]}",
                data=result["data"],
            )

        # Python 实现简单目录枚举
        found = []
        words = [w.strip() for w in wordlist.split(",") if w.strip()]
        exts = [e.strip() for e in extensions.split(",") if e.strip()]

        import httpx
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for word in words:
                paths = [f"/{word}"]
                for ext in exts:
                    paths.append(f"/{word}.{ext}")
                for path in paths:
                    try:
                        resp = await client.get(f"{url}{path}")
                        if resp.status_code in (200, 201, 204, 301, 302, 403):
                            found.append({"path": path, "status": resp.status_code,
                                          "length": len(resp.content)})
                    except Exception:
                        continue

        if found:
            lines = [f"  {p['status']} {p['length']:>7}b  {p['path']}" for p in found]
            return ToolResult.ok(
                output=f"发现 {len(found)} 个路径:\n" + "\n".join(lines),
                data={"found": found},
            )
        return ToolResult.ok(output="未发现隐藏路径", data={"found": []})


class SubdomainTool(BaseTool):
    """子域名枚举工具"""
    name = "subdomain_enum"
    description = "子域名枚举：查找目标域名的子域名"
    category = "scanner"
    parameters = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "目标域名，如 example.com"},
        },
        "required": ["domain"],
    }

    async def execute(self, args: dict) -> ToolResult:
        domain = args.get("domain", "")

        # 走 Yakit MCP
        result = await mcp_bridge.call_yakit("subdomain_collection", target=domain)
        if result.get("success"):
            return ToolResult.ok(
                output=f"子域名枚举结果:\n{json.dumps(result['data'], indent=2, ensure_ascii=False)[:2000]}",
                data=result["data"],
            )

        # 简单 DNS 枚举（通过公共 DNS 或 crt.sh）
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                if resp.status_code == 200:
                    entries = resp.json()
                    subs = set()
                    for e in entries:
                        name = e.get("name_value", "")
                        for n in name.split("\n"):
                            if n.endswith(domain):
                                subs.add(n.strip())
                    result_list = sorted(subs)[:50]
                    if result_list:
                        return ToolResult.ok(
                            output=f"发现 {len(result_list)} 个子域名:\n" + "\n".join(result_list),
                            data={"subdomains": result_list},
                        )
        except Exception:
            pass

        return ToolResult.ok(output="未发现子域名", data={"subdomains": []})


class QueryCVETool(BaseTool):
    """CVE 查询工具"""
    name = "query_cve"
    description = "CVE 查询：搜索已知漏洞信息。支持按关键词、CVE编号、产品名查询"
    category = "scanner"
    parameters = {
        "type": "object",
        "properties": {
            "keywords": {"type": "string", "description": "搜索关键词，如 'apache log4j'"},
            "cve": {"type": "string", "description": "CVE 编号，如 'CVE-2021-44228'"},
            "product": {"type": "string", "description": "产品名，如 'tomcat'"},
        },
    }

    async def execute(self, args: dict) -> ToolResult:
        # 优先走 Yakit MCP
        result = await mcp_bridge.call_yakit("query_cve", **args)
        if result.get("success"):
            return ToolResult.ok(
                output=f"CVE 查询结果:\n{json.dumps(result['data'], indent=2, ensure_ascii=False)[:2000]}",
                data=result["data"],
            )

        # 回退到 NVD API
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15) as client:
                params = {}
                if args.get("keywords"):
                    params["keywordSearch"] = args["keywords"]
                if args.get("cve"):
                    params["cveId"] = args["cve"]
                resp = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                        params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])[:10]
                    if vulns:
                        lines = []
                        for v in vulns:
                            c = v.get("cve", {})
                            cid = c.get("id", "N/A")
                            desc = ""
                            for d in c.get("descriptions", []):
                                if d.get("lang") == "en":
                                    desc = d["value"][:150]
                                    break
                            lines.append(f"  {cid}: {desc}")
                        return ToolResult.ok(
                            output=f"发现 {len(vulns)} 个漏洞:\n" + "\n".join(lines),
                            data={"vulnerabilities": vulns},
                        )
        except Exception:
            pass

        return ToolResult.ok(output="未查询到相关 CVE", data={"vulnerabilities": []})
