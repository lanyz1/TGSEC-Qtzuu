"""FOFA asset search MCP server (stdio).

三账号：优先主号 FOFA_EMAIL/FOFA_KEY；遇 429/限流/820041 依次切
FOFA_EMAIL_BACKUP/FOFA_KEY_BACKUP，再用 FOFA_EMAIL_BACKUP2/FOFA_KEY_BACKUP2。
"""

from __future__ import annotations

import base64
import os
from typing import Any

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

mcp = FastMCP("fofasearch")

FOFA_API_BASE = "https://fofa.info/api/v1/search/all"
USER_AGENT = "fofa-mcp/1.0"

# Prefer env (Grok config.toml env=...); fall back to .env file.
FOFA_EMAIL = os.getenv("FOFA_EMAIL", "").strip()
FOFA_KEY = os.getenv("FOFA_KEY", "").strip() or os.getenv("FOFA_API_KEY", "").strip()
FOFA_EMAIL_BACKUP = os.getenv("FOFA_EMAIL_BACKUP", "").strip()
FOFA_KEY_BACKUP = (
    os.getenv("FOFA_KEY_BACKUP", "").strip()
    or os.getenv("FOFA_API_KEY_BACKUP", "").strip()
)
FOFA_EMAIL_BACKUP2 = os.getenv("FOFA_EMAIL_BACKUP2", "").strip()
FOFA_KEY_BACKUP2 = (
    os.getenv("FOFA_KEY_BACKUP2", "").strip()
    or os.getenv("FOFA_API_KEY_BACKUP2", "").strip()
)

# 会话内记住已限流的号，后续请求优先走还没限的
_exhausted: set[str] = set()


def _account_list() -> list[tuple[str, str, str]]:
    """返回 [(label, email, key), ...]，主号 → 备用1 → 备用2；已限流的排后。"""
    accs = [
        ("primary", FOFA_EMAIL or os.getenv("FOFA_EMAIL", "").strip(), FOFA_KEY),
        (
            "backup",
            FOFA_EMAIL_BACKUP or os.getenv("FOFA_EMAIL_BACKUP", "").strip(),
            FOFA_KEY_BACKUP or os.getenv("FOFA_KEY_BACKUP", "").strip(),
        ),
        (
            "backup2",
            FOFA_EMAIL_BACKUP2 or os.getenv("FOFA_EMAIL_BACKUP2", "").strip(),
            FOFA_KEY_BACKUP2 or os.getenv("FOFA_KEY_BACKUP2", "").strip(),
        ),
    ]
    valid = [a for a in accs if a[2]]
    live = [a for a in valid if a[0] not in _exhausted]
    dead = [a for a in valid if a[0] in _exhausted]
    return live + dead


def _is_rate_limited(result: dict[str, Any] | None, status_code: int | None = None) -> bool:
    if status_code in (429, 403):
        return True
    if not result:
        return False
    msg = str(result.get("message") or result.get("errmsg") or result.get("error") or "")
    low = msg.lower()
    if "429" in low or "too many" in low or "rate" in low:
        return True
    # FOFA 业务限流码
    if "820041" in msg or "今日" in msg or "上限" in msg or "F点" in msg or "fpoint" in low:
        return True
    if result.get("error") and ("[-4]" in msg or "请求频繁" in msg or "访问频率" in msg):
        return True
    return False


async def make_fofa_request(url: str) -> dict[str, Any]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            try:
                data = response.json()
            except Exception:
                data = {"error": True, "message": response.text[:500], "http_status": response.status_code}
            if not isinstance(data, dict):
                data = {"error": True, "message": str(data), "http_status": response.status_code}
            data.setdefault("http_status", response.status_code)
            if response.status_code >= 400 and "error" not in data:
                data["error"] = True
                data["message"] = data.get("errmsg") or data.get("message") or f"HTTP {response.status_code}"
            return data
        except Exception as e:
            return {"error": True, "message": str(e)}


def format_alerts(alerts: list[list[Any]]) -> str:
    """Format FOFA rows (fields=host,ip,port) into readable text."""
    if not alerts:
        return ""

    lines: list[str] = []
    for result in alerts:
        if not isinstance(result, (list, tuple)):
            lines.append(str(result))
            continue
        # Default request uses host,ip,port
        if len(result) >= 3:
            host, ip, port = result[0], result[1], result[2]
            lines.append(f"主机名: {host}\nIP地址: {ip}\n端口: {port}\n")
        else:
            lines.append(" | ".join(str(x) for x in result) + "\n")
    return "\n".join(lines)


def _build_url(email: str, key: str, query_str: str) -> str:
    params: dict[str, Any] = {
        "key": key,
        "qbase64": base64.b64encode(query_str.encode()).decode(),
        "size": 100,
        "fields": "host,ip,port",
    }
    # FOFA 官方接口 email+key；部分 key 形态可只传 key
    if email:
        params["email"] = email
    return f"{FOFA_API_BASE}?{httpx.QueryParams(params)}"


@mcp.prompt()
async def search_prompt(query_params: str, assets_data: str) -> str:
    """生成包含资产上下文的安全分析提示词。"""
    return (
        f"你是一个资深网络安全分析师，请基于以下查询条件：{query_params}\n"
        f"和发现的资产信息：\n{assets_data}\n\n"
        "请分析潜在安全风险并提供以下内容：\n"
        "1. 资产暴露面分析\n2. 潜在漏洞评估\n3. 加固建议"
    )


@mcp.tool()
async def get_alerts(
    domain: str = "",
    ip: str = "",
    port: str = "",
    host: str = "",
    body: str = "",
    icon_hash: str = "",
    icp: str = "",
    status_code: str = "200",
) -> dict[str, Any] | str:
    """FOFA 网络资产搜索。可按域名/IP/端口/主机名/网页内容/图标哈希/ICP/状态码组合查询。

    Args:
        domain: 域名
        ip: IP 地址
        port: 端口
        host: 主机名
        body: 网页内容
        icon_hash: 图标哈希
        icp: ICP 备案号
        status_code: HTTP 状态码（默认 200；传空字符串可取消该条件）
    """
    accounts = _account_list()
    if not accounts:
        return {
            "error": "未配置 FOFA_KEY。请在 ~/.grok/config.toml 的 [mcp_servers.fofa] env 中设置 FOFA_EMAIL 与 FOFA_KEY；备用号用 FOFA_KEY_BACKUP / FOFA_KEY_BACKUP2。"
        }

    query_parts: list[str] = []
    if domain:
        query_parts.append(f'domain="{domain}"')
    if ip:
        query_parts.append(f'ip="{ip}"')
    if port:
        query_parts.append(f'port="{port}"')
    if host:
        query_parts.append(f'host="{host}"')
    if body:
        query_parts.append(f'body="{body}"')
    if icon_hash:
        query_parts.append(f'icon_hash="{icon_hash}"')
    if icp:
        query_parts.append(f'icp="{icp}"')
    if status_code:
        query_parts.append(f"status_code={status_code}")

    if not query_parts:
        return {"error": "至少提供一个查询条件（domain/ip/port/host/body/icon_hash/icp）"}

    query_str = "&&".join(query_parts)
    last_error: dict[str, Any] | None = None
    used_accounts: list[str] = []

    for label, email, key in accounts:
        used_accounts.append(label)
        url = _build_url(email, key, query_str)
        result = await make_fofa_request(url)

        if result is None:
            last_error = {"error": "请求失败或无响应", "account": label}
            continue

        http_status = result.get("http_status")
        if _is_rate_limited(result, http_status if isinstance(http_status, int) else None):
            _exhausted.add(label)
            last_error = {
                "error": f"限流/配额: {result.get('message') or result.get('errmsg') or result}",
                "account": label,
                "http_status": http_status,
            }
            continue

        if result.get("error") is True and "message" in result and "results" not in result:
            # 非限流硬错误：若还有备用则试；否则返回
            last_error = {"error": f"请求异常: {result['message']}", "account": label}
            if _is_rate_limited(result):
                _exhausted.add(label)
                continue
            # 鉴权失败等仍可试备用
            msg = str(result.get("message") or "")
            if any(x in msg for x in ("401", "403", "[-1]", "[-3]", "不正确", "无效", "unauthorized")):
                continue
            # 其它异常仍试下一账号
            continue

        if result.get("error") and result.get("errmsg") and "results" not in result:
            if _is_rate_limited(result):
                _exhausted.add(label)
                last_error = {"error": result.get("errmsg"), "account": label, "raw": result}
                continue
            last_error = {"error": result.get("errmsg"), "account": label, "raw": result}
            continue

        if "results" in result:
            formatted = format_alerts(result.get("results") or [])
            out = {
                "query": query_str,
                "size": result.get("size"),
                "page": result.get("page"),
                "mode": result.get("mode"),
                "query_consumed": result.get("consumed_fpoint") or result.get("required_fpoints"),
                "count": len(result.get("results") or []),
                "data": formatted,
                "raw_results": result.get("results"),
                "account_used": label,
            }
            if used_accounts != [label]:
                out["account_tried"] = used_accounts
            return out

        last_error = {"error": "未找到匹配的资产", "raw": result, "account": label}

    if last_error:
        last_error["account_tried"] = used_accounts
        return last_error
    return {"error": "未找到匹配的资产", "account_tried": used_accounts}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
