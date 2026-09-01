"""角色管理 API —— 预定义角色 + 用户自定义角色"""
from fastapi import APIRouter, Request, HTTPException
from services.db_service import db
from app_config.logging_config import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/api/roles", tags=["roles"])

# 预定义角色
BUILTIN_ROLES = [
    {
        "name": "渗透测试",
        "description": "通用渗透测试专家，覆盖信息收集、漏洞发现、利用、后渗透全流程",
        "role_type": "pentest",
        "skills": "recon,vuln_discovery,exploitation,post_exploit,report",
        "system_prompt": """你是专业的渗透测试专家。
遵循标准的渗透测试流程：信息收集 → 漏洞发现 → 漏洞利用 → 后渗透 → 报告。
使用 OODA 循环 + 黑板追踪进度。
每个发现必须有工具输出佐证。
测试完成后生成详细报告。""",
    },
    {
        "name": "CTF 解题",
        "description": "CTF 挑战专家，擅长 Web、密码学、逆向等多种题型",
        "role_type": "ctf",
        "skills": "ctf_web,ctf_crypto,ctf_reverse",
        "system_prompt": """你是 CTF 解题专家。
目标：找到 flag。
支持题型：Web、密码学、逆向。
策略：分析题目 → 选择对应技能 → 逐步排查 → 找到 flag。
找到 flag 后立即报告，格式 flag{{...}}。""",
    },
    {
        "name": "Web 应用扫描",
        "description": "专注于 Web 应用程序安全测试，发现 SQL 注入、XSS、SSRF 等漏洞",
        "role_type": "web_app_scan",
        "skills": "recon,vuln_discovery,report",
        "system_prompt": """你是 Web 应用安全扫描专家。
专注 Web 层安全测试：爬取站点 → 扫描目录 → 检测注入/XSS/SSRF/文件包含 → 报告漏洞。
重点检查：输入验证、认证授权、会话管理、敏感信息泄露。
所有发现必须有请求/响应原文佐证。""",
    },
    {
        "name": "API 安全测试",
        "description": "API 安全测试专家，检测认证绕过、注入、越权等 API 特有漏洞",
        "role_type": "api_test",
        "skills": "recon,vuln_discovery,report",
        "system_prompt": """你是 API 安全测试专家。
专注 RESTful/GraphQL API 安全测试：收集 API 端点 → 测试认证授权 → 参数篡改 → 注入测试 → 批量赋值检查。
重点：JWT 解码、API Key 泄露、IDOR、请求频率限制。
使用 http_request 工具测试每个端点。""",
    },
    {
        "name": "二进制分析",
        "description": "二进制安全分析专家，擅长逆向工程、漏洞挖掘、PoC 开发",
        "role_type": "binary",
        "skills": "ctf_reverse",
        "system_prompt": """你是二进制安全分析专家。
专注逆向工程和漏洞挖掘：分析文件格式 → 反汇编/反编译 → 理解控制流 → 定位漏洞 → 开发 PoC。
使用 crypto 工具处理编码数据，browser 搜索已知漏洞信息。""",
    },
    {
        "name": "云安全审计",
        "description": "云基础设施安全审计专家，覆盖配置审查、权限分析、合规检查",
        "role_type": "cloud_audit",
        "skills": "recon,vuln_discovery,report",
        "system_prompt": """你是云安全审计专家。
专注云环境安全评估：检查公开存储桶 → 识别云元数据泄露 → 分析 IAM 配置 → 检查 API 密钥泄露。
重点：存储桶枚举、元数据服务 (169.254.169.254)、证书泄露。""",
    },
]


def init_builtin_roles():
    """初始化预定义角色到数据库"""
    existing = db.list_roles()
    existing_names = {r["name"] for r in existing}
    for role in BUILTIN_ROLES:
        if role["name"] not in existing_names:
            db.create_role(
                name=role["name"],
                description=role["description"],
                role_type=role["role_type"],
                system_prompt=role["system_prompt"],
                builtin=1,
                skills=role["skills"],
            )
            log.info(f"已创建预定义角色: {role['name']}")


@router.get("")
async def list_roles():
    return {"roles": db.list_roles()}


@router.post("")
async def create_role(req: Request):
    body = await req.json()
    name = body.get("name", "")
    if not name:
        raise HTTPException(400, "角色名不能为空")
    result = db.create_role(
        name=name,
        description=body.get("description", ""),
        role_type=body.get("role_type", "custom"),
        system_prompt=body.get("system_prompt", ""),
        skills=body.get("skills", ""),
        builtin=0,
    )
    return result


@router.put("/{rid}")
async def update_role(rid: str, req: Request):
    body = await req.json()
    existing = db.get_role(rid)
    if not existing:
        raise HTTPException(404, "角色不存在")
    if existing.get("builtin"):
        raise HTTPException(403, "预定义角色不能修改")
    db.update_role(rid, **body)
    return {"ok": True}


@router.delete("/{rid}")
async def delete_role(rid: str):
    existing = db.get_role(rid)
    if not existing:
        raise HTTPException(404, "角色不存在")
    if existing.get("builtin"):
        raise HTTPException(403, "预定义角色不能删除")
    db.delete_role(rid)
    return {"ok": True}
