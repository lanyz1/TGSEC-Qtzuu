"""Stopen FastAPI 入口"""
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

APP_START = time.time()
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from app_config.logging_config import setup_logging, LOG_DIR

logger = setup_logging()
logger.info("=" * 50)
logger.info("Stopen 启动中...")

from routes import agent, tools, tasks, config, c2, webshell, mcp_config, roles, chat
from routes import vulnerabilities, yaml_tools
from routes.roles import init_builtin_roles
from services.skills_service import list_all_skills, get_skill_prompt
from services.tool_registry import tool_registry
from services.tools.scanners import PortScanTool, DirBruteTool, SubdomainTool, QueryCVETool
from services.tools.web_tools import HTTPRequestTool, BrowserTool, BurpTool
from services.tools.crypto_tools import CryptoCodecTool
from services.tools.space_search import FOFASearchTool, HunterSearchTool, ShodanSearchTool
from services.tools.js_discovery import JSDiscoveryTool
from services.tools import yaml_loader
from app_config.auth import AuthMiddleware

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """应用启动时注册所有工具，关闭时释放 MCP 连接"""
    registry = tool_registry
    # 扫描器
    registry.register(PortScanTool())
    registry.register(DirBruteTool())
    registry.register(SubdomainTool())
    registry.register(QueryCVETool())
    # Web 工具
    registry.register(HTTPRequestTool())
    registry.register(BrowserTool())
    registry.register(BurpTool())
    # 编解码
    registry.register(CryptoCodecTool())
    # 网络空间搜索引擎
    registry.register(FOFASearchTool())
    registry.register(HunterSearchTool())
    registry.register(ShodanSearchTool())
    # JS 资产发现
    registry.register(JSDiscoveryTool())
    # 从 DB 加载自定义 YAML 工具
    yaml_loader.load_from_db()
    logger.info(f"已注册 {registry.count} 个工具")
    # 初始化预定义角色
    init_builtin_roles()
    logger.info("预定义角色已初始化")
    yield
    from services.tools.mcp_bridge import mcp_bridge
    await mcp_bridge.close()
    logger.info("Stopen 已关闭")


app = FastAPI(title="Stopen", version="1.0.0", lifespan=lifespan)

# 认证中间件（/api/auth/config 仅本机可读，详见 app_config/auth.py）
app.add_middleware(AuthMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000",
                    "http://localhost:8080", "http://127.0.0.1:8080",
                    "http://localhost:8081", "http://127.0.0.1:8081"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # HTTPException(401/403/404 等) 直接透传，不记录为错误
    if isinstance(exc, FastAPIHTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    logger.error(f"未捕获异常 [{request.method} {request.url.path}]: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "内部服务器错误"})


app.include_router(agent.router)
app.include_router(tools.router)
app.include_router(tasks.router)
app.include_router(config.router)
app.include_router(c2.router)
app.include_router(webshell.router)
app.include_router(mcp_config.router)
app.include_router(roles.router)
app.include_router(vulnerabilities.router)
app.include_router(yaml_tools.router)
app.include_router(chat.router)


@app.get("/api/health")
async def health():
    return {
        "status": "ok", "name": "Stopen", "version": "1.0.0",
        "features": [
            "ooda_agent", "mcp_yakit", "mcp_burp",
            "c2_framework", "webshell_manager",
            "pentest_tasks", "ctf_mode", "report_generation",
        ],
    }


@app.get("/api/skills")
async def list_skills():
    """列出所有可用技能"""
    names = list_all_skills()
    skills = []
    for name in names:
        content = get_skill_prompt(name)
        first_line = content.split("\n")[0] if content else ""
        skills.append({"name": name, "title": first_line.lstrip("# ")})
    return {"skills": skills, "count": len(skills)}


@app.get("/api/skills/{name}")
async def get_skill(name: str):
    """读取单个技能文档内容"""
    content = get_skill_prompt(name)
    if not content:
        raise FastAPIHTTPException(404, "技能不存在")
    return {"name": name, "content": content}


@app.get("/api/stats")
async def stats():
    """仪表盘聚合统计"""
    from services.db_service import db
    from services.c2_service import c2_service
    listeners = db.list_listeners()
    sessions = db.list_sessions()
    webshells = db.list_webshells()
    vulns = db.vulnerability_stats()
    tasks = db.list_tasks()
    conversations = db.list_conversations()
    skills = list_all_skills()
    tools = tool_registry
    running_tasks = sum(1 for t in tasks if t.get("status") == "running")
    try:
        c2_engine = c2_service.get_status().get("engine", "unknown")
    except Exception:
        c2_engine = "unknown"
    return {
        "c2_engine": c2_engine,
        "uptime_seconds": int(time.time() - APP_START),
        "listeners": {"total": len(listeners),
                      "running": sum(1 for l in listeners if l.get("status") == "running")},
        "sessions": {"total": len(sessions),
                     "active": sum(1 for s in sessions if s.get("status") == "active")},
        "webshells": {"total": len(webshells),
                      "active": sum(1 for w in webshells if w.get("status") == "active")},
        "vulnerabilities": vulns,
        "tasks": {"total": len(tasks), "running": running_tasks},
        "conversations": {"total": len(conversations)},
        "skills": {"total": len(skills)},
        "tools": {"total": tools.count},
    }


@app.get("/api/logs")
async def view_logs(type: str = "all", lines: int = 100):
    lines = min(max(lines, 1), 5000)
    path = LOG_DIR / ("errors.log" if type == "errors" else "stopen.log")
    if not path.exists():
        return {"logs": [], "message": "暂无日志"}
    log_lines, total_lines = _tail(path, lines)
    return {"logs": log_lines, "file": path.name, "total_lines": total_lines}


def _tail(path: Path, n: int) -> tuple[list[str], int]:
    """读取文件末尾 n 行，返回 (行列表, 文件总行数)"""
    max_read = 512 * 1024  # 日志有轮转上限，单次读末尾 512KB 足够
    size = path.stat().st_size
    with open(path, "rb") as f:
        if size <= max_read:
            data = f.read()
        else:
            f.seek(-max_read, 2)
            data = f.read()
    all_lines = data.decode("utf-8", errors="replace").splitlines()
    # 从中间截断时首行可能不完整，丢弃
    if size > max_read and all_lines:
        all_lines = all_lines[1:]
    total = len(all_lines)
    return all_lines[-n:], total


FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    from fastapi.staticfiles import StaticFiles
    # 挂载前先注册 /api/auth/config
    from app_config.auth import _load_or_create_secret
    token = _load_or_create_secret()

    @app.get("/api/auth/config")
    async def auth_config():
        return {"token": _load_or_create_secret()}

    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")
    logger.info(f"前端已挂载: {FRONTEND_DIST}")
    logger.info(f"认证 token 已生成 (保存至 storage/.auth_secret)")
else:
    logger.info("前端 dist 不存在，仅 API 模式运行")

logger.info("Stopen 启动就绪")
