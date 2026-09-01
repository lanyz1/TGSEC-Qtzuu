"""应用全局设置"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage"
CONFIG_DIR = STORAGE_DIR
UPLOADS_DIR = STORAGE_DIR / "uploads"
DB_PATH = STORAGE_DIR / "stopen.db"

for d in [CONFIG_DIR, UPLOADS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_SIZE = 10 * 1024 * 1024

# Agent 循环常量
MAX_ITERATIONS = 15          # 最大 OODA 轮数
MAX_TOOL_CALLS = 30          # 单次执行总工具调用上限
MAX_CONSECUTIVE_FAILURES = 3 # 连续工具失败自动熔断
MAX_PARALLEL_INTERITS = 3    # 黑板并行 intent 数
