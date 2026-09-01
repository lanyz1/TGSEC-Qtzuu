"""pytest 全局配置：隔离测试存储路径，避免污染真实 storage/"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STOPEN_DIR = ROOT / "stopen"
sys.path.insert(0, str(STOPEN_DIR))

# 必须在导入任何 stopen 模块之前打补丁：
# db_service / report_service 等模块在 import 时绑定这些路径
import app_config.settings as settings  # noqa: E402

TEST_STORAGE = Path(tempfile.mkdtemp(prefix="stopen-tests-"))
settings.STORAGE_DIR = TEST_STORAGE
settings.CONFIG_DIR = TEST_STORAGE
settings.UPLOADS_DIR = TEST_STORAGE / "uploads"
settings.DB_PATH = TEST_STORAGE / "test.db"
