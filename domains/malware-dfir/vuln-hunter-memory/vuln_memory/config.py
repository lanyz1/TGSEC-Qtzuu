"""全局配置与业务常量。

存储后端为「文件级」：Redis→JSON 文件，FAISS→numpy 索引，Neo4j→networkx+JSON。
这样在无任何外部服务的 Windows 环境下可立即运行；同时保留可插拔接口
（见 backends.py），可随时切换到真实 Redis / Neo4j / FAISS 而不动业务层。
"""
import os
from datetime import timedelta


class Config:
    # --- 存储根目录：项目下 vuln_memory_data/ ---
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(ROOT, "vuln_memory_data")

    # 各层目录
    INSTANT_DIR = os.path.join(DATA_DIR, "instant")
    WORKING_DIR = os.path.join(DATA_DIR, "working")
    SHORT_DIR = os.path.join(DATA_DIR, "shortterm")
    LONG_DIR = os.path.join(DATA_DIR, "longterm")
    PROJECT_DIR = os.path.join(DATA_DIR, "project")

    # --- 业务常量（沿用原方案）---
    INSTANT_MAX_TOKEN = 8000        # 瞬时缓冲上限（按字符近似）
    INSTANT_KEEP_RATIO = 0.6       # 溢出时保留最近比例
    WORKING_TEXT_MAXLEN = 15       # 工作记忆文本环路最大条数
    SHORT_MEM_EXPIRE = timedelta(days=7)   # 短时向量有效期
    DISTILL_CYCLE_HINT = 86400     # 蒸馏周期（秒，仅提示；实际由 Claude Code 触发）

    # --- 向量维度（哈希向量化用，无依赖）---
    EMBED_DIM = 512

    # 可选：若安装了 sentence-transformers 则用真模型，否则回退哈希向量化
    ST_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

    @classmethod
    def ensure_dirs(cls):
        for d in (cls.INSTANT_DIR, cls.WORKING_DIR, cls.SHORT_DIR, cls.LONG_DIR, cls.PROJECT_DIR):
            os.makedirs(d, exist_ok=True)
