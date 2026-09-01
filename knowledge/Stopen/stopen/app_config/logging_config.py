"""日志配置"""
import logging, sys
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "storage" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    fh = logging.FileHandler(LOG_DIR / "stopen.log", encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
