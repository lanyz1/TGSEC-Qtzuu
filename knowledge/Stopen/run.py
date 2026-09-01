"""Stopen 启动入口

用法:
    python run.py                          # 默认 8080
    python run.py --port 8081              # 指定端口
    python run.py --host 0.0.0.0 --port 8081 --no-reload

环境变量:
    STOPEN_PORT=8081 优先于默认值，--port 参数优先于环境变量
"""
import argparse
import os

parser = argparse.ArgumentParser(description="Stopen 自动化渗透测试平台")
parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认 0.0.0.0，局域网可访问；设为 127.0.0.1 仅本机)")
parser.add_argument("--port", type=int, default=int(os.environ.get("STOPEN_PORT", 8080)),
                    help=f"监听端口 (默认 8080, 环境变量 STOPEN_PORT)")
parser.add_argument("--no-reload", action="store_true", help="禁用热重载")
args = parser.parse_args()

from stopen.main import app
import uvicorn

if __name__ == "__main__":
    uvicorn.run("stopen.main:app", host=args.host, port=args.port,
                reload=not args.no_reload)
