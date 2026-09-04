#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
停止 HTTP/HTTPS 请求记录代理（start.py 启动的 mitmdump），按监听端口结束进程，单文件、跨平台。

    python proxy/stop.py                                       # 默认结束 127.0.0.1:24304 上的监听进程
    python proxy/stop.py --port 9090                           # 指定端口
    python proxy/stop.py --config pentest-data\\{id}\\config.json  # 从 config 读 proxy_port（与 start.py 同源）

端口解析优先级：--port > --config 的 proxy_port > 24304（与 start.py DEFAULT_PROXY_PORT 一致）。
与在代理终端按 Ctrl+C 等效，但可脚本化、跨会话可靠——报告阶段收尾时释放端口、停止抓包。
本工具只负责「结束监听指定端口的进程」，不修改任何环境变量或配置文件；幂等（无监听进程也正常退出）。
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

# 控制台/重定向 UTF-8（Windows 下中文输出不乱码，与 start.py / recorder.py 一致）
for _stream in ("stdout", "stderr"):
    try:
        getattr(sys, _stream).reconfigure(encoding="utf-8")
    except Exception:
        pass

DEFAULT_PROXY_PORT = 24304
IS_WINDOWS = os.name == "nt"


def _run(cmd):
    """运行命令，返回 (returncode, stdout)；命令不存在或失败时返回 (None, "")。"""
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return cp.returncode, cp.stdout or ""
    except (FileNotFoundError, OSError):
        return None, ""


def _find_pids_windows(host, port):
    """Windows：解析 netstat -ano，取 LISTENING 且本地地址匹配 host:port 的 PID（去重）。"""
    _, out = _run(["netstat", "-ano", "-p", "tcp"])
    pids = []
    suffix = ":%d" % port
    for line in out.splitlines():
        parts = line.split()
        # 形如: TCP  127.0.0.1:24304  0.0.0.0:0  LISTENING  12345
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
            local = parts[1]
            if local.endswith(suffix):
                try:
                    pid = int(parts[-1])
                except ValueError:
                    continue
                if pid and pid not in pids:
                    pids.append(pid)
    return pids


def _find_pids_posix(host, port):
    """POSIX：优先 lsof，回退 ss，取监听指定端口的 PID（去重）。"""
    pids = []
    rc, out = _run(["lsof", "-ti", "tcp:%d" % port, "-sTCP:LISTEN"])
    if rc is not None:
        for tok in out.split():
            try:
                pid = int(tok)
            except ValueError:
                continue
            if pid and pid not in pids:
                pids.append(pid)
        if pids:
            return pids
    # 回退 ss -ltnp，从 "pid=12345" 中提取
    _, out = _run(["ss", "-ltnp"])
    suffix = ":%d" % port
    for line in out.splitlines():
        fields = line.split()
        if not any(f.endswith(suffix) for f in fields):
            continue
        for m in re.finditer(r"pid=(\d+)", line):
            pid = int(m.group(1))
            if pid and pid not in pids:
                pids.append(pid)
    return pids


def _kill(pid):
    """结束单个进程；返回 True 表示已发出结束指令且进程消失。"""
    if IS_WINDOWS:
        rc, _ = _run(["taskkill", "/PID", str(pid), "/F"])
        return rc == 0
    # POSIX：先 SIGTERM，短暂等待仍存活则 SIGKILL
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    for _ in range(10):
        time.sleep(0.2)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return True


def main():
    p = argparse.ArgumentParser(
        description="停止记录代理（按监听端口结束 mitmdump 进程）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--port", type=int, default=None,
                   help="要停止的监听端口（默认 24304；用 --config 时取 config.proxy_port）")
    p.add_argument("--host", default="127.0.0.1", help="监听地址（仅用于展示/匹配）")
    p.add_argument("--config", default=None, metavar="PATH",
                   help="从 config.json 读 proxy_port（与 start.py --config 同源）；与 --port 互斥")
    args = p.parse_args()

    # ---- 解析端口：--port > --config 的 proxy_port > 默认 ----
    if args.config:
        if args.port is not None:
            sys.exit("--config 与 --port 互斥，请二选一。")
        if not os.path.exists(args.config):
            sys.exit("未找到 config 文件：%s" % args.config)
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            sys.exit("读取 config 失败：%s → %s" % (args.config, e))
        port = cfg.get("proxy_port") or DEFAULT_PROXY_PORT
        source_desc = "config: %s" % args.config
    else:
        port = args.port or DEFAULT_PROXY_PORT
        source_desc = "命令行"

    print("\n==== 停止 HTTP/HTTPS 请求记录代理 ====")
    print("目标端口  : %s:%d" % (args.host, port))
    print("端口来源  : %s" % source_desc)

    finder = _find_pids_windows if IS_WINDOWS else _find_pids_posix
    pids = finder(args.host, port)

    if not pids:
        print("结果      : 端口 %d 无监听进程（代理可能已停止）。\n" % port)
        sys.exit(0)

    killed, failed = [], []
    for pid in pids:
        (killed if _kill(pid) else failed).append(pid)

    if killed:
        print("已结束进程: %s（端口 %d）" % (", ".join(map(str, killed)), port))
    if failed:
        print("结束失败  : %s —— 请手动结束（可能权限不足或非本用户进程）" % ", ".join(map(str, failed)))
    print("")
    sys.exit(0)


if __name__ == "__main__":
    main()
