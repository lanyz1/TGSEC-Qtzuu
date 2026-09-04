# -*- coding: utf-8 -*-
"""准备阶段：推导 project-id、建目录、登记 index.json、初始化 config.json / state.json。

幂等 + 断点：已存在同名项目则识别为「续测」并回报应跳转的阶段；target 冲突则报错。

用法：
    python init_project.py --target http://www.TGSEC.com:8080/ \
        [--project <id>] [--data-root pentest-data] \
        [--security-level high] [--proxy-port 24304]
"""

import argparse
import os
import re
import sys
from urllib.parse import urlsplit

import common as c


def derive_project_id(target):
    """从 target 的 hostname[:port] 推导：去用户信息、`.`/`:`→`-`、转小写。"""
    netloc = urlsplit(target).netloc or target
    netloc = netloc.split("@")[-1]
    return netloc.lower().replace(".", "-").replace(":", "-")


def main():
    p = argparse.ArgumentParser(description="威胁建模项目初始化（准备阶段）")
    p.add_argument("--target", required=True, help="目标根地址，如 http://www.TGSEC.com:8080/")
    p.add_argument("--project", default="", help="手动指定 project-id（默认由 target 推导）")
    p.add_argument("--data-root", default="pentest-data", help="数据根目录（默认 pentest-data）")
    p.add_argument("--security-level", default="high", choices=sorted(c.SECURITY_LEVELS),
                   help="安全等级（默认 high）")
    p.add_argument("--proxy-port", type=int, default=24304, help="代理监听端口（默认 24304，写入 config.proxy_port）")
    args = p.parse_args()

    pid = args.project or derive_project_id(args.target)
    if not re.fullmatch(r"[a-z0-9-]+", pid):
        print("[错误] project-id 含非法字符（仅允许 a-z 0-9 -）：%s" % pid)
        print("       请用 --project 手动指定合法 id。")
        sys.exit(1)

    paths = c.project_paths(args.data_root, pid)
    idx_path = c.index_path(args.data_root)

    # 建目录（含子目录）
    for key in ("dir", "pages_html", "js_files", "perm_dir", "reports_dir", "vuln_matrix_dir",
                "url_context_dir", "proxy_logs", "sessions_dir", "tmp_dir"):
        os.makedirs(paths[key], exist_ok=True)

    idx = c.load_json(idx_path, default={"_note": "项目清单", "projects": []})
    existing = next((proj for proj in idx["projects"] if proj.get("project_id") == pid), None)
    now = c.now_iso()

    if existing is not None:
        if existing.get("target") != args.target:
            print("[冲突] 已存在同名 project-id 但 target 不同：")
            print("       已登记 target = %s" % existing.get("target"))
            print("       本次   target = %s" % args.target)
            print("       请用 --project 换一个 id。")
            sys.exit(1)
        existing["last_active"] = now
        c.atomic_write_json(idx_path, idx)
        state = c.load_json(paths["state"], default={"phase": existing.get("phase", 1)})
        phase = state.get("phase", 1)
        print("[续测] project-id = %s" % pid)
        print("       当前阶段 phase = %s（断点恢复，跳到对应阶段）" % phase)
        print("       配置文件：%s" % paths["config"])
        sys.exit(0)

    # 新建项目
    idx["projects"].append({
        "project_id": pid,
        "target": args.target,
        "dir": paths["dir"].replace("\\", "/"),
        "created": now,
        "last_active": now,
        "phase": 1,
        "status": "in_progress",
    })
    c.atomic_write_json(idx_path, idx)

    if not os.path.exists(paths["config"]):
        c.atomic_write_json(paths["config"], {
            "project_id": pid,
            "target": args.target,
            "scope": [],
            "exclude": [],
            "scope_regex": False,
            "exclude_regex": False,
            "test_accounts": [],
            "goals": "",
            "constraints": "",
            "work_guidelines": "",
            "security_level": args.security_level,
            "proxy_port": args.proxy_port,
            "created": now,
            "notes": c.DEFAULT_NOTES,
        })
    if not os.path.exists(paths["state"]):
        c.atomic_write_json(paths["state"], {
            "phase": 1,
            "phase_status": {
                "preparation": "in_progress",
                "breadth": "pending",
                "vuln_mining": "pending",
                "threat_convergence": "pending",
            },
            "updated": now,
        })

    print("[新建] project-id = %s" % pid)
    print("       目录：%s" % paths["dir"])
    print("       配置：%s（请补全 scope / test_accounts / goals 等）" % paths["config"])
    print("       当前阶段 phase = 1（准备阶段）")
    sys.exit(0)


if __name__ == "__main__":
    main()
