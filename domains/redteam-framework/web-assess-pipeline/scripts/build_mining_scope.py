# -*- coding: utf-8 -*-
"""固化漏洞挖掘「必挖清单」基线到 mining-scope.json。

进入漏洞挖掘阶段前运行一次，把当前 url-inventory.json 中全部 page/api URL 的
{id, url, category, param_names} 快照冻结为必挖清单基线，作 check_vuln_mining.py 覆盖度硬门禁的依据。

冻结语义：mining-scope.json 已存在则不覆盖（保护基线不被挖掘阶段 payload 产生的新 URL/参数污染），
仅打印当前基线规模。挖掘阶段代理新记录的 URL/参数由门禁列为软复核项——确为正规业务接口用
`--add URLID...` 追加进基线（从当前 inventory 取其最新 param_names），payload 副产物忽略、不入必挖清单。

用法：
    python build_mining_scope.py --project <id> [--data-root pentest-data]
    python build_mining_scope.py --project <id> --add URL00098 URL00099
"""

import argparse
import sys

import common as c


def scope_record(u):
    """从 inventory URL 记录取必挖基线快照字段。"""
    return {
        "id": u.get("id"),
        "url": u.get("url", ""),
        "category": u.get("category", "unknown"),
        "param_names": sorted(u.get("param_names", []) or []),
    }


def freeze(paths):
    """首次固化：从当前 inventory 的 page/api URL 快照必挖清单基线。"""
    inv = c.load_json(paths["inventory"], default=None)
    if inv is None:
        print("[错误] 未找到 url-inventory.json，请先运行 build_url_inventory.py")
        sys.exit(1)
    urls = [scope_record(u) for u in inv.get("urls", []) if u.get("category") in ("page", "api")]
    urls.sort(key=lambda u: u["id"])
    scope = {
        "_note": "漏洞挖掘必挖清单基线（进入漏洞挖掘阶段前固化，作覆盖度硬门禁）",
        "frozen_at": c.now_iso(),
        "urls": urls,
    }
    c.atomic_write_json(paths["mining_scope"], scope)
    with_params = sum(1 for u in urls if u["param_names"])
    print("[已固化] 必挖清单基线：%s" % paths["mining_scope"])
    print("       page/api URL 共 %d 个（有参数 %d 个）。" % (len(urls), with_params))


def add_urls(paths, add_ids):
    """AI 复核后把正规业务新接口追加进已固化基线（取当前 inventory 的最新 param_names）。"""
    scope = c.load_json(paths["mining_scope"], default=None)
    if scope is None:
        print("[错误] mining-scope.json 尚未固化，请先运行 build_mining_scope.py 固化基线再 --add")
        sys.exit(1)
    inv = c.load_json(paths["inventory"], default={"urls": []})
    inv_by_id = {u.get("id"): u for u in inv.get("urls", [])}
    existing = {u.get("id") for u in scope.get("urls", [])}

    added = skipped = missing = 0
    for uid in add_ids:
        if uid in existing:
            skipped += 1
            continue
        u = inv_by_id.get(uid)
        if u is None:
            print("[警告] %s 不在 url-inventory.json，无法追加（先走通接口并重跑 build_url_inventory.py）" % uid)
            missing += 1
            continue
        rec = scope_record(u)
        rec["added_at"] = c.now_iso()
        scope["urls"].append(rec)
        existing.add(uid)
        added += 1

    scope["urls"].sort(key=lambda u: u["id"])
    c.atomic_write_json(paths["mining_scope"], scope)
    print("[已更新] 必挖清单基线：%s" % paths["mining_scope"])
    print("       本次追加 %d 个；已在基线跳过 %d 个；inventory 缺失无法追加 %d 个；基线现共 %d 个。"
          % (added, skipped, missing, len(scope["urls"])))


def main():
    p = argparse.ArgumentParser(description="固化漏洞挖掘必挖清单基线（冻结/追加）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--add", nargs="+", default=None, metavar="URLID",
                   help="把 AI 复核确认应纳入必挖的新 URL 追加进已固化基线")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)

    if args.add:
        add_urls(paths, args.add)
        return

    existing = c.load_json(paths["mining_scope"], default=None)
    if existing is not None:
        urls = existing.get("urls", [])
        with_params = sum(1 for u in urls if u.get("param_names"))
        print("[已固化·不覆盖] 必挖清单基线已存在：%s" % paths["mining_scope"])
        print("       固化于 %s；page/api URL 共 %d 个（有参数 %d 个）。"
              % (existing.get("frozen_at", "?"), len(urls), with_params))
        print("       如需纳入挖掘阶段新走通的正规接口，用 --add URLID... 追加；重新固化请先删除该文件。")
        return

    freeze(paths)


if __name__ == "__main__":
    main()
