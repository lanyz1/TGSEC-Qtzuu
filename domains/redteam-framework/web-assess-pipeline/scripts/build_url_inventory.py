# -*- coding: utf-8 -*-
"""从代理 proxy-logs/url_index.jsonl 生成/更新 url-inventory.json。

幂等：以 url id 为键 upsert——新增 URL、并入新出现的 param_names；
绝不覆盖已有的 permission_matrix_status / *_mining_* / category / notes 等状态字段，
保护人工/AI 已填进度。只纳入 category 为 page/api/other 的记录（js/resource/unknown 跳过）。

用法：
    python build_url_inventory.py --project <id> [--data-root pentest-data]
"""

import argparse
import sys

import common as c


def default_url_record(rec):
    out = {
        "id": rec["id"],
        "url": rec.get("url", ""),
        "category": rec.get("category", "unknown"),
        "methods": rec.get("methods", []),
        "param_names": rec.get("param_names", []),
        "permission_matrix_status": "pending",
        "generic_vuln_mining_done": "pending",
        "generic_vuln_mining_result": "pending",
        "business_logic_mining_done": "pending",
        "business_logic_mining_result": "pending",
        "notes": c.DEFAULT_NOTES,
    }
    if rec.get("category") == "other":
        out["needs_review"] = True
    return out


def main():
    p = argparse.ArgumentParser(description="生成/更新 URL 清单（幂等）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    src = c.load_jsonl(paths["url_index"])
    if not src:
        print("[警告] 未找到或为空：%s" % paths["url_index"])

    inv = c.load_json(paths["inventory"], default={"_note": "URL清单", "urls": []})
    by_id = {u["id"]: u for u in inv["urls"]}

    added = params_merged = reviewed = 0
    for rec in src:
        if rec.get("category") not in ("page", "api", "other"):
            continue  # js / resource / unknown 不纳入
        uid = rec.get("id")
        if not uid:
            continue
        if uid not in by_id:
            new = default_url_record(rec)
            inv["urls"].append(new)
            by_id[uid] = new
            added += 1
            if new.get("category") == "other":
                reviewed += 1
        else:
            cur = by_id[uid]
            names = set(cur.get("param_names", []))
            incoming = set(rec.get("param_names", []))
            if incoming - names:
                cur["param_names"] = sorted(names | incoming)
                params_merged += 1

    inv["urls"].sort(key=lambda u: u["id"])
    c.atomic_write_json(paths["inventory"], inv)

    print("[完成] URL 清单：%s" % paths["inventory"])
    print("       本次新增 %d 个 URL；并入新参数 %d 个；新增待复核(other) %d 个。"
          % (added, params_merged, reviewed))
    pending = [u["id"] for u in inv["urls"] if u.get("needs_review")]
    if pending:
        print("       [待 AI 复核] category=other，判断是否实为页面/接口：%s" % ", ".join(pending))


if __name__ == "__main__":
    main()
