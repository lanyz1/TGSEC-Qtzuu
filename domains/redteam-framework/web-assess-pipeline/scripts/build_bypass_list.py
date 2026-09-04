# -*- coding: utf-8 -*-
"""生成/更新绕过台账 bypass-list.json（威胁收敛阶段·专项绕过目标）。

汇集所有参数漏洞矩阵 vuln-matrix/*.json 中 status=filtered 的条目（存在漏洞信号但防护绕不过）
为绕过目标：每条 (url_id, 参数, 漏洞类型) 一项，交 pentest-bypass-miner 逐 URL 专项绕过突破。

幂等：以 (url_id, 参数, 漏洞类型) 为键 upsert——保留已填的 bypass_status/access_note/notes，
刷新矩阵带入的 filter_probe 摘要；每次按当前 filtered 集重算，已突破/已改判（不再 filtered）的自动剔除。

用法：
    python build_bypass_list.py --project <id> [--data-root pentest-data]
"""

import argparse
import glob
import os

import common as c


def _fp_summary(fp):
    """filter_probe 摘要：object 取 key:防护情况 拼接，兼容旧 string。"""
    if isinstance(fp, dict):
        return " ".join("%s:%s" % (k, (v[0] if isinstance(v, list) and v else "")) for k, v in fp.items())
    if isinstance(fp, str):
        return fp.strip()
    return ""


def _iter_filtered(matrix):
    """遍历一份矩阵，yield (参数名或 _url_level, entry)，其中 entry.status == filtered。"""
    params = matrix.get("params", {}) or {}
    for pname, entries in params.items():
        if not isinstance(entries, list):
            continue
        for e in entries:
            if isinstance(e, dict) and e.get("status") == "filtered":
                yield pname, e
    for e in matrix.get("_url_level", []) or []:
        if isinstance(e, dict) and e.get("status") == "filtered":
            yield "_url_level", e


def default_item(url_id, url, param, e):
    return {
        "id": "%s|%s|%s" % (url_id, param, e.get("vuln_type", "")),
        "url_id": url_id,
        "url": url,
        "param": param,
        "vuln_type": e.get("vuln_type", ""),
        "category": e.get("category", ""),
        "filter_probe_summary": _fp_summary(e.get("filter_probe")),
        "bypass_status": "pending",
        "access_note": "",
        "notes": c.DEFAULT_NOTES,
    }


def main():
    p = argparse.ArgumentParser(description="生成/更新绕过台账（filtered 矩阵条目汇集）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)

    old = {it.get("id"): it for it in c.load_json(paths["bypass_list"], default={"items": []}).get("items", [])}
    new_by_id, added, updated = {}, 0, 0

    for mf in sorted(glob.glob(os.path.join(paths["vuln_matrix_dir"], "*.json"))):
        matrix = c.load_json(mf, default={}) or {}
        url_id = matrix.get("url_id") or os.path.splitext(os.path.basename(mf))[0]
        url = matrix.get("url", "")
        for param, e in _iter_filtered(matrix):
            item = default_item(url_id, url, param, e)
            key = item["id"]
            if key in old:
                # 保留人工/AI 研判字段，刷新矩阵带入的 filter_probe 摘要
                old[key]["filter_probe_summary"] = item["filter_probe_summary"]
                old[key]["url"] = url or old[key].get("url", "")
                old[key]["category"] = item["category"] or old[key].get("category", "")
                new_by_id[key] = old[key]
                updated += 1
            else:
                new_by_id[key] = item
                added += 1
    removed = len(old) - updated  # 已突破 / 已改判（不再 filtered）的自动剔除

    out = {"_note": "绕过台账（威胁收敛阶段专项绕过目标）：vuln-matrix 中 status=filtered 条目汇集；"
                    "默认 pending，交 pentest-bypass-miner 逐 URL 绕过后回填 bypass_status=retested + access_note",
           "items": sorted(new_by_id.values(), key=lambda x: x.get("id", ""))}
    c.atomic_write_json(paths["bypass_list"], out)

    print("[完成] 绕过台账：%s" % paths["bypass_list"])
    print("       本次新增 %d，刷新 %d，剔除 %d，现存 %d 条 filtered 绕过目标。"
          % (added, updated, removed, len(out["items"])))
    pend = [it for it in out["items"] if it.get("bypass_status") == "pending"]
    if pend:
        # 按漏洞类型分组待绕过目标：主代理据此建队列，每类型 URL 切块 ≤5 成一个绕过任务，同批 URL 绕过手法可互通复用
        by_type = {}
        for it in pend:
            by_type.setdefault(it.get("vuln_type", ""), set()).add(it.get("url_id", ""))
        print("       [待绕过 bypass_status=pending] 按漏洞类型分组下发 pentest-bypass-miner（每任务 ≤5 个同类型 URL）：")
        for vt in sorted(by_type):
            urls = sorted(u for u in by_type[vt] if u)
            print("         · %s（%d URL）：%s" % (vt or "(未标类型)", len(urls), ", ".join(urls)))
    else:
        print("       无待绕过项。")


if __name__ == "__main__":
    main()
