# -*- coding: utf-8 -*-
"""参数漏洞矩阵自检——子代理提交前对本批 url-id 的矩阵做合规检查。

供 pentest-vuln-miner 子代理在返回工作总结前运行，对本批 url-id 的 vuln-matrix/{URLID}.json
做与阶段门禁【同源】的合规检查（复用 check_vuln_mining 的 check_matrix / check_entry），
在源头拦下不合规矩阵（参数漏测、filter_probe 结构错误、checkpoint_response 漏答、探到防护却判
tested_not_found 等），减轻阶段质量门禁的修复压力。

与阶段门禁的区别：
- 只查本批 url-id 的矩阵，不查 inventory 挖掘状态回填 / 一致性 / 补测清单（那些是主代理职责）；
- found→report_id 以 reports/ 目录【已落盘报告文件】校验（子代理写了报告文件、尚未由主代理登记 vuln-reports.json）；
- 只读、不写 state.json（≤3 子代理并发，避免竞争）。

退出码：0=本批矩阵合规，1=有硬错误须修复后再提交。

用法：
    python check_matrix.py --project <id> --url-id URL00007 URL00012 [--data-root pentest-data]
"""

import argparse
import glob
import os
import sys

import common as c
import check_vuln_mining as cvm


def param_names_of(uid, inv_by_id, retest_by_id):
    """取该 url-id 的 param_names（page/api 从 url-inventory；补测 URL 从 retest-list）。
    返回 (param_names, 是否已知)。两处都查不到 → 未知（主代理未纳入清单）。"""
    if uid in inv_by_id:
        return list(inv_by_id[uid].get("param_names", []) or []), True
    if uid in retest_by_id:
        return list(retest_by_id[uid].get("param_names", []) or []), True
    return [], False


def main():
    p = argparse.ArgumentParser(description="参数漏洞矩阵自检（子代理提交前）")
    p.add_argument("--project", required=True)
    p.add_argument("--url-id", nargs="+", required=True, metavar="URLID",
                   help="本批待自检的 url-id（≤5 个）")
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    errors, reviews, filtered_items = [], [], []

    inv_by_id = {u.get("id"): u for u in c.load_json(paths["inventory"], default={"urls": []}).get("urls", [])}
    retest_by_id = {it.get("id"): it for it in c.load_json(paths["retest_list"], default={"items": []}).get("items", [])}

    # 已落盘报告文件名（去 .md）作 found→report_id 的校验集
    report_ids = {os.path.splitext(os.path.basename(fp))[0]
                  for fp in glob.glob(os.path.join(paths["reports_dir"], "VULN-VD-*.md"))}

    n_with_params = n_matrix = 0
    for uid in args.url_id:
        param_names, known = param_names_of(uid, inv_by_id, retest_by_id)
        if not known:
            errors.append("[自检] %s 不在 url-inventory.json / retest-list.json（主代理未纳入清单，核对 url-id 是否正确）" % uid)
            continue
        matrix_file = os.path.join(paths["vuln_matrix_dir"], "%s.json" % uid)
        if param_names:
            n_with_params += 1
            if not os.path.exists(matrix_file):
                errors.append("[矩阵] %s 有参数但缺矩阵文件：%s（先产出 vuln-matrix/%s.json）" % (uid, matrix_file, uid))
                continue
            n_matrix += 1
            cvm.check_matrix(uid, param_names, c.load_json(matrix_file, default={}),
                             report_ids, errors, reviews, filtered_items)
        else:
            # 无参数 URL 不强制矩阵；若已产出（记 _url_level）则校验其条目
            if os.path.exists(matrix_file):
                cvm.check_matrix(uid, [], c.load_json(matrix_file, default={}),
                                 report_ids, errors, reviews, filtered_items)

    print("==== 参数漏洞矩阵自检（本批 %d 个 url-id；有参数 %d，已校验矩阵 %d） ===="
          % (len(args.url_id), n_with_params, n_matrix))
    print("")
    if errors:
        print("【须修复后再提交（%d）】" % len(errors))
        for e in errors:
            print("  - " + e)
    else:
        print("【自检通过】本批矩阵无硬错误，可提交工作总结。")
    if reviews:
        print("")
        print("【软告警（%d，自查确认，不阻塞提交）】" % len(reviews))
        for r in reviews:
            print("  - " + r)

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
