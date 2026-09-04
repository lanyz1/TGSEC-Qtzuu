# -*- coding: utf-8 -*-
"""威胁收敛质量门禁——机器硬检查。

检查：
- 前置门禁 breadth + vuln_mining 均已清零（读各自 state.json 落盘退出态）；
- 威胁清单每条 verification_status 非 pending（∈ confirmed/excluded/doubtful/filtered）——
  confirmed 的 verification_report_id 非空且在漏洞报告清单（消账到某 VULN-VD 报告）；
  excluded/doubtful/filtered 的 verification_detail 有详述（引用挖掘产出矩阵结论作证据）；
- 绕过台账 bypass-list.json 每条 bypass_status 非 pending（每个 filtered 条目均经专项绕过：
  转 found 或仍 filtered 且证据已扩充），非 pending 项须填 access_note；
- 漏洞报告清单字段/枚举合法、report_file 存在、无 pending_review（全部 approved/rejected）。

退出码：0=硬检查通过（仍须 AI 复核），1=有硬错误。

用法：
    python check_threat_convergence.py --project <id> [--data-root pentest-data]
"""

import argparse
import os
import sys

import common as c

REPORT_REQUIRED = ["vuln_id", "title", "vuln_type", "severity", "phase", "source",
                   "related_url_id", "related_threat_id", "report_file",
                   "review_status", "review_note"]


def check_reports(paths, errors, reviews):
    """校验漏洞报告清单，返回 (全部报告集合, 全部报告号集合, 已通过报告号集合)。"""
    vr = c.load_json(paths["vuln_reports"], default={"reports": []})
    reports = vr.get("reports", [])
    all_ids, approved_ids = set(), set()
    for i, r in enumerate(reports):
        rid = r.get("vuln_id", "(无id第%d条)" % (i + 1))
        all_ids.add(r.get("vuln_id"))
        for fld in REPORT_REQUIRED:
            if fld not in r:
                errors.append("[报告清单] %s 缺字段：%s" % (rid, fld))
        if r.get("severity") not in c.PRIORITIES:
            errors.append("[报告清单] %s severity 非法：%r" % (rid, r.get("severity")))
        if r.get("phase") not in c.REPORT_PHASE:
            errors.append("[报告清单] %s phase 非法：%r" % (rid, r.get("phase")))
        if r.get("source") not in c.REPORT_SOURCE:
            errors.append("[报告清单] %s source 非法：%r" % (rid, r.get("source")))
        if r.get("review_status") not in c.REVIEW_STATUS:
            errors.append("[报告清单] %s review_status 非法：%r" % (rid, r.get("review_status")))
        elif r.get("review_status") == "pending_review":
            errors.append("[报告清单] %s 仍为 pending_review（须审核为 approved/rejected）" % rid)
        elif r.get("review_status") == "rejected" and not (r.get("review_note") or "").strip():
            errors.append("[报告清单] %s 已拒绝但 review_note 为空（须写明拒绝理由）" % rid)
        if r.get("review_status") == "approved":
            approved_ids.add(r.get("vuln_id"))
        rf = r.get("report_file", "")
        if not rf:
            errors.append("[报告清单] %s report_file 为空" % rid)
        elif not os.path.exists(os.path.join(paths["dir"], rf)):
            errors.append("[报告清单] %s 报告文件不存在：%s" % (rid, rf))
    return reports, all_ids, approved_ids


def check_threats(paths, report_ids, errors, reviews):
    """威胁消账：每条威胁映射到挖掘产出结论。
    confirmed→VULN-VD 报告号；excluded/doubtful/filtered→详述引用矩阵结论；无 pending。"""
    threats = c.load_jsonl(paths["threats"])
    n_conf = n_excl = n_doubt = n_filtered = 0
    for t in threats:
        tid = t.get("id")
        vs = t.get("verification_status")
        if vs not in c.VERIFICATION_STATUS:
            errors.append("[威胁] %s verification_status 非法：%r" % (tid, vs))
            continue
        if vs == "pending":
            errors.append("[威胁] %s 仍为 pending（收敛阶段须对账挖掘产出：confirmed 引用 VULN-VD 报告号，"
                          "或 excluded 附矩阵证据；找不到对应结论则调 pentest-vuln-miner 补测该 URL）" % tid)
        elif vs == "confirmed":
            n_conf += 1
            rep = t.get("verification_report_id", "")
            if not rep:
                errors.append("[威胁] %s 已确认但 verification_report_id 为空（须消账到某 VULN-VD 报告）" % tid)
            elif rep not in report_ids:
                errors.append("[威胁] %s 关联报告号不在报告清单：%s" % (tid, rep))
            else:
                reviews.append("[复核] 已确认威胁 %s 报告 %s 的证据真实性与危害评级" % (tid, rep))
        else:  # excluded（已排除）/ doubtful（客观或边界不可测）/ filtered（有防护绕不过）
            n_excl += vs == "excluded"
            n_doubt += vs == "doubtful"
            n_filtered += vs == "filtered"
            det = (t.get("verification_detail") or "").strip()
            if not det or det == "pending":
                errors.append("[威胁] %s 为 %s 但 verification_detail 缺详细说明（须引用相关 URL 矩阵结论作消账证据）" % (tid, vs))
            reviews.append("[复核] %s 威胁 %s：对账挖掘产出是否真实（引用的报告/矩阵结论确对应该威胁攻击面），测试是否充分" % (vs, tid))
    return threats, n_conf, n_excl, n_doubt, n_filtered


def check_bypass_list(paths, errors, reviews):
    """绕过台账硬校验：每个 filtered 绕过目标已处置（bypass_status 非 pending）、非 pending 项填 access_note。"""
    doc = c.load_json(paths["bypass_list"], default={"items": []})
    items = doc.get("items", []) if isinstance(doc, dict) else []
    n_done = n_pending = 0
    for it in items:
        key = "%s·%s·%s" % (it.get("url_id"), it.get("param"), it.get("vuln_type"))
        bs = it.get("bypass_status")
        if bs not in c.BYPASS_STATUS:
            errors.append("[绕过台账] %s bypass_status 非法（须∈%s）：%r" % (key, "/".join(sorted(c.BYPASS_STATUS)), bs))
            continue
        if bs == "pending":
            n_pending += 1
            errors.append("[绕过台账] %s 仍为 pending（须由 pentest-bypass-miner 对该 URL 专项绕过后回填 retested）" % key)
            continue
        n_done += 1
        if not (it.get("access_note") or "").strip():
            errors.append("[绕过台账] %s 为 %s 但缺 access_note（记录绕过结论：突破转 found 的报告号 / 仍绕不过已试的绕过族）" % (key, bs))
    if items:
        reviews.append("[复核] 逐条复核绕过台账：突破项报告证据真实、仍 filtered 项的 filter_probe 是否已扩充已试绕过族且判定成立")
    return items, n_done, n_pending


def main():
    p = argparse.ArgumentParser(description="威胁收敛质量门禁")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    errors, reviews = [], []

    # 前置门禁：广度 + 漏洞挖掘两道门禁须已清零（读各自 state.json 落盘退出态，未清零禁止流转）
    errors += c.check_prior_gate(paths, "breadth")
    errors += c.check_prior_gate(paths, "vuln_mining")

    reports, report_ids, approved_ids = check_reports(paths, errors, reviews)
    threats, n_conf, n_excl, n_doubt, n_filtered = check_threats(paths, report_ids, errors, reviews)
    bypass_items, n_bp_done, n_bp_pending = check_bypass_list(paths, errors, reviews)

    reviews.append("[复核] 威胁消账映射专项：每条 confirmed/excluded 是否真能在挖掘产出（vuln-matrix/报告）中找到对应结论，无缺账蒙混")
    reviews.append("[复核] 逐份审核收敛阶段新增报告（补测 / 绕过突破）：描述 / 复现 / 证据 / 危害；不过则打回重写或拒绝")
    reviews.append("[复核] 报告被拒后，若关联威胁为 confirmed，须反向修正该威胁状态并补 verification_detail、清空 verification_report_id")
    reviews.append("[复核] 所有 notes 特殊情况说明是否符合实际、合理")

    print("==== 威胁收敛质量门禁——脚本硬检查 ====")
    print("威胁 %d（确认 %d / 排除 %d / 存疑 %d / 被防护 %d） | 绕过目标 %d（已处置 %d / 待绕过 %d） | 报告 %d（已通过 %d）"
          % (len(threats), n_conf, n_excl, n_doubt, n_filtered,
             len(bypass_items), n_bp_done, n_bp_pending, len(reports), len(approved_ids)))
    print("")
    # 落盘退出态到 state.json.gates.threat_convergence（收尾门禁）
    nb = c.emit_gate_result(paths, "threat_convergence", errors, reviews)
    sys.exit(1 if nb else 0)


if __name__ == "__main__":
    main()
