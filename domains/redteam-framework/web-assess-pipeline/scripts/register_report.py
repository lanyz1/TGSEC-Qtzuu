# -*- coding: utf-8 -*-
"""分配漏洞报告编号并登记到 vuln-reports.json（漏洞报告清单）。

编号规则：VULN-VD-{URLID}-NNNN（内嵌具体 URLID，逐 URL 归属；并发子代理各自分配不冲突）。
漏洞挖掘与威胁收敛阶段（补测 / 绕过突破）产出的报告均用此编号，在该 URL 内续编。

登记后 review_status=pending_review，待质量门禁审核为 approved / rejected。
脚本输出分配到的报告号与应写入的报告 markdown 路径（报告正文由 AI 按 report-template.md 撰写）。

用法：
    python register_report.py --project <id> --url-id URL00010 \
        --title "..." --vuln-type "注入/SQL注入" --severity high [--related-threat-id THREAT0005]
"""

import argparse
import os
import re
import sys

import common as c


def next_report_id(prefix, reports):
    """在 vuln_id 形如 {prefix}-0001 中求下一个递增号。"""
    mx = 0
    pat = re.compile(re.escape(prefix) + r"-0*(\d+)$")
    for r in reports:
        m = pat.match(str(r.get("vuln_id", "")))
        if m:
            mx = max(mx, int(m.group(1)))
    return "%s-%04d" % (prefix, mx + 1)


def main():
    p = argparse.ArgumentParser(description="分配并登记漏洞报告")
    p.add_argument("--project", required=True)
    p.add_argument("--url-id", required=True, help="关联 URLID（逐 URL 归属，必填）")
    p.add_argument("--title", required=True)
    p.add_argument("--vuln-type", required=True)
    p.add_argument("--severity", required=True, choices=sorted(c.PRIORITIES))
    p.add_argument("--related-threat-id", default="")
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    if not args.url_id:
        print("[错误] 必须提供 --url-id")
        sys.exit(1)
    prefix = "VULN-VD-%s" % args.url_id

    paths = c.project_paths(args.data_root, args.project)
    os.makedirs(paths["reports_dir"], exist_ok=True)
    vr = c.load_json(paths["vuln_reports"], default={"_note": "漏洞报告清单", "reports": []})
    reports = vr.setdefault("reports", [])

    vuln_id = next_report_id(prefix, reports)
    report_file = "reports/%s.md" % vuln_id
    now = c.now_iso()
    reports.append({
        "vuln_id": vuln_id,
        "title": args.title,
        "vuln_type": args.vuln_type,
        "severity": args.severity,
        "phase": "VD",
        "source": "URL",
        "related_url_id": args.url_id,
        "related_threat_id": args.related_threat_id,
        "report_file": report_file,
        "review_status": "pending_review",
        "review_note": "",
        "created": now,
        "updated": now,
    })
    c.atomic_write_json(paths["vuln_reports"], vr)

    print("[已登记] %s（%s / 危害 %s / 审核 pending_review）" % (vuln_id, args.vuln_type, args.severity))
    print("报告正文请按 report-template.md 写到：%s" % os.path.join(paths["dir"], report_file))


if __name__ == "__main__":
    main()
