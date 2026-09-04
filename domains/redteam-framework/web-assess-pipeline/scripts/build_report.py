# -*- coding: utf-8 -*-
"""汇总本项目四阶段数据 → 完整 WEB 应用安全评估报告（Markdown + HTML + DOCX）。

读取 config/state(gates)/vuln-reports/reports/threats/url-inventory/pages/js/business-chains/
permission-matrix/bypass-list/retest-list/sessions，自动拼出完整报告 Markdown，
写 pentest-data/{id}/report/{id}-report-{YYYYMMDD}.md，并渲染同名 .html 与 .docx。

漏洞详情仅纳入 review_status=approved 的报告，按危害降序，嵌入 reports/{vuln_id}.md 正文。
门禁未过不硬阻塞（在概述如实标注退出态，供出草稿）。

用法：
    python build_report.py --project <id> [--data-root pentest-data] [--title 系统名]
"""

import argparse
import os
import re
from collections import Counter
from datetime import datetime
from urllib.parse import urlsplit

import common as c
import render_report as rr

SEV_EN2CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
LEVEL_CN = {"high": "高（生产环境，测试账号内且不可回退操作受限）",
            "medium": "中（生产中的测试账号，可增删改）", "low": "低（测试环境，可任意增删改查）"}
VS_CN = {"confirmed": "已确认", "excluded": "已排除", "doubtful": "存疑", "filtered": "被防护", "pending": "待收敛"}


def sev_cn(sev):
    return SEV_EN2CN.get(sev, sev or "?")


def system_name(cfg, project_id, override):
    if override:
        return override
    tgt = cfg.get("target", "") or ""
    seg = [s for s in urlsplit(tgt).path.split("/") if s]
    if seg:
        return seg[-1]
    host = urlsplit(tgt).netloc
    return host or project_id


def demote_report_body(md_text):
    """嵌入单份报告正文：丢弃首个 `# 漏洞报告…` H1，其余标题降 2 级（## → ####）。"""
    out = []
    for ln in md_text.split("\n"):
        m = re.match(r"^(#{1,6})\s+(.*)$", ln)
        if m:
            lvl = len(m.group(1))
            if lvl == 1:
                continue
            out.append("#" * min(lvl + 2, 6) + " " + m.group(2))
        else:
            out.append(ln)
    return "\n".join(out).strip()


def extract_section(md_text, title):
    """取 `## {title}` 到下一个同/更高级标题之间的正文（供修复建议汇总）。"""
    lines = md_text.split("\n")
    out, grab = [], False
    for ln in lines:
        m = re.match(r"^(#{1,6})\s+(.*)$", ln)
        if m:
            if grab:
                break
            if len(m.group(1)) <= 2 and title in m.group(2):
                grab = True
            continue
        if grab and ln.strip():
            out.append(ln.strip())
    return out


def project_dates(data_root, project_id):
    """从 index.json 取本项目 created..last_active 日期区间；缺失则用今日。"""
    idx = c.load_json(c.index_path(data_root), default={"projects": []}) or {"projects": []}
    for p in idx.get("projects", []):
        if p.get("project_id") == project_id:
            cr = (p.get("created", "") or "")[:10]
            la = (p.get("last_active", "") or "")[:10]
            if cr and la and cr != la:
                return "%s 至 %s" % (cr, la)
            return la or cr or datetime.now().strftime("%Y-%m-%d")
    return datetime.now().strftime("%Y-%m-%d")


class MD:
    """轻量 Markdown 累积器。"""
    def __init__(self):
        self.buf = []

    def line(self, s=""):
        self.buf.append(s)

    def h(self, level, text):
        self.buf.append("")
        self.buf.append("#" * level + " " + text)
        self.buf.append("")

    def table(self, header, rows):
        self.buf.append("| " + " | ".join(header) + " |")
        self.buf.append("|" + "|".join(["---"] * len(header)) + "|")
        for r in rows:
            self.buf.append("| " + " | ".join(str(x) for x in r) + " |")
        self.buf.append("")

    def text(self):
        return "\n".join(self.buf) + "\n"


def main():
    p = argparse.ArgumentParser(description="汇总生成安全评估报告（md+html+docx）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--title", default=None, help="系统名（缺省从 target 路径末段推导）")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    cfg = c.load_json(paths["config"], default={}) or {}
    state = c.load_json(paths["state"], default={}) or {}
    gates = state.get("gates", {}) or {}

    sysname = system_name(cfg, args.project, args.title)
    dates = project_dates(args.data_root, args.project)

    # ---- 漏洞报告 ----
    all_reports = c.load_json(paths["vuln_reports"], default={"reports": []}).get("reports", [])
    approved = [r for r in all_reports if r.get("review_status") == "approved"]
    approved.sort(key=lambda r: (SEV_RANK.get(r.get("severity"), 9), r.get("vuln_id", "")))
    n_pending = sum(1 for r in all_reports if r.get("review_status") == "pending_review")
    n_rejected = sum(1 for r in all_reports if r.get("review_status") == "rejected")
    sev_counter = Counter(r.get("severity") for r in approved)
    stats = {k: sev_counter.get(k, 0) for k in ("critical", "high", "medium", "low")}

    # ---- 攻击面 ----
    pages = c.load_jsonl(paths["pages"])
    jss = c.load_jsonl(paths["js"])
    chains = c.load_jsonl(paths["chains"])
    inv_urls = c.load_json(paths["inventory"], default={"urls": []}).get("urls", [])
    pageapi = [u for u in inv_urls if u.get("category") in ("page", "api")]
    threats = c.load_jsonl(paths["threats"])

    # 权限矩阵异常 URL 数
    perm_abnormal = 0
    if os.path.isdir(paths["perm_dir"]):
        for fn in os.listdir(paths["perm_dir"]):
            if not fn.endswith(".json"):
                continue
            pm = c.load_json(os.path.join(paths["perm_dir"], fn), default={}) or {}
            if any(res.get("judgment") == "abnormal" for res in pm.get("results", [])):
                perm_abnormal += 1

    md = MD()
    # ========== 封面 ==========
    md.line("# %s WEB 应用安全评估报告" % sysname)
    md.line()
    md.line("> 目标：%s" % (cfg.get("target", "") or "-"))
    md.line("> 测试范围：%s" % ("；".join(cfg.get("scope", []) or []) or "目标路径下全部"))
    md.line("> 安全等级：%s" % LEVEL_CN.get(cfg.get("security_level"), cfg.get("security_level", "-")))
    md.line("> 测试时间：%s" % dates)
    md.line("> 测试方法：攻击面测绘 → 威胁建模与权限矩阵验证 → 逐 URL 逐参数漏洞挖掘 → 威胁收敛")
    md.line("> 漏洞统计：严重 %d / 高危 %d / 中危 %d / 低危 %d"
            % (stats["critical"], stats["high"], stats["medium"], stats["low"]))
    md.line()
    md.line("---")

    # ========== 1. 测试概述 ==========
    md.h(2, "1. 测试概述")
    md.line("- **目标**：%s" % (cfg.get("target", "") or "-"))
    md.line("- **测试范围**：%s" % ("；".join(cfg.get("scope", []) or []) or "目标路径下全部"))
    md.line("- **安全等级**：%s" % LEVEL_CN.get(cfg.get("security_level"), cfg.get("security_level", "-")))
    if cfg.get("goals"):
        md.line("- **评估目标**：%s" % cfg.get("goals"))
    md.line("- **测试方法**：基于业务功能与攻击面的威胁建模，逐 URL 逐参数独立挖掘，非套用固定漏洞清单。")
    md.line()
    total = sum(stats.values())
    md.line("**整体结论**：本次评估共确认 **%d 个漏洞**（严重 %d / 高危 %d / 中危 %d / 低危 %d）。"
            % (total, stats["critical"], stats["high"], stats["medium"], stats["low"]))
    if n_pending or n_rejected:
        md.line("另有待审核 %d 份、已拒绝 %d 份报告（不计入上述确认漏洞）。" % (n_pending, n_rejected))
    gate_bits = []
    for gk, gn in (("breadth", "广度建模"), ("vuln_mining", "漏洞挖掘"), ("threat_convergence", "威胁收敛")):
        g = gates.get(gk)
        if g is not None:
            gate_bits.append("%s blocking=%d" % (gn, g.get("blocking_count", 0)))
    if gate_bits:
        allpass = all(gates.get(k, {}).get("blocking_count", 1) == 0
                      for k in ("breadth", "vuln_mining", "threat_convergence") if gates.get(k) is not None)
        md.line("质量门禁退出态：%s（0 表示通过）。%s"
                % ("，".join(gate_bits), "三阶段门禁均已通过。" if allpass else "存在未清零门禁，本报告为阶段性结果。"))
    md.line()

    # ========== 2. 测试账号与角色 ==========
    md.h(2, "2. 测试账号与角色")
    accts = cfg.get("test_accounts", []) or []
    sess = {s.get("role"): s for s in c.load_json(paths["sessions"], default={"sessions": []}).get("sessions", [])}
    if accts:
        rows = []
        for i, a in enumerate(accts, 1):
            role = a.get("role", "-")
            st = sess.get(role, {}).get("login_status", "-")
            rows.append([i, role, a.get("username", "-"), st])
        md.table(["#", "角色", "账号", "登录状态"], rows)
    else:
        md.line("未配置测试账号（或纯未授权基线测试）。")
        md.line()

    # ========== 3. 攻击面测绘概览 ==========
    md.h(2, "3. 攻击面测绘概览")
    md.table(["测绘对象", "数量"], [
        ["页面（pages）", len(pages)],
        ["脚本（JS）", len(jss)],
        ["业务链", len(chains)],
        ["接口/页面 URL（page/api）", len(pageapi)],
        ["权限矩阵越权/未授权异常", perm_abnormal],
        ["威胁建模条目", len(threats)],
    ])
    wt = Counter(ch.get("walkthrough_status") for ch in chains)
    if wt:
        md.line("业务链走通情况：%s。"
                % "，".join("%s %d" % ({"completed": "完整走通", "partial": "部分走通",
                                        "blocked": "未走通", "pending": "待走通"}.get(k, k), v)
                           for k, v in wt.items()))
        md.line()

    # ========== 4. 漏洞统计概览 ==========
    md.h(2, "4. 漏洞统计概览")
    md.table(["危害等级", "数量"], [
        ["严重（critical）", stats["critical"]],
        ["高危（high）", stats["high"]],
        ["中危（medium）", stats["medium"]],
        ["低危（low）", stats["low"]],
        ["**合计**", "**%d**" % total],
    ])
    vt = Counter(r.get("vuln_type", "-") for r in approved)
    if vt:
        md.line("按漏洞类型分布：")
        md.table(["漏洞类型", "数量"], [[k, v] for k, v in vt.most_common()])

    # ========== 5. 漏洞详情 ==========
    md.h(2, "5. 漏洞详情")
    if not approved:
        md.line("本次评估未确认漏洞。")
        md.line()
    for i, r in enumerate(approved, 1):
        md.h(3, "%d. %s（%s）" % (i, r.get("title", "未命名"), sev_cn(r.get("severity"))))
        meta = ["**漏洞类型**：%s" % r.get("vuln_type", "-"),
                "**危害等级**：%s" % sev_cn(r.get("severity")),
                "**关联 URLID**：%s" % r.get("related_url_id", "-")]
        if r.get("related_threat_id"):
            meta.append("**关联威胁**：%s" % r.get("related_threat_id"))
        md.line("｜".join(meta))
        md.line()
        rf = os.path.join(paths["dir"], r.get("report_file", "reports/%s.md" % r.get("vuln_id")))
        if os.path.exists(rf):
            with open(rf, encoding="utf-8") as f:
                md.line(demote_report_body(f.read()))
            md.line()
        else:
            md.line("> 报告正文缺失：%s" % r.get("report_file", ""))
            md.line()
        md.line("---")

    # ========== 6. 威胁收敛结论 ==========
    md.h(2, "6. 威胁收敛结论")
    vs = Counter(t.get("verification_status") for t in threats)
    if threats:
        md.table(["威胁状态", "数量"], [[VS_CN.get(k, k), v] for k, v in vs.items()])
        confirmed = [t for t in threats if t.get("verification_status") == "confirmed"]
        if confirmed:
            md.line("已确认威胁与消账报告映射：")
            md.table(["威胁", "关联报告"],
                     [[t.get("name", t.get("id", "-")), t.get("verification_report_id", "-")] for t in confirmed])
    else:
        md.line("无威胁建模条目。")
        md.line()

    # ========== 7. 被防护与残余缺口 ==========
    md.h(2, "7. 被防护与残余缺口")
    bypass = c.load_json(paths["bypass_list"], default={"items": []}).get("items", [])
    filtered = [b for b in bypass if b.get("bypass_status") != "retested" or b.get("bypass_status") == "pending"]
    if bypass:
        md.line("**被防护信号（filtered）** %d 项：有漏洞信号但防护经真实尝试绕不过，留待后续跟踪。" % len(bypass))
        md.table(["URL", "参数", "漏洞类型", "绕过状态"],
                 [[b.get("url_id", "-"), b.get("param", "-"), b.get("vuln_type", "-"),
                   b.get("bypass_status", "-")] for b in bypass[:50]])
    residual = []
    for gk, g in gates.items():
        for a in (g or {}).get("acknowledged", []) or []:
            if a.get("reason_code") == "accepted_residual":
                residual.append([gk, a.get("match", "-"), a.get("note", "-")])
    if residual:
        md.line("**显式接受的残余风险（accepted_residual）**：")
        md.table(["门禁", "命中项", "说明"], residual)
    retest = c.load_json(paths["retest_list"], default={"items": []}).get("items", [])
    blocked = [it for it in retest if it.get("disposition") == "blocked"]
    if blocked:
        md.line("**未补测项（安全边界所限或无需测，blocked）** %d 项：" % len(blocked))
        md.table(["URL", "原因"], [[it.get("url", it.get("id", "-")), it.get("access_note", "-")] for it in blocked[:50]])
    if not (bypass or residual or blocked):
        md.line("无被防护信号、无显式接受的残余风险、无未补测项。")
        md.line()

    # ========== 8. 修复建议汇总 ==========
    md.h(2, "8. 修复建议汇总")
    if approved:
        rows = []
        for r in approved:
            rf = os.path.join(paths["dir"], r.get("report_file", "reports/%s.md" % r.get("vuln_id")))
            fix = ""
            if os.path.exists(rf):
                with open(rf, encoding="utf-8") as f:
                    items = extract_section(f.read(), "修复建议")
                fix = "；".join(re.sub(r"^[-*]\s*", "", x) for x in items if x)[:200]
            rows.append([r.get("title", "-"), sev_cn(r.get("severity")), fix or "详见漏洞详情"])
        md.table(["漏洞", "危害", "修复要点"], rows)
    else:
        md.line("无。")
        md.line()

    # ========== 附录. 质量门禁退出态 ==========
    md.h(2, "附录. 质量门禁退出态")
    md.table(["门禁", "exit", "blocking_count", "核验时间"],
             [[gn, gates.get(gk, {}).get("exit", "-"), gates.get(gk, {}).get("blocking_count", "-"),
               (gates.get(gk, {}).get("checked_at", "-") or "-")[:19]]
              for gk, gn in (("breadth", "广度建模"), ("vuln_mining", "漏洞挖掘"), ("threat_convergence", "威胁收敛"))])
    md.line("> 门禁退出态由 check_*.py 脚本落盘，blocking_count=0 为放行判据。")

    # ---- 落盘 md + 渲染 html/docx ----
    os.makedirs(paths["report_out_dir"], exist_ok=True)
    stem = "%s-report-%s" % (args.project, datetime.now().strftime("%Y%m%d"))
    md_path = os.path.join(paths["report_out_dir"], stem + ".md")
    html_path = os.path.join(paths["report_out_dir"], stem + ".html")
    docx_path = os.path.join(paths["report_out_dir"], stem + ".docx")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md.text())
    title, produced = rr.render_file(md.text(), html_path, docx_path)

    print("==== 报告已生成（确认漏洞 %d：严重 %d / 高危 %d / 中危 %d / 低危 %d）===="
          % (total, stats["critical"], stats["high"], stats["medium"], stats["low"]))
    print("  MD  : %s" % md_path)
    for pth in produced:
        print("  %s: %s (%d bytes)" % ("HTML" if pth.endswith(".html") else "DOCX", pth, os.path.getsize(pth)))
    if n_pending:
        print("  [提示] 有 %d 份报告仍 pending_review，未纳入漏洞详情；建议门禁通过后再出正式报告。" % n_pending)
    print("  [提示] 报告含完整请求/响应（可能含凭据），交付前请加密或内网传输。")


if __name__ == "__main__":
    main()
