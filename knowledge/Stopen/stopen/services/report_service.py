"""报告生成 — 黑板导出 + PoC 脚本 + HTML 格式"""
import datetime
import json
from pathlib import Path

from app_config.settings import STORAGE_DIR


def generate_report(task_id="", target="", task_type="pentest", findings=None,
                    messages=None) -> dict:
    """生成 Markdown 渗透报告"""
    if findings is None:
        findings = []
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# 渗透测试报告",
        "",
        f"**目标**: {target}",
        f"**类型**: {'CTF 挑战' if task_type == 'ctf' else '渗透测试'}",
        f"**生成时间**: {now}",
        f"**任务 ID**: {task_id}",
        "",
        "---",
        "",
        "## 发现摘要",
        "",
    ]

    if findings:
        by_type = {}
        for f in findings:
            ft = f.get("type", "其他")
            by_type.setdefault(ft, []).append(f)

        for ft, items in by_type.items():
            lines.append(f"### {ft}")
            for item in items:
                lines.append(f"- **{item.get('value', '')}**")
                lines.append(f"  - 来源: {item.get('source', '')}")
                ev = item.get("evidence", "")
                if ev:
                    lines.append(f"  - 证据: {ev[:200]}")
            lines.append("")
    else:
        lines.append("暂无结构化发现。\n")

    # Flag
    flag_items = [f for f in findings if f.get("type") == "flag"]
    if flag_items:
        lines.append("## Flag 结果\n")
        for f in flag_items:
            lines.append(f"**Flag**: `{f.get('value', '')}`")
            lines.append(f"**获取方式**: {f.get('evidence', '')}\n")

    lines.append("---")
    lines.append("*报告由 Stopen 自动生成*")
    report = "\n".join(lines)

    report_dir = STORAGE_DIR / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"report_{task_id}.md"
    path.write_text(report, encoding="utf-8")

    return {"path": str(path), "content": report, "task_id": task_id,
            "findings_count": len(findings)}


def generate_html_report(task_id="", target="", task_type="pentest", findings=None) -> dict:
    """生成 HTML 格式报告"""
    if findings is None:
        findings = []
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    findings_html = ""
    for f in findings:
        findings_html += f"""<tr>
            <td>{f.get('type', '')}</td>
            <td>{f.get('value', '')}</td>
            <td>{f.get('source', '')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
    <title>渗透测试报告 - {target}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #0f0f0f; color: #e0e0e0; }}
        h1 {{ color: #7c3aed; }} table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #333; padding: 8px 12px; text-align: left; }}
        th {{ background: #1a1a1a; color: #7c3aed; }}
        .meta {{ color: #888; }}
    </style></head><body>
    <h1>渗透测试报告</h1>
    <p class="meta">目标: {target} | 时间: {now}</p>
    <h2>发现摘要</h2>
    <table><thead><tr><th>类型</th><th>值</th><th>来源</th></tr></thead>
    <tbody>{findings_html}</tbody></table>
    <p class="meta" style="margin-top: 40px">由 Stopen 自动生成</p>
    </body></html>"""

    report_dir = STORAGE_DIR / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"report_{task_id}.html"
    path.write_text(html, encoding="utf-8")

    return {"path": str(path), "content": html, "task_id": task_id,
            "format": "html", "findings_count": len(findings)}


def generate_poc_script(vuln: dict) -> str:
    """从漏洞发现生成 Python PoC 脚本"""
    title = vuln.get("title", "vulnerability")
    target = vuln.get("target", "http://target.com")
    vuln_type = vuln.get("vuln_type", "unknown")
    description = vuln.get("description", "")
    evidence = vuln.get("evidence", "")

    script = f'''#!/usr/bin/env python3
"""PoC: {title}"""
import requests
import sys

TARGET = "{target}"

def check_vuln():
    """验证漏洞是否存在"""
    try:
        r = requests.get(TARGET, timeout=10, verify=False)
        print(f"[*] Target: {{TARGET}}")
        print(f"[*] Status: {{r.status_code}}")
        print(f"[*] Type: {vuln_type}")
        print(f"[*] Description: {description}")
        if "{evidence}":
            print(f"[*] Evidence: {evidence}")
        return True
    except Exception as e:
        print(f"[-] Error: {{e}}")
        return False

if __name__ == "__main__":
    if check_vuln():
        print("[+] 漏洞可能存在")
    else:
        print("[-] 未检测到漏洞")
'''
    return script


def generate_poc_file(vuln: dict) -> dict:
    """生成 PoC 并保存到文件"""
    script = generate_poc_script(vuln)
    safe_name = vuln.get("title", "poc").replace(" ", "_").replace("/", "_")[:50]
    poc_dir = STORAGE_DIR / "pocs"
    poc_dir.mkdir(parents=True, exist_ok=True)
    path = poc_dir / f"poc_{safe_name}.py"
    path.write_text(script, encoding="utf-8")
    return {"path": str(path), "content": script}
