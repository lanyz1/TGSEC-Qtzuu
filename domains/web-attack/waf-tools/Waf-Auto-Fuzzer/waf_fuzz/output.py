"""结果输出与持久化模块。"""

import csv
import json
import os


def save_json(results, path):
    """保存结果为 JSON。"""
    data = [r.to_dict() for r in results]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path


def save_csv(results, path):
    """保存结果为 CSV。"""
    if not results:
        return path
    fields = ["category", "payload", "encoding", "sent_value",
              "blocked", "reason", "status_code", "response_size", "elapsed"]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            d = r.to_dict()
            d["sent_value"] = d["sent_value"][:200]
            w.writerow(d)
    return path


def save_bypass_report(bypass_results, path):
    """保存绕过摘要报告。"""
    if not bypass_results:
        with open(path, "w", encoding="utf-8") as f:
            f.write("未发现绕过方式。\n")
        return path

    with open(path, "w", encoding="utf-8") as f:
        f.write("=== WAF 绕过报告 ===\n\n")
        # Group by category
        cats = {}
        for r in bypass_results:
            cats.setdefault(r.category, []).append(r)

        for cat in sorted(cats):
            items = cats[cat]
            f.write(f"\n## [{cat}] {len(items)} 种绕过\n")
            f.write(f"{'编码方式':20s} {'状态码':8s} {'Payload'}\n")
            f.write("-" * 80 + "\n")
            for r in items:
                pw = r.payload[:40]
                f.write(f"{r.encoding:20s} {r.status_code:<8d} {pw}\n")
    return path


def write_html_report(results, bypass_list, path, duration, waf_names):
    """生成 HTML 报告。"""
    total = len(results)
    bypassed = len(bypass_list)
    blocked = total - bypassed

    # Group by category
    cats = {}
    for r in results:
        cats.setdefault(r.category, {"total": 0, "bypass": 0})
        cats[r.category]["total"] += 1
        if r.is_bypass():
            cats[r.category]["bypass"] += 1

    rows = ""
    for cat, v in sorted(cats.items()):
        bar = "█" * int(v["bypass"] / max(v["total"], 1) * 30)
        rows += f"<tr><td>{cat}</td><td>{v['total']}</td><td>{v['bypass']}</td><td>{bar}</td></tr>\n"

    bypass_rows = ""
    for r in bypass_list[:50]:  # top 50
        bypass_rows += (
            f"<tr><td>{r.category}</td><td>{r.encoding}</td>"
            f"<td>{r.status_code}</td><td>{r.payload[:50]}</td></tr>\n"
        )

    waf_line = ", ".join(f"{n}({c*100:.0f}%)" for n, c in waf_names[:3]) if waf_names else "未知"

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>WAF 绕过测试报告</title>
<style>
body {{ font-family: sans-serif; margin: 20px; background: #f5f5f5; }}
.card {{ background: #fff; border-radius: 8px; padding: 20px; margin: 16px 0; box-shadow: 0 2px 4px rgba(0,0,0,.1); }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #4a90d9; color: #fff; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 12px; }}
.badge-ok {{ background: #27ae60; }} .badge-block {{ background: #e74c3c; }}
</style>
</head>
<body>
<h1>WAF 绕过测试报告</h1>
<div class="card">
<p><strong>测试总览:</strong> {total} 次请求 | {bypassed} 绕过 | {blocked} 拦截 | 耗时 {duration:.0f}s</p>
<p><strong>WAF 识别:</strong> {waf_line}</p>
</div>
<div class="card"><h2>分类统计</h2>
<table><tr><th>分类</th><th>总数</th><th>绕过</th><th>比例</th></tr>
{rows}</table></div>
<div class="card"><h2>Top 50 绕过 Payload</h2>
<table><tr><th>分类</th><th>编码</th><th>状态码</th><th>Payload</th></tr>
{bypass_rows}</table></div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
