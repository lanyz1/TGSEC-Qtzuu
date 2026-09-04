# -*- coding: utf-8 -*-
"""按 URL 提取关联上下文：从 pages / js / business-chains 清单抽取与指定 URL 关联的整条记录，
写入 url-context/{URLID}.json，供漏洞挖掘子代理快速聚焦分析（无需通读全部清单）。

关联判定（规范化 URL 比对：去 query / fragment / 尾斜杠）：
- 页面：页面自身 url == 目标 url，或目标 url 出现在其 discovered_urls；
- JS：目标 url 出现在其 discovered_urls；
- 业务链：目标 url 在其 related_urls。

同时给出该 URL 的代理参数详情与原始请求报文文件路径指针（params_file / requests_log）。

用法：
    python extract_url_context.py --project <id> --url-id URL00010 [URL00011 ...]
"""

import argparse
import os
import sys
from urllib.parse import urlsplit, urlunsplit

import common as c


def norm_url(u):
    """规范化：去 query / fragment、去尾斜杠，便于跨清单比对（与 check_breadth 一致）。"""
    try:
        s = urlsplit(u)
        return urlunsplit((s.scheme, s.netloc, s.path, "", "")).rstrip("/")
    except Exception:
        return (u or "").rstrip("/")


def url_of(url_id, inv_urls, idx, failed):
    """返回 (url 字符串, 记录 dict 或 None)。
    依次在 url-inventory / 代理成功清单 / 代理失败清单(补测来源) 中查找；
    三者的 category/methods/param_names 字段同名，供下游统一取用（含补测/失败 URL）。"""
    for u in inv_urls:
        if u.get("id") == url_id:
            return u.get("url", ""), u
    for r in idx:
        if r.get("id") == url_id:
            return r.get("url", ""), r
    for r in failed:
        if r.get("id") == url_id:
            return r.get("url", ""), r
    return "", None


def main():
    p = argparse.ArgumentParser(description="按 URL 提取关联上下文")
    p.add_argument("--project", required=True)
    p.add_argument("--url-id", required=True, nargs="+", help="一个或多个 URL id")
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    inv_urls = c.load_json(paths["inventory"], default={"urls": []}).get("urls", [])
    idx = c.load_jsonl(paths["url_index"])
    failed = c.load_jsonl(paths["failed_index"])  # 补测/失败 URL 也能生成上下文
    pages = c.load_jsonl(paths["pages"])
    jss = c.load_jsonl(paths["js"])
    chains = c.load_jsonl(paths["chains"])

    os.makedirs(paths["url_context_dir"], exist_ok=True)

    for uid in args.url_id:
        target, rec = url_of(uid, inv_urls, idx, failed)
        if not target:
            print("[警告] 未找到 URL id：%s（跳过）" % uid)
            continue
        t = norm_url(target)

        related_pages = [pg for pg in pages
                         if norm_url(pg.get("url", "")) == t
                         or any(norm_url(d.get("url", "")) == t for d in pg.get("discovered_urls", []))]
        related_js = [j for j in jss
                      if any(norm_url(d.get("url", "")) == t for d in j.get("discovered_urls", []))]
        related_chains = [ch for ch in chains
                          if any(norm_url(x) == t for x in ch.get("related_urls", []))]

        out = {
            "url_id": uid,
            "url": target,
            "category": rec.get("category", "") if rec else "",
            "methods": rec.get("methods", []) if rec else [],
            "param_names": rec.get("param_names", []) if rec else [],
            "params_file": ("proxy-logs/params/%s.json" % uid),
            "requests_log": ("proxy-logs/requests/%s.log" % uid),
            "related_pages": related_pages,
            "related_js": related_js,
            "related_chains": related_chains,
            "generated": c.now_iso(),
        }
        out_path = os.path.join(paths["url_context_dir"], "%s.json" % uid)
        c.atomic_write_json(out_path, out)
        print("[完成] %s → %s（页面 %d / JS %d / 业务链 %d）"
              % (uid, out_path, len(related_pages), len(related_js), len(related_chains)))


if __name__ == "__main__":
    main()
