#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web 目录爆破: 多线程字典扫描 + 状态码/大小过滤
用法:
  python dir_brute.py -u http://target.com -w dirs.txt
  python dir_brute.py -u https://target.com/base/ -e php,html,bak -t 30
"""
import argparse
import concurrent.futures
import sys
import urllib.error
import urllib.request
import ssl

EXTENSIONS = ["php", "html", "htm", "txt", "bak", "old", "zip", "tar.gz", "json", "xml", "sql", "conf", "log"]

def fetch(url, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(4096)
            return r.status, len(body), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096)
        except Exception:
            body = b""
        return e.code, len(body), dict(e.headers)
    except Exception:
        return None, 0, {}

def main():
    ap = argparse.ArgumentParser(description="Web 目录爆破")
    ap.add_argument("-u", "--url", required=True, help="目标 URL,如 http://target.com")
    ap.add_argument("-w", "--wordlist", required=True, help="字典文件(每行一个路径)")
    ap.add_argument("-e", "--extensions", help=f"附加扩展名,逗号分隔 (默认: {','.join(EXTENSIONS[:5])}...)")
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("--ignore", default="404", help="忽略的状态码,逗号分隔")
    ap.add_argument("--min-size", type=int, default=0, help="过滤响应体小于该值的结果")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    if args.extensions:
        exts = [e.strip().lstrip(".") for e in args.extensions.split(",") if e.strip()]
    else:
        exts = EXTENSIONS
    ignore = {int(x) for x in args.ignore.split(",") if x.strip().isdigit()}

    with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
        words = [w.strip() for w in f if w.strip() and not w.startswith("#")]

    targets = []
    for w in words:
        targets.append(f"{base}/{w}")
        for e in exts:
            if "." not in w:
                targets.append(f"{base}/{w}.{e}")

    print(f"[*] 目标 {base} | {len(targets)} 个请求 | 线程 {args.threads}")

    def worker(u):
        code, size, hdrs = fetch(u)
        if code in ignore or code is None:
            return None
        if size < args.min_size:
            return None
        ctype = (hdrs.get("Content-Type", "") if hdrs else "")[:40]
        return u, code, size, ctype

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for res in ex.map(worker, targets):
            if res:
                found.append(res)

    found.sort(key=lambda x: (x[1], -x[2]))
    print(f"\n[+] 发现 {len(found)} 个可访问路径:")
    for u, code, size, ctype in found:
        print(f"    [{code}] {size:>7}B  {u:<70} {ctype}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
