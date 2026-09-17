#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""URL 钓鱼检测: 同形字/IDN 伪装域名分析 + 短链展开
用法:
  python url_phish_check.py -u "https://g00gle.com/login"
  python url_phish_check.py -f urls.txt
"""
import argparse, re, ssl, sys, urllib.request

HOMOGLYPHS = {
    '0': 'O', '1': 'l', '2': 'Z', '5': 'S', '6': 'G', '8': 'B',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'і': 'i', 'х': 'x', 'К': 'K', 'М': 'M', 'Т': 'T',
}

BRANDS = ["google", "facebook", "microsoft", "apple", "amazon", "paypal", "netflix",
          "instagram", "twitter", "linkedin", "dropbox", "github", "steam", "spotify",
          "adobe", "alibaba", "taobao", "wechat", "qq", "baidu", "yandex", "sberbank"]

def expand_short(url):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            return r.geturl()
    except Exception as e:
        return url

def detect_phish(url):
    flags = []
    from urllib.parse import urlparse
    try:
        p = urlparse(url)
    except Exception:
        return ["无法解析"]
    host = p.hostname or ""
    path = p.path or ""

    # IP 地址
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
        flags.append(f"IP 地址 ({host})")

    # 端口
    if p.port and p.port not in (80, 443):
        flags.append(f"非标准端口 ({p.port})")

    # 同形字分析
    domain = host.replace("[.]", ".")
    for c in domain:
        if c in HOMOGLYPHS:
            flags.append(f"同形字: '{c}'→'{HOMOGLYPHS[c]}'")
            break

    # 品牌仿冒
    for brand in BRANDS:
        if brand in domain.lower():
            # 排除正牌
            if domain.endswith(f".{brand}.com") or domain == f"{brand}.com" or domain == f"www.{brand}.com":
                break
            flags.append(f"品牌仿冒: '{brand}' 非官方域名")

    # 过长域名
    if len(host) > 50:
        flags.append("过长域名")

    # 证书式链接
    if path and any(x in path.lower() for x in ("login", "signin", "verify", "account", "password", "reset")):
        flags.append("登录页路径")

    return flags

def main():
    ap = argparse.ArgumentParser(description="URL 钓鱼检测(同形字/品牌仿冒/短链展开)")
    ap.add_argument("-u", "--url", help="单 URL")
    ap.add_argument("-f", "--file", help="URL 列表文件")
    ap.add_argument("--expand", action="store_true", help="展开短链接")
    args = ap.parse_args()
    if not args.url and not args.file:
        ap.print_help(); sys.exit(1)

    urls = [args.url] if args.url else []
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            urls.extend(l.strip() for l in f if l.strip())

    for url in urls:
        if args.expand and len(url) < 30:
            url2 = expand_short(url)
            if url2 != url:
                print(f"[*] {url} -> {url2}")
                url = url2
        flags = detect_phish(url)
        if flags:
            print(f"[!] {url}")
            for f in flags:
                print(f"    {f}")
        else:
            print(f"[-] {url} (未检测到异常)")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
