#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S3 存储桶枚举: 从关键词生成桶名并探测公开读写权限
用法:
  python s3_bucket_enum.py -k companyname -o buckets.txt
  python s3_bucket_enum.py -f keywords.txt --check
"""
import argparse, re, ssl, sys, urllib.request, urllib.error

PREFIXES = ["", "www.", "cdn.", "assets.", "static.", "media.", "uploads.", "backup.", "logs."]
SUFFIXES = ["", "-dev", "-test", "-staging", "-prod", "-backup", "-images", "-data", "-files"]

def gen_names(keywords):
    names = set()
    for kw in keywords:
        kw = kw.lower().strip()
        for p in PREFIXES:
            for s in SUFFIXES:
                names.add(f"{p}{kw}{s}")
    return sorted(names)

def check_bucket(name, timeout=6):
    url = f"https://{name}.s3.amazonaws.com"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", "ignore")
            return r.status, body[:500]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        return e.code, body[:500]
    except Exception:
        return None, ""

def main():
    ap = argparse.ArgumentParser(description="S3 存储桶枚举")
    ap.add_argument("-k", "--keyword", help="关键词,如 companyname")
    ap.add_argument("-f", "--file", help="关键词文件(每行一个)")
    ap.add_argument("-o", "--output", default="s3_buckets.txt", help="输出文件")
    ap.add_argument("--check", action="store_true", help="探测桶是否可访问")
    args = ap.parse_args()
    if not args.keyword and not args.file:
        ap.print_help(); sys.exit(1)

    keywords = []
    if args.keyword:
        keywords = [args.keyword]
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            keywords.extend(l.strip() for l in f if l.strip())

    names = gen_names(keywords)
    print(f"[*] 生成 {len(names)} 个桶名")

    with open(args.output, "w", encoding="utf-8") as f:
        for n in names:
            f.write(n + "\n")

    if args.check:
        print(f"\n[*] 探测可访问性...")
        for n in names:
            code, body = check_bucket(n)
            if code == 200:
                print(f"  [!] 公开: {n} -> {code}")
            elif code == 403:
                print(f"  [*] 拒绝: {n} -> 403")
    else:
        print(f"[+] 已保存 {args.output}, 用 --check 探测")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
