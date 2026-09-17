#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""子域枚举: crt.sh 证书透明日志 + 字典爆破 + DNS 解析验证
用法:
  python subdomain_enum.py -d example.com
  python subdomain_enum.py -d example.com -w subdomains.txt --threads 30
"""
import argparse
import concurrent.futures
import json
import socket
import ssl
import sys
import urllib.request

DEFAULT_WORDLIST = [
    "www", "mail", "webmail", "admin", "api", "app", "dev", "test", "staging",
    "vpn", "remote", "portal", "cms", "blog", "shop", "store", "ftp", "smtp",
    "pop", "imap", "mx", "ns1", "ns2", "dns", "git", "jenkins", "ci", "cd",
    "docker", "k8s", "kubernetes", "grafana", "prometheus", "monitor", "status",
    "jira", "confluence", "wiki", "docs", "help", "support", "ticket", "billing",
    "pay", "payment", "gateway", "m", "mobile", "old", "new", "beta", "demo",
    "auth", "login", "sso", "oauth", "ws", "websocket", "stream", "cdn", "static",
    "assets", "img", "media", "upload", "download", "file", "files", "backup",
]

def fetch_ct(domain):
    """crt.sh 证书透明日志"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    subs = set()
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith("." + domain):
                    subs.add(name)
    except Exception:
        pass
    return subs

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser(description="子域枚举: CT日志 + 字典 + 解析验证")
    ap.add_argument("-d", "--domain", required=True, help="目标域名")
    ap.add_argument("-w", "--wordlist", help="字典文件(每行一个前缀)")
    ap.add_argument("-t", "--threads", type=int, default=20, help="并发数")
    args = ap.parse_args()

    domain = args.domain.lower().strip()
    print(f"[*] 目标: {domain}")

    candidates = set()
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if w and not w.startswith("#"):
                    candidates.add(f"{w}.{domain}")
    else:
        for w in DEFAULT_WORDLIST:
            candidates.add(f"{w}.{domain}")

    print(f"[*] CT 日志收集...")
    ct = fetch_ct(domain)
    print(f"[+] crt.sh 发现 {len(ct)} 个子域")
    candidates |= ct

    print(f"[*] 解析验证 {len(candidates)} 个候选...")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        results = {ex.submit(resolve, h): h for h in candidates}
        for fut in concurrent.futures.as_completed(results):
            h = results[fut]
            ip = fut.result()
            if ip:
                found.append((h, ip))

    found.sort()
    print(f"\n[+] 存活子域 {len(found)} 个:")
    for h, ip in found:
        print(f"    {h:<45} {ip}")
    if found:
        with open(f"subdomains_{domain}.txt", "w", encoding="utf-8") as f:
            for h, ip in found:
                f.write(f"{h}\n")
        print(f"[+] 已保存 subdomains_{domain}.txt")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
