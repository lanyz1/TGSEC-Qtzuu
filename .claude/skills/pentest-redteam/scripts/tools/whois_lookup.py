#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WHOIS 查询（纯 socket，端口 43，Windows 无需外部 whois 命令）
单域名看注册信息；批量文件筛近 N 天新注册域（黑产/钓鱼拓线常用）。
用法:
  python whois_lookup.py example.com                 # 单域名摘要
  python whois_lookup.py example.com --raw            # 打印完整记录
  python whois_lookup.py -f domains.txt --days 60     # 批量筛新注册
流程: whois.iana.org 查 TLD referral → 注册局/注册商 whois → 抽 creation date。
纯 socket 实现，去除对系统 whois 二进制的依赖，Windows 免安装。仅授权使用。
"""
import argparse, datetime, re, socket, sys
from concurrent.futures import ThreadPoolExecutor

IANA = "whois.iana.org"
CREATE_PATS = [
    r"(?i)creation date:\s*([0-9T:\-\.Zz/ ]+)",
    r"(?i)created(?:\s*on)?:\s*([0-9T:\-\.Zz/ ]+)",
    r"(?i)registration time:\s*([0-9T:\-\.Zz/ ]+)",
    r"(?i)registered(?:\s*on)?:\s*([0-9T:\-\.Zz/ ]+)",
    r"(?i)registered:\s*([0-9T:\-\.Zz/ ]+)",
]


def whois_query(server, query, timeout=25):
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 1_000_000:
                    break
        return buf.decode("utf-8", "ignore")
    except Exception as e:
        return f"__ERROR__ {e}"


def whois_full(domain, timeout=25):
    """两跳 WHOIS：IANA referral → 具体 whois 服务器。返回完整文本。"""
    root = whois_query(IANA, domain, timeout)
    if root.startswith("__ERROR__"):
        return root
    m = re.search(r"(?im)^refer:\s*(\S+)", root)
    if not m:
        return root
    ref = whois_query(m.group(1), domain, timeout)
    return ref if not ref.startswith("__ERROR__") else root


def extract_creation(text):
    for pat in CREATE_PATS:
        m = re.search(pat, text)
        if m:
            return m.group(1).strip()
    return None


def parse_date(s):
    if not s:
        return None
    try:
        return datetime.date.fromisoformat(s[:10].replace("/", "-"))
    except ValueError:
        return None


def read_domains(path):
    doms = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            for p in re.split(r"[|,\s]+", line.strip()):
                p = p.strip().lower().lstrip("*.")
                if re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", p):
                    doms.add(p)
    return sorted(doms)


def main():
    ap = argparse.ArgumentParser(description="WHOIS 查询 / 新注册域筛选（纯 socket）")
    ap.add_argument("domain", nargs="?", help="单个域名")
    ap.add_argument("-f", "--file", help="域名列表文件（批量模式）")
    ap.add_argument("--days", type=int, default=60, help="批量模式：近 N 天新注册（默认 60）")
    ap.add_argument("--workers", type=int, default=10, help="批量并发（默认 10）")
    ap.add_argument("--timeout", type=int, default=25, help="单查询超时秒（默认 25）")
    ap.add_argument("--raw", action="store_true", help="单域名模式打印完整记录")
    args = ap.parse_args()

    if args.file:
        doms = read_domains(args.file)
        cutoff = datetime.date.today() - datetime.timedelta(days=args.days)
        print(f"待查 {len(doms)} 域名 (并发 {args.workers})...", file=sys.stderr)

        def work(d):
            return d, extract_creation(whois_full(d, args.timeout))

        rows = []
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            for d, created in ex.map(work, doms):
                dt = parse_date(created)
                if dt and dt >= cutoff:
                    rows.append((created, d))
        for created, d in sorted(rows):
            print(f"{created}\t{d}")
        print(f"# {len(rows)}/{len(doms)} 个近 {args.days} 天新注册", file=sys.stderr)
        return

    if not args.domain:
        ap.error("需提供单个域名，或用 -f 指定列表文件")
    text = whois_full(args.domain, args.timeout)
    if text.startswith("__ERROR__"):
        print(text)
        sys.exit(1)
    if args.raw:
        print(text)
    else:
        created = extract_creation(text)
        reg = re.search(r"(?im)^registrar:\s*(.+)$", text)
        ns = re.findall(r"(?im)^name server:\s*(\S+)", text)
        print(f"域名:     {args.domain}")
        print(f"注册时间: {created or '未解析'}")
        print(f"注册商:   {reg.group(1).strip() if reg else '未解析'}")
        if ns:
            print(f"NS:       {', '.join(sorted(set(n.lower() for n in ns)))}")


if __name__ == "__main__":
    main()
