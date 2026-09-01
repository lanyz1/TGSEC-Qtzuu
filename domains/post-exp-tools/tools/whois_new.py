#!/usr/bin/env python3
"""whois_new.py — 批量查域名注册时间，筛近 N 天新注册
用法: whois_new.py <域名文件> <天数:默认60> [并发:默认12]
输出: 新域名列表 (tab: 注册时间 域名)"""
import re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

def get_creation(domain):
    try:
        r = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=25)
        out = r.stdout
        for pat in [r'(?i)creation date:\s*([\d-]+)', r'(?i)created(?:-on)?:\s*([\d-]+)',
                    r'(?i)registration time:\s*([\d-]+)', r'(?i)registered(?:-on)?:\s*([\d-]+)']:
            m = re.search(pat, out)
            if m:
                return domain, m.group(1)
    except Exception:
        pass
    return domain, None

def main():
    infile = sys.argv[1]
    days = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    domains = set()
    for line in open(infile):
        parts = line.strip().split('|')
        for p in parts:
            p = p.strip()
            if re.match(r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$', p) and '.' in p:
                domains.add(p.lower())
    domains = list(domains)
    print(f'待查 {len(domains)} 个域名 (并发{workers})...', file=sys.stderr)
    import datetime
    cutoff = datetime.date.today() - datetime.timedelta(days=days)
    new_domains = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for domain, created in ex.map(get_creation, domains):
            if created:
                try:
                    d = datetime.date.fromisoformat(created[:10])
                    if d >= cutoff:
                        new_domains.append((created, domain))
                except ValueError:
                    pass
    for created, domain in sorted(new_domains):
        print(f'{created}\t{domain}')

if __name__ == '__main__':
    main()
