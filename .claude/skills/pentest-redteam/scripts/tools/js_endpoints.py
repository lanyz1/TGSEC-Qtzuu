#!/usr/bin/env python3
"""JS 端点 URL/API 提取: 从 JS 文件中正则提取 API 路由和端点
用法: python js_endpoints.py -f app.js -o api.txt"""
import argparse, re, sys, urllib.request, urllib.error, ssl

PATTERNS = [
    r'(?:"|\')(/[a-zA-Z0-9_-]+)+/\w*(?:"|\')',  # /api/xxx/yyy
    r'(?:"|\')(/api/[^"\'\s]+)(?:"|\')',         # /api/...
    r'(?:fetch\(|axios\(|\.get\(|\.post\()\s*["\']([^"\']+)["\']',
    r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    r'(?:url|URL|uri|URI|path|endpoint)\s*[:=]\s*["\']([^"\']+)["\']',
    r'https?://[^"\'\s<>]+',
]

def extract(text):
    found = set()
    for pat in PATTERNS:
        for m in re.finditer(pat, text):
            val = m.group(1).strip()
            if val and len(val) > 2 and not val.startswith("http") and val[0] == "/":
                found.add(val)
    return sorted(found)

def main():
    ap = argparse.ArgumentParser(description="JS 端点 URL/API 提取")
    ap.add_argument("-f","--file",help="JS 文件路径")
    ap.add_argument("-u","--url",help="JS 文件 URL")
    ap.add_argument("-o","--output",default="endpoints.txt")
    args = ap.parse_args()
    if args.url:
        ctx = ssl.create_default_context()
        ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        req = urllib.request.Request(args.url,headers={"User-Agent":"Mozilla/5.0"})
        text = urllib.request.urlopen(req,context=ctx).read().decode("utf-8","ignore")
    elif args.file:
        with open(args.file,encoding="utf-8",errors="ignore") as f:
            text = f.read()
    else:
        ap.print_help(); sys.exit(1)
    eps = extract(text)
    with open(args.output,"w") as f:
        for e in eps: f.write(e+"\n")
    print(f"[+] {len(eps)} 个端点 -> {args.output}")
    for e in eps[:30]: print(f"    {e}")
if __name__ == "__main__": main()
