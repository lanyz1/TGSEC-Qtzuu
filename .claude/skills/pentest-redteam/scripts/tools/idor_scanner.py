#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDOR 扫描器: 从请求文件批量替换 ID 参数, 对比响应差异找越权
用法:
  python idor_scanner.py -r request.txt --param id --start 1 --end 200
  python idor_scanner.py -r request.txt --param user_id --dict ids.txt
"""
import argparse, re, ssl, sys, urllib.request, urllib.error, concurrent.futures

def parse_request(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        raw = f.read()
    parts = raw.split("\n\n", 1)
    header = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = header.split("\n")
    fl = lines[0]
    method, path_url, _ = (fl.split(" ", 2) + ["", ""])[:3]
    url = path_url if path_url.startswith("http") else None
    host = ""
    hdrs = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if k.lower() == "host":
                hdrs["Host"] = v
                host = v
            elif k.lower() not in ("content-length",):
                hdrs[k] = v
    if not url:
        proto = "https" if "443" in str(hdrs.get("Host","")) else "http"
        url = f"{proto}://{host}{path_url}"
    return method.strip(), url.strip(), dict(hdrs), body

def send(method, url, headers, body, param, value, timeout=8):
    url2 = re.sub(rf"{param}=[^&\s#]*", f"{param}={value}", url)
    body2 = re.sub(rf"{param}=[^&\s#]*", f"{param}={value}", body)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = body2.encode() if body2 else None
    req = urllib.request.Request(url2, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            resp = r.read()
            return value, r.status, len(resp), resp[:200]
    except urllib.error.HTTPError as e:
        resp = e.read()
        return value, e.code, len(resp), resp[:200]
    except Exception as e:
        return value, None, 0, b""

def main():
    ap = argparse.ArgumentParser(description="IDOR 扫描器(从 Burp 请求文件批量替换 ID)")
    ap.add_argument("-r", "--request", required=True, help="Burp 导出的请求文件")
    ap.add_argument("--param", required=True, help="要替换的 ID 参数名")
    ap.add_argument("--start", type=int, default=1, help="起始 ID")
    ap.add_argument("--end", type=int, default=100, help="结束 ID")
    ap.add_argument("--dict", help="ID 字典文件(每行一个值,可选)")
    ap.add_argument("-t", "--threads", type=int, default=15)
    args = ap.parse_args()

    method, url, headers, body = parse_request(args.request)
    print(f"[*] 请求: {method} {url}")
    print(f"[*] 参数: {args.param}")

    if args.dict:
        with open(args.dict, encoding="utf-8") as f:
            values = [l.strip() for l in f if l.strip()]
    else:
        values = list(range(args.start, args.end + 1))

    # 基线请求
    bv, bc, bl, bb = send(method, url, headers, body, args.param, values[0])
    print(f"[*] 基线: ID={bv} -> {bc} ({bl}B)")

    print(f"[*] 扫描 {len(values)} 个 ID...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(send, method, url, headers, body, args.param, v): v for v in values}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda x: x[0])
    findings = []
    for v, code, sz, frag in results:
        if code is None:
            continue
        a_flag = ""
        if code != bc:
            a_flag += " [状态码差异]"
        if abs(sz - bl) > 200 and code == bc:
            a_flag += " [长度差异]"
        if a_flag:
            findings.append((v, code, sz, a_flag, frag.decode("utf-8","ignore")[:60] if frag else ""))

    if findings:
        print(f"\n[+] 异常响应 {len(findings)} 个:")
        for v, code, sz, flag, frag in findings[:50]:
            print(f"    ID={v:<10} {code} {sz:>6}B {flag}  {frag}")
    else:
        print("\n[-] 未发现异常响应")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
