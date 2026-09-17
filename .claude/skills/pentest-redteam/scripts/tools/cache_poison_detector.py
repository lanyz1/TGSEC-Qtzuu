#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web 缓存投毒探测：测试常见未键控(unkeyed)请求头是否可污染缓存
原理：注入带唯一 marker 的头 → 看是否回显 → 不带头重放 → marker 仍在=缓存命中(可投毒)
用法:
  python cache_poison_detector.py -u https://target.com/page
  python cache_poison_detector.py -u https://target.com/ --headers custom.txt --timeout 10
纯标准库 Python 单文件实现（注入 marker → 重放验缓存命中）。仅用于明确授权目标。
"""
import argparse, os, secrets, ssl, sys, time, urllib.request, urllib.error

# (头名, payload, 风险)——未键控头污染缓存的高频面
DEFAULT_HEADERS = [
    ("X-Forwarded-Host", "evil.example", "XSS via script src / 绝对 URL 注入"),
    ("X-Forwarded-Host", 'evil.example"><cpmark>', "反射型注入点"),
    ("X-Forwarded-Scheme", "http", "混合内容 / 重定向注入"),
    ("X-Forwarded-For", "127.0.0.1", "IP 伪造"),
    ("X-Original-URL", "/admin", "路径覆盖"),
    ("X-Rewrite-URL", "/admin", "路径覆盖"),
    ("X-HTTP-Method-Override", "PUT", "方法覆盖"),
    ("Origin", "https://evil.example", "CORS 误配"),
    ("X-Host", "evil.example", "Host 覆盖"),
    ("Forwarded", "for=evil.example;host=evil.example", "Forwarded 头"),
    ("X-Forwarded-Port", "8443", "端口覆盖"),
    ("True-Client-IP", "127.0.0.1", "IP 伪造"),
    ("X-Real-IP", "127.0.0.1", "IP 伪造"),
    ("X-Client-IP", "127.0.0.1", "IP 伪造"),
]
CACHE_HINT_HEADERS = ["X-Cache", "CF-Cache-Status", "Age", "Via", "X-Served-By", "X-CDN", "X-Cache-Hits"]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _fetch(url, header=None, value=None, method="GET", timeout=10):
    """返回 (status, headers_lower, body). 失败返回 (None, '', '')."""
    hdrs = {"User-Agent": UA}
    if header:
        hdrs[header] = value
    req = urllib.request.Request(url, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            body = "" if method == "HEAD" else r.read().decode("utf-8", "ignore")
            return r.status, {k.lower(): v for k, v in r.headers.items()}, body
    except urllib.error.HTTPError as e:
        body = "" if method == "HEAD" else e.read().decode("utf-8", "ignore")
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
    except Exception:
        return None, {}, ""


def detect_cache(url, timeout):
    st, hdrs, _ = _fetch(url, method="HEAD", timeout=timeout)
    if st is None:
        return None, []
    hints = [f"{h}: {hdrs[h.lower()]}" for h in CACHE_HINT_HEADERS if h.lower() in hdrs]
    return st, hints


def probe(url, header, payload, timeout):
    """返回 (reflected, cached)."""
    marker = "CPMARK" + secrets.token_hex(5)
    st, hdrs, body = _fetch(url, header, payload + marker, timeout=timeout)
    if st is None:
        return False, False
    reflected = marker in body or any(marker in v for v in hdrs.values())
    # 无任何缓存迹象则不把回显算作可投毒信号（降误报）
    has_cache_hint = any(h.lower() in hdrs for h in CACHE_HINT_HEADERS)
    if reflected and not has_cache_hint:
        reflected = False
    if not reflected:
        return False, False
    # 第二阶段：不带头重放，marker 仍在 = 被缓存（未键控）
    time.sleep(0.5)
    _, _, body2 = _fetch(url, timeout=timeout)
    return True, (marker in body2)


def load_headers(path):
    hs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hs.append((line, "cpval", "自定义头"))
    return hs


def main():
    ap = argparse.ArgumentParser(description="Web 缓存投毒探测（未键控头 → 缓存污染）")
    ap.add_argument("-u", "--url", required=True, help="目标 URL（含路径）")
    ap.add_argument("--headers", help="自定义头列表文件（每行一个头名）")
    ap.add_argument("--timeout", type=int, default=10, help="请求超时秒数（默认 10）")
    args = ap.parse_args()

    print(f"[*] 目标: {args.url}")
    st, hints = detect_cache(args.url, args.timeout)
    if st is None:
        print("[!] 无法连接目标")
        sys.exit(1)
    if hints:
        print(f"[+] 检测到缓存层: {', '.join(hints)}")
    else:
        print("[-] 未见明显缓存头（仍可能存在缓存）")

    headers = load_headers(args.headers) if args.headers else DEFAULT_HEADERS
    print(f"[*] 探测 {len(headers)} 个头...\n")
    crit = 0
    for name, payload, risk in headers:
        reflected, cached = probe(args.url, name, payload, args.timeout)
        if reflected and cached:
            crit += 1
            print(f"[CRITICAL] {name}  可缓存投毒（头未键控）")
            print(f"           payload={payload!r}  风险={risk}\n")
        elif reflected:
            print(f"[REFLECTED] {name}（回显但未确认缓存——可能已键控）")
    print(f"\n[✓] 完成，CRITICAL={crit}。命中需回证据链：观察(回显)→复现(重放缓存命中)→影响。")


if __name__ == "__main__":
    main()
