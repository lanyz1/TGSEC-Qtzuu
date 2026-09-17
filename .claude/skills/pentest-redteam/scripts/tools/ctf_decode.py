#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTF 编码解码工具箱: base64/hex/rot/url/morse/xor
用法:
  python ctf_decode.py -t "dGVzdA=="
  python ctf_decode.py -t "68656c6c6f" --hex
  python ctf_decode.py -t "uryyb" --rot 13
"""
import argparse, base64, binascii, sys, urllib.parse

def decode_all(s):
    results = []
    # Base64
    for fmt in [(base64.b64decode, "base64"), (base64.b32decode, "base32"),
                (base64.b16decode, "base16")]:
        try:
            pad = s + "=" * ((4 - len(s) % 4) % 4)
            r = fmt[0](pad)
            results.append((fmt[1], r.decode("utf-8","ignore")))
        except Exception:
            pass
    # Hex
    try:
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
            r = bytes.fromhex(s)
            results.append(("hex", r.decode("utf-8","ignore")))
    except Exception:
        pass
    # URL
    results.append(("urldecode", urllib.parse.unquote(s)))
    # ROT 1-25
    for n in range(1, 26):
        decoded = rot_decode(s, n)
        if is_english_like(decoded):
            results.append((f"ROT{n}", decoded))
            break
    return results

def rot_decode(s, n):
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

def is_english_like(s):
    return sum(1 for c in s if c.isalpha()) > len(s) * 0.6

def main():
    ap = argparse.ArgumentParser(description="CTF 编码解码工具箱")
    ap.add_argument("-t", "--text", required=True, help="待解码文本")
    ap.add_argument("--hex", action="store_true", help="仅 hex")
    ap.add_argument("--b64", action="store_true", help="仅 base64")
    ap.add_argument("--rot", type=int, help="仅 ROT N")
    ap.add_argument("--url", action="store_true", help="仅 URL decode")
    args = ap.parse_args()

    s = args.text.strip()
    if args.hex:
        print(f"hex解码: {bytes.fromhex(s).decode('utf-8','ignore')}")
    elif args.b64:
        print(f"b64解码: {base64.b64decode(s+'===').decode('utf-8','ignore')}")
    elif args.rot is not None:
        print(f"ROT{args.rot}: {rot_decode(s, args.rot)}")
    elif args.url:
        print(f"URL: {urllib.parse.unquote(s)}")
    else:
        results = decode_all(s)
        print(f"输入: {s[:80]}")
        for method, result in results:
            print(f"  [{method}] {result[:120]}")

if __name__ == "__main__":
    main()
