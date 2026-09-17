#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""哈希类型识别 + hashcat mode 推荐
用法:
  python hash_id.py -h '$2y$10$abcdef...'
  python hash_id.py -f hashes.txt
"""
import argparse, hashlib, re, sys

# (正则, hashcat mode, 名称, 示例格式)
SIGNATURES = [
    (r"^\$2[aby]\$\d+\$.{53}$", 3200, "bcrypt", "$2y$10$..." ),
    (r"^\$6\$[^$]+\$[^$]+", 1800, "sha512crypt (Linux /etc/shadow)", "$6$salt$hash"),
    (r"^\$5\$[^$]+\$[^$]+", 7400, "sha256crypt", "$5$salt$hash"),
    (r"^\$1\$[^$]+\$[^$]+", 500, "md5crypt", "$1$salt$hash"),
    (r"^\$sha1\$[0-9]+\$", 1710, "sha1(pass.salt)", "$sha1$1000$salt$hash"),
    (r"^[0-9a-f]{32}$", 0, "MD5", "8743b52063cd84097a65d1633f5c74f5"),
    (r"^[0-9a-f]{40}$", 100, "SHA-1", "b89eaac7e61417341b710b727768294d0e6a277b"),
    (r"^[0-9a-f]{64}$", 1400, "SHA-256", "..." ),
    (r"^[0-9a-f]{96}$", 1700, "SHA-512", "..." ),
    (r"^[0-9a-f]{40}:[0-9a-f]{32}$", 20, "md5($pass.$salt)", "hash:salt"),
    (r"^[0-9a-f]{32}:[0-9a-f]{32}$", 10, "md5($pass.$salt) v2", "salt:hash"),
    (r"^(\$P\$|$H\$|$J\$)[a-zA-Z0-9./]{31}$", 400, "phpass (WordPress)", "$P$B..."),
    (r"^\$2a\$10\$[a-zA-Z0-9./]{53}$", 3200, "bcrypt v2a", "$2a$..."),
    (r"^[a-zA-Z0-9\+\/]{20,}={0,2}$", -1, "Base64(可能是二次编码)", "YXNkZg=="),
    (r"d{4,5}-d{4,5}-d{4,5}-d{4,5}$", 4800, "iSCSI CHAP", "0000-1111-2222-3333"),
    (r"^[0-9a-f]{48}$", 10800, "SHA-384", "..."),
    (r"^scrypt:[0-9]+:[0-9]+:[0-9]+:", 8900, "scrypt", "scrypt:N:r:p:..."),
    (r"^\$argon2[di]\$", 9100, "Argon2", "$argon2i$..."),
]

def identify(hash_str):
    h = hash_str.strip()
    matches = []
    for pat, mode, name, example in SIGNATURES:
        if re.match(pat, h, re.I):
            matches.append((mode, name, example))
    if not matches:
        # 尝试长度推断
        ln = len(h)
        if ln == 32 and all(c in '0123456789abcdef' for c in h): matches.append((0, "MD5 (推测)", "32字符hex"))
        elif ln == 40 and h.isalnum(): matches.append((100, "SHA-1 (推测)", "40字符hex"))
        elif ln == 64 and h.isalnum(): matches.append((1400, "SHA-256 (推测)", "64字符hex"))
        elif ln == 128 and h.isalnum(): matches.append((1700, "SHA-512 (推测)", "128字符hex"))
    return matches

def main():
    ap = argparse.ArgumentParser(description="哈希类型识别 + hashcat mode 推荐")
    ap.add_argument("-f", "--file", help="哈希文件(每行一个)")
    ap.add_argument("hash", nargs="?", help="单个哈希值")
    args = ap.parse_args()

    hashes = []
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            hashes = [l.strip() for l in f if l.strip()]
    elif args.hash:
        hashes = [args.hash]
    else:
        ap.print_help()
        sys.exit(1)

    for h in hashes:
        matches = identify(h)
        short = h[:50] + ("..." if len(h) > 50 else "")
        if matches:
            for mode, name, ex in matches:
                cmd = f"  hashcat -m {mode} -a 0 '{h}' wordlist.txt" if mode > 0 else f"  hashcat -m {mode} '{h}' wordlist.txt"
                print(f"[{short}]")
                print(f"  → {name} (mode={mode})")
                print(cmd)
        else:
            print(f"[{short}] → 未识别")

if __name__ == "__main__":
    main()
