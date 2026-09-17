#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""二进制静态分析: 快速扫描 PE/ELF/任意文件的字符串/导入/熵值
用法:
  python binary_scan.py -f target.exe
  python binary_scan.py -f target.bin --strings --entropy
"""
import argparse, math, os, re, sys, struct

SENSITIVE_PATTERNS = [
    (r'https?://[^\s\x00]{4,}', "URL"),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', "IP"),
    (r'(?:AKIA|ASIA)[A-Z0-9]{16}', "AWS Access Key"),
    (r'(?:eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})', "JWT"),
    (r'(?:[a-zA-Z0-9+/]{30,}={0,2})', "Base64 blob"),
    (r'(?:password|passwd|pwd|secret|token|private|key)\s*[:=]', "凭据关键词"),
    (r'SQLite format 3', "SQLite DB"),
    (r'(?:cmd\.exe|powershell\.exe|/bin/sh|/bin/bash)', "Shell 引用"),
]

def extract_strings(data, min_len=4):
    pat = re.compile(b'[\x20-\x7E]{' + str(min_len).encode() + b',}')
    return [m.group().decode("ascii") for m in pat.finditer(data)]

def shannon_entropy(data):
    if not data:
        return 0
    counts = {b: data.count(b) for b in set(data)}
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def pe_imports(data):
    """粗略 PE 导入表提取"""
    imports = []
    for m in re.finditer(rb'([a-zA-Z0-9_-]+\.dll)\x00', data, re.I):
        dll = m.group(1).decode("ascii", "ignore").lower()
        if dll not in imports:
            imports.append(dll)
    return imports[:20]

def main():
    ap = argparse.ArgumentParser(description="二进制静态分析(PE/ELF/通用)")
    ap.add_argument("-f", "--file", required=True, help="目标文件")
    ap.add_argument("--strings", action="store_true", help="提取可读字符串")
    ap.add_argument("--entropy", action="store_true", help="计算熵值")
    ap.add_argument("--imports", action="store_true", help="提取 DLL 导入")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    sz = len(data)
    print(f"[*] 文件: {args.file} ({sz} 字节)")

    # 文件类型探测
    if data[:2] == b"MZ":
        print(f"    类型: PE (Windows 可执行文件)")
    elif data[:4] == b"\x7fELF":
        print(f"    类型: ELF (Linux 可执行文件)")
    elif data[:2] in (b"PK", b"\x50\x4b"):
        print(f"    类型: ZIP / APK / JAR 归档")

    # 熵值
    if args.entropy or args.all:
        ent = shannon_entropy(data)
        print(f"\n[*] 熵值: {ent:.2f} / 8.0")
        if ent > 7.5:
            print(f"    [!] 高熵 → 可能加密/加壳")

    # 字符串
    if args.strings or args.all:
        strings = extract_strings(data)
        print(f"\n[*] 可读字符串: {len(strings)} 条")
        found = []
        for s in strings:
            for pat, label in SENSITIVE_PATTERNS:
                if re.search(pat, s):
                    found.append((s[:80], label))
        if found:
            print("    敏感字符串:")
            for s, label in set(found)[:20]:
                print(f"      [{label}] {s}")

    # PE 导入
    if args.imports or args.all:
        imps = pe_imports(data)
        if imps:
            print(f"\n[*] DLL 导入: {' '.join(imps[:20])}")

if __name__ == "__main__":
    main()
