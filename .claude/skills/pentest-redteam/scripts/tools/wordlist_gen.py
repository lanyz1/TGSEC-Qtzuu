#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""字典生成器: 从 URL 爬取页面文字→提取单词→组合规则输出
用法:
  python wordlist_gen.py -u https://target.com -o custom.txt --min 4 --max 16
  python wordlist_gen.py -u https://target.com --keywords 公司名,产品名 -o custom.txt
"""
import argparse, collections, html as htmllib, re, sys, urllib.request, urllib.error, ssl

def crawl_text(url, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read().decode("utf-8", "ignore")
    except Exception as e:
        print(f"[!] 抓取失败: {e}")
        return ""
    # 去标签
    text = re.sub(r'<script.*?</script>', ' ', raw, flags=re.S|re.I)
    text = re.sub(r'<style.*?</style>', ' ', text, flags=re.S|re.I)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = htmllib.unescape(text)
    return text

def extract_words(text, min_len=4, max_len=20):
    words = re.findall(r'[a-zA-Z0-9]{' + str(min_len) + r',' + str(max_len) + r'}', text.lower())
    cnt = collections.Counter(words)
    return [w for w, _ in cnt.most_common(3000)]

def common_mutations(words, base_words):
    """给核心词加常见后缀/前缀/规则变换"""
    suffixes = ["", "1", "123", "1234", "12345", "!", "@", "#", "2024", "2025", "2026"]
    prefixes = ["", "admin_", "test_", "dev_", "prod_"]
    combinations = []
    for w in base_words:
        w = w.lower()
        for s in suffixes:
            combinations.append(w + s)
        for p in prefixes:
            if p:
                combinations.append(p + w)
        # 首字母大写
        if w[0].isalpha():
            combinations.append(w.capitalize())
            for s in suffixes:
                combinations.append(w.capitalize() + s)
    return list(set(combinations))

def main():
    ap = argparse.ArgumentParser(description="字典生成器(CeWL 式: 爬页面取词+规则组合)")
    ap.add_argument("-u", "--url", required=True, help="目标 URL 或文件(含多个URL)")
    ap.add_argument("-o", "--output", default="custom_wordlist.txt", help="输出文件")
    ap.add_argument("--min", type=int, default=4, help="最小单词长度")
    ap.add_argument("--max", type=int, default=20, help="最大单词长度")
    ap.add_argument("--keywords", default="", help="手动指定核心词,逗号分隔")
    args = ap.parse_args()

    all_words = []
    if args.keywords:
        all_words = [k.strip() for k in args.keywords.split(",") if k.strip()]

    urls = [args.url]
    # 支持文件输入
    try:
        with open(args.url, encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
    except Exception:
        pass

    for u in urls:
        if u.startswith("http"):
            print(f"[*] 抓取: {u}")
            text = crawl_text(u)
            words = extract_words(text, args.min, args.max)
            print(f"    [+] 提取 {len(words)} 个词")
            all_words.extend(words)

    # 去重 + 规则变换
    all_words = list(set(all_words))
    base = all_words[:500]  # 取高频词
    mutated = common_mutations(all_words, base)
    final = sorted(set(all_words + mutated), key=lambda x: (len(x), x))

    with open(args.output, "w", encoding="utf-8") as f:
        for w in final:
            f.write(w + "\n")
    print(f"\n[+] 生成 {len(final)} 条, 已保存 {args.output}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
