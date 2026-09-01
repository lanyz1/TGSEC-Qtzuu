#!/usr/bin/env python3
"""crt_find_new.py — CT 日志新证书发现：近 N 天新签发的金融相关域名
用法: crt_find_new.py [天数=60] [关键词=usdt,coin,pay,vip,bet,miner,swap,defi,otc,token]
输出: 去重域名列表，排除托管/自动签发垃圾域
注意: crt.sh 每个查询 5-90 秒，多关键词建议后台跑"""
import json, re, subprocess, sys, time, urllib.request

DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 60
KEYWORDS = (sys.argv[2] if len(sys.argv) > 2
            else 'usdt,coin,pay,vip,bet,miner,swap,defi,otc,token').split(',')

# 托管/自动签发垃圾域（CT 日志噪音主力）
EXCLUDE = re.compile(
    r'hosted\.app|pages\.dev|vercel\.app|cloudfront\.net|run\.app|'
    r'firebaseapp\.com|netlify\.app|azurewebsites\.net|appspot\.com|'
    r'workers\.dev|wingforum\.de|web\.app|cdn\.|static\.|assets\.|'
    r'\.github\.io|\.gitlab\.io|dns\.|mail\.|autodiscover\.')

import datetime
since = (datetime.date.today() - datetime.timedelta(days=DAYS)).isoformat()

seen = {}
for kw in KEYWORDS:
    url = f'https://crt.sh/?q=%25{kw}%25&output=json'
    print(f'[{kw}] 查询中...', file=sys.stderr)
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'sec-research'})
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.loads(r.read().decode())
    except Exception as e:
        print(f'[{kw}] 失败: {e}', file=sys.stderr)
        continue
    for entry in data:
        nb = entry.get('not_before', '')
        if nb < since:
            continue
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lstrip('*.').strip()
            if not name or EXCLUDE.search(name):
                continue
            if name not in seen or nb > seen[name]:
                seen[name] = nb
    time.sleep(1.5)

for name, nb in sorted(seen.items()):
    print(f'{nb}\t{name}')
print(f'# 合计 {len(seen)} 个近 {DAYS} 天新证书域名（{len(KEYWORDS)} 关键词）', file=sys.stderr)
