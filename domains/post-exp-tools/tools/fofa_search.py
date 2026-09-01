#!/usr/bin/env python3
"""FOFA 新资产筛选探测 — 不打印密钥"""
import base64, json, os, sys, urllib.parse, urllib.request

EMAIL = os.environ.get('FOFA_EMAIL', '')
KEY = os.environ.get('FOFA_API_KEY', '')
if not EMAIL or not KEY:
    print('FOFA env missing'); sys.exit(1)

def fofa_search(query, size=10, fields='host,title,port,protocol,lastupdatetime,domain'):
    q = base64.b64encode(query.encode()).decode()
    url = (f'https://fofa.info/api/v1/search/all?email={urllib.parse.quote(EMAIL)}'
           f'&key={urllib.parse.quote(KEY)}&qbase64={q}&size={size}&fields={fields}')
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {'error': str(e)}

if __name__ == '__main__':
    # 参数: query size fields
    query = sys.argv[1] if len(sys.argv) > 1 else 'body="USDT"'
    size = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    fields = sys.argv[3] if len(sys.argv) > 3 else 'host,title,port,protocol,lastupdatetime'
    data = fofa_search(query, size, fields)
    if data.get('error'):
        print('ERROR:', data.get('errmsg', data.get('error')))
        sys.exit(1)
    print(f"total: {data.get('size', '?')}")
    for row in data.get('results', []):
        print(' | '.join(str(x) for x in row))
