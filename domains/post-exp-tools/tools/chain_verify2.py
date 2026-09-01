#!/usr/bin/env python3
"""候选最终判别：攻击者 owner = 对 spender 有 Approval 但无/极少 Transfer"""
import json
import time
import urllib.request

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TG = "https://api.trongrid.io"

CANDIDATES = [
    "TGnC7LMji8hBpyvZt1TTEJhVpAZ5HFyJ3r",
    "TXtEs6t2oUWQsNos7m68gbHdE9Q5n6x2oN",
    "TPuaJ6gnYfE9gLUDFrbWbPx3tMnjG8max1",
    "TTJxU3P8rHycAyFY4kVtGNfmnMH4ezcuM9",
    "TT3kgJohTQJNKDUWwTxtRDMHNNWNvNG3i4",
    "TXwtVpa8hS1e65awzRTWAiLw5LEQBzgZCY",
    "TEWAiPa7Ue5wkge1poiMo4r3Rn1QU5j96x",
    "TXznJsRdSysWc1JvRkRC51AcD6C16FL9TT",
]


def http_get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    for a in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except Exception:
            if a == 3:
                return {}
            time.sleep(3)


for sp in CANDIDATES:
    d = http_get(f"{TG}/v1/accounts/{sp}/transactions/trc20?only_to=true&limit=200&contract_address={USDT}")
    data = d.get("data", [])
    ap_by_owner = {}
    tr_by_owner = {}
    for t in data:
        ow = t.get("from", "")
        if t.get("type") == "Approval":
            ap_by_owner[ow] = ap_by_owner.get(ow, 0) + 1
        elif t.get("type") == "Transfer":
            tr_by_owner[ow] = tr_by_owner.get(ow, 0) + 1
    # 攻击者 = 有 approve 但该 owner 的 transfer 次数远小于 approve 次数
    suspicious = []
    for ow, ac in ap_by_owner.items():
        tc = tr_by_owner.get(ow, 0)
        if tc == 0 and ac >= 2:
            suspicious.append((ow, ac, 0))
        elif tc > 0 and ac >= 3 and ac > tc * 3:
            suspicious.append((ow, ac, tc))
    total_tr = sum(tr_by_owner.values())
    total_ap = sum(ap_by_owner.values())
    print(f"{sp}")
    print(f"  总: Transfer={total_tr} Approval={total_ap} | 来源owner数={len(ap_by_owner)}")
    if suspicious:
        for ow, ac, tc in sorted(suspicious, key=lambda x: -x[1])[:4]:
            print(f"  🔴 攻击者 {ow[:16]}.. | approve x{ac} | transfer x{tc}")
    else:
        print("  🟢 无纯 approve 攻击者（多为正常授权）")
    time.sleep(1.5)
