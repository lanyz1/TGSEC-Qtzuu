#!/usr/bin/env python3
"""链上测绘：从 USDT Approval 事件流反查"被 approve 过的平台充值地址"
原理：approve 伪装充值的攻击者会对平台充值地址(spender)发起 approve；
     正常用户不会 approve 平台地址。因此"被多次 approve 且高频收款"= 高危平台地址。
"""
import json
import time
import urllib.request

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
API = "https://api.trongrid.io"
ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def http_get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def hex41_to_b58(h):
    # h: 41 + 40 hex（可能带 0x 前缀或裸 40 hex）
    h = h.lower().replace("0x", "")
    if h.startswith("41"):
        h = h[2:]
    raw = bytes.fromhex(h)
    payload = b"\x41" + raw
    import hashlib
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload + chk, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = ALPH[r] + s
    for b in payload + chk:
        if b == 0:
            s = "1" + s
        else:
            break
    return s


def fetch_approvals(pages=25, limit=200):
    """拉最近 Approval 事件，返回 spender(hex) -> count"""
    url = f"{API}/v1/contracts/{USDT}/events?event_name=Approval&limit={limit}&order_by=block_timestamp,desc"
    spender_count = {}
    owner_count = {}
    for p in range(pages):
        d = http_get(url)
        if "error" in d or not d.get("data"):
            print(f"  第{p+1}页失败: {d.get('error','empty')}")
            break
        for e in d["data"]:
            r = e.get("result", {})
            sp = r.get("1", "")
            ow = r.get("0", "")
            if sp:
                spender_count[sp] = spender_count.get(sp, 0) + 1
            if ow:
                owner_count[ow] = owner_count.get(ow, 0) + 1
        meta = d.get("meta", {})
        link = meta.get("links", {}).get("next")
        if not link:
            break
        url = link
        time.sleep(0.5)
    return spender_count, owner_count


def check_incoming(addr_b58):
    """查该地址收到的 USDT trc20 事件类型分布"""
    d = http_get(f"{API}/v1/accounts/{addr_b58}/transactions/trc20?only_to=true&limit=100&contract_address={USDT}")
    data = d.get("data", [])
    types = {}
    for t in data:
        tp = t.get("type", "?")
        types[tp] = types.get(tp, 0) + 1
    return types, len(data)


def main():
    pages = int(__import__("sys").argv[1]) if len(__import__("sys").argv) > 1 else 25
    print(f"[*] 拉取 {pages} 页 USDT Approval 事件...")
    spender_count, owner_count = fetch_approvals(pages=pages)

    print(f"[*] 共收集 {len(spender_count)} 个被授权地址(spender)，{len(owner_count)} 个授权者(owner)")
    print(f"[*] 被授权 ≥2 次的地址（疑似平台充值地址）：")
    candidates = [(h, c) for h, c in spender_count.items() if c >= 2]
    candidates.sort(key=lambda x: -x[1])

    results = []
    for hexaddr, cnt in candidates[:40]:
        try:
            b58 = hex41_to_b58(hexaddr)
        except Exception:
            continue
        types, total = check_incoming(b58)
        transfer_n = types.get("Transfer", 0)
        approval_n = types.get("Approval", 0)
        print(f"  {b58} | 被approve次数={cnt} | 收款Transfer={transfer_n} | 收款Approval={approval_n} | 总事件={total}")
        if transfer_n >= 5:  # 高频收款 = 平台特征
            results.append((b58, cnt, transfer_n, approval_n))
        time.sleep(0.3)

    print(f"\n[*] 高危候选（高频收款+被多次approve）：")
    for r in sorted(results, key=lambda x: -x[2]):
        print(f"  {r[0]} | approve次数={r[1]} | 收款笔数={r[2]} | 收款Approval={r[3]}")


if __name__ == "__main__":
    main()
