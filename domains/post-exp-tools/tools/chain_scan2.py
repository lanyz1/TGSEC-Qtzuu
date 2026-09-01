#!/usr/bin/env python3
"""链上测绘 v2：攻击者指纹 = 同一 owner 对同一 spender 多次 approve
正常 DeFi 用户授权一次；(owner,spender) 组合频次≥2 = 攻击者对平台充值地址反复测试
"""
import hashlib
import json
import time
import urllib.request

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
API = "https://api.trongrid.io"
ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# 已知交易所/桥/DeFi 黑名单（避免误报）
BLACKLIST = {
    "TPwezUWpEGmFBENNWJHwXHRG1D2NCEEt5s", "TCFNp179Lg46D16zKoumd4Poa2WFFdtqYj",
    "TTRr81XJt6zESpJw2zHgJNAsxcsyT5MVYv", "TNKG4Mji5CjwaEZ8QXk5B4PaDDtax5pxQ5",
}


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


def hex41_to_b58(h):
    h = h.lower().replace("0x", "")
    if h.startswith("41"):
        h = h[2:]
    raw = bytes.fromhex(h)
    payload = b"\x41" + raw
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


def main():
    pages = int(__import__("sys").argv[1]) if len(__import__("sys").argv) > 1 else 30
    url = f"{API}/v1/contracts/{USDT}/events?event_name=Approval&limit=200&order_by=block_timestamp,desc"
    pairs = {}  # (owner, spender) -> count
    print(f"[*] 拉取 {pages} 页 Approval 事件（攻击指纹：同 owner 多次 approve 同 spender）...")
    for p in range(pages):
        d = http_get(url)
        if not d.get("data"):
            print(f"  第{p+1}页无数据")
            break
        for e in d["data"]:
            r = e.get("result", {})
            ow = r.get("0", "")
            sp = r.get("1", "")
            if ow and sp:
                pairs[(ow, sp)] = pairs.get((ow, sp), 0) + 1
        nxt = d.get("meta", {}).get("links", {}).get("next")
        if not nxt:
            break
        url = nxt
        time.sleep(0.4)

    print(f"[*] 共 {len(pairs)} 个 (owner,spender) 组合")
    multi = {k: v for k, v in pairs.items() if v >= 2}
    print(f"[*] 同 owner 多次 approve 的组合: {len(multi)} 个")

    # 按 spender 聚合
    spender_hits = {}
    for (ow, sp), c in multi.items():
        spender_hits.setdefault(sp, []).append((ow, c))

    print("\n[!] 高危 spender（被同一 owner 多次 approve = 平台充值地址指纹）：")
    for sp, hits in sorted(spender_hits.items(), key=lambda x: -len(x[1]))[:20]:
        try:
            b58 = hex41_to_b58(sp)
        except Exception:
            continue
        if b58 in BLACKLIST:
            continue
        detail = "; ".join(f"{hex41_to_b58(ow)[:10]}.. x{c}" for ow, c in hits[:4])
        print(f"  {b58} | 攻击者组合 {len(hits)} 组 | {detail}")
        time.sleep(0.3)


if __name__ == "__main__":
    main()
