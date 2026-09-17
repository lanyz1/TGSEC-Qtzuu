#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""链上测绘：从 USDT(TRC20) Approval 事件流反查疑似"平台充值地址"
原理：approve 伪装充值骗局中，攻击者会对平台充值地址(spender)发起 approve；
     正常用户不会 approve 平台地址。"被多次 approve 且高频收款" = 疑似平台充值地址。
用途：黑产/发卡/USDT 骗局站的资金入口拓线与取证（配合 realworld-patterns 支付/USDT 线）。
用法:
  python chain_scan.py                       # 默认拉 25 页
  python chain_scan.py --pages 40 --min-approve 3
纯标准库单文件，argparse 参数化。仅用于授权调查/取证。
"""
import argparse, hashlib, json, sys, time, urllib.request

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
API = "https://api.trongrid.io"
ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def hex41_to_b58(h):
    h = h.lower().replace("0x", "")
    if h.startswith("41"):
        h = h[2:]
    payload = b"\x41" + bytes.fromhex(h)
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


def fetch_approvals(pages, limit):
    url = (f"{API}/v1/contracts/{USDT}/events?event_name=Approval"
           f"&limit={limit}&order_by=block_timestamp,desc")
    spender, owner = {}, {}
    for p in range(pages):
        d = http_get(url)
        if "error" in d or not d.get("data"):
            print(f"  第{p+1}页失败: {d.get('error', 'empty')}", file=sys.stderr)
            break
        for e in d["data"]:
            r = e.get("result", {})
            sp, ow = r.get("1", ""), r.get("0", "")
            if sp:
                spender[sp] = spender.get(sp, 0) + 1
            if ow:
                owner[ow] = owner.get(ow, 0) + 1
        link = d.get("meta", {}).get("links", {}).get("next")
        if not link:
            break
        url = link
        time.sleep(0.5)
    return spender, owner


def check_incoming(addr):
    d = http_get(f"{API}/v1/accounts/{addr}/transactions/trc20"
                 f"?only_to=true&limit=100&contract_address={USDT}")
    types = {}
    for t in d.get("data", []):
        tp = t.get("type", "?")
        types[tp] = types.get(tp, 0) + 1
    return types, len(d.get("data", []))


def main():
    ap = argparse.ArgumentParser(description="USDT Approval 事件反查疑似平台充值地址")
    ap.add_argument("--pages", type=int, default=25, help="拉取 Approval 事件页数（默认 25）")
    ap.add_argument("--limit", type=int, default=200, help="每页条数（默认 200）")
    ap.add_argument("--min-approve", type=int, default=2, help="被 approve 次数阈值（默认 2）")
    ap.add_argument("--min-transfer", type=int, default=5, help="收款 Transfer 阈值判平台（默认 5）")
    ap.add_argument("--top", type=int, default=40, help="核查前 N 个候选（默认 40）")
    args = ap.parse_args()

    print(f"[*] 拉取 {args.pages} 页 USDT Approval 事件...")
    spender, owner = fetch_approvals(args.pages, args.limit)
    print(f"[*] 收集 {len(spender)} spender / {len(owner)} owner")

    cands = sorted(((h, c) for h, c in spender.items() if c >= args.min_approve),
                   key=lambda x: -x[1])[:args.top]
    print(f"[*] 被 approve ≥{args.min_approve} 次的候选 {len(cands)} 个，核查收款模式：")
    hits = []
    for hexaddr, cnt in cands:
        try:
            b58 = hex41_to_b58(hexaddr)
        except Exception:
            continue
        types, total = check_incoming(b58)
        tn = types.get("Transfer", 0)
        print(f"  {b58} | approve={cnt} | 收款Transfer={tn} | 总事件={total}")
        if tn >= args.min_transfer:
            hits.append((b58, cnt, tn))
        time.sleep(0.3)

    print("\n[*] 高危候选（高频收款 + 被多次 approve）：")
    for b58, cnt, tn in sorted(hits, key=lambda x: -x[2]):
        print(f"  {b58} | approve={cnt} | 收款笔数={tn}")
    print("[i] 候选需 chain_verify.py 二次判别（平台充值地址 vs DEX 合约）。")


if __name__ == "__main__":
    main()
