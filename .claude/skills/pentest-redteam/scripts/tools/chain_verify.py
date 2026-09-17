#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""链上二次判别：把 chain_scan.py 的候选地址判成"平台充值地址"还是"DEX/合约"
判据（只读、公开链上数据，不做任何交易）：
  - 是否合约(has code)     → 合约多为 DEX/路由/协议，非平台散户充值口
  - 收/发笔数与净流入      → 平台充值口：大量小额入 + 少量大额归集出
  - 交易对手集中度         → 平台口：多对手入、少数对手(归集钱包)出
  - TronScan 标签/风险标记 → 已知交易所/DEX 标签可直接排除或坐实
用法:
  python chain_verify.py TPwezUWpEGmFBENNWJHwXHRG1D2NCEEt5s
  python chain_verify.py -f candidates.txt --json
纯标准库单文件（地址经 argparse 传入，非硬编码）。仅授权取证。
"""
import argparse, json, sys, time, urllib.request

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TG = "https://api.trongrid.io"
TS = "https://apilist.tronscanapi.com/api"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def http_get(url, timeout=30, retry=2):
    for i in range(retry + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            if i == retry:
                return {"error": str(e)}
            time.sleep(1.0 + i)
    return {"error": "unreachable"}


def is_contract(addr):
    d = http_get(f"{TG}/v1/accounts/{addr}")
    data = d.get("data") or []
    if not data:
        return None
    acc = data[0]
    # 合约账户带 type=Contract 或存在 code 字段
    return bool(acc.get("is_contract") or acc.get("type") == "Contract"
                or acc.get("contract") or acc.get("code"))


def tron_tags(addr):
    d = http_get(f"{TS}/account?address={addr}")
    if "error" in d:
        return {}
    return {
        "tag": d.get("addressTag") or d.get("publicTag") or "",
        "name": d.get("name", ""),
        "risk": d.get("riskLevel", ""),
        "redTag": d.get("redTag", ""),
        "blueTag": d.get("blueTag", ""),
    }


def usdt_flows(addr, limit=200):
    """统计 USDT 收/发笔数、去重对手、归集特征。"""
    inc = http_get(f"{TG}/v1/accounts/{addr}/transactions/trc20"
                   f"?only_to=true&limit={limit}&contract_address={USDT}")
    out = http_get(f"{TG}/v1/accounts/{addr}/transactions/trc20"
                   f"?only_from=true&limit={limit}&contract_address={USDT}")
    ins = inc.get("data", []) if "error" not in inc else []
    outs = out.get("data", []) if "error" not in out else []
    in_from = {t.get("from") for t in ins if t.get("from")}
    out_to = {t.get("to") for t in outs if t.get("to")}
    return {
        "in_cnt": len(ins), "out_cnt": len(outs),
        "in_peers": len(in_from), "out_peers": len(out_to),
    }


def analyze(addr):
    r = {"address": addr}
    r["is_contract"] = is_contract(addr)
    r["tags"] = tron_tags(addr)
    time.sleep(0.3)
    r["flows"] = usdt_flows(addr)
    r["verdict"] = _verdict(r)
    return r


def _verdict(r):
    f = r["flows"]
    tag = " ".join(str(v) for v in r["tags"].values()).lower()
    if r["is_contract"]:
        return "合约（DEX/路由/协议——非散户充值口，排除）"
    if any(k in tag for k in ("exchange", "binance", "okx", "huobi", "dex", "swap")):
        return f"已知交易所/DEX 标签（{r['tags'].get('tag') or r['tags'].get('name')}）"
    # 平台充值口画像：多对手入 + 少对手出（归集）+ 入笔数明显多于出
    if f["in_peers"] >= 10 and f["out_peers"] <= 3 and f["in_cnt"] > f["out_cnt"]:
        return "疑似平台充值/归集地址（多入少出，归集特征强）——重点"
    if f["in_peers"] >= 5 and f["out_peers"] <= 5:
        return "可疑（归集特征中等，建议扩样本核验）"
    return "证据不足（对手分布不呈归集态，需人工判读）"


def read_addrs(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            a = line.strip().split()[0] if line.strip() else ""
            if a.startswith("T") and len(a) == 34:
                out.append(a)
    return out


def main():
    ap = argparse.ArgumentParser(description="TRON 候选地址二次判别（平台充值口 vs DEX/合约）")
    ap.add_argument("addresses", nargs="*", help="一个或多个 TRON 地址（T 开头，34 位）")
    ap.add_argument("-f", "--file", help="地址列表文件（每行一个，可接 chain_scan 输出）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    addrs = list(args.addresses)
    if args.file:
        addrs += read_addrs(args.file)
    addrs = [a for a in dict.fromkeys(addrs) if a.startswith("T") and len(a) == 34]
    if not addrs:
        ap.error("需提供至少一个 TRON 地址，或用 -f 指定列表文件")

    results = []
    for a in addrs:
        r = analyze(a)
        results.append(r)
        if not args.json:
            t = r["tags"]
            print(f"\n=== {a} ===")
            print(f"  合约: {r['is_contract']}  标签: {t.get('tag') or t.get('name') or '-'}"
                  f"  风险: {t.get('risk') or '-'}")
            print(f"  USDT 入{r['flows']['in_cnt']}笔/{r['flows']['in_peers']}对手  "
                  f"出{r['flows']['out_cnt']}笔/{r['flows']['out_peers']}对手")
            print(f"  判定: {r['verdict']}")
        time.sleep(0.4)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
