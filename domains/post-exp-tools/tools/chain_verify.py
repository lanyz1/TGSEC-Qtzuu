#!/usr/bin/env python3
"""验证候选地址：区分"平台充值地址" vs "DeFi/DEX 合约"
平台特征: 非合约、收款后归集、approve 金额=整数充值额、owner 少
DEX特征:  合约地址、海量 owner、任意金额
"""
import json
import time
import urllib.request

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TG = "https://api.trongrid.io"
TS = "https://apilist.tronscanapi.com/api"


def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            if attempt == 3:
                return {"error": str(e)}
            time.sleep(3)


def analyze(addr):
    print(f"\n===== {addr} =====")
    # 1. 账户类型（是否合约）
    acct = http_get(f"{TG}/wallet/getaccount?address={addr}")
    if "error" in acct:
        print("  getaccount 失败:", acct.get("error"))
    else:
        is_contract = acct.get("account_type") == 2 or bool(acct.get("code_hash")) or bool(acct.get("address", {}).get("tag"))
        print(f"  account_type={acct.get('account_type')} | 合约标记={is_contract} | TRX余额={acct.get('balance',0)/1e6:.2f}")
    # 2. 合约信息
    ct = http_get(f"{TG}/wallet/getcontract?value={addr}")
    if ct and ct.get("name"):
        print(f"  ⚠️ 是合约: {ct.get('name')}")
    # 3. Tronscan 标签
    ts = http_get(f"{TS}/accountv2?address={addr}")
    if isinstance(ts, dict) and ts.get("data"):
        d = ts["data"][0]
        print(f"  Tronscan: name={d.get('name')} | tag={d.get('tag1')} | 类型={d.get('accountType')} | 交易数={d.get('totalTransactionCount')} | TRC20交易={d.get('trc20token_balances',[{}])[0].get('tokenName','?') if d.get('trc20token_balances') else '无'}")
    # 4. 近期 incoming 前 20 笔的金额模式
    d = http_get(f"{TG}/v1/accounts/{addr}/transactions/trc20?only_to=true&limit=20&contract_address={USDT}")
    vals = []
    owners = set()
    types = {}
    for t in d.get("data", []):
        types[t.get("type", "?")] = types.get(t.get("type", "?"), 0) + 1
        if t.get("type") == "Transfer":
            vals.append(int(t.get("value", 0)) / 1e6)
            owners.add(t.get("from", ""))
    print(f"  事件类型: {types}")
    if vals:
        ints = sum(1 for v in vals if abs(v - round(v)) < 0.01)
        print(f"  Transfer: {len(vals)}笔 | 整数金额占比 {ints}/{len(vals)} | 金额范围 {min(vals):.2f}~{max(vals):.2f} | 来源owner去重 {len(owners)}")
    time.sleep(2)


for a in ["TPwezUWpEGmFBENNWJHwXHRG1D2NCEEt5s", "TCFNp179Lg46D16zKoumd4Poa2WFFdtqYj"]:
    analyze(a)
