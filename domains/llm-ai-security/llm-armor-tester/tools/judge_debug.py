# -*- coding: utf-8 -*-
"""调试模型 judge 的返回格式（一次性排查脚本）。"""
import csv
import io
import os
import sys

sys.path.insert(0, ".")
from armor_tester.client import ChatClient
from armor_tester.judge import JUDGE_SYSTEM, JUDGE_TEMPLATE
from armor_tester.payloads import Payload

key = ""
with open(os.path.expanduser("~/.dsh/.credentials.yaml"), encoding="utf-8") as f:
    for line in f:
        if line.strip().startswith("MIMO_API_KEY:"):
            key = line.split(":", 1)[1].strip().strip('"')

c = ChatClient("https://token-plan-cn.xiaomimimo.com/v1", key, "mimo-v2.6-flash",
               timeout=120, no_proxy=True)
rows = [r for r in csv.DictReader(open("results/mimo_judged_ml.csv", encoding="utf-8-sig"))
        if r["verdict"] == "SUSPECT"]
r = rows[0]
msg = [
    {"role": "system", "content": JUDGE_SYSTEM},
    {"role": "user", "content": JUDGE_TEMPLATE.format(payload="(载荷省略)", response=r["response_full"][:3000])},
]
resp = c.chat(msg, temperature=0.0, max_tokens=300, retries=0)
with io.open("results/judge_debug.txt", "w", encoding="utf-8") as f:
    f.write(f"ok={resp['ok']} err={resp.get('error','')[:200]}\n")
    f.write("--- raw text ---\n")
    f.write(resp.get("text", ""))
print("ok=", resp["ok"], "len=", len(resp.get("text", "")))
