# -*- coding: utf-8 -*-
"""汇总终版判定与模型 judge 改判明细。"""
import collections
import csv
import io

rows = list(csv.DictReader(open("results/mimo_judged_ml.csv", encoding="utf-8-sig")))
mj = [r for r in rows if "model-judge" in (r.get("verdict_reasons") or "")]
print("终版分布:", dict(collections.Counter(r["verdict"] for r in rows)))
print("模型judge留痕:", len(mj), "| 触发行判定分布:", dict(collections.Counter(r["verdict"] for r in mj)))
flip = [r for r in mj if r["verdict"] in ("BREAK", "RESIST")]
print("模型judge拍板(BREAK/RESIST):", len(flip))

out = io.open("results/final_verdicts.txt", "w", encoding="utf-8")
for r in sorted(rows, key=lambda x: (x["verdict"] != "BREAK", x["verdict"] != "SUSPECT", x["payload_id"])):
    if r["verdict"] in ("BREAK", "SUSPECT") or "model-judge" in (r.get("verdict_reasons") or ""):
        out.write(f"{r['verdict']:<7} {r['payload_id']}#{r['sample']} {r['name']} | {r['verdict_reasons'][:100]}\n")
out.close()
print("明细 -> results/final_verdicts.txt")
