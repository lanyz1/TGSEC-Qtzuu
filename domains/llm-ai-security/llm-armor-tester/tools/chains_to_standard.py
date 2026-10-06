# -*- coding: utf-8 -*-
"""把 chains CSV 映射为标准结果列，复用报告引擎。"""
import csv
import sys

src, dst = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(src, encoding="utf-8-sig")))
out_fields = ["run_id", "ts", "payload_id", "name", "category", "severity", "objective",
              "model", "carrier", "sample", "turns", "status", "http_status", "latency_ms",
              "verdict", "verdict_reasons", "response_snippet", "response_full", "error",
              "source", "parent_id"]
with open(dst, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.DictWriter(f, fieldnames=out_fields)
    w.writeheader()
    for r in rows:
        w.writerow({
            "run_id": r.get("run_id", ""), "ts": r.get("ts", ""),
            "payload_id": r.get("chain_id", ""), "name": r.get("name", ""),
            "category": "chain_" + r.get("strategy", ""), "severity": r.get("severity", ""),
            "objective": r.get("objective", ""), "model": r.get("model", ""),
            "carrier": "none", "sample": 1, "turns": r.get("turns", 1),
            "status": r.get("status", ""), "http_status": r.get("http_status", ""),
            "latency_ms": r.get("latency_ms", ""), "verdict": r.get("verdict", ""),
            "verdict_reasons": r.get("verdict_reasons", ""),
            "response_snippet": r.get("response_snippet", ""),
            "response_full": r.get("response_full", ""), "error": r.get("error", ""),
            "source": "chain", "parent_id": "",
        })
print("mapped", len(rows), "->", dst)
