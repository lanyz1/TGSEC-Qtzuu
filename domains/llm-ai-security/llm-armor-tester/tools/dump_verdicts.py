# -*- coding: utf-8 -*-
"""导出某结果 CSV 的判定明细（UTF-8）。用法: python tools/dump_verdicts.py <csv>"""
import csv
import sys

rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
out = open("results/verdicts_dump.txt", "w", encoding="utf-8")
for r in rows:
    line = "%-7s %-6s %-22s | %s\n" % (
        r["verdict"], r["payload_id"], r["name"][:22], r["verdict_reasons"][:95])
    out.write(line)
out.close()
print("dumped", len(rows), "-> results/verdicts_dump.txt")
