#!/usr/bin/env bash
# check-tools.sh — 检测本机工具链
# 用法: bash scripts/check-tools.sh [--category recon,web]
set -euo pipefail

MANIFEST="$(dirname "$0")/tools-manifest.json"
CATEGORY_FILTER="${1:-""}"

echo "🔍 TGSEC 工具链检测 — $(date '+%Y-%m-%d %H:%M')"
echo "==========================================="

python3 - "$MANIFEST" "$CATEGORY_FILTER" <<'PY'
import json, sys, shutil, subprocess

manifest = json.load(open(sys.argv[1]))
filter_cat = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].startswith('--category') else ""

# parse --category value
cats = []
args = sys.argv[1:]
for i, a in enumerate(args):
    if a == '--category' and i+1 < len(args):
        cats = [c for c in args[i+1].split(',') if c]

def check_tool(name, channel):
    # find command on PATH
    for cmd in (name, name.split('.')[0]):
        if shutil.which(cmd):
            try:
                ver = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=5)
                if ver.returncode == 0:
                    return "OK", ver.stdout.strip().split("\n")[0][:60]
            except Exception:
                return "OK", ""
            return "OK", ""
    return "MISS", ""

ok = miss = na = 0
for cat, tools in manifest.get("tools", {}).items():
    if cats and cat not in cats:
        continue
    print(f"\n📁 [{cat}]")
    for t in tools:
        name, channel = t["name"], t["channel"]
        status, ver = check_tool(name, channel)
        if status == "OK":
            ok += 1
            print(f"  ✅ {name:15s} {ver}")
        elif channel in ("system",):
            na += 1
            print(f"  ⚪ {name:15s} N/A (系统自带: ssh)")
        else:
            miss += 1
            print(f"  ❌ {name:15s} MISS → {channel}: {t.get('pkg', '')[:50]}")

print(f"\n===========================================")
print(f"✅ 已安装: {ok}  |  ❌ 缺失: {miss}  |  ⚪ 系统: {na}")
print(f"缺失工具 → 运行 bash scripts/install-tools.sh 自动安装")
PY
