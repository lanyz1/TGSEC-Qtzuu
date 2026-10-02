#!/usr/bin/env bash
# 大文件 / 媒体 / 重复镜像检查 —— CI 或本地 pre-push 均可跑
# FAIL = 阻断（演示媒体、重复镜像、>500KB 非白名单文件）
# WARN = 放行（PoC 二进制 apk/exe/dll/zip 属漏洞武器件，允许入库）
set -uo pipefail
LIMIT_KB=500
fail=0
POT_RE='\.(png|jpg|jpeg|gif|webp|bmp|mp4|mov|avi)$'
BIN_RE='\.(apk|ipa|exe|dll|pdb|img|zip|pyz)$'
# PoC 白名单路径：0day-exploits 与 lpe-toolkit 下的武器件不算违规
WL='domains/0day-exploits/|domains/linux-post/lpe-toolkit/|domains/mobile-security/panda-rev/'

echo "[1/3] 单文件 > ${LIMIT_KB}KB 检查…"
while IFS='|' read -r size path; do
  [ "$size" -le $((LIMIT_KB * 1024)) ] && continue
  # 中文/空格路径完整保留；白名单：PoC 武器目录 + 正文型后缀 → WARN 放行
  if echo "$path" | grep -qE "$WL|\.md$|\.json$|\.txt$|\.cpp$|\.php$"; then
    printf '  WARN %-10d %s\n' "$size" "$path"
  else
    printf '  FAIL %-10d %s\n' "$size" "$path"
    fail=1
  fi
done < <(git -c core.quotePath=false ls-tree -r -l HEAD | awk '{s=$4; $1=$2=$3=""; sub(/^[ \t]+/,""); print s"|"$0}' | sort -rn | head -50)

echo "[2/3] 演示媒体检查…"
media=$(git -c core.quotePath=false ls-files | grep -E "$POT_RE" | grep -vE "$WL" | wc -l)
if [ "$media" -gt 0 ]; then
  echo "  FAIL 演示媒体 $media 个"
  git -c core.quotePath=false ls-files | grep -E "$POT_RE" | grep -vE "$WL" | head -10
  fail=1
else
  echo "  PASS 0"
fi
pocbin=$(git -c core.quotePath=false ls-files | grep -E "$BIN_RE" | wc -l)
echo "  INFO PoC 武器件 $pocbin 个（允许入库）"

echo "[3/3] 重复技能镜像检查…"
dupes=$(git ls-files | grep -cE '^(\.agents|\.codex|\.cursor|\.gemini|hermes-skills)/' || true)
if [ "$dupes" -gt 0 ]; then
  echo "  FAIL 技能镜像 $dupes 个"
  fail=1
else
  echo "  PASS 0"
fi

echo "[vuln-wiki 保留白名单] 3 个无 md 源 PDF："
git -c core.quotePath=false ls-files | grep 'vuln-wiki.*\.pdf$' | sed 's/^/  KEEP /'

[ "$fail" -eq 0 ] && echo "== ALL PASS ==" || echo "== FAIL — 见上 =="
exit $fail
