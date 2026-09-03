#!/bin/bash
# 旧机器一键重装/覆盖 TGSEC：知识库 + Hermes 技能 + 人格
# Usage:
#   curl 不可用时，在已 clone 的仓内: bash scripts/reinstall-tgsec.sh
#   或: bash scripts/reinstall-tgsec.sh /path/to/security-suite
#
# @TGSEC社区 · @TGSEC-Qtzuu 整理

set -euo pipefail

REPO_URL="${TGSEC_REPO_URL:-https://github.com/lanyz1/TGSEC-Qtzuu.git}"
TARGET="${1:-$HOME/security-suite}"

echo "================================================"
echo "  TGSEC 全量重装/覆盖"
echo "  target: $TARGET"
echo "================================================"

if [ -d "$TARGET/.git" ]; then
  echo "[*] updating existing clone"
  git -C "$TARGET" fetch origin
  git -C "$TARGET" checkout master 2>/dev/null || git -C "$TARGET" checkout main
  git -C "$TARGET" pull --ff-only origin master 2>/dev/null || git -C "$TARGET" pull --ff-only origin main || git -C "$TARGET" pull --rebase
else
  if [ -e "$TARGET" ] && [ ! -d "$TARGET/.git" ]; then
    BAK="$TARGET.bak.$(date +%s)"
    echo "[i] non-git $TARGET → backup $BAK"
    mv "$TARGET" "$BAK"
  fi
  echo "[*] cloning $REPO_URL"
  git clone --depth 1 "$REPO_URL" "$TARGET"
fi

cd "$TARGET"

if [ -f ai-config/hermes/setup.sh ]; then
  bash ai-config/hermes/setup.sh || true
elif [ -f hermes-config/setup-hermes.sh ]; then
  bash hermes-config/setup-hermes.sh || true
fi

if [ -f scripts/sync-hermes-skills.sh ]; then
  bash scripts/sync-hermes-skills.sh
else
  echo "[!] hermes-skills sync script missing — pull latest repo"
  exit 1
fi

echo ""
echo "================================================"
echo "  完成"
echo "================================================"
echo "  知识库: $TARGET/domains  (MASTER.md)"
echo "  技能:   ~/.hermes/skills/security"
echo "  下一步: 开新 Hermes 会话，再说渗透任务"
echo "  验证:   ls ~/.hermes/skills/security && test -f $TARGET/MASTER.md"
