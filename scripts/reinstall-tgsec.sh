#!/bin/bash
# 旧机器一条龙: clone/pull + 全量 bootstrap
# Usage: bash scripts/reinstall-tgsec.sh [target_dir]
# @TGSEC社区 · @TGSEC-Qtzuu 整理
set -euo pipefail
REPO_URL="${TGSEC_REPO_URL:-https://github.com/lanyz1/TGSEC-Qtzuu.git}"
TARGET="${1:-$HOME/security-suite}"
echo "=== TGSEC reinstall → $TARGET ==="
if [ -d "$TARGET/.git" ]; then
  git -C "$TARGET" fetch origin || true
  git -C "$TARGET" checkout master 2>/dev/null || git -C "$TARGET" checkout main 2>/dev/null || true
  git -C "$TARGET" pull --ff-only origin master 2>/dev/null || git -C "$TARGET" pull --ff-only origin main 2>/dev/null || git -C "$TARGET" pull --rebase || true
else
  if [ -e "$TARGET" ] && [ ! -d "$TARGET/.git" ]; then
    mv "$TARGET" "$TARGET.bak.$(date +%s)"
  fi
  git clone --depth 1 "$REPO_URL" "$TARGET"
fi
bash "$TARGET/scripts/bootstrap.sh" --force
echo "=== done: $TARGET ==="
