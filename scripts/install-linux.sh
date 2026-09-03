#!/bin/bash
# TGSEC 小白一键（Linux/Mac/WSL）
set -euo pipefail
REPO="${TGSEC_REPO_URL:-https://github.com/lanyz1/TGSEC-Qtzuu.git}"
DIR="${TGSEC_DIR:-$HOME/security-suite}"
echo "[TGSEC] 安装到 $DIR"
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull --ff-only || git -C "$DIR" pull --rebase || true
else
  git clone --depth 1 "$REPO" "$DIR"
fi
if [ -f "$DIR/scripts/bootstrap.sh" ]; then
  bash "$DIR/scripts/bootstrap.sh" --force || bash "$DIR/scripts/bootstrap.sh" || true
fi
echo ""
echo "完成！下一步："
echo "  1. 用 AI 打开文件夹：$DIR"
echo "  2. 对 AI 说：请先读 START.md"
echo "  详见 $DIR/START.md"
