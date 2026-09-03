#!/bin/bash
# TGSEC Hermes memories install
# @TGSEC社区 · @TGSEC-Qtzuu 整理
set -euo pipefail
HERMES_DIR="${HERMES_DIR:-$HOME/.hermes}"
MEMORIES_DIR="$HERMES_DIR/memories"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FORCE_MEM="${FORCE_MEMORIES:-0}"

echo "================================================"
echo "  TGSEC Hermes memories setup"
echo "================================================"

if [ ! -d "$HERMES_DIR" ]; then
  echo "[!] no $HERMES_DIR — skip"
  exit 0
fi
mkdir -p "$MEMORIES_DIR"

install_one() {
  local kind="$1"   # USER or MEMORY
  local payload="$SCRIPT_DIR/${kind}.payload.md"
  local dest="$MEMORIES_DIR/${kind}.md"
  if [ ! -f "$payload" ]; then
    echo "[!] missing $payload"
    return 1
  fi
  if [ -f "$dest" ]; then
    local cur=$(wc -c < "$dest" | tr -d ' ')
    local new=$(wc -c < "$payload" | tr -d ' ')
    # never clobber a larger personalized file unless forced
    if [ "$FORCE_MEM" != "1" ] && [ "$cur" -gt "$new" ]; then
      echo "[i] keep existing $dest (${cur}b > payload ${new}b) — set FORCE_MEMORIES=1 to overwrite"
      return 0
    fi
    cp "$dest" "$dest.bak.$(date +%s)"
    echo "[i] backup $dest"
  fi
  cp -f "$payload" "$dest"
  echo "[✓] $dest ($(wc -c < "$dest" | tr -d ' ') bytes)"
}

install_one USER
install_one MEMORY

echo ""
echo "  done. 开新 Hermes 会话生效。"
echo "  FORCE_MEMORIES=1 bash setup.sh  # 强制覆盖"
