#!/bin/bash
# Sync TGSEC Hermes security skills from this repo → ~/.hermes/skills/security
# Usage:
#   bash scripts/sync-hermes-skills.sh           # overwrite install
#   bash scripts/sync-hermes-skills.sh --pull    # git pull suite first (if inside clone)
#   bash scripts/sync-hermes-skills.sh --dry-run
#
# @TGSEC社区 · @TGSEC-Qtzuu 整理

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUITE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$SUITE_DIR/hermes-skills"
HERMES_DIR="${HERMES_DIR:-$HOME/.hermes}"
DEST="$HERMES_DIR/skills/security"
DRY=0
PULL=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --pull) PULL=1 ;;
    -h|--help)
      sed -n '2,12p' "$0"; exit 0 ;;
  esac
done

echo "================================================"
echo "  TGSEC Hermes skills sync"
echo "  src:  $SRC"
echo "  dest: $DEST"
echo "================================================"

if [ ! -d "$SRC" ]; then
  echo "[!] missing $SRC — repo incomplete. git pull latest TGSEC-Qtzuu first."
  exit 1
fi

if [ ! -d "$HERMES_DIR" ]; then
  echo "[!] Hermes not found at $HERMES_DIR"
  exit 1
fi

if [ "$PULL" = 1 ]; then
  if [ -d "$SUITE_DIR/.git" ]; then
    echo "[*] git pull in $SUITE_DIR"
    git -C "$SUITE_DIR" pull --ff-only || git -C "$SUITE_DIR" pull --rebase
  else
    echo "[!] --pull ignored (not a git clone)"
  fi
fi

mkdir -p "$HERMES_DIR/skills"
STAMP=$(date +%Y%m%d%H%M%S)
if [ -d "$DEST" ] && [ "$DRY" = 0 ]; then
  BAK="$HERMES_DIR/skills/security.bak.$STAMP"
  cp -a "$DEST" "$BAK"
  echo "[i] backup → $BAK"
fi

COUNT=$(find "$SRC" -name SKILL.md | wc -l | tr -d ' ')
echo "[*] will install $COUNT skills from hermes-skills/"

if [ "$DRY" = 1 ]; then
  echo "[dry-run] rsync -a --delete $SRC/ $DEST/"
  find "$SRC" -name SKILL.md | sed "s|$SRC/||" | sort
  exit 0
fi

mkdir -p "$DEST"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete "$SRC/" "$DEST/"
else
  rm -rf "$DEST"
  mkdir -p "$DEST"
  cp -a "$SRC/." "$DEST/"
fi

echo "[✓] installed:"
find "$DEST" -name SKILL.md | sed "s|$DEST/||" | sort | while read -r p; do
  d=$(dirname "$p")
  desc=$(grep -m1 '^description:' "$DEST/$p" | sed 's/description:[[:space:]]*//; s/^"//; s/"$//')
  printf '  - %-28s %s\n' "$d" "$desc"
done

echo ""
echo "[✓] done. 开新会话（或重启 gateway）让 skill 目录刷新。"
echo "    验证: 对 agent 说 skill_view(tgsec-suite) / reverse-skill / pentest-execution"
echo "    知识库仍要: git clone/pull https://github.com/lanyz1/TGSEC-Qtzuu → ~/security-suite"
echo "    人格配置: bash $SUITE_DIR/ai-config/hermes/setup.sh"
