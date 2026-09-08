#!/bin/bash
# Sync TGSEC Hermes security skills from this repo → ~/.hermes/skills/security
# Usage:
#   bash scripts/sync-hermes-skills.sh           # overlay install (keeps private extras)
#   bash scripts/sync-hermes-skills.sh --pull    # git pull suite first (if inside clone)
#   bash scripts/sync-hermes-skills.sh --dry-run
#   bash scripts/sync-hermes-skills.sh --prune   # DANGER: also delete dest entries not in repo
#
# Default is OVERLAY without --delete so private local skills (e.g. defi-authorize-drain)
# are not wiped.
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
PRUNE=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --pull) PULL=1 ;;
    --prune) PRUNE=1 ;;
    -h|--help)
      sed -n '2,14p' "$0"; exit 0 ;;
  esac
done

echo "================================================"
echo "  TGSEC Hermes skills sync"
echo "  src:  $SRC"
echo "  dest: $DEST"
echo "  mode: $([ "$PRUNE" = 1 ] && echo 'PRUNE (delete extras)' || echo 'OVERLAY (keep private extras)')"
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
  if [ "$PRUNE" = 1 ]; then
    echo "[dry-run] rsync -a --delete $SRC/ $DEST/"
  else
    echo "[dry-run] rsync -a $SRC/ $DEST/  # keeps private extras"
  fi
  find "$SRC" -name SKILL.md | sed "s|$SRC/||" | sort
  exit 0
fi

mkdir -p "$DEST"
if command -v rsync >/dev/null 2>&1; then
  if [ "$PRUNE" = 1 ]; then
    rsync -a --delete "$SRC/" "$DEST/"
  else
    rsync -a "$SRC/" "$DEST/"
  fi
else
  if [ "$PRUNE" = 1 ]; then
    rm -rf "$DEST"
    mkdir -p "$DEST"
  fi
  cp -a "$SRC"/. "$DEST"/
fi

echo "[✓] installed/updated from hermes-skills/:"
find "$SRC" -name SKILL.md | sed "s|$SRC/||" | sort | while read -r p; do
  d=$(dirname "$p")
  desc=$(grep -m1 '^description:' "$DEST/$p" 2>/dev/null | sed 's/description:[[:space:]]*//; s/^"//; s/"$//')
  printf '  - %-28s %s\n' "$d" "$desc"
done

echo ""
echo "[i] private extras left in place (dirs in dest not in public hermes-skills/):"
comm -23 \
  <(find "$DEST" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort) \
  <(find "$SRC"  -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort) \
  | sed 's/^/  - /' || true

echo ""
echo "[✓] done. 开新会话（或重启 gateway）让 skill 目录刷新。"
echo "    验证: 对 agent 说 skill_view(tgsec-suite) / reverse-skill / pentest-execution"
echo "    知识库仍要: git clone/pull https://github.com/lanyz1/TGSEC-Qtzuu → ~/security-suite"
echo "    人格配置: bash $SUITE_DIR/ai-config/hermes/setup.sh"
