#!/bin/bash
# TGSEC — 伞形技能一键装到多种 AI（Claude / Cursor / Codex / Gemini / 通用 agents / Hermes）
#
#   bash scripts/sync-agent-skills.sh
#   bash scripts/sync-agent-skills.sh --project-only
#   bash scripts/sync-agent-skills.sh --user-only
#   bash scripts/sync-agent-skills.sh --dest /custom/skills/dir
#
# @TGSEC社区 · @TGSEC-Qtzuu 整理
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$ROOT/hermes-skills"

PROJECT_ONLY=0
USER_ONLY=0
EXTRA_DEST=""

while [ $# -gt 0 ]; do
  case "$1" in
    --project-only) PROJECT_ONLY=1; shift ;;
    --user-only) USER_ONLY=1; shift ;;
    --dest)
      EXTRA_DEST="${2:-}"
      if [ -z "$EXTRA_DEST" ]; then echo "[!] --dest needs path"; exit 1; fi
      shift 2
      ;;
    -h|--help)
      cat <<'H'
用法: bash scripts/sync-agent-skills.sh [选项]
  (默认)           项目内 + 用户主目录 skills
  --project-only   只装到本仓库 .claude/skills 等
  --user-only      只装到 ~/.claude/skills 等
  --dest DIR       额外复制一份到 DIR
H
      exit 0
      ;;
    *) echo "[!] unknown: $1"; exit 1 ;;
  esac
done

if [ ! -d "$SRC" ]; then
  echo "[!] missing $SRC"
  exit 1
fi

rewrite_skill_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  command -v python3 >/dev/null 2>&1 || return 0
  python3 - "$f" "$ROOT" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
root = Path(sys.argv[2]).resolve()
t = p.read_text(encoding="utf-8", errors="replace")
orig = t
for old in (str(root), "/root/security-suite", str(Path.home() / "security-suite")):
    t = t.replace(old + "/", "")
    t = t.replace(old, ".")
note = (
    "\n\n> **路径说明（全 AI）：** 知识正文在包根 `domains/`；"
    "配合 `ROUTING.md` / `MASTER.md` / `START.md`。"
    "Windows 请优先用 `domains/`，勿依赖 Linux 专用绝对路径。\n"
)
if "路径说明（全 AI）" not in t and p.name == "SKILL.md":
    if t.startswith("---"):
        parts = t.split("---", 2)
        if len(parts) >= 3:
            t = "---" + parts[1] + "---" + note + parts[2]
        else:
            t = t + note
    else:
        t = note + t
if t != orig:
    p.write_text(t, encoding="utf-8")
PY
}

copy_tree() {
  local dest="$1"
  mkdir -p "$dest"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude 'README.md' "$SRC"/ "$dest"/
  else
    find "$dest" -mindepth 1 -maxdepth 1 ! -name '.' -exec rm -rf {} + 2>/dev/null || true
    for d in "$SRC"/*/; do
      [ -d "$d" ] || continue
      name="$(basename "$d")"
      rm -rf "$dest/$name"
      cp -a "$d" "$dest/$name"
    done
  fi
  find "$dest" -name 'SKILL.md' -print0 | while IFS= read -r -d '' f; do
    rewrite_skill_file "$f"
  done
  local n
  n="$(find "$dest" -name 'SKILL.md' | wc -l | tr -d ' ')"
  echo "[✓] $dest  ($n skills)"
}

echo "================================================"
echo "  TGSEC sync-agent-skills"
echo "  src: $SRC"
echo "================================================"

DESTS=()
if [ "$USER_ONLY" != 1 ]; then
  DESTS+=(
    "$ROOT/.claude/skills"
    "$ROOT/.cursor/skills"
    "$ROOT/.agents/skills"
    "$ROOT/.codex/skills"
    "$ROOT/.gemini/skills"
  )
fi
if [ "$PROJECT_ONLY" != 1 ]; then
  DESTS+=(
    "${HOME}/.claude/skills"
    "${HOME}/.cursor/skills"
    "${HOME}/.agents/skills"
    "${HOME}/.codex/skills"
    "${HOME}/.gemini/skills"
  )
fi
if [ -n "$EXTRA_DEST" ]; then
  DESTS+=("$EXTRA_DEST")
fi

SEEN="|"
for d in "${DESTS[@]}"; do
  case "$SEEN" in
    *"|$d|"*) continue ;;
  esac
  SEEN="${SEEN}${d}|"
  copy_tree "$d"
done

if [ "$PROJECT_ONLY" != 1 ] && [ -d "${HOME}/.hermes" ] && [ -f "$ROOT/scripts/sync-hermes-skills.sh" ]; then
  bash "$ROOT/scripts/sync-hermes-skills.sh" 2>/dev/null || true
  echo "[✓] Hermes (~/.hermes/skills/security)"
fi

echo ""
echo "完成。请新开 Claude Code / Cursor / 对应 AI 会话。"
echo "  项目内: $ROOT/.claude/skills  （在包根启动 Claude 会加载）"
echo "  用户级: ~/.claude/skills  ~/.cursor/skills  ~/.agents/skills …"
echo "  正文:   $ROOT/domains + ROUTING.md + START.md"
echo ""
