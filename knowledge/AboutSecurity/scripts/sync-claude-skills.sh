#!/usr/bin/env bash
# sync-claude-skills.sh
#
# Generates .claude/skills/ symlinks from the nested skills/ directory.
# This makes AboutSecurity skills compatible with Claude Code,
# which only recognizes .claude/skills/<name>/SKILL.md (flat, one level).
#
# Usage:
#   ./scripts/sync-claude-skills.sh                        # 同步到本仓库 .claude/skills/
#   ./scripts/sync-claude-skills.sh --target /path/to/project  # 同步到指定项目

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILLS_SRC="$REPO_ROOT/skills"

# Parse arguments
TARGET_PROJECT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET_PROJECT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--target /path/to/project]"
            echo ""
            echo "Options:"
            echo "  --target <dir>  Sync skills to target project's .claude/skills/"
            echo "                  If omitted, syncs to this repo's .claude/skills/"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--target /path/to/project]"
            exit 1
            ;;
    esac
done

# Determine target directory
if [ -n "$TARGET_PROJECT" ]; then
    CLAUDE_DIR="$TARGET_PROJECT/.claude/skills"
    # Cross-directory symlinks require absolute paths
    USE_ABSOLUTE=true
else
    CLAUDE_DIR="$REPO_ROOT/.claude/skills"
    USE_ABSOLUTE=false
fi

if [ ! -d "$SKILLS_SRC" ]; then
    echo "❌ Skills directory not found: $SKILLS_SRC"
    exit 1
fi

if [ -n "$TARGET_PROJECT" ] && [ ! -d "$TARGET_PROJECT" ]; then
    echo "❌ Target project directory not found: $TARGET_PROJECT"
    exit 1
fi

# Create .claude/skills/ if it doesn't exist
mkdir -p "$CLAUDE_DIR"

# Remove existing symlinks (stale cleanup)
find "$CLAUDE_DIR" -maxdepth 1 -type l -delete

# Create symlinks
find "$SKILLS_SRC" -name "SKILL.md" -type f | while read -r skill_md; do
    skill_dir="$(dirname "$skill_md")"
    skill_id="$(basename "$skill_dir")"

    if [ -e "$CLAUDE_DIR/$skill_id" ] && [ ! -L "$CLAUDE_DIR/$skill_id" ]; then
        echo "⚠️  Skipping $skill_id (non-symlink file/dir already exists)"
        continue
    fi

    if [ "$USE_ABSOLUTE" = true ]; then
        ln -sfn "$skill_dir" "$CLAUDE_DIR/$skill_id"
    else
        rel_path="$(python3 -c "import os.path; print(os.path.relpath('$skill_dir', '$CLAUDE_DIR'))")"
        ln -sfn "$rel_path" "$CLAUDE_DIR/$skill_id"
    fi
done

# Count results
total=$(find "$CLAUDE_DIR" -maxdepth 1 -type l | wc -l | tr -d ' ')
echo "✅ Synced $total skills → $CLAUDE_DIR"
echo "   Source: $SKILLS_SRC (nested)"
echo "   Target: $CLAUDE_DIR (flat symlinks)"
