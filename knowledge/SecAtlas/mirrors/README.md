# Mirrors — External Repository Backups

These are full-file backups of external security tools, mirrored to prevent loss if the original repositories are deleted. Each mirror is a snapshot at a specific commit.

| Repository | Stars | Purpose | Snapshot Date |
|-----------|-------|---------|---------------|
| codex-keysmith | 1437 | Codex CLI instruction injection tool | 2026-07-23 |
| claude-keysmith | 278 | Claude Code CLAUDE.md injection | 2026-07-23 |
| zcode-keysmith | 43 | ZCode AGENTS.md injection | 2026-07-23 |

## Usage

Browse each directory to study the tool's source code and prompt engineering techniques. These are raw copies — no modifications have been made.

## Updating

To update a mirror to the latest version:

```bash
cd mirrors/<repo>
git pull origin main
git add -A
git commit -m "mirror: update <repo> to latest"
```

## Note

These mirrors are full file copies (not git submodules) to ensure content survives even if the upstream repository is deleted.
