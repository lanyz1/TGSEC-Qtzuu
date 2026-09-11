#!/usr/bin/env bash
# Wrapper: every commit in this repo uses 2026-04-30T19:00:00+01:00
# Usage: ./scripts/git-commit-1900.sh -m "message"
set -euo pipefail
export GIT_AUTHOR_DATE="2026-04-30T19:00:00+01:00"
export GIT_COMMITTER_DATE="2026-04-30T19:00:00+01:00"
git commit --date="2026-04-30T19:00:00+01:00" "$@"
