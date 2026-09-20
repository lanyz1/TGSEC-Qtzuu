#!/bin/sh
# 图形界面。SSH / 无显示器环境请用 ./forge.sh（TUI）。
cd "$(dirname "$0")" || exit 1
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
exec "$PY" gui.py "$@"
