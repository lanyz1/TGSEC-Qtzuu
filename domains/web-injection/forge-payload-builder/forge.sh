#!/bin/sh
# 终端界面（TUI）。零参数交互，不用记任何选项。
cd "$(dirname "$0")" || exit 1
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
exec "$PY" -m forge "$@"
