#!/usr/bin/env bash
# install-tools.sh — 自动安装缺失工具(多通道: apt/pipx/uv/npx/go/gobin/git)
# 用法: bash scripts/install-tools.sh [--category recon,web] [--dry-run] [--channel apt]
set -euo pipefail

MANIFEST="$(dirname "$0")/tools-manifest.json"
DRY_RUN=false
CATS=()
CHANNELS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --category) shift; IFS=',' read -ra CATS <<< "$1"; shift ;;
    --channel) shift; IFS=',' read -ra CHANNELS <<< "$1"; shift ;;
    *) shift ;;
  esac
done

DEST="${TOOLS_DIR:-$HOME/tools}"
mkdir -p "$DEST/bin" "$DEST/src"

log()  { printf '\033[36m[信息]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[WARN]\033[0m %s\n' "$*"; }
err()  { printf '\033[31m[ERR]\033[0m %s\n' "$*"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# 若工具已在 PATH 直接跳过
already() { has_cmd "$1" && return 0; return 1; }

install_gobin() {
  local repo="$1" name="$2"
  log "go install $repo ..."
  if "$DRY_RUN"; then echo "  (dry-run) go install $repo@latest"; return 0; fi
  GO_FLAGS="" go install "$repo@latest" 2>/dev/null || warn "go install $repo 失败(需 go env)"
  # go bin 加到 PATH
  GO_BIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
  if [ -x "$GO_BIN/$name" ]; then
    cp "$GO_BIN/$name" "$DEST/bin/$name" 2>/dev/null || true
    ok "安装成功: $name"
  fi
}

install_pipx() {
  local pkg="$1" name="$2"
  log "pipx install $pkg ..."
  if "$DRY_RUN"; then echo "  (dry-run) pipx install $pkg"; return 0; fi
  if ! has_cmd pipx; then
    python3 -m pip install --user pipx 2>/dev/null || warn "pipx 未安装,尝试 uv"
    if has_cmd uv; then
      uv tool install "$pkg" 2>/dev/null && ok "$name 安装成功(uv)" || warn "uv 安装 $pkg 失败"
      return 0
    fi
  fi
  pipx install "$pkg" 2>/dev/null && ok "$name 安装成功" || warn "pipx 安装 $pkg 失败"
}

install_apt() {
  local pkg="$1" name="$2"
  if already "$name"; then ok "$name 已存在"; return 0; fi
  log "apt install $pkg ..."
  if "$DRY_RUN"; then echo "  (dry-run) apt install -y $pkg"; return 0; fi
  if has_cmd apt-get && (has_cmd sudo || [ "$(id -u)" = "0" ]); then
    (sudo apt-get update -qq 2>/dev/null || apt-get update -qq 2>/dev/null || true)
    if sudo apt-get install -y "$pkg" 2>/dev/null || apt-get install -y "$pkg" 2>/dev/null; then
      ok "$name 安装成功(apt)"
    else
      warn "apt 安装 $pkg 失败"
    fi
  else
    warn "需要 sudo/root 才能 apt 安装 $pkg"
  fi
}

install_git() {
  local url="$1" name="$2"
  if already "$name"; then ok "$name 已存在"; return 0; fi
  log "git clone $url → $DEST/src/$name ..."
  if "$DRY_RUN"; then echo "  (dry-run) git clone $url"; return 0; fi
  git clone --depth 1 "$url" "$DEST/src/$name" 2>/dev/null && ok "$name 克隆成功($DEST/src)" || warn "git clone $name 失败"
}

install_npx() {
  local pkg="$1" name="$2"
  log "npx 运行 $pkg ..."
  if "$DRY_RUN"; then echo "  (dry-run) npx $pkg"; return 0; fi
  if has_cmd npx; then ok "$name 可用(npx 按需运行)"; else warn "缺少 npx(node)" || true; fi
}

install_local() {
  # 仓库自带工具(relative to repo root)
  local rel="$1" name="$2"
  local src="$DEST/../$rel"
  if [ -f "$src" ]; then
    chmod +x "$src" 2>/dev/null || true
    ok "$name 本地工具就绪: $src"
  else
    warn "$name 本地工具未找到: $rel"
  fi
}

echo "🗡️  TGSEC 工具自动安装 — $(date '+%Y-%m-%d %H:%M')"
echo "============================================"
if "$DRY_RUN"; then warn "DRY-RUN 模式:不实际安装,仅预览"; fi

python3 - "$MANIFEST" <<'PY' | while IFS='|' read -r cat name pkg channel url purpose; do
import json, sys
manifest = json.load(open(sys.argv[1]))
cats = __import__('os').environ.get('CATS', '')
channels = __import__('os').environ.get('CHANNELS', '')
cat_list = cats.split(',') if cats else []
ch_list = channels.split(',') if channels else []
for cat, tools in manifest.get("tools", {}).items():
    if cat_list and cat not in cat_list:
        continue
    for t in tools:
        if ch_list and t["channel"] not in ch_list:
            continue
        print(f'{cat}|{t["name"]}|{t.get("pkg","")}|{t["channel"]}|{t.get("url","")}|{t.get("purpose","")}')
PY
    [ -z "$pkg" ] && continue
    case "$channel" in
      apt)   install_apt "$pkg" "$name" ;;
      pipx)  install_pipx "$pkg" "$name" ;;
      uv)    install_pipx "$pkg" "$name" ;;
      npx)   install_npx "$pkg" "$name" ;;
      gobin) install_gobin "$pkg" "$name" ;;
      git)   install_git "$url" "$name" ;;
      local) install_local "$pkg" "$name" ;;
      system) ok "$name 系统自带: $pkg" ;;
      *)     warn "未知通道 $channel: $name" ;;
    esac
done

echo ""
echo "✅ 安装完成! 如需本机全局可用,把路径加入 PATH:"
echo "   export PATH=\"$DEST/bin:\$PATH\""
