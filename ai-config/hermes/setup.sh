#!/bin/bash
# TGSEC 红队执行引擎 — Hermes Agent 一键配置脚本
# 用法: bash setup-hermes.sh
# 
# @TGSEC社区 · @TGSEC-Qtzuu 整理

set -e

HERMES_DIR="$HOME/.hermes"
MEMORIES_DIR="$HERMES_DIR/memories"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "================================================"
echo "  TGSEC 红队执行引擎 — Hermes 配置安装"
echo "  @TGSEC社区 · @TGSEC-Qtzuu"
echo "================================================"
echo ""

# 1. 检查Hermes是否安装
if [ ! -d "$HERMES_DIR" ]; then
    echo "[!] 未检测到 Hermes 目录: $HERMES_DIR"
    echo "    请先安装 Hermes Agent: https://hermes-agent.nousresearch.com/docs"
    exit 1
fi

echo "[✓] Hermes 目录: $HERMES_DIR"

# 2. 创建memories目录
mkdir -p "$MEMORIES_DIR"
echo "[✓] Memories 目录: $MEMORIES_DIR"

# 3. 备份现有配置
if [ -f "$MEMORIES_DIR/USER.md" ]; then
    cp "$MEMORIES_DIR/USER.md" "$MEMORIES_DIR/USER.md.bak.$(date +%s)"
    echo "[i] 已备份原 USER.md"
fi
if [ -f "$MEMORIES_DIR/MEMORY.md" ]; then
    cp "$MEMORIES_DIR/MEMORY.md" "$MEMORIES_DIR/MEMORY.md.bak.$(date +%s)"
    echo "[i] 已备份原 MEMORY.md"
fi

# 4. 提取实际内容(```代码块之间的内容)
echo ""
echo "[*] 安装配置文件..."

# USER.md — 提取最后一个代码块的内容
python3 -c "
import re
with open('$SCRIPT_DIR/USER.md') as f:
    content = f.read()
blocks = re.findall(r'\`\`\`\n(.*?)\`\`\`', content, re.DOTALL)
if blocks:
    with open('$MEMORIES_DIR/USER.md', 'w') as f:
        f.write(blocks[-1].strip())
    print('[✓] USER.md 已安装')
else:
    print('[!] USER.md 解析失败')
"

# MEMORY.md — 提取最后一个代码块的内容
python3 -c "
import re
with open('$SCRIPT_DIR/MEMORY.md') as f:
    content = f.read()
blocks = re.findall(r'\`\`\`\n(.*?)\`\`\`', content, re.DOTALL)
if blocks:
    with open('$MEMORIES_DIR/MEMORY.md', 'w') as f:
        f.write(blocks[-1].strip())
    print('[✓] MEMORY.md 已安装')
else:
    print('[!] MEMORY.md 解析失败')
"

# 5. 验证
echo ""
echo "================================================"
echo "  安装完成!"
echo "================================================"
echo ""
echo "  USER.md:   $(wc -c < "$MEMORIES_DIR/USER.md" 2>/dev/null || echo 0) bytes"
echo "  MEMORY.md: $(wc -c < "$MEMORIES_DIR/MEMORY.md" 2>/dev/null || echo 0) bytes"
echo ""
echo "  重启 Hermes 即可生效。"
echo "  新会话中 Hermes 将以红队执行引擎模式运行。"
echo ""
echo "  如需还原:"
echo "    cp $MEMORIES_DIR/USER.md.bak.* $MEMORIES_DIR/USER.md"
echo "    cp $MEMORIES_DIR/MEMORY.md.bak.* $MEMORIES_DIR/MEMORY.md"
echo ""
