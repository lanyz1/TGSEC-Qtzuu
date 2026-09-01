#!/bin/bash
# mule-review-prs — 黑骡自动 PR 审查器
# 用法: mule-review-prs [--auto-merge] [--dry-run]

set -e

GITHUB_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ 需要设置 GH_TOKEN 环境变量（GitHub Personal Access Token）"
    exit 1
fi
REPO="shuaiqideyu/SecAtlas"
API="https://api.github.com/repos/${REPO}"
HEADER="Authorization: Bearer ${GITHUB_TOKEN}"
AUTO_MERGE=false
DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --auto-merge) AUTO_MERGE=true ;;
        --dry-run) DRY_RUN=true ;;
    esac
done

echo "🔍 黑骡 PR 审查器启动..."
echo "仓库: $REPO"
echo "自动合并: $AUTO_MERGE"
echo ""

# 1. 获取所有开放 PR
prs=$(curl -sk -H "$HEADER" "${API}/pulls?state=open&per_page=10" 2>/dev/null)
pr_count=$(echo "$prs" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

if [ "$pr_count" -eq 0 ]; then
    echo "✅ 无开放 PR，仓库干净。"
    exit 0
fi

echo "发现 $pr_count 个开放 PR"
echo ""

# 2. 逐个审查
echo "$prs" | python3 -c "
import sys, json, subprocess, os, re

prs = json.load(sys.stdin)
token = os.environ.get('GH_TOKEN', '')
auto_merge = os.environ.get('AUTO_MERGE', 'false') == 'true'
dry_run = os.environ.get('DRY_RUN', 'false') == 'true'

for pr in prs:
    num = pr['number']
    title = pr['title']
    user = pr['user']['login']
    head = pr['head']['ref']
    base = pr['base']['ref']
    html_url = pr['html_url']
    body = pr.get('body', '')[:200]
    diff_url = pr['diff_url']
    
    score = 100
    issues = []
    checks = []
    
    # 检查1: 标题格式
    if not re.match(r'^[🔬🔧🐛📚🌐🔴🟡🟢🔵🛡️🗡️🪝🔪🧨📋🛠️📖]', title):
        issues.append('标题缺少类型emoji前缀')
        score -= 10
    
    # 检查2: PR body 非空
    if len(body.strip()) < 10:
        issues.append('PR描述过于简短')
        score -= 10
    
    # 检查3: 文件变更类型合理
    # 这个需要更详细的 diff 分析，先做基本检查
    
    if score >= 80:
        verdict = '✅ 通过'
    elif score >= 60:
        verdict = '⚠️ 需要改进'
    else:
        verdict = '❌ 需要修复'
    
    print(f'PR #{num}: {title}')
    print(f'  作者: {user} | 分支: {head} → {base}')
    print(f'  评分: {score}/100 {verdict}')
    if issues:
        for i in issues:
            print(f'    - {i}')
    print(f'  链接: {html_url}')
    print()
" 2>/dev/null

echo "=== 审查完成 ==="
