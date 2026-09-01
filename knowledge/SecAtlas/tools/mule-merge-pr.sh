#!/bin/bash
# mule-merge-pr — 黑骡合并指定PR
# 用法: source /root/.hermes/secrets/github.env && mule-merge-pr <PR_NUMBER> [reason]

PR_NUM="$1"
REASON="${2:-BlackMule auto-merge}"

[ -z "$PR_NUM" ] && { echo "用法: mule-merge-pr <PR_NUMBER> [reason]"; exit 1; }
[ -z "$GH_TOKEN" ] && { echo "需要 source secrets/github.env"; exit 1; }

API="https://api.github.com/repos/shuaiqideyu/SecAtlas/pulls/${PR_NUM}"

# 获取PR信息
pr_info=$(curl -sk -H "Authorization: Bearer $GH_TOKEN" "$API" 2>/dev/null)
title=$(echo "$pr_info" | python3 -c "import sys,json;print(json.load(sys.stdin).get('title','?'))" 2>/dev/null)
state=$(echo "$pr_info" | python3 -c "import sys,json;print(json.load(sys.stdin).get('state','?'))" 2>/dev/null)
mergeable=$(echo "$pr_info" | python3 -c "import sys,json;print(json.load(sys.stdin).get('mergeable',None))" 2>/dev/null)

echo "PR #${PR_NUM}: $title"
echo "State: $state | Mergeable: $mergeable"

if [ "$state" != "open" ]; then
    echo "PR已关闭，跳过"
    exit 0
fi

# 尝试合并
resp=$(curl -sk -X PUT "${API}/merge" \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    -d "{\"commit_title\":\"${title} (via BlackMule)\",\"merge_method\":\"squash\"}" 2>/dev/null)

merged=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('merged',False))" 2>/dev/null)
message=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('message',''))" 2>/dev/null)

if [ "$merged" = "True" ]; then
    echo "✅ 合并成功!"
    exit 0
else
    echo "❌ 合并失败: $message"
    exit 1
fi
