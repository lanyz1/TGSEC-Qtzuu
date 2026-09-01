#!/bin/bash
# mule-comment-pr — 黑骡在PR下发评论
PR_NUM="$1"
BODY="$2"
[ -z "$PR_NUM" ] || [ -z "$BODY" ] && { echo "用法: mule-comment-pr <PR_NUMBER> '<评论内容>'"; exit 1; }
[ -z "$GH_TOKEN" ] && { echo "需要 source secrets/github.env"; exit 1; }

curl -sk -X POST "https://api.github.com/repos/shuaiqideyu/SecAtlas/issues/${PR_NUM}/comments" \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    -d "$(python3 -c "import sys,json;print(json.dumps({'body':sys.argv[1]}))" "$BODY")" 2>/dev/null | \
    python3 -c "import sys,json;r=json.load(sys.stdin);print('评论已发' if r.get('id') else '失败')" 2>/dev/null
