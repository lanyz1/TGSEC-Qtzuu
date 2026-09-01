#!/bin/bash
# mule-auto-maintain — 黑骡全自动仓库维护器
# 审 + 判 + 合 + 学 四步闭环

set -e

GH_TOKEN="${GH_TOKEN:-}"
[ -z "$GH_TOKEN" ] && { echo "需要 GH_TOKEN"; exit 1; }

REPO="shuaiqideyu/SecAtlas"
API="https://api.github.com/repos/${REPO}"
HEADER="Authorization: Bearer ${GH_TOKEN}"
LOCAL_REPO="/tmp/SecAtlas"

cd "$LOCAL_REPO" 2>/dev/null || { echo "需要 /tmp/SecAtlas 本地克隆"; exit 1; }

# 同步最新
git pull origin main -q 2>/dev/null

echo "⚔️ 黑骡全自动维护器"
echo ""

# === 阶段1: 审查开放PR ===
prs=$(curl -sk -H "$HEADER" "${API}/pulls?state=open&per_page=5" 2>/dev/null)
pr_count=$(echo "$prs" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

if [ "$pr_count" -eq 0 ]; then
    echo "📭 无开放PR"
else
    echo "📋 $pr_count 个开放PR待审查"
    echo ""
    
    echo "$prs" | python3 -c "
import sys, json, subprocess, re, os

prs = json.load(sys.stdin)
token = os.environ.get('GH_TOKEN','')
repo = os.environ.get('REPO','shuaiqideyu/SecAtlas')
api = f'https://api.github.com/repos/{repo}'
header = f'Authorization: Bearer {token}'

for pr in prs:
    num = pr['number']
    title = pr['title']
    user = pr['user']['login']
    diff_url = pr['diff_url']
    
    # 获取diff
    import urllib.request
    req = urllib.request.Request(diff_url)
    diff_resp = urllib.request.urlopen(req, timeout=10)
    diff = diff_resp.read().decode(errors='replace')
    
    # === 黑骡判断逻辑 ===
    score = 100
    reasons = []
    
    # 1. 格式规范
    emoji_map = {'🔬':'case','🗡️':'technique','🔧':'tool','📚':'knowledge','🐛':'fix','📖':'doc','🌐':'meta'}
    emoji = title[:2] if len(title)>=2 else ''
    if emoji in emoji_map:
        reasons.append(f'✅ 类型: {emoji_map[emoji]}')
    else:
        reasons.append('⚠️ 标题缺类型emoji')
        score -= 10
    
    # 2. 是否有实质性新增
    added_lines = len([l for l in diff.split('\n') if l.startswith('+') and not l.startswith('+++')])
    if added_lines >= 10:
        reasons.append(f'✅ 新增{added_lines}行')
    elif added_lines >= 3:
        reasons.append(f'⚠️ 仅新增{added_lines}行')
        score -= 10
    else:
        reasons.append('❌ 几乎无新增内容')
        score -= 30
    
    # 3. 是否含敏感信息
    if 'ghp_' in diff or 'github_pat_' in diff or 'sk-' in diff:
        reasons.append('❌ 检测到疑似密钥泄露!')
        score -= 40
    else:
        reasons.append('✅ 无密钥泄露')
    
    # 4. 文件类型检查
    new_files = re.findall(r'^\+\+\+ b/(.+)$', diff, re.M)
    valid_paths = [f for f in new_files if f.startswith(('blackmule/','通用漏洞技术/','Web与API安全/','网络与协议安全/','云与云原生安全/','源码审计_','scripts/','templates/','AGENTS.md','CONTRIBUTING.md','agent-manifest.yaml'))]
    if valid_paths:
        reasons.append(f'✅ 路径有效: {len(valid_paths)}个文件')
    else:
        reasons.append('⚠️ 文件路径不在标准目录')
        score -= 5
    
    # === 判决 ===
    if score >= 80:
        verdict = 'APPROVE'
        action = '🟢 自动通过'
    elif score >= 60:
        verdict = 'COMMENT'
        action = '🟡 需要改进'
    else:
        verdict = 'REJECT'
        action = '🔴 需要重做'
    
    print(f'PR #{num}: {title}')
    print(f'  作者: {user} | 评分: {score}/100 | {action}')
    for r in reasons:
        print(f'    {r}')
    
    # === 执行合并 ===
    if verdict == 'APPROVE':
        # 尝试合并
        merge_url = f'{api}/pulls/{num}/merge'
        merge_data = json.dumps({
            'commit_title': f'{title} (via BlackMule auto-merge)',
            'merge_method': 'squash'
        }).encode()
        try:
            merge_req = urllib.request.Request(merge_url, data=merge_data, 
                headers={'Authorization': header.replace('Authorization: ',''), 
                         'Content-Type':'application/json',
                         'Accept':'application/vnd.github+json'},
                method='PUT')
            merge_resp = urllib.request.urlopen(merge_req, timeout=15)
            merge_result = json.loads(merge_resp.read())
            if merge_result.get('merged'):
                print(f'    🎉 已自动合并!')
                print(f'    MERGED: true')
            else:
                print(f'    ⚠️ 合并失败: {merge_result.get(\"message\",\"?\")}')
        except Exception as e:
            err = str(e)[:100]
            if '405' in err:
                print(f'    ⚠️ 无法自动合并(可能有冲突)')
            elif '401' in err:
                print(f'    ❌ Token权限不足(需要repo scope)')
            else:
                print(f'    ⚠️ 合并异常: {err}')
    elif verdict == 'COMMENT':
        # 添加评论
        comment_url = f'{api}/issues/{num}/comments'
        comment = f'🤖 黑骡自动审查: {score}/100分\n\n'
        for r in reasons:
            comment += f'- {r}\n'
        comment += f'\n请修正后重新提交。参考 [AGENTS.md](https://github.com/{repo}/blob/main/AGENTS.md)'
        try:
            comment_req = urllib.request.Request(comment_url, 
                data=json.dumps({'body': comment}).encode(),
                headers={'Authorization': header.replace('Authorization: ',''),
                         'Content-Type':'application/json',
                         'Accept':'application/vnd.github+json'})
            urllib.request.urlopen(comment_req, timeout=10)
            print(f'    💬 已评论反馈')
        except:
            pass
    
    print()
" 2>/dev/null
fi

echo ""
echo "=== 维护完成 ==="
