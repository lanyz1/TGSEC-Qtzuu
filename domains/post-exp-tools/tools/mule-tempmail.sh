#!/bin/bash
# mule-tempmail - 黑骡临时邮箱模块
# 基于 GuerrillaMail API，自动获取/检查/等待邮件
# 用途: 注册验证、密码重置等需要邮箱确认的场景

GM_BASE="https://api.guerrillamail.com/ajax.php"
GM_STATE="/tmp/mule_tempmail_state.json"

cmd="${1:-create}"
shift 2>/dev/null

case "$cmd" in
    create)
        resp=$(curl -sk -m 10 "${GM_BASE}?f=get_email_address&ip=127.0.0.1&agent=BlackMule" 2>/dev/null)
        email=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['email_addr'])" 2>/dev/null)
        token=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['sid_token'])" 2>/dev/null)
        echo "{\"email\":\"$email\",\"sid_token\":\"$token\",\"seq\":0}" > "$GM_STATE"
        echo "email: $email"
        echo "token: $token"
        ;;
    check)
        token=$(python3 -c "import json;d=json.load(open('$GM_STATE'));print(d['sid_token'])" 2>/dev/null)
        seq=$(python3 -c "import json;d=json.load(open('$GM_STATE'));print(d.get('seq',0))" 2>/dev/null)
        resp=$(curl -sk -m 10 "${GM_BASE}?f=check_email&sid_token=${token}&seq=${seq}" 2>/dev/null)
        count=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('list',[])))" 2>/dev/null)
        echo "$resp" | python3 -m json.tool 2>/dev/null
        echo "count: $count"
        ;;
    wait)
        timeout="${1:-120}"
        token=$(python3 -c "import json;d=json.load(open('$GM_STATE'));print(d['sid_token'])" 2>/dev/null)
        start=$(date +%s)
        while true; do
            [ $(($(date +%s) - start)) -ge "$timeout" ] && echo "TIMEOUT" && exit 1
            resp=$(curl -sk -m 10 "${GM_BASE}?f=check_email&sid_token=${token}&seq=0" 2>/dev/null)
            count=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('list',[])))" 2>/dev/null)
            if [ "$count" -gt 0 ]; then
                mail_id=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['list'][0]['mail_id'])" 2>/dev/null)
                subject=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['list'][0]['mail_subject'])" 2>/dev/null)
                full=$(curl -sk -m 10 "${GM_BASE}?f=fetch_email&sid_token=${token}&email_id=${mail_id}" 2>/dev/null)
                body=$(echo "$full" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('mail_body',''))" 2>/dev/null)
                echo "FROM: $(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['list'][0]['mail_from'])" 2>/dev/null)"
                echo "SUBJECT: $subject"
                echo "BODY: $body"
                code=$(echo "$body" | grep -oP '\b\d{6}\b' | head -1)
                [ -n "$code" ] && echo "CODE: $code"
                exit 0
            fi
            sleep 5
        done
        ;;
    state)
        [ -f "$GM_STATE" ] && cat "$GM_STATE" | python3 -m json.tool 2>/dev/null || echo "No active temp email"
        ;;
    *)
        echo "Usage: mule-tempmail {create|check|wait [timeout]|state}"
        exit 1
        ;;
esac
