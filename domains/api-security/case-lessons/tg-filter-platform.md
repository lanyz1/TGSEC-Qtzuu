# TG筛号平台 SQLi/认证

- Source report: `TG筛号平台-渗透测试报告.md`
- Full report: `domains/api-security/case-reports/tg-filter-platform/TG筛号平台-渗透测试报告.md`
- Techniques: telegram, sqli, auth
- Fused: 2026-09-17

## Key findings (distilled)

- `{phone}/{phone}.session`(28672B, SQLite = Telethon 会话含 auth key)
- 说明平台有基础 WAF/限流防护,但**核心漏洞(注册提权/越权/会话导出)未修复**
- WAF 强化**:当前对批量操作有限流但未阻断漏洞本身

## Repro snippets

```
匿名 → 注册(role=admin)→ 登录 → GET /api/accounts(读全部账号+session路径)
→ POST /api/accounts/batch-export(下载全部 .session + tdata ZIP)
→ 用 session 登录 = 接管全部 15144+ TG 账号
同时:代理池明文凭据(100+)、TG API 凭据全部泄露
**代理凭据示例:**
```

## When to reuse

- 同类标签命中：telegram, sqli, auth
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
