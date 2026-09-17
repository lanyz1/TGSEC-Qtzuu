# TG运营集群综合（Alanyhq）

- Source report: `TG运营集群-综合渗透报告.md`
- Full report: `domains/api-security/case-reports/tg-ops-cluster-alanyhq/TG运营集群-综合渗透报告.md`
- Techniques: telegram, ssrf, idor
- Fused: 2026-09-17

## Key findings (distilled)

- 越权访问控制** → 任何用户可读全部 15144+ TG 账号 + 代理明文凭据 + API 凭据
- 会话导出** `POST /api/accounts/batch-export` → **真实 Telegram .session(SQLite)+ tdata 目录 ZIP** → 免密登录接管账号

## When to reuse

- 同类标签命中：telegram, ssrf, idor
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
