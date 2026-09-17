# peiioh/乐视会议分发链

- Source report: `peiioh_20260819_完整报告.md`
- Full report: `domains/web-attack/case-reports/peiioh-leshi-meeting/peiioh_20260819_完整报告.md`
- Techniques: rce, auth, waf
- Fused: 2026-09-17

## Key findings (distilled)

- 状态：**PAUSED / A**（未接管；下次从 ThinkPHP 5.0.15 股票站或会议 JWT 续打）
- 未授权读：** `GET /api/meeting/status?meetingId=N` 无 Token
- 证据：** `测绘/http/meeting_idor.json` `meeting_join_self.json`
- 利用：** 平台级关会还差 JWT 密钥或主持人票或服务端 RCE
- 证据：** `测绘/http/meeting_end_idor.json`
- 利用：** 当前不能当 Java/JFinal webshell；需解析漏洞或换口
- 穷尽：** JWT 弱密钥短字典未中（见 §4）
- 未授权行情：** `/api/apiindex/hushen` `/api/apiindex/getSetting` `/api/cjapi/*`

## When to reuse

- 同类标签命中：rce, auth, waf
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
