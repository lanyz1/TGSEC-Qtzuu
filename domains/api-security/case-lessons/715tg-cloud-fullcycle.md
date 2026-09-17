# 715TG 云控全周期（SQLi/上传/TG）

- Source report: `715TG云控_全周期审计报告.md`
- Full report: `domains/api-security/case-reports/715tg-cloud-fullcycle/715TG云控_全周期审计报告.md`
- Techniques: telegram, sqli, upload
- Fused: 2026-09-17

## Key findings (distilled)

- C001 确认**：JWT 密钥 `your_secret_key` HS256，与教程默认值完全一致，从未更换
- :23:04 material 上传测试（SSTI `{{7*7}}`）
- 关键**：JWT 密钥未换、无速率限制、BOLA 零修复
- 平台更换 JWT 密钥，`your_secret_key` → 401
- JWT 硬编码默认密钥**（CWE-798）：`your_secret_key` 是 FastAPI 教程占位值，全周期仅换过一次（R14→R15），R16 后靠 BFLA 绕过
- BOLA/租户隔离建立在 JWT payload 可控声明上**：密钥已知 = 隔离形同虚设

## When to reuse

- 同类标签命中：telegram, sqli, upload
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
