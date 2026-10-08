# 卡商后台接管战报

- Source report: `kashang_takeover.md`
- 全文: 已撤出仓库（原文留本机案卷）
- Techniques: auth, payment
- Fused: 2026-09-17

## Key findings (distilled)

- 已登录JWT token在会话中
- 系统配置表list泄露全部支付密钥+业务配置

## When to reuse

- 同类标签命中：auth, payment
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
