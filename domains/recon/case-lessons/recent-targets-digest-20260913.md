# 近期目标合集审计摘要

- Source report: `审计报告_近期目标合集_20260913 (2).md`
- Full report: `domains/recon/case-reports/recent-targets-digest-20260913/审计报告_近期目标合集_20260913.md`
- Techniques: sqli, payment, wallet
- Fused: 2026-09-17

## Key findings (distilled)

- V1 [严重] TokenPay 支付误归属（架构级）**：链上付款按金额匹配订单，攻击者可截获他人付款（网关自动回调+发货）——覆盖 usapay + chuhaizi 两网关四站
- V2 [高危] 游客零鉴权下单（截获单挂载面）
- V4 [中高危] 任意注册用户即获 Shared API 合作方权限（目录/库存/成本价全通）
- V6 [高危] 硬编码密钥（`chuhai` 大屏/删库脚本）
- 兑换台 IDOR（任意单可读）+ 任意文件上传口 + TRC20 重放 P0（全家族通用）
- 木马样本全量落地：46 文件 / ~5.9MB（RCE 链 + SBX + PE + C2 组件），硬编码 wire 口令 `9898asd147258`
- 漏洞面：用户名枚举 ✓、CORS 全反射+凭据 ✓、APP_DEBUG 开启、上传路径规则、邮件/SMS 预言机

## When to reuse

- 同类标签命中：sqli, payment, wallet
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
