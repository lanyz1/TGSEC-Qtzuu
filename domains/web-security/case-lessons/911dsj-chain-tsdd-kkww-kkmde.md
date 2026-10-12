# 911DSJ 产业链课 · TSDD / kkww / kkmde 三线（吃瓜导流 → 黑产）

- Source report: 报告包 20261012（`911DSJ_SITE_REPORT`；原文留本机案卷）
- Techniques: wukongim-tsdd, shop-mall-jwt, visitor-chat-unauth, electron-reverse
- Fused: 2026-10-12

## 链

1. 入口站 Typecho 后台受保护（CF + nginx 重写 + IP 白名单）→ 从广告位/分发域横向至下游业务链
2. **TSDD（唐僧叨叨 / WuKongIM 系 IM SaaS）总后台**：默认测试账号 + 弱口令 → 超管（role=admin / superAdmin 确认）；**垂直越权：任意用户 token 可读全量 manager 数据** → 导出 2390 用户 / 3514 群 / 453 手机号 / 20 管理员清单；写操作返回「无权」= **受限超管**
3. **kkww 商户中心**：`/shopapi/*`（shop/info、finance、order、goods）全通；26 个弱口令商户 → JWT；368 商户资产；**资金实证：单店全额提现提交 $12,776.02 + 一单 $50 审核中**；配套「提现拒审 → 缴保证金」二次收割话术（归 social-eng 邻域）
4. **kkmde 客服**：`/api/chat/visitor/*` 23 接口无鉴权（chatStart userId 注入、转人工、加解密闭环）；AES 全局硬编码 key=iv
5. **Nectra / 语乐乐**：Electron 拆包 → 签名 + AES-ECB 全复刻；16 个 appKey 收集完毕；滑块 go-captcha 模板匹配已写（服务端容差未过）

## 口径纪律（诚实模板）

报告 §0 专门「对照记忆纠偏」段：明确纠正「总后台和服务器已拿下」的记忆偏差 —— **总后台 = TSDD（已拿）、服务器 = 未拿**。
⚠️ **911DSJ 线与 HEIYT 线勿混**（两条独立战役）。

## 诚实卡点

Windows 宝塔/RDP/FTP 未破（47.96.147.211 / 107.189.2.182）；911dsj 自身 Typecho 真后台；TSDD 写操作 + 内网 MySQL 8306；kkmde 客服端登录；Nectra 有效账号；SafeLine 9443 / Adminer 8099

## When to reuse

- TSDD/WuKongIM SaaS 接管 → `tsdd-wukongim-im-pentest`（本课即来源案例；此前全库零覆盖）
- 客服 visitor 全链 → `chinese-fund-scam-platform-pentest` 客服 SaaS 段 / `pentest-execution/references/ocs-visitor-chat-api.md`
- Electron 协议逆向 → `electron-app-source-recon` / `websocket-encrypted-protocol-reverse`

@TGSEC社区 · @TGSEC-Qtzuu 整理
