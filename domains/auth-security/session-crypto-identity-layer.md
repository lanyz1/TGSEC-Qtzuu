# Session 密码学身份层 · 与「CMS 注入思维」的错位

> 实战复盘：业务系统的真实防线常是 **bcrypt + Telegram HMAC + JWT/签名 Cookie**，不是 WAF。

## 核心结论

把「需要身份的业务系统」当「单点注入 CMS」打 = 低 ROI。  
除非：① 能拿/伪造 session；② 存在 URL/模板/反序列化回调。

## Flask SecureCookie（概念）

`secret_key` 泄露 ⇒ 可离线 `serializer.dumps({... role: admin})` 伪造 session。  
评估：默认 key、.env 泄露、session 内嵌 role 盲信。

## 纵深防御

Session 服务端存储（Redis+随机 id）；敏感操作 MFA；Vault/KMS 轮换；权限以 user_id 查库。

## ROI

优先：密钥泄露、无 auth 写接口、注册/状态机旁路、IDOR。  
避免：对强身份系统无脑 sqlmap。

相关：`redteam-framework/anti-logic-layout.md`



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
