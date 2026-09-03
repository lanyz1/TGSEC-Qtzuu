# Session 密码学身份层 · 业务系统 ≠ CMS 注入

## 核心结论（一句话）

不是「不会挖洞」，而是把**需要身份的业务系统**当成**存在单点注入的 CMS** 来打，并在错误方向上花了 **80% 算力**。

目标的真实防线往往是 **密码学身份层**（bcrypt + Telegram HMAC + JWT HS256 / 签名 Cookie），**不是** WAF/过滤。  
框架里的 SQLi / SSTI / RCE 套路在这种架构上 **天然低 ROI** —— 除非：

1. 先拿到有效 session，或能**伪造** session；或  
2. 找到带 URL / 模板 / 反序列化的**回调点**（才回到经典 RCE 链）。

---

## Flask SecureCookie：密钥 = 签名权

攻击者一旦知道 `secret_key`，就拥有和服务器相同的签名能力（**概念示意，仅授权评估**）：

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
# 与服务器相同的密钥（来自泄露的 .env / 默认 dev key / 配置备份）
app.secret_key = "SECRET_KEY_FROM_LEAK"  # 例：勿使用真实生产 key 入库
serializer = SecureCookieSessionInterface().get_signing_serializer(app)
forged = serializer.dumps({
    "user_id": 1,
    "username": "admin",
    "role": "admin",  # 客户端可读结构里直接写角色 → 危险模型
})
# Cookie: session=<forged>
# 全程可离线完成：不需要 SQLi、不需要撞库、不需要先登录（有 key 的前提下）
```

### 要点

- **前提**是密钥泄露或可预测（`dev-only-insecure-key`、镜像默认值、仓库/备份泄露）  
- session 载荷若含 `role` / `is_admin` 且服务端盲信 → 权限模型在客户端  
- 同类：JWT HS256 弱 secret、alg 混淆、kid 注入  

### 评估检查清单

- [ ] secret 是否默认/硬编码/进 git/进前端包  
- [ ] session/JWT 是否内嵌角色且无服务端再查库  
- [ ] 是否可改为服务端 session（见下）  
- [ ] Telegram `init_data` 是否按 Bot Token 严格 HMAC；空 init / phone-only 是否另开旁路  

---

## 纵深防御（加固）

| 措施 | 说明 |
|------|------|
| Session 服务端存储 | Redis + **随机 session id**；Cookie 只带不透明 id |
| 敏感操作二次验证 | MFA、re-auth；改支付/收款地址强制二次 |
| 密钥管理 | Vault/KMS，定期轮换，**泄露即作废** |
| 权限模型 | **不要**把 role/权限只放在客户端可读/可签结构里；服务端按 `user_id` 查库 |
| 密钥与配置 | 禁止 dev key 上生产；配置与代码分离 |

---

## ROI 决策树

```text
目标是 CMS/老 PHP/明显注入面？
  ├─ 是 → SQLi/上传/RCE 仍可能高 ROI
  └─ 否 → 业务系统 + 登录/Bot/JWT？
        ├─ 身份层（session/JWT/HMAC/bcrypt）→ 优先
        │     密钥泄露 · 伪造 · 注册状态机 · 无 auth 写接口
        └─ 仍要 RCE？→ 仅当存在 回调 URL / 模板 / 反序列化 / 文件解析
```

### 错误算力（避免）

| 错误 | 为何低 ROI |
|------|------------|
| 对强身份业务无脑 sqlmap | 无注入面或 ORM 参数化 |
| 死磕 WAF 当主线 | 真防线在 HMAC/JWT |
| 未拿 session 就喷 RCE | 无入口 |
| 只爆 admin，忽略 user 链与 setup | 旁路在 A2/A4 |

### 正确优先

1. 密钥与配置泄露 → session/JWT 伪造  
2. 无 auth 写接口（settings / payment-methods / setup）  
3. 注册/状态机旁路（无 init、phone-only）  
4. IDOR / 角色混淆  
5. 再考虑 SSRF/回调/模板  

下接 Anti-Logic：`redteam-framework/anti-logic-layout.md`



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
