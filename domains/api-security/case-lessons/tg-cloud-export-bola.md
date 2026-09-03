# 案例课：TG 云控 / 账号库存 — export BOLA

> 脱敏经验。来自授权实战报告提炼，无真实域名/Token/库存文件。

## 模式

平台：Telegram 云控 / 筛号 / 账号库存（Go/Gin 或同类 + Vue SPA + CDN）。

### 高 ROI 链

```text
开放注册/临时邮箱 → 过图形验证码登录拿 JWT
→ JS bundle 挖 API（accounts/export、sessions、open login-code）
→ POST .../export  { ids:[...], format: session_json }
→ 无 owner 校验 → ZIP 内 .session + .json 批量出库
```

### 典型矛盾（侦察信号）

| 接口 | 表现 |
|------|------|
| `GET /accounts/{id}` | 403 no permission |
| `POST /accounts/export` | **200 + ZIP**（缺归属校验） |

→ **读接口严、导出接口松** = BOLA 经典位。

### 次生风险

- 导出 JSON 中 **2FA/两步密码明文**
- session 为 Telethon/Pyrogram 类 SQLite（含 auth_key）→ 等同账号接管
- 密码重置 `email_not_found` 类差异 → 邮箱枚举
- `/current/menus` 泄露完整后台菜单树

### 检查清单

- [ ] 所有 export/download/batch 是否按 owner 或角色过滤
- [ ] ids 数组是否可越权扫大范围 ID
- [ ] 导出是否含 plaintext 2FA / app_id / app_hash
- [ ] 注册是否无邀请码；验证码是否可 OCR 自动化

### 修复

export 强制归属或 admin-only；2FA 加密存储且不随 session 明文出；菜单按角色裁剪；重置接口统一响应。

### 报告写法

Evidence（命令+响应头/结构）→ Finding（BOLA）→ Path（注册→token→export→批量）。  
**PoC 只证「可导出非己资源」**，交付客户时脱敏 session 内容。



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
