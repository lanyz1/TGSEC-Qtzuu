# HEIYT 课 · gFast + 独角兽 SCRM + ClickHouse 三线

- Source report: 报告包 20261012（`HEIYT_SITE_REPORT`；原文留本机案卷）
- Techniques: gfast-unauth, gf-token, clickhouse-privesc, memstore-captcha, scrm
- Fused: 2026-10-12

## 链

1. SCRM 业务超管双线：RSA agentLogin（`client-version: 1227` + 固定出口 IP）+ Google 服务账号 → 两个超管；邀请码 / 7 日 token / openSession（telegram 绑定）；合并导出 216 登录账号
2. **gFast 未授权 CommEdit**：`PUT /api/v1/system/edit` + 固定 key → `code:0` 直接改密/改角色（admin 两次重置成功）；`/api/v1/pub/upload/s3` 任意后缀上传 + 本地空后缀上传；`translationList`(73 渠道) / `renewDetection` / `dbInit` / `api.json` 未授权
3. gFast 登录卡点：验证码为**进程内 MemStore（非 Redis）+ 多节点** —— sticky/OCR/模板多轮全败；外网 Redis 不通 → GfToken 材料（encryptKey/IV/JWT secret）种库后在线校验仍 401（判为：业务读的不是该实例或 online 槽位不一致）
4. **ClickHouse 高权限线（最接近 root）**：`default` 弱口令 → 建高权用户；`file()` 可写 `user_files/`（marker + SSH pubkey 已写）；`CREATE Executable` 语法允许但**运行时仅加载 `user_scripts/`**（Code 291）→ file() 无法穿越；预置 EXECUTABLE 字典 → Code 482；`url()` SSRF 存活（打内网 8805/8806/9442/3000、IMDS）；named collections 全 `display_secrets=0`；MySQL 引擎 1045 泄露用户名；**本机 Redis 经 CH 可达**（INSERT marker 验证）
5. UniTranslate GoFrame `:9442` pprof 裸奔；`getSystemInitConfig` / `getLangList` 未授权；authMode=1 需生产 ServerConfig.Key（未拿）
6. XXL-JOB admin 默认凭据登录成功但**无 ADMIN 角色** → jobgroup 受限、trigger NPE；真执行器在内网 job-bridge
7. 聊天加密：S3 附件泄完整 RSA 私钥 1 把（3072）但线上主流密文 keyId 不同（5 个）→ 未解；密文协议形态 `v1.<keyId>.<b64url-rsa>.<nonce>.<ct>`（OAEP-3072，keyId 轮换）

## When to reuse

- gFast 面 → `gfast-admin-pentest`；ClickHouse 面 → `clickhouse-attack-surface`
- GfToken → `goframe-api-pentest` 增补；XXL 受限态 → `xxljob-admin-glue-chain` 增补
- SCRM → `saas-multitenant-pentest` + `references/dujiaoshou-share-link-case.md`

## 诚实卡点

OS root 未落地（CH 差临门一脚，路径清晰）；gFast 稳定会话未得（MemStore 多节点 + Redis 种错库）；MySQL 有效口令 1045；UT 生产 Key；主流 keyId 聊天私钥；WuwenAI/RabbitMQ 远程管理员明文；XXL ADMIN/job-bridge 内网；外网 16379 强口令

@TGSEC社区 · @TGSEC-Qtzuu 整理
