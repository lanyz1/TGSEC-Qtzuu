# B3W1443 总控攻坚未破：2000+ 域名矩阵与假阳/真阳判据

- Source: `REPORT_B3W1443_总控攻坚.md`（原文留本机案卷，不入库）
- Techniques: gameseal, 2000-plus-domains, totp, fake-positive, negative-evidence
- Fused: 2026-10-17 · pack-20261017
- 档: `/root/cases/_absorb/pack_20261017/`

## 目标
- PIM 总后台 `pim.gameseal.com` / `pim-api`（AdminPanelWeb，Blazor WASM），另有同段旁 IP
- Deskpro 客服（support 子域，tenant `dpc47499`）
- Tracker（Blazor + MariaDB 10.1.48）、Plesk 18.0.80、WinRM、RDP、Grafana/Kabana
- 硬结论：总后台 / OS root / 数据库 **NOT LANDED**，只有旁路 foothold

## 技术栈
- 前端 Blazor WASM（`AdminPanelWeb.Client.wasm`）+ `appsettings.json` 暴露 API 基址
- 后端 .NET API（`/api/Authenticate/Login`），2FA 路径 `verify2fa`/`TwoFaSetup`/`ManageKeys`/`DecryptCode`
- Deskpro SaaS（agent-api / messenger-api / admin-api GraphQL）
- Tracker Blazor + MariaDB 10.1.48；Plesk XML-RPC；Grafana service account token

## 攻击链（走到哪一步）
WASM 静态逆向 → 取 API 基址/登录 schema/硬编码凭据 → 未授权读 `productTypes`（200）→ 受保护资源 403（存在但拒）→ 登录面字段 oracle（401 错口令 / 400 缺字段）→ JWT 伪造（none / HS256 弱 secret / hex64）全败

Deskpro 支线：captcha 协议 100% 复现 → 门户重置邮件稳定触发（26+ 次 SENT）→ 差“读邮箱拿 CODE”；Messenger 真路径出票（票号连续）→ 无人回执

旁路：Tracker Blazor 写 consumers + XSS 稳定；OAST 有自测命中，但无已登录会话可外带

## 可复用原语
1. **Blazor WASM 情报三件套**：抓 `*.Client.wasm` + `appsettings.json` + 字符串表，直接得 API 基址、登录 body 结构、2FA 路由、硬编码 token。
2. **403≠404 鉴权测绘**：`productTypes` 200 / `Products·Companies·Invoices` 403 / `Users/me` 401，可区分“不存在”与“存在但拒”，为定向提供依据。
3. **登录 body 钉死判别**：`{"Username","Password"}`（非 email），错口令 401、缺字段 400 ⇒ 字段级 oracle，兼作契约确认。
4. **Deskpro 重置链**：`reset-password` 恒 200 `[]`（无用户枚举）；`set-password` 的 CSRF ≈ 客户端 `Math.random`；resetCode 带连字符返回 404 ⇒ 格式 oracle。
5. **Deskpro Messenger 真基址**：`/sys/services/messenger-api/<tenant>/messenger/{MID}`，需 `X-Deskpro-VisitorID`；verify 后裸 JWT（勿加 Bearer），input schema 为 `{prompt_id: string}`。
6. **假阳黑名单（重要）**：`PLESK_OWNED_*` / `AK_OWN_*` / `MYSQL_OWNED` / 登录页 200 / `CAPTCHA_OK` 都不等于接管；门户 “SENT” 仅当 HTML 出现真文案；bibo manager ≠ PIM 总控。
7. **硬编码 token 的“可达性折价”**：WASM 里的 Grafana `glsa_` 有效，但目标外网滤死 ⇒ 凭据价值 = 凭据 × 网络可达性，先测达再定性。

## 数据战果
- 只读：`productTypes` 全量；PIM API 基址与登录契约；WASM 程序集与全量字符串
- Deskpro：出票成功（票号 115001 等，历史 6 张以上）；门户重置邮件 SENT 证据 26+ 份
- Tracker：consumers 写入成功、XSS 写入稳定；MariaDB 认证失败（1045）

## 缺口
- PIM 真会话：无有效口令、无 JWT secret、未授权写未成立
- OS root / WinRM whoami / RDP / Plesk 面板：口令未破 + 限流
- 数据库交互：MariaDB 1045，无 PG 外网面，PIM 连接串未泄
- Deskpro agent 会话：差邮箱读 resetCode；Messenger 差人工回执

## 敏感物（类别+数量，不含值）
- 硬编码 Grafana service account token 1 个（WASM 内）
- 外部 curated 口令/邮箱清单 1 套（全线复用未中）
- Deskpro 重置邮件触发证据 26+ 份；工单会话 1 份（票 115001）
- 无明文口令、无 DB 凭据进入本 digest

## 关联

- 伞形：`pentest-execution` / `tgsec-suite`
- 同域其余课见 `domains/redteam-framework/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
