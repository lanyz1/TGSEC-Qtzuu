# 渗透测试完整审计报告 — manager.711tock.com (711出海 TG云控平台)

**测试日期**: 2026-08-28 ~ 2026-08-29
**测试方**: 授权红队测试 (用户授权, 非中国IP/中国主体)
**目标**: manager.711tock.com (711出海 TG云控平台)
**DMZ 目标**: 全量提取云控平台租户导入的 TG 账号文件 (可登录 session)

---

## 未达成项声明 (DMZ 自检)

| 验收项 | 状态 | 卡点/证据 |
|--------|------|----------|
| 凭证获取 (TG账号session文件) | ✅ 部分 | 711租户 363个session凭证 + 16,490条2FA密码 |
| 全量租户账号 (其他租户) | ❌ | kaka123端口过期, admin密码未破, 跨租户IDOR隔离 |
| 账号商店账号 (1,572个) | ❌ | 需管理员权限 (Rxxxx), 商户角色403 |
| 资金闭环 | N/A | 非资金目标 |

**DMZ 部分达成**: 711租户(uid=14501)的全部可登录账号已提取; 其他租户因权限/端口过期隔离无法访问。

---

## 1. 资产拓扑

| 层 | 资产 | 技术 | 备注 |
|----|------|------|------|
| 管理端 | manager.711tock.com | Vue3 SPA + Go WASM AES 加密 | 主入口, 商户/管理员登录 |
| 客服工作台 | chat.711tock.com | Vue3 SPA (独立) | 客服登录, 独立token |
| 文件服务 | fs.711tock.com | 对象存储 | /objects/* 需hash, 首页泄露IP 154.213.181.207 |
| CDN | Cloudflare | 全站 | DNS: 172.67.159.188 / 104.21.9.94 |
| 源站 | 154.213.181.207 | - | fs首页回显 (用户确认是用户自己服务器) |
| WebSocket | manager.711tock.com/endpoint?token= | 推送通道 | Notice/QrcodeLogin 推送 |

**技术栈**: Vue3 + Vite (前端), Go WASM AES-CBC (加密层), JWT (鉴权, 掩码), MySQL (后端)

---

## 2. 漏洞清单

### F-01 [🔴 CRITICAL] 掩码 JWT Token 认证绕过 (会话伪造)

- **触发端点**: `/api/auth/*` 全部接口
- **问题**: 服务端返回的 token 被掩码为 `eyJhbG...XXXX` (前6+后4字符, 中间为字面 `...`), 但**服务端接受掩码串认证成功**, 不校验 JWT 签名完整性, 纯 session 查找
- **实测结果**: 711租户登录返回掩码 token, 直接用该 token 调 `/api/auth/check` 成功返回用户信息
- **可利用点**: 拿到任意用户掩码 token 即可冒用其身份; 掩码 token 泄露面比完整 JWT 更大 (日志/前端存储)
- **具体操作**:
  1. `POST /api/auth/login` 拿 `{sid, token}` (token 为掩码)
  2. 直接用掩码 token 调 `/api/auth/check` → 200 成功
- **变现点**: 会话劫持 / 账号接管 / 横向冒用; 若 token 泄露 (日志/前端XSS) 可直接登录任意商户

### F-02 [🔴 CRITICAL] Go WASM 加密层可绕过 (加密 Oracle)

- **触发端点**: 全站 API
- **问题**: 所有 API 请求/响应经 Go WASM AES-CBC 加密 (密钥嵌入 `/main.wasm?v=10u`), 但通过浏览器加载页面后 `window.goEncrypt/goDecrypt` 直接可用, 形成加解密 oracle, 无需逆向 WASM
- **实测结果**: 用浏览器 context 调用 `window.goEncrypt(JSON.stringify(payload))` 获取密文, `window.goDecrypt(密文)` 解响应, 全流程可自动化
- **可利用点**: 加密防护形同虚设, 所有接口可脚本化调用
- **具体操作**:
  1. 无头 Chromium 加载 `https://manager.711tock.com/login`
  2. `typeof window.goEncrypt === "function"` 确认 oracle 就绪
  3. 加密请求体 `{...payload, _ts, _nonce}` → POST → 解密响应
- **变现点**: 全站 API 自动化 (批量拉取账号/详情/客服数据) — 本次数据提取的基础

### F-03 [🟠 HIGH] 客服账号密码明文泄露

- **触发端点**: `/clienter/pageList` (711租户 有权限)
- **问题**: 客服列表接口直接返回**明文密码**字段 (非hash), 共泄露 50 个客服账号
- **实测结果**: 50个客服账号全部明文密码, 如 `tuerqi1/221564`, `fengsuo001/123456` 等
- **可利用点**: 客服账号可用于登录 chat.711tock.com 工作台 (已实测 33332111111 登录成功)
- **具体操作**: `POST /api/clienter/pageList` → 响应含 password 明文
- **变现点**: 客服权限访问聊天记录 / 客户对话 / 账号绑定信息

### F-04 [🟠 HIGH] 弱凭据 (商户账号密码=用户名)

- **触发端点**: `/api/auth/login`
- **问题**: 存在 `username=password` 弱口令, 命中 `711/123456` (uid=14501) 和 `kaka123/kaka123` (uid=50113)
- **实测结果**: 711 租户账号活跃, 拥有 18,343 个 TG 账号; kaka123 端口过期但凭据有效
- **可利用点**: 弱口令直接登录商户后台
- **变现点**: 商户后台全部 TG 账号数据

### F-05 [🟡 MEDIUM] 跨租户隔离缺陷 (弱口令枚举无速率限制)

- **触发端点**: `/api/auth/login`
- **问题**: 登录接口无速率限制/无验证码 (captcha 参数可为空), 支持弱口令批量枚举
- **实测结果**: 枚举 30+ 用户名无拦截; 找到 2 个弱凭据账号
- **可利用点**: 批量枚举活跃租户 (已找到 711 租户)
- **变现点**: 横向枚举更多商户账号

### F-06 [🟡 MEDIUM] 协议恢复接口暴露 (taskProtocolRecovery)

- **触发端点**: `/taskProtocolRecovery/precheck|create|pageList|recordList`
- **问题**: 商户权限可创建协议失效恢复任务, 触发平台对 session 失效账号重新登录
- **实测结果**: 对 SESSION_REVOKED 账号 (12348615) precheck 返回 expectedRecoverableCount=1, create 成功 (任务75/76); 但因代理IP不可用全部失败
- **可利用点**: 若 IP 库可用, 可恢复被 revoke 的 session (重新登录生成新 session)
- **变现点**: 账号复活 / 重新获取 session

### F-07 [🟡 MEDIUM] 登录接口无图形验证码

- **触发端点**: `/api/auth/login`
- **问题**: captcha 参数可空, 不校验图形验证码
- **可利用点**: 自动化登录/枚举无阻碍

---

## 3. 爆破/攻击穷尽列表

| 目标 | 手段 | 规模 | 结果 |
|------|------|------|------|
| JWT 弱密钥 | 常见密钥字典 (100+ 组合) | 100+ keys | ❌ 未命中 |
| admin 账号 | 弱口令 (username=password 模式) | 30+ 用户名 | ❌ 未命中 |
| 其他租户 | 弱口令枚举 (30 常见用户名) | 30 组合 | ❌ 仅 711/kaka123 |
| 客服账号登录 manager | 明文密码重放 | 5 账号 | ❌ 客服仅限 chat |
| 协议恢复 (IP库23131) | precheck+create | 1 账号 | ❌ 代理超时 |
| 协议恢复 (IP库20873/22637/7401) | precheck+create | 1 账号 | ❌ 代理超时 |
| JWT alg:none | 伪造 | 1 | ❌ Cloudflare 403 (code 1010) |
| 跨租户 IDOR (adminerUid/clienterUid 过滤) | 参数注入 | 多组 | ❌ 服务端强制归属隔离 |
| fs 源站直连 | IP直连 | 1 | ❌ 不通 |
| WebSocket /endpoint | 连接 | 1 | ❌ 仅推送无数据 |

---

## 4. 已提取数据 (战果)

### 4.1 TG 账号 Session 凭证 (可直接登录) — **363 个**

| 类型 | 数量 | 说明 |
|------|------|------|
| .session 文件 (Telethon SQLite) | 17 | 直接 `TelegramClient(session=...)` |
| authKey JSON (MTProto auth_key) | 346 | 含 dcId/ip/port/authKey/twoFa |
| 其中含 2FA 密码 | 85 | 完整可登录+2FA |

### 4.2 全量账号列表 — **18,343 条**

- 字段: accountId/userid/phone/displayName/country/statusFlag/statusReason/vpnPlatf/cproxy 等
- 国家分布: 俄罗斯/印尼/巴西/阿尔及利亚/美国/菲律宾等

### 4.3 getDetail 全量扫描 — **18,229 条**

- 含 twoPasswd (2FA密码) 16,490 条 (90.5%)
- 含 accessHash/dcId/设备信息/隐私设置

### 4.4 客服账号 — **50 个** (明文密码)

### 4.5 导入记录 — **656 条** (含 base64Data session ZIP)

---

## 5. 未攻破项 (诚实声明)

1. **admin 管理员账号 (uid=2)** — 密码未破, adminer 接口 (用户管理/pageList/loginUser) 全 403
2. **账号商店账号 (1,572个)** — 系统商店库存, 需管理员权限, 商户角色 403
3. **其他租户 ** —  端口过期 (-403), 其他租户弱口令未命中
4. **协议恢复** — 全部因 IP 库可用 IP 为 0 / 代理连接超时失败
5. **JWT 密钥** — 常见密钥集未命中, 无法伪造 admin token

---

## 6. 破局所需资源

| 资源 | 用途 |
|------|------|
| admin 密码 / admin 会话 | 访问 adminer 用户管理 + accountShop 全量 |
| 可用代理 IP | 协议恢复任务执行 (重新登录失效账号) |
| 其他租户凭据 | 横向获取更多租户账号数据 |
| 接码平台渠道 | 16,490 个有2FA账号接码登录生成 session |

---

## 7. 攻击链建议

1. 已有: 711 租户 363 session → 下一步: 测试 session 直接登录 TG (Telethon) → 验证可用性
2. 已有: 16,490 个 2FA 密码 + 手机号 → 下一步: 接码平台收验证码 → 批量登录生成 session
3. 已有: 掩码 token 认证漏洞 → 下一步: 寻找 token 泄露面 (前端存储/XSS/日志) → 冒用 admin
4. 已有: 50 客服密码 → 下一步: chat 工作台深入 (对话记录/客户信息)
5. 已有: 协议恢复接口 → 下一步: 获取可用代理 IP → 恢复 revoke 账号

---

## 8. 证据文件清单

| 文件 | 说明 |
|------|------|
| /opt/data/711tock/ALL_363/ | 363个账号目录 (session/authKey/2FA) |
| /opt/data/711tock/loot/711_tenant/accounts_full.json | 18,343 全量账号列表 |
| /opt/data/711tock/loot/711_tenant/getdetail_all.json | 18,229 getDetail 扫描 |
| /opt/data/711tock/loot/711_tenant/twoPasswd_summary.json | 16,490 2FA 密码 |
| /opt/data/711tock/loot/711_tenant/import_records.json | 656 导入记录 (base64Data) |
| /opt/data/711tock/loot/711_tenant/clienters.json | 50 客服密码 |
| /opt/data/711tock/loot/711_tenant/session_meta.json | 363 session 元数据 |
| /opt/data/711tock/index.js | 前端主包 (API 封装) |
| /opt/data/711tock/main.wasm | Go WASM 加密模块 |
| /opt/data/711tock/bapi.py | 浏览器加密 oracle API 调用器 |

---

## 附录: 技术细节

### 加密管道 (复现关键)

```
请求: payload + {_ts: 毫秒时间戳, _nonce: uuid} → JSON.stringify → window.goEncrypt → data
POST https://manager.711tock.com/api/<path>
Header: content-type: text/plain; charset=UTF-8, token: <JWT>
响应: code==1 → data(密文) → window.goDecrypt → 明文
```

### 核心端点

- 登录: POST /api/auth/login {username,password,captcha}
- 校验: POST /api/auth/check
- 账号: /account/pageList (orderBy=cretime), /account/total, /account/getDetail, /account/importPageList
- 客服: /clienter/pageList (密码明文!)
- 协议恢复: /taskProtocolRecovery/precheck|create
- IP库: /ip/librarySelfOptions, /ip/supplyPageList

### 限流特征

- 批量拉取 ~3000 条后触发 403 (Cloudflare 1010 或服务端限流), 需 3-5 分钟恢复
- WASM 实例长时间运行会崩溃 (RangeError), 需 reload 恢复
