# 711出海 TG 云控 XSS/JWT/IDOR

- Source report: `711tock_审计报告.md`
- 全文: 已撤出仓库（原文留本机案卷）
- Techniques: telegram, auth, xss, idor
- Fused: 2026-09-17

## Key findings (distilled)

- 问题**: 服务端返回的 token 被掩码为 `eyJhbG...XXXX` (前6+后4字符, 中间为字面 `...`), 但**服务端接受掩码串认证成功**, 不校验 JWT 签名完整性, 纯 session 查找
- 可利用点**: 拿到任意用户掩码 token 即可冒用其身份; 掩码 token 泄露面比完整 JWT 更大 (日志/前端存储)
- 问题**: 存在 `username=password` 弱口令, 命中 `711/123456` (uid=14501) 和 `kaka123/kaka123` (uid=50113)
- 可利用点**: 弱口令直接登录商户后台
- 问题**: 登录接口无速率限制/无验证码 (captcha 参数可为空), 支持弱口令批量枚举
- 其他租户 ** —  端口过期 (-403), 其他租户弱口令未命中
- JWT 密钥** — 常见密钥集未命中, 无法伪造 admin token
- 已有: 掩码 token 认证漏洞 → 下一步: 寻找 token 泄露面 (前端存储/XSS/日志) → 冒用 admin

## Repro snippets

```
请求: payload + {_ts: 毫秒时间戳, _nonce: uuid} → JSON.stringify → window.goEncrypt → data
POST https://manager.711tock.com/api/<path>
Header: content-type: text/plain; charset=UTF-8, token: <JWT>
响应: code==1 → data(密文) → window.goDecrypt → 明文
```

## When to reuse

- 同类标签命中：telegram, auth, xss, idor
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理

## 2026-10-17 复读增量（同源分享包）

- WASM oracle 补齐：不必逆 `main.wasm`，无头 Chromium 加载登录页直接调 `window.goEncrypt/goDecrypt`；请求体加 `{_ts,_nonce}` 即可全站脚本化（`typeof` 先判就绪）
- 明文口令面：`/clienter/pageList` 直返 password 字段 50 条 → 横向独立域 chat 工作台（独立 token）
- 数据面量级：`/account/pageList` 18,343 → `getDetail` 18,229（twoPasswd 16,490，90.5%，含 accessHash/dcId/设备）→ 可登录 session 363（.session 17 + authKey 346，含 2FA 85）
- 限流指纹：约 3000 条触发 403（CF 1010），冷却 3–5 分钟；WASM 实例长跑 RangeError → reload
- 负结果：`adminerUid/clienterUid` 跨租户 IDOR 被强制归属挡死（已排除，勿重复投入）
- `/taskProtocolRecovery/precheck|create` 可对 SESSION_REVOKED 账号触发重登，成败取决于代理池

@TGSEC社区 · @TGSEC-Qtzuu 整理
