# 案例课：UU钱包/iM云控/8089注单 — 多面未授权链

> 脱敏。来自授权横向战役提炼，无真实 Token/邀请码/账密。

## 骨架

```text
目标簇（同 /24 或同业务）
→ 面A RuoYi后台：未授权 upload + download/resource → 存储XSS
→ 面B iM：WebSocket type=web 未授权设备清单；type=device 可伪注册收指令
→ 面C 8089注单：/api/admin/accounts 未授权CRUD + on-demand SSRF
→ 面D FastAPI群管：OpenAPI全暴露；JSON 422 先于鉴权泄schema；写操作303登录
→ 面E 前台vault：开放注册但 invitation_code 必填卡死
→ 收口：XSS偷 Admin-Token / tg_miner_token；SSRF读内网；C2等真机
```

## 高 ROI 可复用手法

### 1) RuoYi 未授权上传→回读→存储 XSS（CRITICAL）

```text
POST /api/common/upload  (Host: admin.*)  无鉴权
→ {"fileName":"/profile/upload/YYYY/MM/DD/xxx.html","url":"https://..."}
GET /api/common/download/resource?resource=/profile/upload/...  无鉴权回字节
```

- **CF 公网 URL 常 404**；可靠读原语是 **download/resource**，不是静态直链
- `resource` 含 `..` →「非法」；别在穿越上空转
- Admin SPA：`Admin-Token` 在 cookie/localStorage；CORS 常 `ACAC:true`+反射 Origin
- 种 HTML：读 `Admin-Token`/`tg_miner_token`/`RC` → 再 `upload` 成 `TOKEX_*.txt`（需管理员打开预览）

### 2) iM C2 WebSocket（HIGH）

```text
ws://host:9301/?type=web     → type=initial 全量设备表（未授权）
ws://host:9301/?type=device&id={uuid}
  → {"type":"register",...} → register_success
  → REST POST /api/devices/{id}/list-files → WS 收到 list_files
```

- 假设备可收指令；**真机离线时无法读真实文件**
- `online=True` 被我们标亮 ≠ 真机在线；list-files 仍可能「设备未连接WebSocket」
- 握手要点：register 后等 `register_success`/`pong`，再开火；乱序多包易失败

### 3) 8089 注单后台 SSRF（CRITICAL 控制面）

```text
未授权：GET/POST/PUT/DELETE /api/admin/accounts
POST /api/admin/mode {"onDemandFetchEnabled":true}
GET /api/cache/game/{speed5|pk10} → fetchTrigger.results[]
```

- **138 + cookie**：session ready 后，on-demand 会请求  
  `{baseUrl}/agent/control/risk?lottery=SSCJSC&games=...`
- **168 + password**：强制找 `#loginName` / `login.aspx`（彩票选择器）——指到 FastAPI/RuoYi 会超时
- **page snippet ≈ 120 字硬截断**；别指望完整 HTML/密钥
- 密码字段 API 回 `******`；`sha256('******')[:12]` 是假线索
- 代理格式：`host/port/user/pass`；**禁止**把 `127.0.0.1:9050` 配给远端（解析在目标机）
- create 要非空 `username`+`password`（即便 cookie 模式）

### 4) FastAPI 群管 / OpenAPI（MEDIUM）

```text
/openapi.json /docs → 45 路由
JSON POST → 422 泄 Form 字段名（鉴权前）
正确 x-www-form-urlencoded / multipart 后 → 303 /login
标题指纹：登录 - 群管机器人后台
```

- 有密码错 oracle；默认口令/产品名口令常失败 → **禁止开局喷**
- GET mutate（toggle/delete）路径匹配后仍 303

### 5) 前台邀请码门

```text
POST /api/auth/register
body: {account,nickname,password,invitation_code}  # 必须 snake
InvitationCode / inviteCode 大写驼峰 → required 校验失败（绑定不到）
空码→不能为空；任意错码→无效或已被使用（无枚举差异）
```

## 踩坑（已知坑位）

| 坑 | 正解 |
|----|------|
| 未知 app HMAC「软件不存在」当签过 | 仅 `demo-app` 验签；未知 app 跳过 HMAC |
| `secret=undefined` + 毫秒时间戳「时间戳过期」 | 假阳：先校验时间戳形态；秒级+真 secret 才算 |
| make 表「手机号」 | 多为雪flake ID 子串；CMS 新闻内容 |
| 8089 Tor `socks5://127.0.0.1:9050` | 绑在 .86 本机，不是攻击机 |
| password_sha12=2efb… | = sha256(b'\*\*\*\*\*\*')[:12] |
| mem\*.tttiuoiwqerkwer83fer.com | 假百度页，不是真彩票站 |
| HTTP 直链 upload URL 200 | 常是 SPA fallback（iM后台壳），不是文件 |
| JWT 默认 secret 伪造 →「登录已过期」 | 可能签过但 Redis 无 session；≠ secret 一定错 |
| 宽雪花 ID 扫 TOKEX | 易超时；用已知 fileName/meta 回读 |
| TCR e=4 | 账密错，**不是**用户存在枚举（随机用户也 e=4） |
| zi99/123yyy e=14 | 锁号，停碰 |

## 组合链（前置条件）

1. **同段横向**：主目标登录卡死时 → `/24` 扫 8089/9090/8899/8443/8080  
2. **XSS 链**：upload(html) → download/resource 验证 → 等管理员预览 → TOKEX  
3. **SSRF 链**：accounts CRUD → mode onDemand → cache/game 触发 → logs/risk URL  
4. **C2 链**：devices register → WS device → list-files（真机在线才有数据）  
5. **Schema 链**：FastAPI 空 JSON → 422 → 换 Form → 确认需登录

## 指纹 → 打法

| 指纹 | 优先打法 |
|------|----------|
| RuoYi/Vue `Admin-Token` + `/common/upload` | 未授权 upload/download/resource；captchaImage；用户名 oracle |
| `ws` + `/api/devices/register` + type=web\|device | WebWS 清单；假设备控制面 |
| `/api/admin/accounts` + Playwright/on-demand | 未授权 CRUD；138 cookie SSRF；禁乱喷代理 |
| FastAPI `/openapi.json` +「群管机器人」 | 422 schema；Form 登录；勿 JSON 硬怼 |
| vault `invitation_code` + uuvault | snake 字段；错码无枚举；转 XSS/后台 |
| UFO SVG captcha `:8443` | convert→ddddocr/tesseract；15m 锁周期 |
| 9090 `mem*.…` + `_nc` | settings 强制 mem 域；假百度 decoy |

## 检查清单

- [ ] upload 无鉴权？download/resource 无鉴权？后缀白名单含 html？
- [ ] CF URL 与 download/resource 是否行为不一致？
- [ ] WebWS type=web 是否泄设备？
- [ ] 8089 accounts 是否未授权？onDemand + cache 触发？
- [ ] OpenAPI 是否公网？422 是否先于 303？
- [ ] 邀请码绑定名是否 snake？有无差异 oracle？
- [ ] 横向端口是否在主登录卡死前已扫？

## 修复口径

- upload/download 强制鉴权+角色；禁止 html；resource 规范化防穿越  
- WS 管理通道鉴权；device 指令绑定真实 agent 证书/密钥  
- 8089 admin API 鉴权；SSRF allowlist；日志脱敏  
- OpenAPI/docs 生产关闭；写接口鉴权先于校验或统一 401  
- 邀请码服务端强校验+审计；注册限流  

## 报告诚实口径

- VALIDATED：未授权 upload+download/resource；8089 accounts；8899 部分写；WebWS 清单；OpenAPI 映射  
- 未破：有效 invitation_code、Admin-Token 实偷（TOKEX 空）、4000/8080/UFO/.77 密码、真机文件  

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
