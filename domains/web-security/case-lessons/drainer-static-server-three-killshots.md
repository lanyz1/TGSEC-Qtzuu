# 案例课: 自建静态服务器上的盗U站 — 三个一击必杀点

## 场景
`38.145.218.48:8090` = 「Transit Swap & Bridge」多链(EVM+Solana)盗U站。
**Python SimpleHTTP 裸跑前端 + Node 自研后台在 :8080 + 数据后端 :5000。**
应用层 100% 拿下(受害者库+源码+后台),OS 层未破(`startsWith` 前缀校验扎实)。

## 致命点 1: 非标准端口的静态服务器 = 源码直读
```
Server: SimpleHTTP/0.6 Python/3.10.12      ← python -m http.server
:8080  Server 无 banner, /server.js 200 53KB  ← Node 自研服务把源码放在静态目录里
:8080  /authorized-users.json 200          ← 数据文件同目录
```
**必做**: 对任何"静态站"逐端口拉 `/server.js` `/app.js` `/index.js` `/main.py` `/bot.py` `/package.json`
`.env` `config.json`(盗U/诈骗站极常把源码和数据文件一起丢在 static 目录)。
本案 `/server.js` 直接给出: **env 变量全清单 + 接口签名算法 + 收割流程 + TG 通知格式**。

## 致命点 2: 前端 URL 参数就是管理员入口
```javascript
const solAdminMode = new URLSearchParams(location.search).get("soladmin") === "1";
if (solAdminMode) { setTimeout(() => enterSolManager(), 800); }
else { restoreSolWall(); }        // 普通访客走"钱包墙"
```
**姿势**: 从 index.html 全文 grep `location.search|URLSearchParams|sessionStorage|localStorage|getItem`
+ 关键词 `admin|manager|mode|debug|test|internal` → 逐个当参数试
`?soladmin=1` 一进就是运营后台, **零凭据**。
同类变体: `?admin=1` `?dev=1` `?mode=admin` `?debug=true`、`#admin`、
以及 `sessionStorage.setItem('isAdmin',...)` 这类可自设的本地标记。

## 致命点 3: 运营后台的管理 API 往往不带鉴权
```
GET /api/authorized-users      → 受害者全量(含首笔授权交易哈希/时间/source=verified-approval)
GET /api/sol-authorized-users  → 另一条链的受害者
GET /api/sol-users-info        → 逐个余额/授权状态
```
**注意**: 前端的 `?soladmin=1` 只是"进了后台 UI",真正金矿是**同名 API 的未鉴权 GET** ——
`curl` 直打即可,不必用浏览器。

## 读数: 写入类接口 = 红线,先读源码再决定动手
- `POST /api/sol-collect` → 410(服务端签名已禁用)
- `POST /api/sol-collect-prepare` → 需要 EIP-191 管理员签名(`x-bsc-address/timestamp/signature`)
- `POST /api/sol-collect-complete` → 链上核验后 TG 通知
**铁律**: 收割类接口 = 真实转走受害者资产。**只读不写**;验证鉴权用**非法参数**(如 `address=INVALID!!`)
—— 若返回"参数无效"而非 401,即证明鉴权被绕过,且不会构造任何交易。本案实测该绕过线上未生效。

## 静态服务的路径穿越怎么判
```javascript
const relative = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
const filePath = path.join(DIR, relative);
if (!filePath.startsWith(DIR)) { sendText(res, 403, "Forbidden"); return; }
```
- **curl 会自己归一化 `/../x`**,看起来 200 其实是把路径改回了 `/x` → **必须用原始套接字**(`socket` 直发 `GET /../server.js`)才测得准
- 编码变体 `%2e%2e` / `..%2f` / `....//` / `..;/` 逐个试(Node 不解码则 404,说明守卫同时靠"不解码")
- 前缀校验唯一理论缺口 = **同级目录名以 DIR 开头**(`/opt/app` vs `/opt/app2`)→ 需先知道部署路径
- 本案三路全堵 → 结论: OS 层不可达

## 盗U站定性与取证要点(只读)
1. **页面展示地址 ≠ 真收款**:真收款看合约 bytecode / delegate 关系
2. **delegate(委托)模式**(Solana):`getParsedAccountInfo` 里 `delegate` 字段 = 归集方;
   受害者可用 `revoke` 自救 —— 这是报告里最有价值的"受害者救助线索"
3. **allowance 归零 = 已被收割**:`eth_call` 打 `allowance(owner, spender)` + `balanceOf(owner)` 双查
4. **运营时间线**:受害者 `firstReportedAt/firstApprovalTx` 的时间跨度 = 作案窗口(本案 2026-05→08)
5. **代理/推广体系**:源码里 `<DIR>/../notifier/.tg-ref-codes.json` 存 `code → {username, tg_user_id}`
   —— 说明有 TG 代理分佣网络,报告里要提

## 归因速查
- **TLS 证书 CN / 反查同IP域名** = 最快拿到真域名(本案 `transitfor.com` 由证书 + hackertarget 反查双证)
- `crt.sh` 子域数量少 = 专用单用途机器
- rDNS 是 `scalabledns.com` 这类 = 防投诉/隐私 DNS → 站点本身就想藏
- 域名注册 2022 年 + 一次性机器 = 老域名复用/马甲

## 复用清单(下次遇到同类站点 30 分钟跑完)
1. 逐端口 curl 头:看 `Server` / 标题 / 大小
2. 拉首页全文:grep `URLSearchParams|location.search|API_BASE|apiUrl|fetch\(|/api/`
3. 静态站:拉 `/server.js` `/app.js` `.env` `*.json` `package.json`
4. 后台入口:`?soladmin=1` 类参数 + 直接 `curl` 打管理 API
5. 源码精读:env 清单 / 路由表 / 文件路径常量 / 用户输入的流向(找 SSRF/穿越)
6. 原始套接字测穿越;编码变体矩阵
7. 链上只读:contractAddress / tokenAddress / delegate / allowance / 时间线
8. **只写报告,不碰受害者资产,不调用收割接口**
