---
name: ctf-web-methodology
description: "CTF Web 挑战的总体方法论。当面对 CTF 靶场、xbow benchmark、Web 安全挑战赛时使用。包含挑战类型快速识别、攻击策略选择决策树、常见出题模式、何时切换方向的判断标准。与 exploit/ 下的具体漏洞技能配合使用"
metadata:
  tags: "ctf,web,methodology,challenge,benchmark,靶场,比赛,策略,capture the flag"
  category: "ctf"
---

# CTF Web 挑战方法论

## 深入参考

以下参考资料**按需加载**，根据 Phase 2 识别出的挑战类型选择对应文件：

- 服务端注入（SQLi/SSTI/LFI/XXE/SSRF） → [references/server-side.md](references/server-side.md)
- 服务端执行（命令注入/RCE/文件上传/CRLF） → [references/server-side-exec.md](references/server-side-exec.md)
- 服务端高级（Race Condition/HTTP走私/缓存投毒） → [references/server-side-advanced.md](references/server-side-advanced.md)
- 反序列化（PHP/Java/Python/Node/.NET） → [references/server-side-deser.md](references/server-side-deser.md)
- 认证与访问（密码/MFA/OAuth/IDOR/逻辑漏洞） → [references/auth-and-access.md](references/auth-and-access.md)
- JWT 攻击（none/弱密钥/JWK注入/算法混淆） → [references/auth-jwt.md](references/auth-jwt.md)
- 认证基础设施（LDAP/Kerberos/SAML/证书） → [references/auth-infra.md](references/auth-infra.md)
- 客户端（XSS/CSP绕过/DOM/CSS注入） → [references/client-side.md](references/client-side.md)
- 客户端高级（Unicode折叠XSS/CSS字体外泄/CSP nonce绕过/postMessage） → [references/client-side-advanced.md](references/client-side-advanced.md)
- Node.js 与原型链污染 → [references/node-and-prototype.md](references/node-and-prototype.md)
- CVE 利用集（Log4Shell/Gitea/Grafana等） → [references/cves.md](references/cves.md)
- Web3/区块链（Solidity/重入/闪电贷） → [references/web3.md](references/web3.md)
- 服务端注入2（XXE深入/GraphQL利用/变量注入） → [references/server-side-2.md](references/server-side-2.md)
- 服务端执行2（OPcache webshell/disable_functions绕过/LD_PRELOAD） → [references/server-side-exec-2.md](references/server-side-exec-2.md)
- 服务端高级2（SSRF→Docker/Rogue MySQL/URL解析差异/LaTeX RCE） → [references/server-side-advanced-2.md](references/server-side-advanced-2.md)
- SQLi 深入（二阶注入/Shift-JIS编码/PCRE回溯绕WAF/QR码注入） → [references/sql-injection.md](references/sql-injection.md)
- Web 实战笔记(常见陷阱/调试技巧/快速判断) → [references/field-notes.md](references/field-notes.md)
- HTTP 响应分析技巧 → [references/response-analysis.md](references/response-analysis.md)
- Flag 提取方法论 → [references/flag-extraction.md](references/flag-extraction.md)

---

CTF Web 挑战和真实渗透测试有本质区别：目标明确（拿 flag）、漏洞是故意设置的、通常只有一个入口点。本方法论帮助你快速识别挑战类型并选择最短路径。

## 核心思维模型

**CTF 的本质是解谜**。出题者故意留了一条攻击路径，你的任务是找到它。

关键原则：
1. **先广后深** — 花 2-3 轮快速侦察全貌，再深入具体漏洞
2. **线索驱动** — 每一步的结果告诉你下一步该做什么
3. **3 轮法则** — 一种方法尝试 3 轮无实质进展就切换方向
4. **不要硬猜** — 如果需要暴力破解，说明你可能走错了方向（CTF 通常有巧妙的解法）

## Phase 1: 快速侦察（1-3 轮）

按优先级执行（不是全部都做，有发现就停下来分析）：

1. **访问首页** — `http_request` GET 首页，观察：
   - 是什么应用？（登录页/博客/商城/API）
   - 有什么功能？（搜索/上传/注册/评论）
   - 页面底部/注释有没有提示？

2. **查看源码** — 检查 HTML 源码（不是渲染后的页面）：
   - HTML 注释 `<!-- hint: ... -->`
   - 隐藏表单字段 `<input type="hidden">`
   - JavaScript 中的 API 路径和变量
   - 引用的 JS/CSS 文件路径

3. **路径探测** — 检查常见路径：
   - `/robots.txt` — 经常藏着禁止访问的敏感路径
   - `/flag`, `/flag.txt`, `/flag.php`
   - `/.git/`, `/.svn/` — 源码泄露
   - `/backup.sql`, `/www.zip`, `/源码.tar.gz`
   - `/admin`, `/login`, `/api`

4. **指纹识别** — `httpx -tech-detect` 或 `curl -sI` 识别技术栈

## Phase 2: 挑战类型识别与策略选择

根据侦察结果，快速归类：

| 看到什么 | 可能是什么 | 下一步 |
|----------|------------|--------|
| 搜索框/查询参数 | SQL 注入 | 读 `sql-injection-methodology` |
| 登录页面 | 弱密码/SQL注入/JWT | 先按 CSRF 安全登录流程，再试 SQLi |
| 文件上传功能 | 文件上传漏洞 | 读 `file-upload-methodology` |
| 模板渲染/用户输入回显 | SSTI/XSS | 试 `{{7*7}}` 和 `${7*7}` |
| URL 中有文件路径参数 | LFI/目录穿越 | 试 `../../etc/passwd` |
| 反序列化数据（base64 cookie） | 反序列化 RCE | 读 `deserialization-methodology` |
| API 端点 + JSON | IDOR/权限绕过 | 读 `idor-methodology` |
| JWT token（eyJ...） | JWT 攻击 | 读 `jwt-attack-methodology` |
| 源码可见（.git 泄露等） | 源码审计 | 读 `ctf-source-audit` |
| ping/curl 功能 | 命令注入 | 读 `command-injection-methodology` |
| XML 输入/SOAP | XXE | 读 `xxe-injection-methodology` |
| URL/文件路径参数 | SSRF | 读 `ssrf-methodology` |

## Phase 2.5: CSRF-Safe 登录流程（关键！）

很多 Web 应用（DVWA、WordPress 等）的登录表单带有 CSRF token（`user_token`、`csrf_token`、`_token` 等隐藏字段）。**如果不在同一个 session 内先 GET 获取 token 再 POST 提交，即使密码正确也会登录失败。**

### 正确流程（http_request 已自动管理 Cookie）

举例
```
1. GET /login.php              ← 获取页面，自动保存 session cookie
2. 从响应 HTML 提取 user_token 值
3. POST /login.php             ← 自动携带同一 session cookie
   body: username=admin&password=password&Login=Login&user_token=<提取的值>
4. 验证：响应不再是登录页面（body 大小变化、出现 Welcome/Dashboard）
```

### 常见陷阱
- **每次请求新 session** — 如果 GET 和 POST 不在同一 session，token 校验必然失败（服务端 token 绑定 session）
- **token 名称不固定** — 可能是 `user_token`、`csrf_token`、`_token`、`csrfmiddlewaretoken`
- **token 在 meta 标签里** — `<meta name="csrf-token" content="...">`，不一定在 form 里
- **登录后要改配置**（如 DVWA 安全级别）— 必须用同一 session 继续操作，否则改完就丢

### 判断登录是否成功
- 响应 body 大小明显变化（如 1523→7274 bytes）
- 出现 `Welcome`、`Dashboard`、`Logout` 等关键词
- 不再出现 `Login` 表单

## Phase 3: 漏洞利用

- SQL 注入：**UNION SELECT 优先**，EXTRACTVALUE 备选
- 命令注入：**直接 cat /flag.txt**，别折腾反弹 shell
- 需要持续交互（反弹shell/SSH/数据库）时用 `interactive_session` 工具而非 bash+nc
- LFI：**直接读 /flag.txt**，别先读 /etc/passwd
- **假 flag** — `flag{test}` 不是真 flag；**多层漏洞** — LFI 拿源码再挖第二个洞
- **WAF 绕过** — 大小写/双写/注释 `/*!select*/`；**编码** — URL/双重/Unicode

## Phase 4: 策略切换

- 同一 payload 试 5 种变体没成功 → 换方向
- SQL 注入确认但无法读文件 → flag 在数据库里
- 感觉「差一点」但不行 → 最危险信号，退后重新审视

## 漏洞类型判断
- 观察功能：显示功能不是 SQL 注入（不是查询），可能是 SSTI/XSS

## 效率陷阱
- 完整数据无长度限制时不需分段提取
- 分段拼接容易出错，手动拼接有风险
