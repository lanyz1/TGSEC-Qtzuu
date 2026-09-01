# 各语言危险函数清单

## PHP 危险函数（最常见 CTF 语言）

### 命令执行
- `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`
- 反引号 `` `$cmd` ``
- `preg_replace('/e', ...)` — PHP < 7.0 的 /e 修饰符可执行代码

### 代码执行
- `eval()`, `assert()` — 直接执行 PHP 代码
- `create_function()` — 等价于 eval
- `call_user_func()`, `call_user_func_array()` — 动态函数调用

### 文件操作
- `include()`, `require()`, `include_once()`, `require_once()` — LFI
- `file_get_contents()`, `readfile()`, `fopen()` — 任意文件读取
- `file_put_contents()`, `fwrite()` — 任意文件写入 → webshell
- `unlink()` — 任意文件删除
- `move_uploaded_file()` — 文件上传

### 反序列化
- `unserialize()` — 搜索 `__wakeup`, `__destruct`, `__toString` 魔术方法构造 POP 链

### SQL 相关
- 字符串拼接 SQL：`"SELECT * FROM users WHERE id=".$_GET['id']`
- `mysql_query()`, `mysqli_query()`, `PDO::query()` — 参数是否来自用户输入

## Python 危险函数

### 命令执行
- `os.system()`, `os.popen()`, `subprocess.*`
- `eval()`, `exec()` — 代码执行

### 反序列化
- `pickle.loads()`, `yaml.load()` (无 Loader 参数) — RCE
- `marshal.loads()`

### 模板注入
- `render_template_string(user_input)` — Jinja2 SSTI
- `Template(user_input).render()` — SSTI

### Flask 特有
- `app.secret_key` — 泄露可伪造 session
- `@app.route` 缺少认证装饰器 — 未授权访问

## Node.js 危险函数

### 命令执行
- `child_process.exec()`, `child_process.spawn()`
- `eval()`, `new Function()`

### 原型链污染
- `Object.assign()`, `_.merge()`, `_.set()` — source 来自用户输入时
- 递归合并函数 — `__proto__` 或 `constructor.prototype` 注入

### 模板注入
- EJS: `<%= user_input %>` 有时可注入
- Pug/Jade: 模板编译时注入

## 常见 CTF 源码漏洞模式

### 弱比较（PHP）
```php
if ($_GET['password'] == '0e123456') { ... }  // "0e..." == 0 → true
if (md5($a) == md5($b)) { ... }  // 0e 开头的 MD5 碰撞
if ($a != $b && md5($a) === md5($b)) { ... }  // 数组绕过 md5([])===md5([])
```

### 变量覆盖
```php
extract($_GET);  // GET 参数覆盖任意变量
parse_str($str); // 解析字符串为变量
$$key = $value;  // 可变变量
```

### 条件竞争
```php
move_uploaded_file($tmp, $target);
if (is_malicious($target)) unlink($target);  // 有时间窗口
```

### 逻辑漏洞
- username `admin` 被禁止 → 试 `admin ` (trailing space) 或 `Admin`
- 金额/积分为负数 → 购买时扣负数 = 加钱
- 密码重置 token 可预测 → 基于时间戳或弱随机数
