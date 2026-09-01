# PHP 注入类漏洞审计模式参考

6 种注入的危险代码 / 安全代码对比 + EVID_* 证据格式示例。

---

## 1. SQL 注入

### 1.1 PDO/MySQLi 危险模式 vs 安全模式

```php
// 危险: PDO::query/exec 拼接
$pdo->query("SELECT * FROM users WHERE email = '" . $_GET['email'] . "'");
$pdo->exec(sprintf("SELECT * FROM orders WHERE status = '%s'", $_POST['status']));
// 危险: MySQLi 拼接
mysqli_query($conn, "SELECT * FROM products WHERE id = " . $_GET['id']);

// 安全: 预编译
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute(['email' => $_GET['email']]);
$stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");
$stmt->bind_param("i", $_GET['id']); $stmt->execute();
```

### 1.2 ORM 陷阱（Laravel）

```php
// 危险: Raw 方法中拼接变量，ORM 参数化不覆盖 Raw 内部
DB::table('users')->whereRaw("name = '" . $request->name . "'")->get();
Item::orderByRaw($request->input('sort'))->get();
DB::table('orders')->groupBy('user_id')->havingRaw("count(*) > " . $request->min_count)->get();
// 安全: Raw + 绑定参数
DB::table('users')->whereRaw("name = ?", [$request->name])->get();
```

### 1.3 动态 ORDER BY / LIMIT

ORDER BY/LIMIT 不支持参数化（标识符/语法元素），只能白名单或强转:

```php
// 危险
$sql = "SELECT * FROM items ORDER BY " . $_GET['order'] . " LIMIT " . $_GET['limit'];
// 安全
$allowed = ['id', 'name', 'created_at'];
$order = in_array($_GET['order'], $allowed) ? $_GET['order'] : 'id';
$sql = "SELECT * FROM items ORDER BY $order LIMIT " . intval($_GET['limit']);
```

### 1.4 二次注入

入库时转义，出库后被信任为"安全"再拼入新查询:

```php
$pdo->exec("INSERT INTO users(name) VALUES('" . addslashes($_POST['name']) . "')"); // 入库安全
$row = $pdo->query("SELECT name FROM users WHERE id=1")->fetch();
$pdo->query("SELECT * FROM logs WHERE operator = '" . $row['name'] . "'"); // 出库拼接→注入
```

审计要跨越存储边界: 入库过滤不能替代出库参数化。

### 1.5 SQL EVID 证据示例

```
[EVID_SQL_EXEC_POINT]       app/Models/Order.php:142 | $this->db->query($sql)
[EVID_SQL_STRING_CONSTRUCTION]  app/Models/Order.php:139-141
  $sql = "SELECT * FROM orders WHERE user_id=" . $uid . " ORDER BY " . $sort
  方式: $uid 和 $sort 均拼接
[EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT]
  Source: OrderController.php:55 — $uid=$_GET['uid']
  过滤: $uid→intval(安全) | $sort→无过滤(可注入)
```

---

## 2. 命令注入

### 2.1 Sink 函数参数危险位

| 函数 | 危险位 | 说明 |
|------|--------|------|
| `exec` / `system` / `shell_exec` / `passthru` | 第 1 参数 | 完整命令串 |
| `proc_open` | 第 1 参数(字符串时) | 数组模式安全(PHP 7.4+) |
| `popen` | 第 1 参数 | 打开进程管道 |
| `pcntl_exec` | 第 1、2 参数 | 直接 execve |
| `` `$cmd` `` | 整个表达式 | 容易忽视 |

### 2.2 escapeshellarg 绕过场景

```php
// 场景 1: 与 escapeshellcmd 同时使用 → 引号配对被破坏
$broken = escapeshellcmd(escapeshellarg($input)); // 某些组合下引号逃逸

// 场景 2: 多字节/locale — GBK 中 0x5c 是双字节字符的第二字节
setlocale(LC_CTYPE, "C");
$escaped = escapeshellarg($gbk_input); // 可能截断

// 场景 3: 参数注入（非 shell 元字符）
exec("sendmail " . escapeshellarg($to));
// $to="-OQueueDirectory=/tmp -X/var/www/shell.php" → 不含 shell 元字符但滥用命令参数
```

### 2.3 proc_open 数组模式（安全）

```php
// 字符串模式(危险): 经过 shell 解析
proc_open("convert $src $dst", $desc, $pipes);
// 数组模式(安全): 直接 execve，; | & 等元字符不被解释
proc_open(['convert', $src, $dst], $desc, $pipes);
```

### 2.4 CMD EVID 证据示例

```
[EVID_CMD_EXEC_POINT]       app/Services/ImageService.php:78 | exec($cmd)
[EVID_CMD_COMMAND_STRING_CONSTRUCTION]  :75-77
  $cmd = "convert " . escapeshellarg($source) . " -resize " . $size . " " . $output
  $source 已转义 | $size 和 $output 直接拼接
[EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT]
  Source: ImageController.php:31 — $size=$_POST['size'] | 无过滤 → 可注入
```

---

## 3. SSRF

### 3.1 URL 可控检测

```php
// curl_exec
$ch = curl_init($_GET['url']); curl_exec($ch);                    // 完全可控
$ch = curl_init("http://internal-api/" . $_GET['endpoint']);       // 路径拼接
// file_get_contents
file_get_contents($_POST['feed_url']);
file_get_contents($user->avatar_url);     // avatar_url 用户设定时同样危险
// SoapClient
new SoapClient($_GET['wsdl']);
new SoapClient(null, ['location' => $url, 'uri' => $uri]);
```

### 3.2 协议 scheme 与 IP 限制

| 协议 | 风险 |
|------|------|
| `gopher://` | 构造任意 TCP 包，攻击 Redis/SMTP/FastCGI |
| `file://` | 读本地文件 |
| `dict://` | 端口探测 |

安全: `parse_url` 后白名单限制 `['http','https']`。

IP 黑名单绕过: 十进制 `2130706433`、八进制 `0177.0.0.1`、IPv6 `[::1]`/`[::ffff:127.0.0.1]`、DNS Rebinding(TOCTOU)。

重定向风险: `CURLOPT_FOLLOWLOCATION=true` 时可通过 302 跳转绕过 URL 白名单。安全做法是禁用跟随或手动校验 Location。

### 3.3 SSRF EVID 证据示例

```
[EVID_SSRF_URL_NORMALIZATION]  WebhookService.php:45 | $url=$request->input('callback_url')，无协议限制
[EVID_SSRF_FINAL_URL_HOST_PORT]  :52 | curl_setopt($ch, CURLOPT_URL, $url)，完全可控
[EVID_SSRF_DNSIP_AND_INNER_BLOCK]  无内网IP黑名单 | FOLLOWLOCATION=true → 可 gopher/302 绕过
```

---

## 4. 表达式注入

### 4.1 eval / assert

```php
// eval — 间接进入（模板场景）
$tpl = str_replace('{{name}}', $user_input, file_get_contents($path));
eval('?>' . $tpl); // $user_input 含 <?php 标签即可执行

// assert (PHP < 8.0) — 字符串表达式
assert("strlen('$input') > 0");
// $input = "') || system('id') || ('" → 代码执行
// PHP 8.0+ assert 只接受布尔表达式，此风险消失
```

### 4.2 preg_replace /e 与 create_function

```php
// /e 标志 (PHP < 7.0): 替换内容作为代码执行
preg_replace('/(.*)/e', 'strtolower("\\1")', $input);
// $input = '{${phpinfo()}}' → 执行 phpinfo()
// 安全替代: preg_replace_callback

// create_function (PHP < 8.0): 本质是 eval
create_function('$a', 'return $a . "' . $input . '";');
// $input = '"; system("id"); //' → 注入
// 安全替代: 匿名函数 Closure
```

### 4.3 可控回调

```php
// call_user_func / array_map / usort 的回调参数用户可控时等价于代码执行
call_user_func($_GET['callback'], $_GET['data']); // callback=system, data=id
array_map($_GET['func'], $_GET['arr']);

// 安全: 白名单
$allowed = ['strtolower', 'strtoupper', 'trim'];
$func = in_array($_GET['callback'], $allowed) ? $_GET['callback'] : 'trim';
```

### 4.4 EXPR EVID 证据示例

```
[EVID_EXPR_EVAL_CALL]       TemplateEngine.php:112 | eval('?>' . $compiled)
[EVID_EXPR_STRING_CONSTRUCTION]  :105-111 | str_replace 将用户变量值替入模板后进入 eval
[EVID_EXPR_USER_INPUT_INTO_EXPR]
  Source: PageController.php:87 — $values=$request->input('vars') | 无标签过滤 → Critical
```

---

## 5. NoSQL 注入

### 5.1 MongoDB $where

```php
// $where 接受 JS 表达式，用户可控时等价于代码执行
$collection->find(['$where' => "this.username == '" . $_GET['user'] . "'"]);
// user = "' || 1==1 || '" → 全部返回 | "'; sleep(5000); '" → 时间盲注
```

### 5.2 操作符注入

PHP `$_GET/$_POST` 可传数组，直接进入 MongoDB 查询时注入操作符:

```php
// 危险
$collection->findOne(['username'=>$_POST['username'], 'password'=>$_POST['password']]);
// POST: password[$ne]=1 → {password:{$ne:"1"}} → 绕过密码
// 其他: [$gt]="" | [$regex]=.* | [$in][]=admin

// 安全: 类型强转
$collection->findOne(['username'=>(string)$_POST['username'], 'password'=>(string)$_POST['password']]);
```

JSON body 同理: `{"filter":{"$ne":null}}` 注入操作符，需校验 `is_string`。

### 5.3 NoSQL EVID 证据示例

```
[EVID_NOSQL_QUERY_POINT]  UserRepo.php:34 | $collection->findOne($query)
[EVID_NOSQL_PARAM_CONSTRUCTION]  :31-33 | $token 来自请求参数，未类型强转
[EVID_NOSQL_USER_INPUT_INTO_QUERY]  token[$ne]=1 可绕过校验
```

---

## 6. LDAP 注入

### 6.1 过滤器拼接与通配符利用

```php
// 危险: 直接拼入过滤器
$filter = "(&(uid=" . $_POST['username'] . ")(userPassword=" . $_POST['password'] . "))";
ldap_search($conn, $base_dn, $filter);
// username = *)(uid=*))(|(uid=* → 匹配所有用户

// 通配符枚举: search=* → 全部 | admin* → 前缀匹配 | 逐字符 a*→ad*→adm*
```

### 6.2 ldap_escape 检测

```php
// 安全: ldap_escape (PHP 5.6+) 转义 ( ) * \ NUL
$safe = ldap_escape($_POST['username'], '', LDAP_ESCAPE_FILTER);
$filter = "(&(uid=$safe)(userPassword=$safe_pass))";
```

审计: 所有 `ldap_search`/`ldap_list`/`ldap_read` 调用点，回溯过滤器构造过程，确认用户输入是否经过 `ldap_escape`。

### 6.3 LDAP EVID 证据示例

```
[EVID_LDAP_QUERY_CALL]  LdapAuth.php:56 | ldap_search($conn, $dn, $filter)
[EVID_LDAP_FILTER_CONSTRUCTION]  :52-55 | 两参数直接拼接，未调用 ldap_escape
[EVID_LDAP_USER_INPUT_INTO_FILTER]  Source: LoginController.php:28 | 无过滤 → 可注入
```