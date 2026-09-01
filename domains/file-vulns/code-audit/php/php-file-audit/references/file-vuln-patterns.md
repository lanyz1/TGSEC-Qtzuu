# PHP 文件操作类漏洞审计模式参考

5 类文件漏洞的危险代码 / 安全代码对比 + EVID_* 证据格式示例。

---

## 1. 文件上传

### 1.1 扩展名绕过模式清单

| 绕过方式 | 原理 | 示例 |
|----------|------|------|
| 双扩展名 | Web 服务器解析规则差异 | `shell.php.jpg`（Apache 从右向左遇到未知扩展名继续向左） |
| %00 截断 | PHP < 5.3.4 路径处理截断 | `shell.php%00.jpg` → 实际保存为 `shell.php` |
| .htaccess 上传 | 自定义解析规则 | 上传 `.htaccess` 内容 `AddType application/x-httpd-php .jpg` |
| Windows ::$DATA | NTFS 备用数据流 | `shell.php::$DATA` → Windows 下忽略后缀 |
| 图片马 | 文件头 + PHP 代码 | `GIF89a<?php system($_GET['c']);?>` 通过 `getimagesize()` |
| 大小写变体 | 大小写不敏感系统 | `.Php`/`.pHP` — 检查代码是否 `strtolower` |
| 竞争条件 | 先上传后校验 | 并发访问窗口期内执行 |
| 扩展名遗漏 | 黑名单不完整 | `.phtml`/`.pht`/`.php5`/`.php7`/`.phar`/`.shtml` |
| 换行符注入 | 文件名含 `\n` | 某些解析器截断换行后内容 |
| 二次渲染绕过 | 重新生成图片后仍保留代码 | GIF/PNG 特定区块注入，`imagecreatefromgif()` 后存活 |

### 1.2 危险代码 vs 安全代码

```php
// 危险: 黑名单 + 原始文件名
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$blocked = ['php', 'php3', 'php4'];
if (!in_array($ext, $blocked)) {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
}
// 问题: 遗漏 phtml/pht/php5/phar; 未 strtolower; 原始文件名可含 ../

// 危险: 仅检查 MIME — $_FILES['type'] 客户端可伪造
if ($_FILES['file']['type'] === 'image/jpeg') { /* move... */ }

// 安全: 白名单 + 服务端 MIME + 随机命名 + Web 根外
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) { die('Invalid'); }
$mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['file']['tmp_name']);
if (!in_array($mime, ['image/jpeg','image/png','image/gif'], true)) { die('Invalid'); }
$dest = '/var/data/uploads/' . bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], $dest);
```

路径穿越上传: 文件名含 `../` 跳出上传目录，用 `basename()` 剥离路径。

### 1.3 EVID_UPLOAD 证据示例

```
[EVID_UPLOAD_DESTPATH]  AvatarController.php:67
  $path = 'uploads/avatars/' . $_FILES['avatar']['name'] — 无 basename()

[EVID_UPLOAD_FILENAME_EXTENSION_PARSING_SANITIZE]  :58-64
  黑名单 ['php','php3'] 遗漏 phtml/pht/php5/phar | 未 strtolower | 无 MIME 检查

[EVID_UPLOAD_ACCESSIBILITY_PROOF]
  public/uploads/avatars/ Web 根内可直接访问 | 无 .htaccess 禁止执行
```

---

## 2. 文件读取/包含

### 2.1 include 路径拼接模式

```php
// 危险: 用户输入直接拼入
include('templates/' . $_GET['page'] . '.php');
// page=../../etc/passwd%00 (PHP<5.3.4) | page=php://filter/convert.base64-encode/resource=../config/db

// 半安全但有盲区: 仅检查 ..
if (strpos($page, '..') !== false) { die('Hacking'); }
// 绕过: ....// 过滤后变成 ../ | %2e%2e%2f 视 Web 服务器解码而定

// 安全: 白名单
$allowed = ['home', 'about', 'contact'];
$page = in_array($_GET['page'], $allowed, true) ? $_GET['page'] : 'home';
include('pages/' . $page . '.php');
```

### 2.2 php://filter 与 RFI

`php://filter` 读取源码而不执行:

```
php://filter/convert.base64-encode/resource=config/database
php://filter/read=string.rot13/resource=index
```

若代码拼接了固定目录前缀如 `'pages/' . $input`，wrapper 利用受限；`$input` 完全可控则可直接使用。

RFI 条件: `allow_url_include=On`（自 PHP 5.2 默认关闭）。审计时检查 `php.ini` 或 `ini_set()`。

### 2.3 路径穿越 Payload 变体

| Payload | 场景 |
|---------|------|
| `../../../etc/passwd` | 基础穿越 |
| `..%2f..%2f` | URL 编码 |
| `%252e%252e%252f` | 双重 URL 编码 |
| `....//....//` | 递归过滤绕过 |
| `..\/..\/` | 反斜杠替代（Windows） |

### 2.4 EVID_FILE 证据示例

```
[EVID_FILE_WRAPPER_PREFIX]  ThemeController.php:34
  include('themes/' . $theme . '/header.php') — 固定前缀限制 wrapper，../ 穿越可行

[EVID_FILE_RESOLVED_TARGET]  :34
  $theme="../../config/database" → config/database.php | .php 强制拼接

[EVID_FILE_INCLUDE_REQUIRE_EXEC_BOUNDARY]
  Source: $theme=$request->input('theme') | 无过滤 | allow_url_include=Off
  结论: LFI 已确认，可包含任意本地 .php 文件 → High
```

---

## 3. 文件写入

### 3.1 三要素分析

| 条件 | 完全可控 | 部分可控 | 不可控 |
|------|---------|---------|--------|
| 路径 | 写入任意位置 | 固定目录+文件名可控 | 硬编码 |
| 内容 | 写入任意 PHP 代码 | 部分注入(日志/模板) | 固定内容 |
| 可执行 | Web 根内+PHP 扩展 | Web 根内非 PHP 扩展 | Web 根外 |

三要素全部完全可控 = 直接写 Webshell (Critical)。

### 3.2 危险模式

```php
// 危险: 路径+内容均可控
file_put_contents($_POST['filename'], $_POST['content']); // Critical

// 危险: 配置文件写入 — 内容部分可控
$config = "<?php\nreturn ['site_name' => '" . $_POST['name'] . "'];";
file_put_contents('config/site.php', $config);
// name = "'];system($_GET['c']);//" → 注入代码

// 安全: Web 根外 + JSON 格式
file_put_contents('/var/data/config.json', json_encode($data));
```

### 3.3 日志注入 + Session 文件利用

日志注入攻击链: `error_log("Failed: " . $_POST['user'])` 写入 PHP 代码到日志 → 日志被 `include` → RCE。审计时检查日志文件是否可能被其他代码包含。

Session 文件利用: `$_SESSION['name'] = $_POST['name']` 将 PHP 代码存入 `/tmp/sess_PHPSESSID` → 配合 LFI `include('/tmp/sess_' . $_COOKIE['PHPSESSID'])` 执行。

### 3.4 EVID_WRITE 证据示例

```
[EVID_WRITE_WRITE_CALLSITE]  ConfigService.php:89 | file_put_contents($configPath, $configContent)

[EVID_WRITE_DESTPATH_RESOLVED_TARGET]  :85-87
  $configPath='config/'.$module.'.php' | $module: preg_match('/^[a-z]+$/') 穿越不可行
  但 config/ 在 Web 根内

[EVID_WRITE_CONTENT_SOURCE_INTO_WRITE]  :88
  var_export($values) | $values 用户可控 → 字符串值可注入: "'; system('id');//"

[EVID_WRITE_EXECUTION_ACCESSIBILITY_PROOF]
  config/*.php 被框架 include → 写入即执行 → Critical
```

---

## 4. Zip Slip 归档提取漏洞

### 4.1 ZipArchive 路径穿越

```php
// 危险: 直接解压 — 归档条目名含 ../../ 时穿越
$zip = new ZipArchive();
$zip->open($_FILES['archive']['tmp_name']);
$zip->extractTo('uploads/extracted/');
$zip->close();

// 安全: 遍历条目 + realpath 验证
$targetDir = realpath('uploads/extracted/') . DIRECTORY_SEPARATOR;
for ($i = 0; $i < $zip->numFiles; $i++) {
    $entryName = $zip->getNameIndex($i);
    if (strpos($entryName, '..') !== false) { continue; }
    $destPath = realpath(dirname($targetDir . $entryName));
    if ($destPath === false || strpos($destPath, $targetDir) !== 0) { continue; }
    $zip->extractTo($targetDir, $entryName);
}
```

核心: `realpath()` 解析后检查路径前缀是否仍在目标目录内。

PharData 同理: `$phar->extractTo()` 存在相同路径穿越风险。Phar 还有反序列化风险（属于 `php-serialization-audit`）。

### 4.2 EVID_ARCHIVE 证据示例

```
[EVID_ARCHIVE_EXTRACT_CALLSITE]  PluginService.php:45 | $zip->extractTo($pluginDir)

[EVID_ARCHIVE_ENTRY_NAME_VALIDATION]  :38-44
  open 后直接 extractTo | 无条目名称校验 | 无 realpath 验证

[EVID_ARCHIVE_DEST_ACCESSIBILITY]
  $pluginDir='plugins/' Web 根内 | Zip Slip 已确认 → High
```

---

## 5. 竞争条件

### 5.1 TOCTOU

```php
// 危险: 检查→删除之间的竞争窗口
if (is_file($path) && fileowner($path) === $currentUser) {
    // 窗口期: 攻击者替换 $path 为指向 /etc/passwd 的符号链接
    unlink($path);
}

// 危险: 上传先存后验
move_uploaded_file($_FILES['f']['tmp_name'], $dest);
if (!validateImage($dest)) { unlink($dest); }
// 窗口期: move → unlink 之间并发访问执行 PHP

// 安全: 先验再存
if (validateImage($_FILES['f']['tmp_name'])) { move_uploaded_file($tmp, $dest); }
```

### 5.2 符号链接跟随

```php
// 危险: uploads/evil 若是指向 /etc/crontab 的符号链接
unlink('uploads/' . $_GET['file']);

// 安全: realpath + 目录前缀验证
$realPath = realpath('uploads/' . $_GET['file']);
$uploadsDir = realpath('uploads/') . DIRECTORY_SEPARATOR;
if ($realPath && strpos($realPath, $uploadsDir) === 0) { unlink($realPath); }
```

原子操作: 写临时文件 → `rename()` 到目标位置（同一文件系统内原子），避免竞争。

### 5.3 EVID_RACE 证据示例

```
[EVID_RACE_CHECK_OPERATION]  FileService.php:112 | is_file($path)
[EVID_RACE_USE_OPERATION]  :115 | unlink($path) — 间隔 3 行，无锁
[EVID_RACE_WINDOW_ANALYSIS]
  $path 经 basename() | uploads/ 用户可写 → 可创建符号链接
  利用: 并发+精确时序 → Medium
```
