---
name: emergency-response
description: "应急响应方法论。当目标主机疑似被入侵、需要排查后门/木马/异常进程/异常账户、或需要进行安全事件溯源分析时使用。覆盖 Linux 和 Windows 双平台的账户审计、进程排查、网络连接分析、启动项/计划任务检查、日志分析、Rootkit 检测"
metadata:
  tags: "emergency response,应急响应,incident response,IR,入侵排查,后门检测,rootkit,日志分析,进程排查,账户审计,linux,windows,蓝队,blue team"
  category: "dfir"
---

# 应急响应方法论

> Linux + Windows 双平台入侵排查操作手册。按阶段推进，每步产出明确结论后再进入下一步。

---

## Phase 1: 初始响应决策

```
主机疑似被入侵？
├─ 1. 确认事件范围
│   ├─ 单台主机 → 直接排查
│   └─ 多台/不明 → 先网络隔离，再逐台排查
├─ 2. 判断操作系统
│   ├─ Linux → Phase 2
│   └─ Windows → Phase 3
├─ 3. 确认当前权限
│   ├─ root/Administrator → 可完整排查
│   └─ 普通用户 → 先提权或协调管理员权限
└─ 4. 保全证据（排查前）
    ├─ 内存快照（如有条件）
    ├─ 磁盘镜像（关键服务器）
    └─ 记录当前时间戳，后续所有发现标注时间
```

**关键原则**：
- 先收集、后分析、最后清除——不要在排查过程中直接删除可疑文件
- 每一步记录发现，形成时间线
- 优先排查高威胁项：账户 → 进程/网络 → 持久化 → 文件 → 日志

---

## Phase 2: Linux 应急排查

### 2.1 账户审计

**排查清单**：

```bash
# 1. 查找特权用户（uid=0 应该只有 root）
awk -F: '$3==0{print $1}' /etc/passwd

# 2. 查找可远程登录的账户（有密码 hash 的账户）
awk '/\$1|\$6/{print $1}' /etc/shadow

# 3. 检查 sudo 权限异常（非管理员不应有 ALL 权限）
grep -v "^#\|^$" /etc/sudoers | grep "ALL=(ALL)"
cat /etc/sudoers.d/*

# 4. 检查 SSH 授权密钥（攻击者常植入公钥）
find / -name "authorized_keys" -exec ls -la {} \; -exec cat {} \;

# 5. 查看最近登录记录
lastlog           # 所有用户最后登录时间
last              # 历史登录/注销记录
lastb             # 失败登录记录（暴力破解痕迹）
```

**判断标准**：

| 发现 | 风险等级 | 处置 |
|------|---------|------|
| uid=0 的非 root 用户 | 高 | 立即禁用：`usermod -L <user>` |
| 未知用户有 sudo ALL 权限 | 高 | 移除 sudoers 条目 |
| 未知 SSH 公钥 | 高 | 记录公钥指纹后删除 |
| 异常时段登录记录 | 中 | 关联 IP 溯源 |

### 2.2 进程与网络

```bash
# 1. 检查异常网络连接（重点关注 ESTABLISHED 和 LISTEN）
netstat -antlp | grep -E "ESTABLISHED|LISTEN"
# 或
ss -antlp

# 2. 根据可疑连接 PID 定位进程
ls -la /proc/<PID>/exe        # 进程对应的可执行文件
cat /proc/<PID>/cmdline       # 完整命令行
ls -la /proc/<PID>/fd         # 打开的文件描述符

# 3. 检查异常进程
ps aux --sort=-%cpu | head -20    # CPU 占用排序（挖矿检测）
ps aux --sort=-%mem | head -20    # 内存占用排序

# 4. 检查隐藏进程（进程名以 . 开头或伪装为内核线程）
ps -ef | grep -E "^\S+\s+\d+.*\[.*\]" | grep -v "\[kworker"
```

**判断标准**：
- 外连到非业务 IP 的 ESTABLISHED 连接 → 高度可疑（C2 通信）
- 进程可执行文件在 /tmp、/dev/shm、/var/tmp 下 → 高度可疑
- 进程可执行文件已被删除（`/proc/PID/exe -> (deleted)`） → 恶意进程驻留内存

### 2.3 启动项与计划任务

```bash
# 1. 检查 crontab（所有用户）
for user in $(cut -f1 -d: /etc/passwd); do
  crontab -l -u $user 2>/dev/null && echo "=== $user ==="
done
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/

# 2. 检查 systemd 服务（关注非官方和最近修改的）
systemctl list-unit-files --type=service | grep enabled
find /etc/systemd/system/ /usr/lib/systemd/system/ -name "*.service" -mtime -7

# 3. 检查 rc.local 和 init.d
cat /etc/rc.local
ls -la /etc/init.d/
ls -la /etc/rc.d/rc*.d/ 2>/dev/null

# 4. 检查 bashrc/profile 植入
grep -r "curl\|wget\|python\|bash -i\|/dev/tcp" /etc/profile* /etc/bashrc /root/.bashrc /home/*/.bashrc 2>/dev/null
```

**重点关注**：
- 近期新增的 cron 任务（关联创建时间和入侵时间窗口）
- 非标准路径下的服务文件（/tmp、用户主目录）
- rc.local 中的可疑脚本

### 2.4 文件系统排查

```bash
# 1. 查找最近修改的文件（以 3 天为例，根据事件时间调整）
find / -mtime -3 -type f -not -path "/proc/*" -not -path "/sys/*" | head -100

# 2. 查找 SUID/SGID 文件（提权后门常见手段）
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# 3. 检查 /tmp 及隐藏目录
ls -la /tmp/ /var/tmp/ /dev/shm/
find / -name ".. " -o -name "..." -o -name ".hidden" 2>/dev/null

# 4. WebShell 检测（Web 服务器目录）
find /var/www/ -name "*.php" -mtime -7
grep -rl "eval\|system\|exec\|passthru\|shell_exec\|base64_decode" /var/www/ 2>/dev/null

# 5. 检查文件时间戳篡改（mtime 与 ctime 不一致）
stat <可疑文件>   # 对比 Modify 和 Change 时间
```

### 2.5 日志分析

| 日志文件 | 用途 | 查看方式 |
|----------|------|---------|
| /var/log/auth.log 或 /var/log/secure | SSH 登录、sudo、su | `grep "Accepted\|Failed" /var/log/auth.log` |
| /var/log/wtmp | 登录/注销记录 | `last -f /var/log/wtmp` |
| /var/log/btmp | 失败登录 | `lastb -f /var/log/btmp` |
| /var/log/cron | 定时任务执行记录 | `cat /var/log/cron` |
| /var/log/messages 或 /var/log/syslog | 系统事件 | `grep -i "error\|warning\|fail" /var/log/messages` |
| ~/.bash_history | 命令历史 | `cat /root/.bash_history` |

```bash
# 暴力破解检测：统计失败登录 IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# 成功登录排查：关注非常规 IP 和时段
grep "Accepted" /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}'

# 提权行为检测
grep "sudo:" /var/log/auth.log | grep -v "session opened\|session closed"
```

### 2.6 Rootkit 检测

```bash
# 方法 1: chkrootkit
apt install chkrootkit -y   # 或 yum install chkrootkit
chkrootkit

# 方法 2: rkhunter
apt install rkhunter -y     # 或 yum install rkhunter
rkhunter --update
rkhunter --check --sk

# 方法 3: 手动检查（工具不可信时）
# 比较系统命令 hash（与已知干净环境对比）
md5sum /usr/bin/ps /usr/bin/netstat /usr/bin/ls /usr/bin/find /usr/bin/top
# 检查 LD_PRELOAD 劫持
echo $LD_PRELOAD
cat /etc/ld.so.preload
# 检查内核模块
lsmod | grep -v "^Module"
```

---

## Phase 3: Windows 应急排查

### 3.1 账户审计

```cmd
:: 1. 查看当前登录会话
query user

:: 2. 列出所有用户和管理员组成员
net user
net localgroup administrators

:: 3. 检查隐藏/克隆账户
:: 隐藏账户名末尾带 $
wmic useraccount list full
:: 对比注册表 SAM 与 net user 结果
:: HKLM\SAM\SAM\Domains\Account\Users（需 SYSTEM 权限）

:: 4. 踢出可疑会话
logoff <SessionID>
```

**辅助工具**：
- D盾：检测隐藏账户和克隆账户
- 查看 SID 历史：`wmic useraccount get name,sid` —— SID 末尾非 500/501 的管理员需核实

### 3.2 进程与网络

```cmd
:: 1. 查看所有网络连接及对应进程
netstat -ano | findstr "ESTABLISHED LISTENING"

:: 2. 根据 PID 查进程信息
tasklist /FI "PID eq <PID>" /V
wmic process where processid=<PID> get name,executablepath,commandline

:: 3. 检查可疑进程
tasklist /V
wmic process get name,processid,executablepath,commandline /format:list

:: 4. 查看网络代理配置（是否被篡改）
REG QUERY "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

:: 5. 查看路由表
route print
```

**判断标准**：
- 可执行文件路径在 %TEMP%、%APPDATA%、用户 Downloads 下 → 可疑
- 进程名模仿系统进程（如 svchost.exe 但不在 C:\Windows\System32 下） → 高度可疑
- 异常外连 IP 的 ESTABLISHED 连接 → 关联威胁情报

### 3.3 启动项与服务

```cmd
:: 1. 检查注册表启动项
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
REG QUERY "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
REG QUERY "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"

:: 2. 检查计划任务
schtasks /query /fo LIST /v

:: 3. 检查启动文件夹
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"

:: 4. 检查服务（关注非标准服务和最近创建的服务）
wmic service list brief
wmic service get name,displayname,pathname,startmode | findstr /i "auto"

:: 5. 检查启动信息
wmic startup get command,caption
```

**重点关注**：
- Run/RunOnce 中指向临时目录或非标准路径的项
- 计划任务中执行 PowerShell、cmd /c、mshta 等的项
- 服务可执行路径包含空格且无引号（Unquoted Service Path）

### 3.4 文件系统排查

```cmd
:: 1. 查看最近访问的文件
dir %USERPROFILE%\Recent /a /o:-d

:: 2. 检查临时目录
dir %TEMP% /a /o:-d
dir %SYSTEMROOT%\Temp /a /o:-d

:: 3. 检查浏览器下载目录
dir "%USERPROFILE%\Downloads" /a /o:-d

:: 4. 查看回收站
dir C:\$Recycle.Bin /s /a

:: 5. 检查 ADS（备用数据流，可隐藏恶意代码）
dir /r <可疑目录>
```

**检查预取文件（Prefetch）**：
- 路径：`C:\Windows\Prefetch\`
- 可还原程序执行历史，即使可执行文件已被删除

### 3.5 日志分析

打开事件查看器：`eventvwr.msc`

**日志位置**：

| 日志类型 | 默认路径 | 关注内容 |
|----------|---------|---------|
| 安全日志 | `%SystemRoot%\System32\Winevt\Logs\Security.evtx` | 登录事件、账户管理、特权使用 |
| 系统日志 | `%SystemRoot%\System32\Winevt\Logs\System.evtx` | 服务安装、驱动加载、系统错误 |
| 应用程序日志 | `%SystemRoot%\System32\Winevt\Logs\Application.evtx` | 应用崩溃、程序错误 |

**关键 Event ID**：

| Event ID | 含义 | 排查价值 |
|----------|------|---------|
| 4624 | 登录成功 | 结合登录类型判断攻击方式 |
| 4625 | 登录失败 | 暴力破解痕迹 |
| 4634 | 注销 | 会话持续时间分析 |
| 4672 | 特权登录 | 管理员登录事件 |
| 4720 | 创建用户 | 后门账户检测 |
| 7045 | 服务安装 | 持久化/横向移动痕迹 |

**登录类型参考**：

| 类型 | 描述 | 常见场景 |
|------|------|---------|
| 2 | 交互登录 | 本地控制台登录 |
| 3 | 网络登录 | 共享文件夹、PsExec |
| 4 | 批处理 | 计划任务 |
| 5 | 服务 | 服务启动 |
| 7 | 解锁 | 屏保解锁 |
| 10 | 远程交互 | RDP 远程桌面 |

```powershell
# PowerShell 查询安全日志（筛选登录失败）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} |
  Select-Object TimeCreated,@{N='IP';E={$_.Properties[19].Value}} |
  Group-Object IP | Sort-Object Count -Descending

# 查询新建用户事件
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720} |
  Format-List TimeCreated,Message
```

---

## Phase 4: 溯源与加固

### 4.1 时间线重建

```
收集所有发现 → 按时间排序 → 构建攻击链：
1. 初始入侵时间点（最早的异常记录）
2. 攻击路径（如何从入口扩展）
3. 持久化手段（留了哪些后门）
4. 数据泄露（是否有大量数据外传）
```

### 4.2 IOC 提取

从排查中提取以下指标，用于威胁情报关联：

| IOC 类型 | 来源 | 用途 |
|----------|------|------|
| 恶意 IP/域名 | 网络连接、日志 | 封禁 + 情报查询 |
| 文件 Hash | 可疑文件 MD5/SHA256 | VirusTotal/微步查询 |
| 攻击者账户 | 新增/异常账户 | 内网横向排查 |
| 恶意文件路径 | 文件系统排查 | 全网扫描同类文件 |

### 4.3 加固建议

**立即措施**：
- 修改所有受影响账户密码
- 清除攻击者植入的持久化机制（计划任务、服务、启动项、SSH 密钥）
- 封禁恶意 IP（防火墙/安全组）
- 修补入侵利用的漏洞

**长期加固**：
- 启用集中日志收集（防止本地日志被清除）
- 部署 HIDS/EDR 监控
- 实施最小权限原则
- 定期审计账户和服务

## 注意事项

- 排查过程中不要重启服务器——内存中的恶意进程和网络连接信息会丢失
- 不要直接删除可疑文件——先备份取证再清除
- 如果怀疑系统命令（ps/netstat/ls）被替换（Rootkit），使用静态编译的 busybox 或从可信源拷贝工具排查
- 日志可能被攻击者清除或篡改——多源交叉验证（系统日志 + 网络设备日志 + 应用日志）
