---
name: log-evasion
description: "日志分析与日志逃逸方法论。理解蓝队如何通过日志追踪攻击行为（SIEM/Event Log/Syslog），以及红队如何规避日志记录或精准清除痕迹。当需要设计无痕操作或分析日志监控覆盖范围时使用"
metadata:
  tags: "log,evasion,event-log,syslog,siem,etw,反日志,痕迹清除,audit,detection"
  category: "dfir"
  mitre_attack: "T1070.001,T1070.002,T1562.002,T1562.001,T1562.006"
---

# 日志分析与日志逃逸

> **核心原则**：最好的反日志策略是不产生日志，而非事后删除

## ⛔ 深入参考

- Windows Event Log 详细 ID 映射与清除 → [references/windows-eventlog.md](references/windows-eventlog.md)
- Linux audit/syslog 绕过技术 → [references/linux-log-evasion.md](references/linux-log-evasion.md)

---

## Part A: 蓝队视角 — 日志检测关键点

### Windows 关键 Event ID

| Event ID | 日志源 | 含义 | 红队动作触发 |
|----------|--------|------|-------------|
| 4624 | Security | 登录成功 | PTH/PTT/RDP |
| 4625 | Security | 登录失败 | 密码喷洒 |
| 4648 | Security | 显式凭据登录 | runas/PsExec |
| 4672 | Security | 特权分配 | 特权提升 |
| 4688 | Security | 新进程创建 | 工具执行 |
| 4698 | Security | 计划任务创建 | 持久化 |
| 4720 | Security | 用户创建 | 后门账户 |
| 5140 | Security | 网络共享访问 | 横向移动 |
| 5156 | Security | 网络连接 | C2 通信 |
| 7045 | System | 服务安装 | 持久化/PsExec |
| 1102 | Security | 日志清除 | ⛔ 反取证暴露！ |
| 4104 | PowerShell | 脚本块日志 | PS 攻击工具 |
| 4103 | PowerShell | 模块日志 | PS 命令执行 |
| 1 | Sysmon | 进程创建（含hash） | 所有工具执行 |
| 3 | Sysmon | 网络连接 | C2 通信 |
| 8 | Sysmon | CreateRemoteThread | 进程注入 |
| 10 | Sysmon | 进程访问 | LSASS dump |
| 11 | Sysmon | 文件创建 | 工具落盘 |

### Linux 关键日志

| 日志 | 位置 | 记录内容 |
|------|------|---------|
| auth.log/secure | /var/log/ | SSH 登录、sudo、su |
| wtmp | /var/log/ | 登录/注销记录 |
| btmp | /var/log/ | 失败登录 |
| lastlog | /var/log/ | 最后登录时间 |
| audit.log | /var/log/audit/ | auditd 规则匹配 |
| syslog/messages | /var/log/ | 系统事件 |
| journal | /var/log/journal/ | systemd 日志 |
| .bash_history | ~/ | 命令历史 |

### SIEM 常见检测规则（需要绕过的）

```
Sigma 规则示例（蓝队部署）：
├─ 进程注入: Sysmon EventID 8 (CreateRemoteThread to lsass)
├─ 凭据 Dump: EventID 10 (OpenProcess to lsass)
├─ 横向移动: EventID 4648 + 4624 LogonType 3
├─ 持久化: EventID 7045 (新服务) / 4698 (新计划任务)
├─ 日志清除: EventID 1102 / 104 → 高优先级告警！
└─ PowerShell: EventID 4104 含 "IEX" / "Invoke-" / "-enc"
```

---

## Part B: 红队视角 — 日志逃逸

### 策略 1: 阻止日志产生（最优）

```
Windows:
├─ 禁用 ETW Provider → 阻止 PowerShell/AMS 日志
│   patch ntdll!EtwEventWrite → ret
│   或 NtTraceEvent hook
├─ 关闭 ScriptBlock Logging
│   reg: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → 0
├─ 使用 .NET 避免 PowerShell 日志
│   C# 直接调用 .NET → 不走 PS 引擎 → 无 4104
├─ Thread detach from ETW
│   patch 当前线程的 ETW context → 不再产生事件
└─ Sysmon 绕过
    unload sysmon driver / patch 事件回调

Linux:
├─ 操作前: unset HISTFILE; export HISTSIZE=0; export HISTFILESIZE=0
├─ 或: set +o history
├─ 使用空格前缀命令（bash HISTCONTROL=ignorespace）
├─ kill -9 auditd（需 root，会产生停止日志）
└─ auditctl -e 0（关闭审计，更隐蔽）
```

### 策略 2: 绕过日志（不触发检测规则）

```
绕过 Sysmon:
├─ 进程注入: 避免 CreateRemoteThread → 用 APC/Callback/Early Bird
├─ LSASS 访问: 避免直接 OpenProcess → 用 Handle 复制/MiniDump
├─ 网络: 使用 raw socket → Sysmon EID 3 可能不捕获
└─ 文件: 使用已存在文件名/路径 → 不触发新文件规则

绕过 PowerShell 日志:
├─ 降级攻击: powershell -version 2（无 ScriptBlock 日志）
├─ 使用 C#/.NET: 直接反射调用 → 无 PS 日志
├─ AMSI bypass → 阻止脚本内容被记录
└─ 使用 WMI/COM → 不走 PowerShell 引擎

绕过 4688 进程创建:
├─ 进程名伪装: 复制合法程序名执行
├─ 使用 LOLBins: rundll32/mshta/certutil → 合法进程
├─ 父进程欺骗: 设置 PPID 为正常进程
└─ 命令行混淆: 环境变量展开、特殊字符
```

### 策略 3: 精准清除（已产生日志时的补救）

```
⛔ NEVER 清空整个日志 → EventID 1102 会立即告警！
⛔ ALWAYS 精准删除特定条目

Windows 精准清除:
├─ 方式 1: 停止 EventLog 服务 → 修改 .evtx 文件 → 重启服务
│   net stop eventlog（需 SYSTEM）
│   修改 evtx 二进制结构删除特定记录
│   net start eventlog
├─ 方式 2: Danderspritz eventlogedit（NSA 工具）
│   精准删除指定 EventID 的记录，修复文件校验
├─ 方式 3: Invoke-Phant0m
│   杀掉 EventLog 服务的所有线程 → 服务在但不写日志
└─ 方式 4: MiniNT 注册表键
    HKLM\SYSTEM\CurrentControlSet\Control\MiniNT → 阻止日志写入

Linux 精准清除:
├─ auth.log: sed -i '/特定IP/d' /var/log/auth.log
├─ wtmp: utmpdump /var/log/wtmp > tmp.txt
│         编辑删除特定行
│         utmpdump -r < tmp.txt > /var/log/wtmp
├─ lastlog: 工具修改特定用户的 lastlog 记录
├─ audit.log: aureport 确认记录 → sed 删除
└─ journal: journalctl --vacuum-time=1s（⛔ 会清全部）
```

### 策略 4: 实时日志转发对抗

```
现代企业会实时转发日志到 SIEM → 本地删除无效！

应对方案：
├─ 从一开始就不产生日志（策略 1）→ 最优
├─ 绕过 Sysmon/ETW（策略 2）→ 不产生特定事件
├─ 使用 SSH 隧道/DNS 隧道 → 网络日志中混入合法流量
├─ 操作时间选择 → 凌晨/节假日 → SOC 响应慢
└─ 理解 SIEM 规则阈值 → 低于告警阈值操作
    例：密码喷洒锁定阈值 5次 → 每用户只尝试 2 次
```

## 对照表

| 蓝队监控 | 触发条件 | 红队对策 |
|----------|---------|---------|
| EventID 4624 | 任何登录 | 正常时段+合法用户名 |
| EventID 4688 | 新进程 | LOLBins / PPID spoofing |
| EventID 4104 | PS 脚本 | .NET / AMSI bypass / PS v2 |
| Sysmon EID 1 | 进程+hash | 修改已知白名单程序 |
| Sysmon EID 8 | 远程线程 | APC / Timer callback |
| Sysmon EID 10 | 进程访问 | Handle duplicate |
| auditd | syscall审计 | 关闭 auditd / 直接 syscall |
| 网络日志 | 连接记录 | 域前置 / CDN / 合法服务 |
