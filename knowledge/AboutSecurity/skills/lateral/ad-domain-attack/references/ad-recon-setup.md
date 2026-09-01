# AD 初始侦察与环境配置

## SMB 扫描输出解读

### 基础扫描

```bash
netexec smb <SUBNET>/24
```

### 输出示例

```
SMB  10.10.10.10  445  DC01    [*] Windows Server 2019 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB  10.10.10.11  445  DC02    [*] Windows Server 2019 x64 (name:DC02) (domain:child.corp.local) (signing:True) (SMBv1:False)
SMB  10.10.10.20  445  SRV01   [*] Windows Server 2019 x64 (name:SRV01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB  10.10.10.21  445  WKS01   [*] Windows 10 x64 (name:WKS01) (domain:corp.local) (signing:False) (SMBv1:False)
```

### 字段含义与判断依据

| 字段 | 含义 | 判断逻辑 |
|------|------|----------|
| `signing:True` | SMB Signing 强制开启 | **域控制器** -- 记录为 DC，用于后续 LDAP/Kerberos 查询 |
| `signing:False` | SMB Signing 未强制 | **普通服务器/工作站** -- 记录为 NTLM 中继目标 |
| `SMBv1:True` | 支持 SMBv1 | 可能存在 EternalBlue (MS17-010) 等历史漏洞 |
| `SMBv1:False` | 已禁用 SMBv1 | 较新系统或已加固 |
| `domain:xxx.local` | 主机所属域 | 区分父域/子域/外部域，多域名 = 多域环境 |
| `name:HOSTNAME` | NetBIOS 主机名 | 用于 /etc/hosts 和 Kerberos 配置 |
| `Windows Server 20xx` | 操作系统版本 | Server 通常是高价值目标 |

### 侦察记录模板

```
=== 域结构 ===
- corp.local (父域)
- child.corp.local (子域)

=== DC 列表 (signing:True) ===
- 10.10.10.10  DC01  corp.local
- 10.10.10.11  DC02  child.corp.local

=== 中继目标 (signing:False) ===
- 10.10.10.20  SRV01
- 10.10.10.21  WKS01
```

---

## DNS SRV 记录确认 DC 角色

SMB 扫描中 `signing:True` 通常是 DC，但需要 DNS SRV 记录做最终确认。

### 查询命令

```bash
# 标准 DC SRV 记录查询
nslookup -type=srv _ldap._tcp.dc._msdcs.<DOMAIN> <DC_IP>

# 示例
nslookup -type=srv _ldap._tcp.dc._msdcs.corp.local 10.10.10.10
```

### 输出示例

```
_ldap._tcp.dc._msdcs.corp.local  service = 0 100 389 dc01.corp.local.
```

### 解读

- 返回的主机名 = 确认的域控制器
- `389` = LDAP 端口（默认）
- 查询失败 = DNS 配置错误或目标域不存在，改用 DC IP 作 DNS 服务器重试

### 其他有用的 SRV 记录

```bash
# Kerberos KDC
nslookup -type=srv _kerberos._tcp.<DOMAIN> <DC_IP>

# Global Catalog
nslookup -type=srv _gc._tcp.<FOREST_ROOT> <DC_IP>

# PDC Emulator
nslookup -type=srv _ldap._tcp.pdc._msdcs.<DOMAIN> <DC_IP>
```

---

## Kerberos 客户端配置

### 安装

```bash
# Debian/Ubuntu/Kali
sudo apt install -y krb5-user
# 安装过程中的提示可直接回车跳过，后续手动配置
```

### /etc/krb5.conf 单域模板

```ini
[libdefaults]
    default_realm = DOMAIN.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    DOMAIN.LOCAL = {
        kdc = dc01.domain.local
        admin_server = dc01.domain.local
        default_domain = domain.local
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
```

### /etc/krb5.conf 多域模板

```ini
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local
        admin_server = dc01.corp.local
        default_domain = corp.local
    }
    CHILD.CORP.LOCAL = {
        kdc = dc02.child.corp.local
        admin_server = dc02.child.corp.local
        default_domain = child.corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
    .child.corp.local = CHILD.CORP.LOCAL
    child.corp.local = CHILD.CORP.LOCAL
```

### 配置项说明

| 节 | 选项 | 说明 |
|----|------|------|
| `[libdefaults]` | `default_realm` | 默认 realm（大写域名） |
| | `dns_lookup_realm` | 设 false 使用本地配置 |
| | `dns_lookup_kdc` | 设 false 使用本地配置 |
| `[realms]` | `kdc` | KDC（域控）的 FQDN |
| | `admin_server` | 管理服务器（通常与 KDC 相同） |
| | `default_domain` | 默认域名（小写） |
| `[domain_realm]` | `.domain.local` | 匹配所有 *.domain.local 主机 |
| | `domain.local` | 匹配 domain.local 本身 |

### 用 NetExec 自动生成

```bash
netexec smb <DC_IP> --generate-krb5-file /tmp/krb5.conf
cat /tmp/krb5.conf
sudo cp /tmp/krb5.conf /etc/krb5.conf
```

---

## NTP 时间同步

Kerberos 协议要求攻击机与 DC 时间差在 **5 分钟** 以内，否则认证失败。

### 同步方法

```bash
# ntpdate（最常用）
sudo ntpdate <DC_IP>

# rdate（备选）
sudo rdate -n <DC_IP>

# 检查当前时间差
net time -S <DC_IP>

# timedatectl（systemd 系统）
sudo timedatectl set-ntp false
sudo date -s "$(curl -sI http://<DC_IP> | grep Date | cut -d' ' -f2-)"
```

### 时间不同步的常见报错

| 错误信息 | 含义 |
|----------|------|
| `KRB_AP_ERR_SKEW` / `Clock skew too great` | 时间差超过 5 分钟 |
| `Kerberos SessionError: KRB_AP_ERR_SKEW` | impacket 工具的同类报错 |

---

## ccache 票据管理

### 基本操作

```bash
# 设置 ccache 文件路径
export KRB5CCNAME=/tmp/username.ccache

# 用密码获取 TGT
kinit username@DOMAIN.LOCAL

# 用 NTLM Hash 获取 TGT（impacket）
getTGT.py -hashes :<NT_HASH> DOMAIN.LOCAL/username
export KRB5CCNAME=/tmp/username.ccache

# 查看当前票据
klist

# 查看票据详细信息（包含过期时间）
klist -e

# 销毁当前票据
kdestroy
```

### 多票据切换

```bash
# 为不同用户/域保存不同 ccache
export KRB5CCNAME=/tmp/user1.ccache
kinit user1@CORP.LOCAL

export KRB5CCNAME=/tmp/user2.ccache
kinit user2@CHILD.CORP.LOCAL

# 切换回 user1
export KRB5CCNAME=/tmp/user1.ccache
klist   # 确认当前票据
```

### 与攻击工具集成

```bash
# impacket 使用 -k 表示 Kerberos 认证
export KRB5CCNAME=/tmp/admin.ccache
impacket-psexec -k -no-pass DOMAIN.LOCAL/administrator@dc01.domain.local
impacket-secretsdump -k -no-pass DOMAIN.LOCAL/administrator@dc01.domain.local

# netexec 使用 -k / --use-kcache
netexec smb <TARGET> -k
netexec smb <TARGET> --use-kcache

# evil-winrm 使用 Kerberos
evil-winrm -i <TARGET> -r DOMAIN.LOCAL
```

---

## Nmap AD 专用 NSE 脚本

### SMB 枚举脚本

```bash
# SMB 安全模式（signing 状态）
nmap -p 445 --script smb-security-mode <TARGET>

# SMB 共享枚举
nmap -p 445 --script smb-enum-shares <TARGET>

# SMB 用户枚举
nmap -p 445 --script smb-enum-users <TARGET>

# SMB 漏洞检测（EternalBlue 等）
nmap -p 445 --script smb-vuln-ms17-010 <TARGET>
nmap -p 445 --script "smb-vuln-*" <TARGET>

# 所有 SMB 脚本
nmap -p 445 --script "smb-*" <TARGET>
```

### LDAP 枚举脚本

```bash
# LDAP 根 DSE（域名、功能级别等基础信息）
nmap -p 389 --script ldap-rootdse <TARGET>

# LDAP 搜索
nmap -p 389 --script ldap-search <TARGET>
```

### Kerberos 脚本

```bash
# Kerberos 用户名枚举（无需凭据）
nmap -p 88 --script krb5-enum-users \
  --script-args krb5-enum-users.realm='DOMAIN.LOCAL' <TARGET>
```

### AD 关键端口一次性扫描

```bash
nmap -Pn -p 53,88,135,139,389,445,464,636,3268,3269,5985,5986 -sC -sV <TARGET>
```

| 端口 | 服务 | 用途 |
|------|------|------|
| 53 | DNS | 域名解析 |
| 88 | Kerberos | 认证 |
| 135 | RPC | 远程过程调用 |
| 139/445 | SMB | 文件共享 |
| 389/636 | LDAP/LDAPS | 目录查询 |
| 3268/3269 | Global Catalog | 跨域查询 |
| 5985/5986 | WinRM | 远程管理 |

---

## NetExec 多协议命令速查

### 协议探测

```bash
# SMB（文件共享/主机发现）
netexec smb <TARGET>

# LDAP（目录查询/用户枚举）
netexec ldap <TARGET>

# WinRM（远程命令执行）
netexec winrm <TARGET>

# MSSQL（数据库访问）
netexec mssql <TARGET>

# RDP（远程桌面）
netexec rdp <TARGET>
```

### 认证测试（所有协议通用格式）

```bash
netexec <PROTOCOL> <TARGET> -u '<USER>' -p '<PASSWORD>'
netexec <PROTOCOL> <TARGET> -u '<USER>' -H '<NT_HASH>'
netexec <PROTOCOL> <TARGET> -k    # Kerberos 认证
```

### 实用辅助功能

```bash
# 自动生成 /etc/hosts
netexec smb <SUBNET>/24 --generate-hosts-file /tmp/hostsfile
cat /tmp/hostsfile | sudo tee -a /etc/hosts

# 自动生成 Kerberos 配置
netexec smb <DC_IP> --generate-krb5-file /tmp/krb5.conf

# 输出为 JSON
netexec smb <TARGET> --export json
```

### Null Session 匿名枚举

```bash
# 测试匿名连接（[+] = 可用，[-] = 禁用）
netexec smb <DC_IP> -u '' -p ''

# 匿名枚举用户
netexec smb <DC_IP> -u '' -p '' --users

# 匿名枚举共享
netexec smb <DC_IP> -u '' -p '' --shares

# 获取密码策略（喷洒前必查锁定阈值）
netexec smb <DC_IP> -u '' -p '' --pass-pol
```

---

## 通过代理执行（SOCKS 场景）

```bash
# 配置 proxychains4
sudo sed -i 's/^socks4.*/socks5 127.0.0.1 1080/' /etc/proxychains4.conf

# 通过代理执行扫描
proxychains4 -q netexec smb <SUBNET>/24
proxychains4 -q nmap -sT -Pn -p 445,389,88,135 <SUBNET>/24
```

**注意**：
- 通过代理只能用 `-sT`（TCP Connect），不能用 `-sS`（SYN）
- 使用 `-q` 避免 proxychains 输出干扰结果
