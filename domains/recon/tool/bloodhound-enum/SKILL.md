---
name: bloodhound-enum
description: "使用 BloodHound.py 进行 Active Directory 信息采集。当需要枚举域内用户、组、计算机、会话、ACL、信任关系，分析域内攻击路径时使用。BloodHound.py 是 BloodHound 的 Python 采集器，通过 LDAP/DNS/Kerberos 协议采集 AD 数据并输出 JSON 供 BloodHound GUI 分析。任何涉及域渗透、AD 枚举、攻击路径分析的场景都应使用此技能"
metadata:
  tags: "bloodhound,AD,域渗透,Active Directory,LDAP,Kerberos,枚举,ACL,信任关系,攻击路径,域控"
  category: "tool"
---

# BloodHound.py AD 信息采集方法论

BloodHound.py 是 BloodHound 的 Python 采集器。核心优势：**无需在目标执行**（通过 LDAP/DNS 远程采集）+ **全面覆盖**（用户/组/计算机/会话/ACL/信任关系）+ **JSON 输出**（导入 BloodHound GUI 分析攻击路径）。

项目地址：https://github.com/dirkjanm/BloodHound.py

## Phase 1: 基本采集

```bash
# 全量采集（最常用）
bloodhound-python -d corp.local -u user -p 'P@ssw0rd' -c All

# 指定域控 IP
bloodhound-python -d corp.local -u user -p 'P@ssw0rd' -c All -dc 10.0.0.1

# 指定 DNS 服务器
bloodhound-python -d corp.local -u user -p 'P@ssw0rd' -c All -ns 10.0.0.1

# 输出压缩包
bloodhound-python -d corp.local -u user -p 'P@ssw0rd' -c All --zip
```

## Phase 2: 认证方式

```bash
# 密码认证
bloodhound-python -d corp.local -u user -p 'P@ssw0rd' -c All

# NTLM Hash 认证（Pass the Hash）
bloodhound-python -d corp.local -u user --hashes aad3b435b51404eeaad3b435b51404ee:hash -c All

# Kerberos 认证
bloodhound-python -d corp.local -u user -p 'P@ssw0rd' -c All -k

# 使用 ccache 票据
export KRB5CCNAME=/tmp/krb5cc_user
bloodhound-python -d corp.local -u user -c All -k --auth-method kerberos
```

## Phase 3: 采集方式选择

```bash
# 默认采集（Group + LocalAdmin + Session + Trusts）
bloodhound-python -d corp.local -u user -p pass -c Default

# 仅采集组成员关系
bloodhound-python -d corp.local -u user -p pass -c Group

# 仅采集本地管理员
bloodhound-python -d corp.local -u user -p pass -c LocalAdmin

# 仅采集会话信息
bloodhound-python -d corp.local -u user -p pass -c Session

# ACL 采集（分析权限关系）
bloodhound-python -d corp.local -u user -p pass -c ACL

# 信任关系
bloodhound-python -d corp.local -u user -p pass -c Trusts
```

## Phase 4: 导入与分析

采集完成后将 JSON/ZIP 文件导入 BloodHound GUI：

```bash
# 启动 Neo4j（BloodHound 后端）
sudo neo4j start

# 打开 BloodHound GUI，拖拽 JSON/ZIP 文件导入
# 常用查询：
# - Find all Domain Admins
# - Shortest Path to Domain Admins
# - Find Kerberoastable Users
# - Find AS-REP Roastable Users
```

## 渗透测试常用场景

| 场景 | 命令 |
|------|------|
| 全量采集 | `bloodhound-python -d corp.local -u user -p pass -c All --zip` |
| PTH 采集 | `bloodhound-python -d corp.local -u user --hashes LM:NT -c All` |
| 仅 ACL 分析 | `bloodhound-python -d corp.local -u user -p pass -c ACL` |
| 指定 DC | `bloodhound-python -d corp.local -u user -p pass -c All -dc 10.0.0.1 -ns 10.0.0.1` |
