---
name: cloud-iam-audit
description: "云 IAM 权限审计与提权。当获取了云平台凭据（AWS AK/SK、Azure SPN、GCP SA、腾讯云 SecretId/SecretKey）需要评估权限范围和提权路径时使用。覆盖 AWS/Azure/GCP/腾讯云的 IAM/CAM 策略分析、常见提权路径（PassRole、AssumeRole、Lambda/SCF 提权）、跨账号攻击、CloudTrail/CloudAudit 规避。发现任何云凭据、AK/SK、SecretId/SecretKey 时都应使用此技能"
metadata:
  tags: "cloud,iam,cam,audit,privilege,escalation,aws,azure,gcp,tencent,腾讯云,提权,权限,凭据,PassRole,SecretId"
  category: "cloud"
---

# 云 IAM 权限审计与提权方法论

IAM/CAM 权限就是攻击面——一个过度授权的策略比一个 RCE 漏洞更危险。

## ⛔ 深入参考（必读）

- AWS 5 条提权路径详细命令、高价值数据搜索、CloudTrail 隐蔽性 → [references/aws-escalation.md](references/aws-escalation.md)
- 腾讯云 CAM 提权路径、tccli/SDK 命令、CloudAudit 隐蔽性 → [references/tencent-cam-escalation.md](references/tencent-cam-escalation.md)

---

## Phase 1: 凭据识别与身份确认

| 凭据 | 格式 | 来源 |
|------|------|------|
| AWS AK/SK | `AKIA...` (20字符) | 配置文件、环境变量、元数据 |
| AWS 临时凭据 | `ASIA...` + SessionToken | IMDS、STS AssumeRole |
| Azure SPN | client_id + client_secret + tenant_id | 配置文件 |
| GCP SA Key | JSON 文件含 `private_key` | 服务账号密钥文件 |
| 腾讯云 SecretId/SecretKey | `AKIDz...` (36字符) / `xxx=` (Base64) | 配置文件、环境变量、元数据 |
| 腾讯云临时凭据 | SecretId/SecretKey + Token/ExpiredTime | 元数据、STS AssumeRole |

```bash
# AWS: 我是谁
aws sts get-caller-identity

# Azure
az account show

# GCP
gcloud auth list

# 腾讯云: 我是谁（优先使用 tccli）
tccli sts GetCallerIdentity
# 或使用 SDK
python3 -c "
from tencentcloud.sts.v20180813 import sts_client, models
from tencentcloud.common import credential
cred = credential.Credential('SecretId', 'SecretKey')
client = sts_client.StsClient(cred, 'ap-guangzhou')
print(client.GetCallerIdentity(models.GetCallerIdentityRequest()).to_json_string())
"
```

### 腾讯云凭据配置

```bash
# 交互式配置 tccli（优先）
tccli configure
# 输入: SecretId, SecretKey, Region(如 ap-guangzhou), Output(json)

# 使用临时凭据时需额外设置 Token
tccli configure set token "TOKEN_VALUE"

# 也可通过环境变量设置
export TENCENTCLOUD_SECRET_ID="AKIDz..."
export TENCENTCLOUD_SECRET_KEY="xxxx="
export TENCENTCLOUD_SESSION_TOKEN="TOKEN"  # 临时凭据时
```

---

## Phase 2: 权限枚举

### AWS 权限枚举
```bash
aws iam list-attached-user-policies --user-name <user>
aws iam list-attached-role-policies --role-name <role>
# 暴力枚举
aws s3 ls 2>&1; aws ec2 describe-instances 2>&1; aws iam list-users 2>&1
```

### 腾讯云 CAM 权限枚举（tccli 优先）

```bash
# 1. 账户概览
tccli cam GetAccountSummary

# 2. 列出子用户
tccli cam ListUsers

# 3. 列出用户组
tccli cam ListGroups --Page 1 --Rp 50

# 4. 列出角色（关键——角色可被 AssumeRole 利用）
tccli cam DescribeRoleList --Page 1 --Rp 50

# 5. 列出策略（自定义策略是提权关键）
tccli cam ListPolicies --Scope Local --Page 1 --Rp 100   # 仅自定义策略
tccli cam ListPolicies --Scope All --Page 1 --Rp 100      # 全部策略

# 6. 查看具体策略内容
tccli cam GetPolicy --PolicyId <PolicyId> --PolicyVersion 1

# 7. 查看用户关联的策略
tccli cam ListAttachedUserPolicies --TargetUin <UIN>

# 8. 查看角色关联的策略
tccli cam ListAttachedRolePolicies --RoleId <RoleId>

# 9. 查看用户组关联的策略
tccli cam ListAttachedGroupPolicies --GroupId <GroupId>

# 10. 列出用户的 AccessKey
tccli cam ListAccessKeys

# 11. 查看角色详情（含 Trust Policy——跨账号攻击关键）
tccli cam GetRole --RoleId <RoleId>

# 12. 查看用户所属的组
tccli cam ListGroupsForUser --Uin <UIN>
```

### 腾讯云暴力枚举（逐服务探测）

```bash
# COS 存储（tccli cos 不支持 GetService，需用 SDK 或 coscli）
coscli ls 2>&1
# 或 Python SDK:
# pip install cos-python-sdk-v5
# from qcloud_cos import CosConfig, CosS3Client
# client = CosS3Client(CosConfig(Region='ap-guangzhou', SecretId='Sid', SecretKey='Skey'))
# print(client.list_buckets())

# CVM 实例
tccli cvm DescribeInstances 2>&1

# SCF 云函数（类似 Lambda 提权路径）
tccli scf ListFunctions --Namespace default --Limit 50 2>&1

# CBS 云硬盘
tccli cbs DescribeDisks 2>&1

# SSL 证书（可能包含私钥）
tccli ssl DescribeCertificates --Limit 50 2>&1

# TDSQL/MySQL
tccli cdb DescribeDBInstances 2>&1

# 密钥管理（KMS）
tccli kms ListKeys --Limit 50 2>&1
```

### 权限等级速查
| 能做的操作 | 提权可能 |
|------------|----------|
| GetCallerIdentity 仅此 | 低 |
| cos:GetObject / s3:GetObject | 中（可能找到更多凭据） |
| cam:List*, cam:Get* / iam:List*, iam:Get* | 中（可分析提权路径） |
| cam:CreateUser/AttachUserPolicy | **高**（直接提权） |
| cam:CreateRole/AttachRolePolicy | **高**（创建高权限角色） |
| cam:PassRole + scf:CreateFunction | **高**（间接提权——SCF 挂高权限角色） |
| sts:AssumeRole | **高**（跳到更高权限角色） |

---

## Phase 3: 提权决策树

```
当前权限？
├─ 能操作 IAM/CAM（CreatePolicy/AttachPolicy）→ 直接提权
├─ 有 PassRole + Lambda/SCF → 间接提权（创建服务挂高权限 Role）
├─ 有 AssumeRole → 角色链跳转
├─ 只有数据读取 → 找更多凭据（COS/S3/Secrets/Lambda/SCF 代码/User-Data）
└─ 详细命令
    ├─ AWS → [references/aws-escalation.md](references/aws-escalation.md)
    └─ 腾讯云 → [references/tencent-cam-escalation.md](references/tencent-cam-escalation.md)
```

## 注意事项
- 云凭据提权核心：能操作 **IAM/CAM 本身** 才能提权
- 临时凭据有过期时间，优先用长期 AK/SK 或创建后门 Access Key
- 跨账号 Trust Policy 是关键审计点
- 腾讯云角色 Trust Policy 用 `qcs::cam::uin/ROOT_UIN:uin/ANY_UIN` 格式
- 腾讯云策略语法与 AWS 类似但用 `qcs` 资源描述符
- 操作会产生 CloudTrail/CloudAudit 日志，注意操作痕迹

## 提权路径概览
- **直接提权**：创建策略赋予自己 `*:*` 权限
- **间接提权**：PassRole + SCF/Lambda 创建函数挂高权限角色
- **角色链**：当前身份 → AssumeRole → 更高权限角色
- **权限枚举工具**：enumerate-iam、Pacu (AWS)；自定义脚本 (腾讯云)
