---
name: aws-iam-policy-analysis
description: "AWS IAM / Resource Policy 分析方法论。当目标涉及 AWS 云服务且提供了 IAM Policy、Resource Policy、Lambda 代码、CloudFormation 模板等策略文件时使用。覆盖 IAM Policy 危险模式识别、Resource Policy Principal 分析、Condition 键绕过模式、服务信任关系图推导。发现 AWS 策略文件（json/yaml）、*.amazonaws.com 端点、IAM ARN 时应使用此技能"
metadata:
  tags: "aws,iam,policy,cloud,resource-policy,principal,condition,trust,策略分析,权限分析"
  category: "cloud"
---

# AWS IAM / Resource Policy 分析方法论

拿到 AWS 策略文件（IAM Policy、Resource Policy、Lambda 代码等）后的系统化分析方法。核心目标：**从策略中推导攻击面，而非盲目枚举**。

## ⛔ 深入参考（必读）

- S3 策略分析 + 常见漏洞模式 → [references/s3-attack-techniques.md](references/s3-attack-techniques.md)
- Lambda/API Gateway/SNS 资源策略漏洞模式 → [references/aws-resource-policy-exploits.md](references/aws-resource-policy-exploits.md)

---

## 核心原则

1. **策略文件优先** — 拿到 IAM Policy / 源代码 / CloudFormation 模板时，**第一时间分析**，不要先盲目枚举
2. **从策略推导攻击面** — 策略告诉你"允许什么"，攻击面就在"允许范围的边界"
3. **Principal 是入口** — `"Principal": "*"` 意味着跨账户/匿名访问，是最高优先级检查项
4. **Condition 可能被绕过** — `StringLike` 通配符在不同协议/上下文中含义不同
5. **信任关系 > 单个权限** — 关注服务之间的信任链（谁能调用谁、谁能传递角色给谁）

---

## Step 1: 策略文件快速分类

拿到附件/下载的文件后，先分类：

| 文件类型 | 识别方式 | 关注点 |
|---------|---------|--------|
| IAM Policy | `"Version": "2012-10-17"`, `"Statement"` | Action/Resource 范围 |
| Resource Policy | 同上，但有 `Principal` 字段 | 谁能访问、条件限制 |
| Lambda 代码 | `.py`/`.js` 文件，`handler(event, context)` | 输入处理、路径拼接、注入点 |
| CloudFormation | `AWSTemplateFormatVersion`, `Resources` | 完整架构、角色绑定 |
| Trust Policy | `"Action": "sts:AssumeRole"` | 角色可被谁 assume |

---

## Step 2: IAM Policy 危险模式识别

### 2.1 检查 Principal

```
🔴 "Principal": "*"              → 任何 AWS 身份（含匿名）可访问
🔴 "Principal": {"AWS": "*"}     → 同上
🟡 "Principal": {"Service": "lambda.amazonaws.com"}  → 特定服务可调用
🟢 "Principal": {"AWS": "arn:aws:iam::123456:root"}  → 限定账户
```

### 2.2 检查 Action 范围

| Action 模式 | 风险 |
|------------|------|
| `"Action": "*"` | 🔴 完全控制 |
| `"Action": "s3:*"` | 🔴 S3 完全控制 |
| `"Action": ["s3:GetObject", "s3:PutObject"]` | 🟡 可读可写 |
| `"Action": "s3:GetObject"` on `"Resource": "*"` | 🟡 可读所有 Bucket |
| `"Action": "sts:AssumeRole"` | 🟡 可切换角色（权限提升入口） |
| `"Action": "iam:PassRole"` | 🟡 可传递角色（间接提权） |
| `"Action": "lambda:InvokeFunction"` with `Principal:*` | 🔴 任何人可调用 Lambda |

### 2.3 检查 Resource 范围

```
🔴 "Resource": "*"                          → 所有资源
🟡 "Resource": "arn:aws:s3:::bucket/*"      → bucket 内所有对象
🟢 "Resource": "arn:aws:s3:::bucket/public/*" → 仅 public 前缀
```

### 2.4 检查 Condition 绕过

```json
// StringLike 通配符 — 不同上下文含义不同
"Condition": {"StringLike": {"sns:Endpoint": "*@company.com"}}
// email 协议: Endpoint = 邮箱 → 必须是 xxx@company.com
// https 协议: Endpoint = URL → URL 中包含 @company.com 即可绕过

// IpAddress 条件 — 可能有 VPN/代理绕过
"Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}

// StringEquals vs StringLike — 前者精确匹配，后者支持通配符
```

---

## Step 3: 服务信任关系图推导

从策略文件中画出"谁信任谁"的调用关系：

```
读取所有策略文件
    ↓
识别所有 Principal（谁是调用者）
    ↓
识别所有 Resource（谁被访问）
    ↓
连线: Principal → Action → Resource
    ↓
找到最弱一环（Principal:* 或过宽权限的边）
```

常见服务关系：
- API Gateway → Lambda（API GW 触发 Lambda）
- Lambda → S3/DynamoDB/SNS（Lambda 执行角色权限）
- SNS → Lambda/SQS/HTTP（消息推送目标）
- IAM User → AssumeRole → 高权限角色

**关键**: 分析 Lambda Execution Role 的权限 — 这决定了 Lambda 能访问什么资源。

---

## Step 4: Lambda / 应用代码审计

拿到 Lambda 代码（handler.py/index.js）后重点检查：

| 漏洞类型 | 代码模式 | 利用方式 |
|---------|---------|---------|
| 路径穿越 | `os.path.join(prefix, user_input)` | 绝对路径绕过：`/flag` |
| 命令注入 | `os.system(f"cmd {user_input}")` | `; cat /flag` |
| SSRF | `requests.get(user_input)` | `http://169.254.169.254/...` |
| 环境变量泄露 | `os.environ['SECRET']` | 错误信息/Stack Trace |
| SQL 注入 | 字符串拼接 SQL | `' OR 1=1 --` |
| 反序列化 | `pickle.loads()`/`yaml.load()` | 构造恶意对象 |

---

## Step 5: AWS 服务端点发现

```bash
# 从目标页面提取 AWS 相关 URL
curl -s TARGET_URL | grep -oE 'https?://[a-z0-9.-]+\.amazonaws\.com[^"]*'
curl -s TARGET_URL | grep -oE 'https?://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com[^"]*'

# 从 JS/HTML 中提取 S3 Bucket、API GW URL
curl -s TARGET_URL | grep -oE 's3\.amazonaws\.com/[^"]*'

# Presigned URL 信息泄露
# X-Amz-Credential 包含 AccessKeyId 和 Region
```

---

## Step 6: 常用辅助工具

```bash
# webhook.site — 接收 AWS 服务回调（SNS、S3 Event 等）
# 当需要外部 Endpoint 接收 AWS 推送时使用

# AWS CLI 策略检查
aws iam get-policy-version --policy-arn ARN --version-id v1
aws s3api get-bucket-policy --bucket BUCKET
aws lambda get-policy --function-name FUNC

# ScoutSuite — AWS 安全配置审计
# Prowler — AWS 安全基线检查
```

---

## ⚠️ 避免的错误

1. **不要盲目枚举** — 连续 3 次 AccessDenied/404 后应停下来重新分析策略
2. **不要忽略附件** — 附件中的策略文件包含了解题所需的全部信息
3. **不要假设固定攻击链** — 每个场景的服务组合和漏洞点不同，从策略分析出发而非套模板
4. **不要忽略 Condition 字段** — 很多看似安全的策略，其 Condition 可被绕过
