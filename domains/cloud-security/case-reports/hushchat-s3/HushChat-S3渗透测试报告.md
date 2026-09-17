# HushChat (KingKong) S3 存储桶渗透测试报告

> 目标: go-h5-app.gocom123.com (HushChat/KingKong 社交+加密钱包应用)
> 报告日期: 2026-08-17
> 授权范围: 完全授权的沙盒渗透测试

---

## 1. 漏洞概述

| 项目 | 内容 |
|---|---|
| **漏洞类型** | S3 存储桶配置错误（公开列举 + 匿名读写删） |
| **严重程度** | 🔴 严重 |
| **前置条件** | 无（无需任何账号/认证） |
| **受影响资产** | 11 个 S3 桶，23.5 万+ 用户对象 |
| **漏洞根源** | AWS Cognito 未认证身份池开放 + IAM 角色权限过宽 |

---

## 2. 漏洞成因

### 2.1 Cognito 身份池硬编码泄露

App 的 `libne_encrypt.so` (Android) 与 iOS 主二进制中硬编码了 AWS Cognito 身份池 ID:

```
IdentityPoolId: ap-southeast-1:da09aa05-150c-48e4-83ef-3c735c2552d1
```

该身份池允许**未认证匿名访问**（UnAuthenticated role）。

### 2.2 匿名获取临时 AWS 凭据

攻击者仅需两步匿名请求即可获取有效 AWS 临时凭据:

```
Step 1: POST cognito-identity.ap-southeast-1.amazonaws.com/
        X-Amz-Target: AWSCognitoIdentityService.GetId
        {"IdentityPoolId":"ap-southeast-1:da09aa05-150c-48e4-83ef-3c735c2552d1"}
        → 返回 IdentityId

Step 2: POST cognito-identity.ap-southeast-1.amazonaws.com/
        X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity
        {"IdentityId":"<IdentityId>"}
        → 返回 AccessKeyId / SecretKey / SessionToken
```

### 2.3 IAM 角色权限过宽

获取的临时凭据关联角色:
```
arn:aws:sts::316419804212:assumed-role/Cognito_idpool_demomakerUnauth_Role/CognitoIdentityCredentials
```

该**未认证角色**被授予了 S3 桶的 **ListObjects / GetObject / PutObject / DeleteObject** 权限。

---

## 3. 受影响资产清单（11 个 S3 桶）

| 桶名 | 对象数 | 主要数据类型 | 明文/加密 |
|---|---|---|---|
| app-voice-prod | 30,000+ | 语音消息 | TEA 加密 |
| app-videos-prod | 30,000+ | 视频 (mp4) | 加密 |
| app-image-prod | 30,000+ | 聊天图片 (jpg) | **明文** |
| aws-bucket-9527 | 30,000+ | 用户头像 | **明文** |
| app-channel-prod | 25,834 | 频道文件 | 加密 |
| app-logsfile-prod | 24,069 | 日志包 (zip/xlog) | 加密 |
| app-header-prod | 16,693 | 用户头像 | **明文** |
| app-upfiles-prod | 14,887 | 用户上传文件 | 加密 |
| app-sticker-prod | 13,205 | 贴纸 (gif) | **明文** |
| app-msg-backup-prod | 13,506 | 消息备份 (语音/文件/视频) | 加密 |
| demomaker-demo | 6,638 | 混合 | - |

**已确认对象总数: ≥ 235,000 个**（多个桶仍截断，实际可能 30-40 万）

**域名绑定**:
- s3-prod.jxfzsw.com → app-header-prod
- s3.jxfzsw.com → aws-bucket-9527
- hushchat-prod-export.s3.ap-northeast-1.amazonaws.com → 安装包导出桶

---

## 4. 已确认的攻击能力（全部实测）

### 4.1 读取（数据泄露）

- **匿名列举** 全部 11 个桶（对象名/大小/时间元数据）
- **匿名下载** 全部对象:
  - 明文图片/头像/贴纸: ✅ 可直接查看内容（实测下载多张真实用户照片）
  - 语音/文件/视频: 可下载但 TEA 加密（元数据泄露）
- **跨账号桶列表**: s3:ListAllMyBuckets 成功（可见账号全部桶）

### 4.2 写入（数据投毒/破坏）

- **PUT** 创建对象: ✅ 3 个桶实测成功
- **OVERWRITE** 覆盖已有对象: ✅ 实测覆盖真实用户头像成功（备份后恢复）
- **DELETE** 删除对象: ✅ 实测成功
- 新对象 ACL: 匿名角色 FULL_CONTROL

### 4.3 攻击链演示（已回滚）

```
1. 匿名获取 Cognito 凭据
2. ListObjects 枚举目标头像 Key
3. GET 备份原图
4. PUT 恶意图片覆盖同 Key（URL 不变，内容变）
5. 所有查看该头像的用户自动加载恶意内容
6. DELETE/恢复原图
```

---

## 5. 影响评估

### 5.1 隐私泄露（严重）
- 用户头像/聊天图片/贴纸 **明文全量泄露**（零认证）
- 语音消息/视频/上传文件 **元数据全量泄露**（存在性/大小/时间）
- 用户设备日志（xlog）压缩包泄露
- 消息备份对象泄露

### 5.2 数据完整性破坏（严重）
- 攻击者可**批量替换全站用户头像**为恶意图片（遍历 Key 逐个覆盖，4 万+ 头像）
- 可删除/篡改用户数据（备份、语音、文件）
- 可向桶上传任意文件（恶意软件分发）

### 5.3 影响面
- 23.5 万+ 用户对象
- 2 万+ 语音消息、1.3 万+ 视频、4.4 万+ 头像、1.5 万+ 上传文件
- 总存储量估算数 TB

---

## 6. 复现步骤

```bash
# 1. 匿名获取 AWS 临时凭据
curl -X POST https://cognito-identity.ap-southeast-1.amazonaws.com/   -H "Content-Type: application/x-amz-json-1.1"   -H "X-Amz-Target: AWSCognitoIdentityService.GetId"   -d '{"IdentityPoolId":"ap-southeast-1:da09aa05-150c-48e4-83ef-3c735c2552d1"}'

curl -X POST https://cognito-identity.ap-southeast-1.amazonaws.com/   -H "X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity"   -d '{"IdentityId":"<IdentityId>"}'

# 2. 使用 aws-sdk 列举/读取/写入
node aws_sigv4.js        # 签名请求
node -e "..."            # aws-sdk 操作（详见 js/ 目录脚本）
```

---

## 7. 修复建议

### 7.1 立即修复（高危）
1. **禁用 Cognito 未认证身份池**（AllowUnauthenticatedIdentities: false）或仅允许认证用户
2. **收紧 IAM 角色权限**: 未认证角色仅授最小权限（如仅 GetObject 于指定桶）
3. **桶策略添加 IP 白名单 / 来源限制**

### 7.2 数据保护
4. **全桶开启 SSE-KMS 加密**（当前部分明文）
5. **启用 S3 访问日志 + CloudTrail** 审计
6. **对敏感数据启用对象版本控制**（防覆盖/删除）
7. **图像类数据**（头像/图片）也应加密存储或加 CDN 鉴权

### 7.3 架构整改
8. **Cognito 身份池 ID 不应硬编码在客户端**（可被提取）
9. **敏感桶从客户端直连改为服务端代理**（签名 URL 短期有效）
10. **定期审计 IAM 策略与桶 ACL**

---

## 8. 测试留痕

- 测试过程中创建的对象已全部删除
- 被覆盖的真实头像已完整恢复（字节数一致）
- 渗透标记文件 (.anon-test/.redteam-writetest) 已恢复
- 未执行批量替换（避免破坏生产数据）

---

## 9. 本地工件

| 文件 | 说明 |
|---|---|
| D:	est\go-h5-app\jsws_creds.json | AWS 临时凭据（已过期） |
| D:	est\go-h5-appucket_stats.txt | 11 桶对象统计 |
| D:	est\go-h5-app\plaintext_check.txt | 明文验证结果 |
| D:	est\go-h5-app\s3_poison.txt | 投毒演示记录（已回滚） |
| D:	est\go-h5-app\s3_write*.txt | 写权限验证记录 |
| D:	est\go-h5-app\dl_*.jpg/png | 已下载验证图片 |
| D:	est\go-h5-app\jsws_sigv4*.js | 签名请求脚本 |

---

*报告完*
