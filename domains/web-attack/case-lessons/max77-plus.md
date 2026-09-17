# max77.plus 中间报告

- Source report: `max77.plus-渗透测试报告.md`
- Full report: `domains/web-attack/case-reports/max77-plus/max77.plus-渗透测试报告.md`
- Techniques: idor, upload, wallet
- Fused: 2026-09-17

## Key findings (distilled)

- 平台的**用户 RPC 网关存在未授权 IDOR**，可在完全未登录状态下读取任意数字 user_id 对应的用户资料、投注/游戏记录、钱包信息（用户 ID 空间约 2100 万）。此为最高危发现。
- 存储面（S3 / CloudFront / 图床）均拒绝匿名写入与目录列举，未发现可直接写入 webshell 的入口；上传链（预签名 S3 上传）经第二轮实测：服务端对上传 key 做白名单校验，未取得任何有效的匿名预签名 URL，**未发现可利用的上传路径**（见 4.3）。
- 认证后接口（GetUserInfo / GetUserRecord 等）经越权实测均按 token 身份返回，**未发现认证后 IDOR**；品牌间（10005 vs 10001）用户数据不互通（见 4.5、4.6）。
- 影响**：批量注册、撞库/弱口令面扩大。
- 无 sourcemap、无目录列举、无 dev 端点。
- 端点与逻辑（前端 JS 逆向确认）：`NA.GetUploadUrl({key:<uploadKey>, content_type:<MIME>})` → 返回 S3 预签名 PUT URL → XHR 上传 → `UpdateAwsS3UploadResult` 登记；上传组件（UploadBox，chunk 4435）的 `uploadKey` 由 CMS 页面配置在运行时下发，前端代码无硬编
- 结论**：上传 key 由服务端白名单控制且无法从公开前端枚举，未取得任何预签名 URL；content_type 是否可指定为 `text/html`、上传路径是否可控等问题因无法获得有效 key 而无法实测。**未发现可利用的匿名/越权上传路径。** 该项从"待验证线索"降级为"已排查（阴性）"。若后续获得 CMS 后台访问权，可复核白名单 key 对应的上传类型与内容校验。
- 结论**：认证后用户资料/记录类接口均按 token 解析身份，未发现认证后 IDOR。唯一的用户数据越权面仍是 3.1 的免认证 `NA.GetUserInfoByUserID`（无需 token 即可按 user_id 读取）。`GetAllLoginSessionsList` / `RemoveLoginDevice` 未见他人身份参数，风险有限。

## When to reuse

- 同类标签命中：idor, upload, wallet
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
