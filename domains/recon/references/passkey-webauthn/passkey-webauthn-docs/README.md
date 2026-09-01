# Passkey 与 WebAuthn

本方向整理 Passkey / WebAuthn 依赖方服务端安全：怎样正确验证注册与认证、为什么它能抵抗凭据钓鱼、同步型与设备绑定型凭据有什么保证差异，以及新增凭据和账号恢复为何决定整体安全上限。

只使用公开资料，不保存网页原文、真实凭据、生产域名或用户生物信息。

## 阅读入口

1. [公开来源索引](./公开来源索引.md)：来源状态、许可、章节定位和交叉核验。
2. [依赖方安全基线](./TECH-2026-3070-Passkey_WebAuthn依赖方安全基线.md)：完整威胁模型、服务端验证与生命周期要求。
3. [依赖方审计清单](./依赖方审计清单.md)：上线前代码审计和低影响回归项。

## 核心结论

- Passkey 不是取代 WebAuthn 的新协议；Web 场景仍由 WebAuthn 完成公钥凭据操作和依赖方验证。
- 抗钓鱼来自 challenge、origin 与 RP ID 的密码学交易绑定，不来自“用了生物识别”这一界面现象。
- 浏览器 API 成功不等于登录成功；最终决定必须由服务端完成完整验证。
- UP 只表示用户在场，UV 才表示认证器完成本地用户验证；`preferred` 也不保证 UV。
- 同步型 passkey 可提供抗钓鱼并支持适当配置下的 NIST AAL2，但因密钥可导出不能用于 AAL3。
- attestation 是高保证准入工具，不是公众网站验证 assertion 签名的必需条件。
- 弱恢复、静默新增认证器、会话劫持和 XSS 可以绕开或削弱正常 passkey 登录带来的收益。

## 规范状态

- WebAuthn Level 2：W3C Recommendation，作为稳定核心基线。
- WebAuthn Level 3：截至 2026-07-20 为 2026-05-26 Candidate Recommendation Snapshot，涉及同步凭据和备份标志的内容保留候选状态。
- NIST SP 800-63B-4：2025-07-31 Final Publication。
