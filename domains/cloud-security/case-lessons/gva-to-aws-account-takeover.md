# GVA 后台绕过 → AWS 账号级接管 (28 台 root + CI/CD 全源码)

**链路**: 外网入口 → 后台超管 → 云账号 AdministratorAccess → 28 台 EC2 root → Rancher/K8s → GitLab 17 仓库

## 八步链 (可复用)
1. 后台认证绕过 → GVA 超管会话 (authorityId=2)
2. `/api/system/getSystemConfig` **未脱敏** → MySQL 口令 / JWT 签名密钥 / Redis / **AWS S3 AK/SK**
3. S3 密钥 = IAM `user_s3` + **AdministratorAccess** → `aws sts get-caller-identity` 验证 → 全区域 `describe-instances`
4. **EC2 Instance Connect 横向核弹**: `send-ssh-public-key` 推临时公钥 → SSH (ubuntu/ec2-user) → `sudo -n` root; 17 台 → 横向 28 台
5. Rancher/K8s Secret 明文: GitLab token(glpat-*) / Harbor / DB / 下游 kubeconfig
6. GitLab API: 17 仓库 repository/archive.tar.gz 全量导出
7. 微服务配置: 13 组提现签名密钥 (`withdrawalSecretkey`) + PayPal RSA 私钥 + 网关凭据 → 资金面
8. **跨层持久化**: 主机公钥 ×28 / 隐藏 IAM 用户 / 超管账号+JWT密钥 / 代码层 token (抗单点清理)

## 教训
- **GVA getSystemConfig = 信任根放大器**: 一处配置接口未脱敏 → 云账号级 + 源码级失陷 (L4/L5)
- **EC2 Instance Connect = 云管理员权限的横向核弹**: 无需碰 SSH 密钥, 直接推送公钥
- Scope 锚定: 用"所有权锚" (AWS 账号 / 运维域 / 商户网关) 判归属, 旁站不碰
- 防守视角: S3 AK/SK 绑 AdministratorAccess 是典型错误; Redis/Consul 未鉴权是常见放大器; player API 回显明文 password 扩大撞库面
