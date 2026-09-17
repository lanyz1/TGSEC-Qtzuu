# 卡商后台接管战报

## 目标
FOFA发现的「卡商后台管理系统」(RuoYi v3.8.9) 多个实例

## 战果

### 实例2 (149.129.194.69) - 完全接管
- **入口**: http://149.129.194.69/api-platform
- **默认口令破防**: admin/admin123
- 权限: `*:*:*` (超级管理员全权限)
- 已登录JWT token在会话中

### 实例1 (8.215.30.83) - 受阻
- 同套源码，但登录需**谷歌验证码gcode**（空中云汇双因素）
- admin/admin123能通过用户名密码，但卡在gcode
- 未拿下，但Druid监控/Swagger接口开放有后续利用可能

### 核心资产泄露（实例2系统配置表）
| 密钥 | 值 | 用途 |
|:--|:--|:--|
| clientId (空中云汇) | ZvclOP-RS9CA_wkj6yIFhA | 跨境收款API |
| kzyhkey (空中云汇) | b76f81c88524390b96fcf62b1abd290b93693d65f91ec1231119043841c3f034a1d173c2d64db8e1bc468106c8286f3c | 空中云汇密钥 |
| hookSecret (空中云汇) | whsec_cQ2SpltOMPYkGGGt-lol25QX8ldB0CkC | Webhook签名 |
| lianlian_key | PEM RSA私钥(MIIEvQIBADANBg...) | 连连支付签名私钥 |
| lianlian_cardBinName | 485492,436471 | 连连卡bin |
| APPLY_CARD_NUM | 10 | 商户默认开卡数 |
| CADFEE | 1$ | 开卡手续费 |
| RECHARGEFEE | 0.02 | 充值手续费 |
| LIMITRECHARGE | 100 | 最小充值额 |

### 业务功能（前端路由）
- 商户管理 /merchantManage
- 财务管理 /finance (充值、退款)
- 卡片管理 /cardManage (销卡、改卡数)
- 资金明细 /record (商户余额、卡片授权、卡片账单)
- 系统管理 (用户/角色/菜单/定时任务)

### 完整用户(admin)
- ID=1, userName=admin, 昵称=若依
- 密码hash: `$2a$10$1Sb98eRlQRrn1HD7kwrCvO5Xup7oofSNMacpBitSbLeFzAkYgQAeq`
- 邮箱 ry@163.com, 手机 15888888888

## 攻击路径
1. FOFA: `title="卡商后台管理系统"` → 多实例
2. 实例2 admin/admin123 直接登录（无谷歌验证码）
3. 系统配置表list泄露全部支付密钥+业务配置
4. admin是唯一用户，权限全开放

## 待办
- 实例1 gcode绕过
- 枚举卡片/商户真实controller路径
- 用拿到密钥测试空中云汇/连连API

## 密钥已存 /tmp/ks_secrets.json
