# 钓鱼邮件模板集

> @TGSEC社区 · @TGSEC-Qtzuu 整理
> 仅用于授权红队演练/安全意识培训

## 一、中文钓鱼模板

### 1. 密码过期通知
```
主题: [紧急] 您的企业邮箱密码将于24小时后过期

尊敬的用户:

您的企业邮箱密码将于24小时后过期。为确保您正常使用邮件服务,
请立即点击以下链接更新密码:

[立即更新密码](https://PHISHING_URL)

如果您未在规定时间内更新,您的邮箱将被暂时锁定。

IT信息安全部
```

### 2. 系统升级通知
```
主题: 关于OA系统升级维护的通知

各位同事:

OA系统将于本周六进行升级维护,升级后需要重新登录。
请提前在以下页面验证您的账号,以确保升级后正常使用:

[账号验证入口](https://PHISHING_URL)

升级时间: 本周六 22:00-次日06:00
影响范围: 所有OA用户

信息技术部
```

### 3. HR薪资通知
```
主题: 2026年Q3绩效奖金发放通知

各位同事:

2026年第三季度绩效奖金已核算完毕,请登录HR系统查看详情:

[查看奖金详情](https://PHISHING_URL)

请于本周五前确认无误,逾期将视为认可。

人力资源部
```

### 4. 财务报销
```
主题: 您有一笔报销待审核

您好:

您提交的报销单(编号: BX-2026-0892)已进入审核流程。
由于金额较大,需要您登录系统补充材料:

[补充报销材料](https://PHISHING_URL)

请于3个工作日内完成,否则将退回重新提交。

财务部
```

### 5. VPN/安全更新
```
主题: [安全更新] 请立即更新VPN客户端

尊敬的用户:

我们检测到您当前使用的VPN客户端存在安全漏洞(CVE-2026-XXXX),
请立即下载最新版本:

[下载更新](https://PHISHING_URL)

未更新的客户端将于48小时后无法连接。

网络安全组
```

## 二、英文钓鱼模板

### 1. Microsoft 365
```
Subject: Action Required: Verify Your Microsoft 365 Account

Your Microsoft 365 account requires verification due to unusual sign-in activity.

[Verify Now](https://PHISHING_URL)

If you don't verify within 24 hours, your account will be suspended.

Microsoft 365 Team
```

### 2. DocuSign
```
Subject: Document Ready for Your Signature

Hi,

A document has been sent to you for review and signature via DocuSign.

[REVIEW DOCUMENT](https://PHISHING_URL)

Sender: John Smith (john.smith@partner-company.com)
Document: NDA_Agreement_2026.pdf

DocuSign
```

### 3. IT Support
```
Subject: [Ticket #28491] Your Password Expires Tomorrow

Dear User,

Our records indicate your network password will expire in 24 hours.
Please use the link below to update your credentials:

[Update Password](https://PHISHING_URL)

Failure to update will result in account lockout.

IT Help Desk
```

## 三、钓鱼基础设施搭建

### GoPhish配置
```bash
# 1. 安装
wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip
unzip gophish*.zip && chmod +x gophish
./gophish

# 2. 配置发送邮件
# SMTP: 使用自建邮件服务器或第三方SMTP

# 3. 创建模板 → Landing Page → Campaign → 发送

# 4. 追踪打开率/点击率/提交率
```

### 邮件服务器
```bash
# 快速搭建(postfix)
apt install postfix mailutils
# 配置SPF/DKIM/DMARC提高送达率

# 或使用: mail-in-a-box, mailu
```

### 域名配置
```
1. 注册相似域名(target-inc.com)
2. 配置DNS:
   A记录 → 攻击机IP
   MX记录 → 邮件服务器
   SPF: v=spf1 ip4:ATTACKER_IP ~all
   DKIM: 使用opendkim生成
3. 申请Let's Encrypt证书
```
