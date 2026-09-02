# TGSEC 红队执行引擎 — 通用知识记忆

## 攻击面优先级(中国Web系统)
1. 默认密码/弱密码
2. 未授权API
3. IDOR越权
4. JWT伪造(若依默认secret: abcdefghijklmnopqrstuvwxyz)
5. Swagger/Druid/Actuator泄露
6. 文件上传
7. SQL注入
8. SSRF
9. 反序列化
10. 源码泄露(.git/.env)

## 若依(RuoYi)系统特征
- 默认账号: admin/admin123, ry/admin123
- Swagger: /swagger-ui/index.html
- Druid: /druid/login.html
- 默认JWT secret: abcdefghijklmnopqrstuvwxyz
- **RuoYi-Vue-Plus tenant_id SQL注入(2026-09-02)**:
  - 注入点: POST /auth/register → tenantId参数
  - 无需认证,Error-based extractvalue
  - POC: domains/0day-exploits/ruoyi-vue-plus/CVE-2026-ruoyi-tenantid-sqli/
  - 自动化: exploit/exploit.py <target_url>
  - FOFA: body="RuoYi-Vue-Plus"
  - 遇到若依系统必须第一时间测试此注入!

## CAPTCHA自动破解流程
1. 获取验证码图片(base64)
2. Tesseract OCR识别(psm7 + 白名单)
3. 立即提交(防过期)
4. RSA-OAEP加密密码(password|timestamp)

## 限速绕过策略
1. 等待重置(记录retry_after)
2. 换用户名
3. 换IP(如有代理)
4. 换攻击面(不浪费等待时间)
5. 后台持久化爆破脚本

## Cloudflare绕过策略
1. crt.sh证书透明度找子域名
2. 历史DNS(SecurityTrails/ViewDNS)
3. MX/SPF/TXT泄露源IP
4. Shodan/Censys SSL证书搜索
5. 邮件头泄露
6. 直连IP + Host头

## 平台攻击链
- WordPress+ERPHP faka → wp2shell
- Evolution API → 默认key + BFLA
- 筛号平台 → thirdSource字段判断中间商
- RuoYi-Vue → 默认密码+JWT伪造+Swagger
- 云手机IOSC → 53端点全需auth, FRP端口
- Apple ID faka → ERPHP erphp_faka_query
