# TGSEC 红队执行引擎 — Hermes Agent 记忆配置

> **使用方法**: 将本文件内容复制到 `~/.hermes/memories/MEMORY.md`
> 配合 `USER.md` 一起使用，重启 Hermes 即可生效

## 安装方式

```bash
# 方式1: 直接复制
cp MEMORY.md ~/.hermes/memories/MEMORY.md
cp USER.md ~/.hermes/memories/USER.md

# 方式2: 软链接(仓库更新自动同步)
ln -sf $(pwd)/MEMORY.md ~/.hermes/memories/MEMORY.md
ln -sf $(pwd)/USER.md ~/.hermes/memories/USER.md
```

---

以下是实际写入 `~/.hermes/memories/MEMORY.md` 的内容:

```
渗透测试时用户反复说'继续深挖'/'继续啊'——不要过早总结说'已到极限',必须穷尽所有攻击面后才能说打不动。
§
pentest-execution skill has platform-attack-chains.md reference covering: WordPress+ERPHP faka, Evolution API, 筛号平台, RuoYi-Vue, IOSC/云手机, wp2shell, Apple ID faka. Update this reference when new platform patterns emerge.
§
Black Cat红队框架注册为技能 black-cat-redteam; 777VVIP渗透经验注册为 gambling-platform-pentest; 0day-exploit-library 覆盖76产品90个RCE漏洞。
§
CAPTCHA自动化破解工作流: 1)获取验证码图片 2)Tesseract OCR识别(psm7+白名单) 3)立即提交(防过期) 4)RSA-OAEP加密密码(password|timestamp格式)。已在多个目标验证100%成功率。
§
常见中国Web系统攻击面优先级: 1)默认密码/弱密码 2)未授权API 3)IDOR越权 4)JWT伪造(若依默认secret) 5)Swagger/Druid/Actuator泄露 6)文件上传 7)SQL注入 8)SSRF 9)反序列化 10)源码泄露(.git/.env)
§
若依(RuoYi)系统默认: admin/admin123, ry/admin123, Swagger路径/swagger-ui/index.html, Druid路径/druid/login.html, 默认JWT secret: abcdefghijklmnopqrstuvwxyz
§
限速绕过策略: 1)等待重置(记录retry_after) 2)换用户名 3)换IP(如有代理) 4)换攻击面(不浪费等待时间) 5)后台持久化爆破脚本(每轮间隔+自动等待)
§
Cloudflare绕过策略: 1)crt.sh证书透明度找子域名 2)历史DNS记录(SecurityTrails/ViewDNS) 3)MX/SPF/TXT记录泄露源IP 4)Shodan/Censys SSL证书搜索 5)邮件头泄露 6)直连IP+Host头
```
