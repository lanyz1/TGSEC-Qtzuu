---
name: nikto-scan
description: "使用 Nikto 进行 Web 服务器漏洞扫描。当需要检测 Web 服务器的已知漏洞、过时软件版本、危险文件/CGI、配置错误时使用。Nikto 内置 7000+ 检查项，覆盖 OWASP 常见问题。任何涉及 Web 漏洞扫描、服务器安全检查、配置审计的场景都应使用此技能"
metadata:
  tags: "nikto,web,scan,漏洞扫描,Web服务器,CGI,配置错误,OWASP,SSL,过时软件"
  category: "tool"
---

# Nikto Web 服务器漏洞扫描方法论

Nikto 是经典的 Web 服务器漏洞扫描器。核心优势：**检查项丰富**（7000+ 项）+ **开箱即用**（无需配置）+ **覆盖面广**（过时软件/危险文件/配置错误/已知漏洞）。

项目地址：https://github.com/sullo/nikto

## Phase 1: 基本扫描

```bash
# 扫描单个目标
nikto -h http://target.com

# 指定端口
nikto -h target.com -p 8080

# HTTPS 扫描
nikto -h https://target.com

# 多端口扫描
nikto -h target.com -p 80,443,8080,8443
```

## Phase 2: 扫描调优

```bash
# 指定扫描类型（Tuning）
# 1=文件上传 2=默认文件 3=信息泄露 4=注入 5=远程获取 6=DoS 7=远程shell 8=命令执行 9=SQL注入
nikto -h http://target.com -Tuning 123489

# 只做信息泄露检查
nikto -h http://target.com -Tuning 3

# 排除 DoS 类检查
nikto -h http://target.com -Tuning x6

# 指定插件
nikto -h http://target.com -Plugins apache_expect_xss,ssl

# 设置最大扫描时间
nikto -h http://target.com -maxtime 300
```

## Phase 3: 认证和代理

```bash
# Basic Auth
nikto -h http://target.com -id admin:password

# Cookie 认证
nikto -h http://target.com -Add-header "Cookie: session=abc123"

# 自定义 User-Agent
nikto -h http://target.com -useragent "Mozilla/5.0"

# 通过代理
nikto -h http://target.com -useproxy http://127.0.0.1:8080

# 禁用 404 猜测（减少误报）
nikto -h http://target.com -no404
```

## Phase 4: 输出格式

```bash
# JSON 输出
nikto -h http://target.com -Format json -output results.json

# HTML 报告
nikto -h http://target.com -Format html -output report.html

# CSV 输出
nikto -h http://target.com -Format csv -output results.csv

# XML 输出
nikto -h http://target.com -Format xml -output results.xml
```

## 常用场景速查

| 场景 | 命令 |
|------|------|
| 快速扫描 | `nikto -h http://target.com -maxtime 120` |
| 全面扫描 | `nikto -h http://target.com -Tuning 123456789abc` |
| SSL 检查 | `nikto -h https://target.com -Plugins ssl` |
| 信息泄露 | `nikto -h http://target.com -Tuning 3` |
| 带认证扫描 | `nikto -h http://target.com -id admin:pass` |
