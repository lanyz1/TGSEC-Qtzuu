---
name: httpx-probe
description: "使用 httpx 进行 HTTP 探活、指纹识别和信息收集。当需要批量检测 HTTP/HTTPS 服务存活、识别 Web 技术栈、提取页面标题/状态码/响应头、CDN 检测、截图时使用。httpx 是 ProjectDiscovery 出品的多功能 HTTP 探针工具，是渗透测试管道中连接端口扫描和漏洞扫描的关键桥梁。任何涉及 HTTP 存活检测、Web 指纹识别、技术栈识别、批量 URL 探测的场景都应使用此技能"
metadata:
  tags: "httpx,probe,http,fingerprint,存活检测,指纹识别,技术栈,CDN,截图,projectdiscovery,title"
  category: "tool"
---

# httpx HTTP 探活与指纹识别方法论

httpx 是 ProjectDiscovery 出品的多功能 HTTP 探针工具。核心优势：**高速并发**（默认 50 线程）+ **丰富探针**（状态码/标题/技术栈/CDN/截图等）+ **管道核心**（连接端口扫描和漏洞扫描的桥梁）。

项目地址：https://github.com/projectdiscovery/httpx

## Phase 1: 基本存活检测

```bash
# 单个目标
httpx -u http://target.com

# 批量目标（从文件）
httpx -l urls.txt

# 从 stdin 管道
cat urls.txt | httpx

# 静默输出（只显示存活 URL）
cat urls.txt | httpx -silent
```

## Phase 2: 信息探针（核心能力）

```bash
# 显示状态码 + 标题 + 技术栈（最常用组合）
httpx -l urls.txt -sc -title -tech-detect

# 显示状态码 + 内容长度 + Web 服务器
httpx -l urls.txt -sc -cl -server

# 显示 IP + CNAME + ASN
httpx -l urls.txt -ip -cname -asn

# CDN/WAF 检测
httpx -l urls.txt -cdn

# 响应时间
httpx -l urls.txt -rt

# 完整信息输出
httpx -l urls.txt -sc -title -tech-detect -server -ip -cdn -cl
```

## Phase 3: 技术栈识别（指纹识别）

httpx 内置 Wappalyzer 数据集，能识别 Web 框架、CMS、编程语言等：

```bash
# 技术栈检测
httpx -u http://target.com -tech-detect

# 输出示例：
# http://target.com [200] [WordPress] [PHP,MySQL,Apache]

# 批量识别 + JSON 输出
httpx -l urls.txt -tech-detect -json -o fingerprints.json

# 自定义指纹文件
httpx -l urls.txt -tech-detect -custom-fingerprint-file /path/to/fingerprints.json
```

## Phase 4: 过滤与匹配

```bash
# 只显示 200 OK 的目标
httpx -l urls.txt -mc 200

# 排除 404 和 403
httpx -l urls.txt -fc 404,403

# 匹配包含特定字符串的响应
httpx -l urls.txt -ms "admin"

# 正则匹配
httpx -l urls.txt -mr "login|admin|dashboard"

# 按响应长度过滤
httpx -l urls.txt -fl 0

# 匹配特定 CDN
httpx -l urls.txt -match-cdn cloudflare

# 过滤错误页面
httpx -l urls.txt -filter-page-type error,parked
```

## Phase 5: 截图（Headless）

```bash
# 页面截图
httpx -l urls.txt -screenshot

# 使用系统 Chrome
httpx -l urls.txt -screenshot -system-chrome

# 截图 + 技术栈 + 状态码
httpx -l urls.txt -screenshot -tech-detect -sc -title
```

## Phase 6: 管道集成

httpx 是 ProjectDiscovery 工具链的**核心枢纽**：

```bash
# 子域名 → HTTP 存活
subfinder -d target.com -silent | httpx -silent

# 端口扫描 → HTTP 存活 → 指纹
naabu -host target.com -silent | httpx -tech-detect -title -sc

# 子域名 → 存活 → 漏洞扫描
subfinder -d target.com -silent | httpx -silent | nuclei -severity critical,high

# 子域名 → 存活 → 爬虫 → 漏洞扫描（完整链）
subfinder -d target.com -silent | httpx -silent | katana -jc -silent | nuclei

# 网段扫描 → HTTP 存活 → 指纹 → 高价值目标筛选
naabu -host 10.0.0.0/24 -p 80,443,8080 -silent | httpx -tech-detect -title -sc -silent
```

## Phase 7: 高级用法

```bash
# 探测多端口（单个主机的多端口 HTTP 检测）
echo target.com | httpx -ports 80,443,8080,8443

# 自定义请求方法
httpx -l urls.txt -x GET,POST

# 自定义 Header
httpx -l urls.txt -H "Cookie: session=abc"

# 跟随重定向
httpx -l urls.txt -follow-redirects

# TLS 信息抓取
httpx -l urls.txt -tls-grab

# 提取正则匹配内容（如提取邮箱）
httpx -l urls.txt -extract-preset mail,ipv4

# 自定义正则提取
httpx -l urls.txt -extract-regex "api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]+)"

# JSON 输出（包含完整信息）
httpx -l urls.txt -json -o results.json

# 控制并发和速率
httpx -l urls.txt -threads 100 -rate-limit 50

# 去重（过滤相似页面）
httpx -l urls.txt -filter-duplicates
```

## 常用场景速查

| 场景 | 命令 |
|------|------|
| 快速存活检测 | `cat urls.txt \| httpx -silent` |
| 技术栈识别 | `httpx -l urls.txt -tech-detect -sc -title` |
| 找管理后台 | `httpx -l urls.txt -mr "admin\|login\|dashboard" -sc -title` |
| CDN 识别 | `httpx -l urls.txt -cdn -ip` |
| 批量截图 | `httpx -l urls.txt -screenshot -system-chrome` |
| 提取子域名 | `httpx -l urls.txt -extract-fqdn -json` |
| 连接 naabu | `naabu -host target -silent \| httpx -tech-detect` |
