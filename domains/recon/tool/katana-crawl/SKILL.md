---
name: katana-crawl
description: "使用 katana 进行 Web 爬虫和 URL 发现。当需要爬取目标网站的所有页面和端点、发现隐藏的 API 路径、JavaScript 中的端点、表单提取时使用。katana 是 ProjectDiscovery 出品的下一代爬虫框架，支持标准模式和 Headless 浏览器模式，能解析 JavaScript 发现动态端点。任何涉及 Web 爬虫、URL 发现、JS 端点提取、表单发现、站点地图的场景都应使用此技能"
metadata:
  tags: "katana,crawl,spider,爬虫,URL发现,JS解析,endpoint,表单,projectdiscovery,headless"
  category: "tool"
---

# katana Web 爬虫方法论

katana 是 ProjectDiscovery 出品的下一代 Web 爬虫框架。核心优势：**JavaScript 解析**（发现动态端点）+ **Headless 模式**（渲染 SPA）+ **管道友好** + **表单自动填充**。

项目地址：https://github.com/projectdiscovery/katana

## Phase 1: 基本爬取

```bash
# 爬取单个目标（默认深度 3）
katana -u http://target.com

# 指定爬取深度
katana -u http://target.com -d 5

# 静默输出（只显示 URL）
katana -u http://target.com -silent

# 输出到文件
katana -u http://target.com -silent -o urls.txt
```

## Phase 2: JavaScript 解析（关键能力）

现代 Web 应用大量使用 JS 框架，传统爬虫无法发现 JS 中硬编码的 API 端点：

```bash
# 启用 JS 端点解析（推荐始终开启）
katana -u http://target.com -jc

# 启用 jsluice 深度 JS 解析（更全面，内存消耗大）
katana -u http://target.com -jsluice

# Headless 模式（渲染页面后爬取，适合 SPA/React/Vue）
katana -u http://target.com -headless

# Headless + 使用系统 Chrome
katana -u http://target.com -headless -system-chrome
```

## Phase 3: 批量爬取

```bash
# 从文件读取目标
katana -list urls.txt -silent

# 从 stdin 管道
cat urls.txt | katana -silent

# 配合其他工具
subfinder -d target.com -silent | httpx -silent | katana -silent -jc
```

## Phase 4: 输出过滤

```bash
# 只输出特定扩展名
katana -u http://target.com -em php,jsp,asp -silent

# 排除静态资源
katana -u http://target.com -ef png,jpg,css,gif,svg,woff -silent

# 正则匹配（只输出包含 api 的 URL）
katana -u http://target.com -mr "api|admin|login" -silent

# 正则过滤（排除包含 logout 的 URL）
katana -u http://target.com -fr "logout|static" -silent

# 提取表单元素
katana -u http://target.com -form-extraction -jsonl
```

## Phase 5: 范围控制

```bash
# 限制在同一域名内（默认行为）
katana -u http://target.com

# 显示外部端点（不爬取，只显示）
katana -u http://target.com -display-out-scope

# 自定义范围（正则）
katana -u http://target.com -crawl-scope "target\.com|api\.target\.com"

# 排除特定路径
katana -u http://target.com -crawl-out-scope "logout|signout"

# 无范围限制（危险，慎用）
katana -u http://target.com -no-scope
```

## Phase 6: 高级配置

```bash
# 限时爬取（比赛场景重要）
katana -u http://target.com -crawl-duration 60s

# 控制并发和速率
katana -u http://target.com -c 20 -rl 100

# 自定义 Header（带 Cookie 访问需要认证的页面）
katana -u http://target.com -H "Cookie: session=abc123"

# 使用代理
katana -u http://target.com -proxy http://127.0.0.1:8080

# JSONL 输出（包含完整请求信息）
katana -u http://target.com -jsonl -o results.jsonl

# 已知文件扫描（robots.txt, sitemap.xml）
katana -u http://target.com -known-files all -d 3

# 技术检测
katana -u http://target.com -tech-detect

# XHR 请求提取（Headless 模式）
katana -u http://target.com -headless -xhr-extraction
```

## Phase 7: 管道集成

```bash
# 爬虫 → 漏洞扫描
katana -u http://target.com -jc -silent | nuclei -severity critical,high

# 爬虫 → 筛选 JS 文件 → 敏感信息提取
katana -u http://target.com -jc -silent -em js | while read url; do
  curl -s "$url" | grep -iE "api_key|password|secret|token"
done

# 爬虫 → 参数提取 → SQLi 测试
katana -u http://target.com -jc -silent | grep "?" | sort -u > params.txt

# 子域名 → 存活 → 爬虫 → 漏洞扫描（完整链）
subfinder -d target.com -silent | httpx -silent | katana -jc -silent | nuclei
```

## 爬取策略选择

| 场景 | 策略 | 命令 |
|------|------|------|
| 快速发现（比赛） | 浅爬 + JS | `katana -u URL -d 2 -jc -silent` |
| 全面爬取 | 深爬 + Headless | `katana -u URL -d 5 -headless -jc` |
| API 端点发现 | JS 解析 + 过滤 | `katana -u URL -jc -em js,json -silent` |
| 认证后爬取 | 带 Cookie | `katana -u URL -H "Cookie: ..." -jc` |
| SPA 应用 | Headless 必须 | `katana -u URL -headless -system-chrome` |
