---
name: dnsx-resolve
description: "使用 dnsx 进行批量 DNS 记录查询和解析。当需要批量 DNS 解析、验证子域名存活、查询 A/AAAA/CNAME/NS/MX/TXT 记录、通配符过滤时使用。dnsx 是 ProjectDiscovery 出品的高速 DNS 工具包，支持多记录类型查询和通配符自动过滤。任何涉及 DNS 解析、子域名验证、DNS 记录收集的场景都应使用此技能"
metadata:
  tags: "dnsx,dns,resolve,DNS解析,子域名验证,A记录,CNAME,MX,TXT,通配符,projectdiscovery"
  category: "tool"
---

# dnsx DNS 批量解析方法论

dnsx 是 ProjectDiscovery 出品的高速 DNS 工具。核心优势：**多记录类型** + **通配符自动过滤** + **管道友好**。

项目地址：https://github.com/projectdiscovery/dnsx

## Phase 1: 基本解析

```bash
# 单域名 A 记录
echo target.com | dnsx -a -resp

# 批量解析
dnsx -l subdomains.txt -a -resp -silent

# 多记录类型
echo target.com | dnsx -a -aaaa -cname -ns -mx -txt -resp
```

## Phase 2: 子域名验证

```bash
# 验证子域名存活
subfinder -d target.com -silent | dnsx -silent

# 过滤通配符域名
subfinder -d target.com -silent | dnsx -wd target.com -silent

# 提取 IP 地址
subfinder -d target.com -silent | dnsx -a -resp-only -silent | sort -u
```

## Phase 3: 高级用法

```bash
# 暴力枚举子域名
dnsx -d target.com -w subdomains-wordlist.txt -silent

# 自定义 DNS 解析器
dnsx -l domains.txt -a -resp -r 8.8.8.8,1.1.1.1

# PTR 反向解析
echo 10.0.0.1 | dnsx -ptr -resp

# JSON 输出
dnsx -l domains.txt -a -resp -json -o results.json

# 控制并发
dnsx -l domains.txt -a -t 200 -silent
```

## 管道集成

```bash
# 子域名 → DNS 解析 → IP 去重
subfinder -d target.com -silent | dnsx -a -resp-only -silent | sort -u

# 子域名 → DNS 验证 → HTTP 探活
subfinder -d target.com -silent | dnsx -silent | httpx -silent

# CNAME 提取（用于子域名接管检测）
subfinder -d target.com -silent | dnsx -cname -resp -silent
```
