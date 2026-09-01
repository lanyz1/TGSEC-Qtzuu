---
name: gau-urlfetch
description: "使用 gau 从历史数据源收集目标域名的已知 URL。当需要发现目标的历史 URL、隐藏端点、参数、API 路径时使用。gau 聚合 Wayback Machine、Common Crawl、OTX、URLScan 四大数据源。任何涉及 URL 收集、攻击面发现、参数发现、历史页面收集的场景都应使用此技能"
metadata:
  tags: "gau,url,fetch,URL收集,Wayback,历史URL,攻击面,参数发现,OSINT,信息收集"
  category: "tool"
---

# gau URL 历史收集方法论

gau (getallurls) 从历史数据源收集已知 URL。核心优势：**四大数据源聚合**（Wayback/CommonCrawl/OTX/URLScan）+ **纯被动** + **管道友好**。

项目地址：https://github.com/lc/gau

## Phase 1: 基本使用

```bash
# 收集目标域名的所有已知 URL
gau target.com

# 包含子域名
gau --subs target.com

# 输出到文件
gau target.com -o urls.txt

# 过滤静态资源
gau --blacklist png,jpg,gif,svg,woff,ttf,ico,css target.com
```

## Phase 2: 数据源控制

```bash
# 指定数据源
gau --providers wayback target.com
gau --providers wayback,commoncrawl target.com

# 时间范围
gau --from 202301 --to 202612 target.com

# 控制线程
gau --threads 10 target.com

# 从 stdin
echo target.com | gau
cat domains.txt | gau
```

## Phase 3: 管道集成

```bash
# URL 收集 → 提取带参数的 URL → XSS 扫描
gau target.com | grep "=" | sort -u | dalfox pipe --silence

# URL 收集 → 提取 JS 文件
gau target.com | grep "\.js$" | sort -u

# URL 收集 → 提取 API 端点
gau target.com | grep -E "/api/|/v[0-9]/" | sort -u

# URL 收集 → 存活检测
gau target.com | httpx -silent

# URL 收集 → 敏感路径
gau target.com | grep -iE "admin|backup|config|\.env|\.git|debug"
```

## 常用场景速查

| 场景 | 命令 |
|------|------|
| 全量收集 | `gau --subs target.com -o all_urls.txt` |
| 参数URL | `gau target.com \| grep "=" \| sort -u` |
| JS 文件 | `gau target.com \| grep "\\.js$" \| sort -u` |
| API 发现 | `gau target.com \| grep -E "/api/" \| sort -u` |
