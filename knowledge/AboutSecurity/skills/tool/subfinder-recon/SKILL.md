---
name: subfinder-recon
description: "使用 subfinder 进行被动子域名枚举。当需要发现目标域名的子域名、扩展攻击面时使用。subfinder 是 ProjectDiscovery 出品的被动子域名发现工具，聚合 Shodan、Censys、SecurityTrails、VirusTotal 等多数据源，快速且隐蔽。任何涉及子域名枚举、攻击面发现、被动信息收集的场景都应使用此技能"
metadata:
  tags: "subfinder,subdomain,recon,子域名,被动枚举,信息收集,攻击面,projectdiscovery"
  category: "tool"
---

# subfinder 被动子域名枚举方法论

subfinder 是 ProjectDiscovery 出品的被动子域名发现工具。核心优势：**纯被动**（不产生目标流量）+ **多数据源聚合**（40+ 源）+ **管道友好**。

项目地址：https://github.com/projectdiscovery/subfinder

## Phase 1: 基本使用

```bash
# 单个域名
subfinder -d target.com

# 静默输出（只输出子域名）
subfinder -d target.com -silent

# 多个域名
subfinder -dL domains.txt -silent

# 输出到文件
subfinder -d target.com -o subdomains.txt
```

## Phase 2: 数据源配置

```bash
# 使用全部数据源（更全面，较慢）
subfinder -d target.com -all

# 指定数据源
subfinder -d target.com -s crtsh,github,shodan

# 查看可用数据源
subfinder -ls

# 排除特定数据源
subfinder -d target.com -es github,rapiddns
```

API Key 配置：编辑 `~/.config/subfinder/provider-config.yaml` 添加 API Key 可大幅提升效果。

## Phase 3: 管道集成

```bash
# 子域名 → HTTP 存活检测
subfinder -d target.com -silent | httpx -silent

# 子域名 → 端口扫描 → HTTP 存活
subfinder -d target.com -silent | naabu -p 80,443 -silent | httpx -silent

# 子域名 → 存活 → 漏洞扫描（完整链）
subfinder -d target.com -silent | httpx -silent | nuclei -severity critical,high

# 子域名 → DNS 解析
subfinder -d target.com -silent | dnsx -a -resp -silent

# 子域名 → IP 去重
subfinder -d target.com -silent | dnsx -a -resp-only -silent | sort -u
```

## Phase 4: 高级选项

```bash
# 递归子域名发现
subfinder -d target.com -recursive

# JSON 输出
subfinder -d target.com -json -o results.json

# 控制并发
subfinder -d target.com -t 50

# 设置超时
subfinder -d target.com -timeout 30

# 只显示特定数据源的结果
subfinder -d target.com -cs -silent
```

## 常用场景速查

| 场景 | 命令 |
|------|------|
| 快速枚举 | `subfinder -d target.com -silent` |
| 全面枚举 | `subfinder -d target.com -all -silent` |
| 批量域名 | `subfinder -dL domains.txt -silent -o all_subs.txt` |
| 接管检测链 | `subfinder -d target.com -silent \| httpx -silent \| nuclei -t takeovers/` |
