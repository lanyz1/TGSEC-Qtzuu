---
name: uncover-search
description: "使用 uncover 聚合查询网络空间搜索引擎。当需要从 Shodan/Censys/FOFA/Hunter/Quake/ZoomEye 等引擎快速发现暴露资产时使用。uncover 统一了多个搜索引擎的查询接口，一条命令查询多个引擎。任何涉及资产发现、互联网测绘、暴露面排查的场景都应使用此技能"
metadata:
  tags: "uncover,search,shodan,censys,fofa,hunter,quake,zoomeye,资产发现,互联网测绘,OSINT"
  category: "tool"
---

# uncover 网络空间搜索引擎聚合方法论

uncover 是 ProjectDiscovery 出品的搜索引擎聚合工具。核心优势：**多引擎统一接口**（Shodan/Censys/FOFA/Hunter/Quake/ZoomEye/Netlas）+ **一条命令查多源** + **管道友好**。

项目地址：https://github.com/projectdiscovery/uncover

API Key 配置：编辑 `~/.config/uncover/provider-config.yaml` 添加各引擎 API Key。

## Phase 1: 基本搜索

```bash
# Shodan 搜索
uncover -q "org:target.com" -e shodan

# FOFA 搜索
uncover -q 'domain="target.com"' -e fofa

# Censys 搜索
uncover -q "target.com" -e censys

# 多引擎同时查询
uncover -q "target.com" -e shodan,censys,fofa
```

## Phase 2: 高级搜索

```bash
# 限制结果数量
uncover -q "apache" -e shodan -l 200

# JSON 输出
uncover -q "org:target.com" -e shodan -json -o results.json

# 静默输出（只显示 IP:Port）
uncover -q "org:target.com" -e shodan -silent

# 从文件读取查询
uncover -ql queries.txt -e shodan
```

## Phase 3: 管道集成

```bash
# 资产发现 → HTTP 探活
uncover -q "org:target.com" -e shodan -silent | httpx -silent

# 资产发现 → 端口扫描
uncover -q "org:target.com" -e shodan -silent | naabu -silent

# 资产发现 → 漏洞扫描
uncover -q 'domain="target.com"' -e fofa -silent | httpx -silent | nuclei
```

## 各引擎查询语法

| 引擎 | 域名查询 | 组织查询 |
|------|---------|---------|
| Shodan | `hostname:target.com` | `org:"Target Inc"` |
| Censys | `target.com` | `autonomous_system.name:"Target"` |
| FOFA | `domain="target.com"` | `org="Target Inc"` |
| Hunter | `domain="target.com"` | `icp.name="Target"` |
| Quake | `domain:"target.com"` | `org:"Target Inc"` |
