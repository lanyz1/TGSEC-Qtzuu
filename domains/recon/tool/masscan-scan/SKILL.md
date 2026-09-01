---
name: masscan-scan
description: "使用 masscan 进行超大规模高速端口扫描。当需要扫描大范围 CIDR 网段、全互联网规模扫描时使用。masscan 是异步无状态扫描器，速度可达每秒百万包级别，适合大规模资产发现。需要 root 权限。任何涉及大规模网段扫描、高速端口发现、互联网测绘的场景都应使用此技能"
metadata:
  tags: "masscan,port,scan,端口扫描,高速扫描,大规模,CIDR,网段,资产发现,异步扫描"
  category: "tool"
---

# masscan 超大规模高速端口扫描方法论

masscan 是异步无状态端口扫描器，核心优势：**极致速度**（理论可达 1000 万包/秒）+ **大规模扫描**（专为全网扫描设计）+ **nmap 兼容输出**。需要 root 权限。

项目地址：https://github.com/robertdavidgraham/masscan

## 工具选择策略

masscan 适合大规模网段（/16 以上）扫描，速度远超 nmap 和 naabu。但不做服务识别，推荐流程：masscan 快速发现端口 → nmap -sV 做服务识别。小范围扫描用 naabu 更方便。

## Phase 1: 基本扫描

```bash
# 扫描单个目标（需 root）
sudo masscan 192.168.1.1 -p 80,443,8080

# 扫描网段
sudo masscan 10.0.0.0/24 -p 1-1000

# 全端口扫描
sudo masscan 192.168.1.0/24 -p 0-65535

# 控制发包速率（默认 100 包/秒）
sudo masscan 10.0.0.0/16 -p 80,443 --rate 10000
```

## Phase 2: 大规模扫描

```bash
# B 段扫描（65536 个 IP）
sudo masscan 10.0.0.0/16 -p 22,80,443,3389 --rate 50000

# A 段扫描（谨慎使用）
sudo masscan 10.0.0.0/8 -p 80,443 --rate 100000

# 从文件读取目标
sudo masscan -iL targets.txt -p 80,443

# 排除特定 IP
sudo masscan 10.0.0.0/16 -p 80 --excludefile exclude.txt
```

## Phase 3: 输出格式

```bash
# List 格式（简洁，推荐）
sudo masscan 10.0.0.0/24 -p 80,443 -oL results.txt

# JSON 格式
sudo masscan 10.0.0.0/24 -p 80,443 -oJ results.json

# nmap XML 格式（兼容 nmap 工具链）
sudo masscan 10.0.0.0/24 -p 80,443 -oX results.xml

# Grepable 格式
sudo masscan 10.0.0.0/24 -p 80,443 -oG results.gnmap
```

## Phase 4: 高级选项

```bash
# Banner 抓取
sudo masscan 10.0.0.0/24 -p 80 --banners

# 指定网卡
sudo masscan 10.0.0.0/24 -p 80 -e eth0

# 指定源 IP
sudo masscan 10.0.0.0/24 -p 80 --adapter-ip 192.168.1.100

# 暂停和恢复扫描
sudo masscan 10.0.0.0/8 -p 80 --resume paused.conf
# Ctrl+C 暂停时会生成 paused.conf

# 使用配置文件
sudo masscan -c masscan.conf
```

## 渗透测试常用组合

| 场景 | 命令 |
|------|------|
| 内网快速发现 | `sudo masscan 10.0.0.0/16 -p 22,80,443,3389 --rate 10000 -oL results.txt` |
| Web 服务发现 | `sudo masscan CIDR -p 80,443,8080,8443 --rate 50000 -oL web.txt` |
| 数据库端口 | `sudo masscan CIDR -p 3306,5432,1433,6379,27017 --rate 10000` |
| 全端口扫描 | `sudo masscan target -p 0-65535 --rate 10000 -oL all.txt` |
