---
name: nmap-scan
description: "使用 nmap 进行端口扫描和服务识别。当需要对目标进行精细端口扫描、服务版本探测、操作系统指纹识别、NSE 脚本漏洞扫描时使用。nmap 是最经典的网络扫描器，支持 SYN/TCP/UDP/ACK 等多种扫描模式，内置 600+ NSE 脚本。任何涉及端口扫描、服务识别、漏洞脚本扫描、操作系统指纹的场景都应使用此技能。速度不如 naabu，但功能远超 naabu"
metadata:
  tags: "nmap,port,scan,端口扫描,服务识别,NSE,脚本扫描,操作系统指纹,SYN,TCP,UDP,版本探测"
  category: "tool"
---

# nmap 端口扫描与服务识别方法论

nmap 是最经典的网络扫描器，核心优势：**服务版本识别**（-sV）+ **NSE 脚本生态**（600+ 脚本）+ **操作系统指纹**（-O）。虽然速度不如 naabu，但在深度探测方面无可替代。

项目地址：https://nmap.org

## 工具选择策略

推荐流程：先用 naabu 快速发现开放端口，再用 nmap 对关键端口做深度探测。nmap 适合精细扫描，不适合大规模快速发现。

注意：SYN 扫描（-sS）需要 root 权限，非 root 自动使用 TCP Connect（-sT）。

## Phase 1: 基本端口扫描

```bash
# SYN 半开扫描（默认，需 root，最快最隐蔽）
sudo nmap -sS target.com

# TCP 全连接扫描（不需 root）
nmap -sT target.com

# 指定端口范围
nmap -p 1-1000 target.com

# 指定常用端口
nmap -p 22,80,443,3306,8080 target.com

# 全端口扫描
nmap -p- target.com

# UDP 扫描（慢，需 root）
sudo nmap -sU -p 53,161,500 target.com
```

## Phase 2: 服务版本与操作系统识别

```bash
# 服务版本探测（核心能力）
nmap -sV target.com

# 操作系统指纹识别
sudo nmap -O target.com

# 版本 + 操作系统 + 默认脚本（最常用组合）
sudo nmap -A target.com

# 精确版本探测（更慢但更准）
nmap -sV --version-intensity 9 target.com
```

## Phase 3: NSE 脚本扫描

```bash
# 默认安全脚本
nmap -sC target.com

# 漏洞扫描脚本
nmap --script vuln target.com

# 特定漏洞检测
nmap --script smb-vuln-ms17-010 -p 445 target.com
nmap --script http-shellshock -p 80 target.com

# 暴力破解脚本
nmap --script ssh-brute -p 22 target.com
nmap --script http-brute -p 80 target.com

# HTTP 信息收集
nmap --script http-title,http-headers,http-methods -p 80,443 target.com

# SMB 枚举
nmap --script smb-enum-shares,smb-enum-users -p 445 target.com

# SSL/TLS 检查
nmap --script ssl-cert,ssl-enum-ciphers -p 443 target.com
```

## Phase 4: 高级扫描技术

```bash
# 绕过防火墙（分片包）
sudo nmap -f target.com

# 伪造源 IP（Decoy 扫描）
sudo nmap -D RND:5 target.com

# 指定源端口（绕过简单防火墙规则）
sudo nmap --source-port 53 target.com

# 空闲扫描（最隐蔽，需找到僵尸主机）
sudo nmap -sI zombie_host target.com

# 控制速率（避免 IDS）
nmap --scan-delay 1s --max-rate 10 target.com

# 时序模板（T0 最慢最隐蔽，T5 最快最暴力）
nmap -T4 target.com
```

## Phase 5: 输出格式

```bash
# 正常输出
nmap -oN scan.txt target.com

# XML 输出（便于工具解析）
nmap -oX scan.xml target.com

# Grepable 输出（便于 grep 处理）
nmap -oG scan.gnmap target.com

# 三种格式同时输出
nmap -oA scan target.com
```

## 渗透测试常用组合

| 场景 | 命令 |
|------|------|
| 快速全端口 | `nmap -sS -p- -T4 --open target` |
| 深度扫描已知端口 | `nmap -sV -sC -p 22,80,443 target` |
| 综合扫描 | `sudo nmap -A -T4 target` |
| 漏洞扫描 | `nmap --script vuln -p 80,443,445 target` |
| 内网存活探测 | `nmap -sn 10.0.0.0/24` |
| SMB 漏洞检测 | `nmap --script smb-vuln* -p 445 target` |
| Web 信息收集 | `nmap --script http-title,http-headers -p 80,443,8080 target` |
