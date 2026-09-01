---
name: internal-recon
description: "内网信息收集与拓扑绘制。当已突破边界获取到内网立足点后使用。覆盖存活主机发现、端口扫描、服务识别、关键基础设施定位（域控/数据库/邮件/文件服务器）。内网渗透的第一步——先看清地图再行动"
metadata:
  tags: "internal,recon,network,discovery,内网,侦察,拓扑,存活探测,端口扫描,域控"
  category: "lateral"
---

# 内网信息收集方法论

内网侦察和外网侦察的区别：内网通常没有 CDN/WAF 保护，但你的操作空间受限于当前立足点的网络位置。核心目标是**快速绘制内网地图**——有哪些主机、什么服务、哪些是高价值目标。

## ⛔ 深入参考（必读）

- 存活探测命令、端口→服务→价值映射表、域控/数据库定位 → [references/network-mapping.md](references/network-mapping.md)
- fscan 详细用法（弱口令爆破、POC 检测、代理扫描）→ 加载 `fscan-scan` 技能
- **工具投递方法**（怎么把后渗透 需要的工具 传到目标上、为什么要在目标上执行而非本地）→ 加载 `tool-delivery` 技能

## Phase 1: 当前位置分析

```bash
# Linux
ip addr && ip route && cat /etc/resolv.conf && arp -a && cat /etc/hosts
# Windows
ipconfig /all && route print && arp -a && net view /domain
```

**关键判断**：多网卡=跳板 | DNS→内网IP=域环境 | ARP表大=活跃网段

## Phase 2: 存活主机发现（fscan 优先）
```bash
# fscan 一把梭（存活+端口+服务+弱口令+漏洞，速度远超 nmap）
fscan -h 10.0.0.0/24 -nopoc          # 快速存活+端口
fscan -h 10.0.0.0/24                  # 全量（含 POC 检测+弱口令）

# nmap 补充（fscan 不可用时降级）
nmap -sn 10.0.0.0/24                  # ICMP ping
nmap -PR -sn 10.0.0.0/24             # ARP（同网段最可靠）
```

## Phase 3: 端口扫描（聚焦关键端口）
```bash
# fscan 指定端口（推荐，速度快且自动识别服务）
fscan -h TARGETS -p 22,80,135,139,443,445,1433,3306,3389,5432,5985,6379,8080,9200

# nmap 深度识别（需要服务版本/NSE 脚本时用）
nmap -sT -sV -p 22,80,445,3389 TARGETS
```

**高价值端口**：88(域控) | 445(SMB) | 3389(RDP) | 1433(MSSQL) | 6379(Redis)

→ 完整端口→服务→价值映射表 → [references/network-mapping.md](references/network-mapping.md)

## Phase 4: 关键基础设施定位

- **域控**：88+389+445 = 确认域控 | DNS IP 通常就是域控
- **数据库**：用收集到的凭据尝试连接
- **管理系统**：`httpx -tech-detect` / `curl -sI` 发现 Jenkins/GitLab/Zabbix

## Phase 5: 输出内网地图
网络拓扑 + 高价值目标清单（域控→数据库→管理系统→跳板机）+ 优先攻击路径

## 注意事项
- 优先**被动发现**（ARP/路由表），再主动扫描
- 分批扫描，避免扫 /16 导致网络问题

## 被动发现技术
- NBNS / LLMNR 广播监听：NetBIOS 名称服务可被动获取主机名
- tcpdump 抓包、监听、嗅探网络流量
- 端口 3268 — Active Directory Global Catalog（全局编录）

## 多网卡 Pivot
- 发现双网卡主机（两个网段），可作为跨网段的 pivot 跳板
- 通过此机器设置代理/转发，访问新网段
- 新攻击面：扩大范围，深入内网
