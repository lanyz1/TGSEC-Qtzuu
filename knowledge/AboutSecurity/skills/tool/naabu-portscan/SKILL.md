---
name: naabu-portscan
description: "使用 naabu 进行高速端口扫描。当需要对目标主机/网段进行端口发现、存活检测时使用。naabu 是 ProjectDiscovery 出品的快速端口扫描器，支持 SYN/CONNECT/UDP 扫描，性能远超 nmap，支持批量目标、CDN 排除、nmap 集成。任何涉及端口扫描、端口发现、主机存活检测、网段探测的场景都应使用此技能。如果 naabu 结果不足再降级用 nmap"
metadata:
  tags: "naabu,port,scan,端口扫描,存活检测,SYN,CONNECT,UDP,projectdiscovery,网段探测"
  category: "tool"
---

# naabu 端口扫描方法论

naabu 是 ProjectDiscovery 出品的高速端口扫描器。核心优势：**极致速度**（SYN 扫描 + 高并发）+ **轻量简洁** + **管道友好**（与 httpx/nuclei 无缝衔接）。

项目地址：https://github.com/projectdiscovery/naabu

## 工具选择策略

naabu 的 SYN 扫描 + 高并发设计让它在端口发现速度上远超 nmap（通常快 10 倍以上），所以端口扫描的第一选择是 naabu。nmap 的优势在服务版本识别（`-sV`）和 NSE 脚本，因此推荐流程是：先用 naabu 快速发现端口，再对关键端口用 nmap 做深度探测。

注意：SYN 扫描需要 root 权限，非 root 环境会自动降级为 CONNECT 扫描（稍慢但功能一致）。

## Phase 1: 基本端口扫描

```bash
# 扫描单个主机（默认 Top 100 端口）
naabu -host target.com

# 指定端口
naabu -host target.com -p 80,443,8080,8443

# 端口范围
naabu -host target.com -p 1-1000

# 全端口扫描
naabu -host target.com -p -

# UDP 扫描（指定 UDP 端口）
naabu -host target.com -p u:53,u:161,u:500
```

## Phase 2: 预定义端口列表

```bash
# Top 100 端口（默认，最快）
naabu -host target.com -top-ports 100

# Top 1000 端口（平衡速度和覆盖）
naabu -host target.com -top-ports 1000

# 全端口（慢，仅在前两者无结果时使用）
naabu -host target.com -p -
```

## Phase 3: 批量目标扫描

```bash
# 从文件读取目标
naabu -l targets.txt -p 80,443,8080

# 从 stdin 读取（管道）
cat targets.txt | naabu -p 80,443,8080

# 扫描 CIDR 网段
naabu -host 10.0.0.0/24 -p 22,80,135,445,3389,5985

# 扫描 ASN
echo AS14421 | naabu -p 80,443
```

## Phase 4: 高价值端口策略

渗透测试中优先扫描的端口组合：

```bash
# Web 服务
naabu -host target -p 80,443,8080,8443,8888,9090,3000,5000

# 数据库
naabu -host target -p 3306,5432,6379,27017,1433,1521,9200

# 远程管理
naabu -host target -p 22,3389,5900,5985,5986

# 域控相关
naabu -host target -p 88,135,139,389,445,636,3268,3269

# 中间件
naabu -host target -p 8009,7001,4848,9090,8161,61616

# 综合高价值端口（一条命令）
naabu -host target -p 22,80,135,139,443,445,1433,3306,3389,5432,5900,5985,6379,8080,8443,9200,27017
```

## Phase 5: 管道集成

naabu 的核心价值在于与其他 ProjectDiscovery 工具组成扫描链：

```bash
# 端口扫描 → HTTP 存活检测
naabu -host target.com -p 80,443,8080 -silent | httpx -silent

# 端口扫描 → HTTP 存活 → 漏洞扫描
naabu -host target.com -silent | httpx -silent | nuclei -severity critical,high

# 子域名 → 端口扫描 → HTTP 存活
subfinder -d target.com -silent | naabu -p 80,443 -silent | httpx -silent

# 网段扫描 → 存活主机 → Web 指纹
naabu -host 10.0.0.0/24 -p 80,443,8080 -silent | httpx -tech-detect -silent
```

## Phase 6: 高级选项

```bash
# 排除 CDN/WAF（只扫 80,443）
naabu -host target.com -p - -exclude-cdn

# 显示 CDN 信息
naabu -host target.com -display-cdn

# 排除特定端口
naabu -host target.com -p - -exclude-ports 80,443

# 控制速率
naabu -host target.com -rate 500 -c 10

# 主机存活探测（不扫端口）
naabu -host 10.0.0.0/24 -sn

# SYN 扫描（需要 root）
sudo naabu -host target.com -s s

# 集成 nmap 服务识别
naabu -host target.com -nmap-cli "nmap -sV"

# JSON 输出
naabu -host target.com -json -o results.json

# 静默输出（只显示 host:port）
naabu -host target.com -silent
```

## 与 nmap 对比决策

| 场景 | 推荐工具 | 原因 |
|------|---------|------|
| 快速端口发现 | **naabu** | 速度快 10x+ |
| 批量目标/网段 | **naabu** | 并发性能优越 |
| 服务版本识别 | **nmap** (`-sV`) | naabu 不做版本识别 |
| 漏洞脚本扫描 | **nmap** (`--script`) | NSE 脚本生态 |
| UDP 深度扫描 | **nmap** | UDP 扫描更成熟 |
| 操作系统指纹 | **nmap** (`-O`) | naabu 不支持 |

**推荐流程**：naabu 快速发现端口 → 对关键端口用 nmap -sV 做服务识别
