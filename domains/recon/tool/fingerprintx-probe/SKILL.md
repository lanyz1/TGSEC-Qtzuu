---
name: fingerprintx-probe
description: "使用 fingerprintx 进行应用层服务指纹识别。当需要识别开放端口运行的具体服务和协议时使用。fingerprintx 支持 51 种协议识别（SSH/RDP/MySQL/Redis/HTTP/SMB/FTP 等），JSON 输出含服务元数据。任何涉及服务识别、协议探测、端口指纹的场景都应使用此技能"
metadata:
  tags: "fingerprintx,fingerprint,probe,服务识别,协议探测,端口指纹,SSH,RDP,MySQL,Redis"
  category: "tool"
---

# fingerprintx 服务指纹识别方法论

fingerprintx 是 Praetorian 出品的服务指纹识别工具。核心优势：**51 种协议** + **快速精准** + **JSON 元数据输出**。

项目地址：https://github.com/praetorian-inc/fingerprintx

## Phase 1: 基本使用

```bash
# 单个目标
fingerprintx -t 192.168.1.1:22

# 多个目标
fingerprintx -t 192.168.1.1:22,192.168.1.1:80,192.168.1.1:443

# 从文件读取（host:port 格式）
fingerprintx -l targets.txt

# 从 stdin
echo "192.168.1.1:80" | fingerprintx
```

## Phase 2: 扫描模式

```bash
# 快速模式（只尝试端口默认服务）
fingerprintx -t 192.168.1.1:22 --fast

# UDP 服务探测
fingerprintx -t 192.168.1.1:161 -U

# 设置超时
fingerprintx -t 192.168.1.1:22 -w 1000

# JSON 输出
fingerprintx -t 192.168.1.1:22 --json
```

## Phase 3: 管道集成

```bash
# naabu 端口扫描 → 服务识别
naabu -host 192.168.1.0/24 -silent | fingerprintx

# masscan → 服务识别
sudo masscan 10.0.0.0/24 -p 22,80,443 -oL - | \
  grep "^open" | awk '{print $4":"$3}' | fingerprintx --json
```
