---
name: nerva-scan
description: "使用 nerva 进行高性能服务指纹识别。当需要识别开放端口的具体服务时使用。nerva 支持 120+ 协议（数据库、远程访问、消息队列、工控、Web 等），是 fingerprintx 的升级版。任何涉及服务识别、协议探测、端口指纹的场景都应使用此技能"
metadata:
  tags: "nerva,fingerprint,scan,服务识别,协议探测,端口指纹,120+协议,工控,数据库"
  category: "tool"
---

# nerva 高性能服务指纹识别方法论

nerva 是 Praetorian 出品的服务指纹识别工具（fingerprintx 升级版）。核心优势：**120+ 协议** + **TCP/UDP/SCTP 多传输层** + **丰富元数据提取**。

项目地址：https://github.com/praetorian-inc/nerva

## Phase 1: 基本使用

```bash
# 单个目标
nerva -t 192.168.1.1:22

# 多个目标
nerva -t 192.168.1.1:22,192.168.1.1:80,192.168.1.1:3306

# 从文件读取
nerva -l targets.txt

# JSON 输出
nerva -t 192.168.1.1:22 --json
```

## Phase 2: 扫描模式

```bash
# 快速模式（只尝试默认服务）
nerva -t 192.168.1.1:22 --fast

# UDP 探测
nerva -t 192.168.1.1:161 -U

# 设置超时和并发
nerva -t targets -w 2000 -W 50

# 限速
nerva -l targets.txt -R 100
```

## Phase 3: 管道集成

```bash
# naabu 端口扫描 → 服务识别
naabu -host 192.168.1.0/24 -silent | nerva --json

# masscan → 服务识别
sudo masscan 10.0.0.0/24 -p 1-10000 -oL - | \
  grep "^open" | awk '{print $4":"$3}' | nerva --json -o services.json
```
