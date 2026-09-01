---
name: mapcidr-cidr
description: "使用 mapcidr 进行 CIDR 网段处理。当需要展开 CIDR 为 IP 列表、聚合 IP 为 CIDR、切片网段、IP 数量统计、打乱 IP 顺序时使用。mapcidr 是 ProjectDiscovery 出品的 CIDR 处理工具，支持 IPv4/IPv6。任何涉及 CIDR 计算、IP 列表处理、网段切片的场景都应使用此技能"
metadata:
  tags: "mapcidr,cidr,ip,网段,展开,聚合,切片,IPv4,IPv6,projectdiscovery"
  category: "tool"
---

# mapcidr CIDR 网段处理方法论

mapcidr 是 ProjectDiscovery 出品的 CIDR 处理工具。核心优势：**展开/聚合/切片/打乱** + **IPv4/IPv6 双栈** + **管道友好**。

项目地址：https://github.com/projectdiscovery/mapcidr

## 基本操作

```bash
# CIDR 展开为 IP 列表
echo 192.168.1.0/24 | mapcidr

# 统计 IP 数量
echo 10.0.0.0/16 | mapcidr -count

# IP 列表聚合为 CIDR
cat ips.txt | mapcidr -aggregate

# 打乱 IP 顺序（避免顺序扫描触发告警）
echo 192.168.1.0/24 | mapcidr -si

# 跳过基址和广播地址
echo 192.168.1.0/24 | mapcidr -skip-base -skip-broadcast
```

## 网段切片

```bash
# 按主机数切片（每片 256 个 IP）
echo 10.0.0.0/16 | mapcidr -sbh 256

# 按 CIDR 大小切片（切成 /24）
echo 10.0.0.0/16 | mapcidr -sbc 24

# 切片后分发扫描
echo 10.0.0.0/16 | mapcidr -sbc 24 | \
  while read cidr; do naabu -host "$cidr" -p 80,443 -silent; done
```

## 管道集成

```bash
# CIDR 展开 → 端口扫描
echo 10.0.0.0/24 | mapcidr -si | naabu -p 80,443 -silent

# IP 去重聚合
cat scan_results.txt | mapcidr -aggregate

# 过滤 IP 范围
echo 10.0.0.0/8 | mapcidr -fi 10.0.1.0/24
```
