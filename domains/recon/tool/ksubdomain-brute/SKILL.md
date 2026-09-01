---
name: ksubdomain-brute
description: "使用 ksubdomain 进行无状态子域名爆破。当需要极高速子域名爆破和验证时使用。ksubdomain 直接操作网卡原始套接字发包，速度比 dnsx 快 10 倍，支持验证和枚举两种模式。需要 root 权限。任何涉及高速子域名爆破、大规模子域名验证的场景都应使用此技能"
metadata:
  tags: "ksubdomain,subdomain,brute,子域名爆破,无状态,高速,DNS,验证,枚举"
  category: "tool"
---

# ksubdomain 无状态子域名爆破方法论

ksubdomain 是无状态子域名爆破工具。核心优势：**极致速度**（原始套接字发包，比 dnsx 快 10x）+ **验证/枚举双模式** + **带宽控制**。需要 root 权限。

项目地址：https://github.com/boy-hack/ksubdomain

## Phase 1: 验证模式

```bash
# 验证子域名列表存活
sudo ksubdomain verify -d subdomains.txt -o alive.txt

# 控制带宽
sudo ksubdomain verify -d subdomains.txt -b 5m -o alive.txt

# 配合 subfinder 验证
subfinder -d target.com -o subs.txt
sudo ksubdomain verify -d subs.txt --silent -o verified.txt
```

## Phase 2: 枚举模式

```bash
# 枚举子域名
sudo ksubdomain enum -d target.com -o results.txt

# 使用自定义字典
sudo ksubdomain enum -d target.com -f wordlist.txt -o results.txt

# 控制带宽和重试
sudo ksubdomain enum -d target.com -b 10m --retry 3 -o results.txt
```

## Phase 3: 高级选项

```bash
# 自定义 DNS 解析器
sudo ksubdomain verify -d subs.txt -r resolvers.txt

# 静默输出
sudo ksubdomain verify -d subs.txt --silent

# 高带宽（内网环境）
sudo ksubdomain enum -d target.com -b 1g -o results.txt
```
