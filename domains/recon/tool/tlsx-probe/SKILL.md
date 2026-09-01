---
name: tlsx-probe
description: "使用 tlsx 进行 TLS 证书和配置分析。当需要提取 SSL/TLS 证书信息（SAN/CN）、检测 TLS 版本、加密套件、JARM/JA3 指纹、证书错误配置时使用。tlsx 是 ProjectDiscovery 出品的 TLS 探针工具。任何涉及 SSL/TLS 分析、证书信息收集、JARM 指纹的场景都应使用此技能"
metadata:
  tags: "tlsx,tls,ssl,证书,certificate,SAN,CN,JARM,JA3,加密套件,projectdiscovery"
  category: "tool"
---

# tlsx TLS 证书分析方法论

tlsx 是 ProjectDiscovery 出品的 TLS 探针工具。核心优势：**证书信息提取** + **JARM/JA3 指纹** + **配置错误检测** + **管道友好**。

项目地址：https://github.com/projectdiscovery/tlsx

## Phase 1: 基本探测

```bash
# 单个目标
echo target.com | tlsx

# 提取证书信息
echo target.com | tlsx -san -cn -so -silent

# TLS 版本和加密套件
echo target.com | tlsx -tv -cipher -silent

# JARM 指纹
echo target.com | tlsx -jarm -silent
```

## Phase 2: 证书分析

```bash
# 完整证书信息
echo target.com | tlsx -san -cn -so -tv -cipher -jarm -json

# 证书过期检测
echo target.com | tlsx -ex -silent

# 自签名检测
echo target.com | tlsx -ss -silent

# 域名不匹配检测
echo target.com | tlsx -mm -silent

# 批量检测证书问题
tlsx -l hosts.txt -ex -ss -mm -re -un -silent
```

## Phase 3: 管道集成

```bash
# 子域名 → TLS 证书收集
subfinder -d target.com -silent | tlsx -san -cn -resp-only -silent

# 端口扫描 → TLS 探测
naabu -host target.com -p 443,8443 -silent | tlsx -san -cn -silent

# 从 TLS SAN 发现更多子域名
echo target.com | tlsx -san -resp-only -silent | sort -u

# JSON 输出
tlsx -l hosts.txt -san -cn -tv -jarm -json -o results.json
```
