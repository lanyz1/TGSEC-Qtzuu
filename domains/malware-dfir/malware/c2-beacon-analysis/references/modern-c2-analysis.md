# 现代 C2 框架 Implant 分析

> 除 Cobalt Strike 外，越来越多的红队和攻击者使用 Sliver、Havoc、Mythic、Brute Ratel 等新一代 C2 框架。理解这些框架的特征是蓝队检测的基础，也是红队 OPSEC 的前提。

---

## 1. Sliver C2

### 1.1 架构概述

```
Sliver 架构:
├─ Server: Go 编写，单二进制部署
├─ Implant 类型:
│   ├─ Session: 实时交互（持久 TCP/mTLS/WireGuard 连接）
│   ├─ Beacon: 异步回调（HTTP(S)/DNS，类似 CS Beacon）
│   └─ 区分: Session = 实时 shell, Beacon = sleep + callback
├─ 通信协议:
│   ├─ mTLS (mutual TLS) — 默认端口 8888
│   ├─ WireGuard — 默认端口 51820
│   ├─ HTTP(S) — 可配置端口
│   └─ DNS — 任意域名
└─ 特点: 开源、Go 跨平台、天然免杀较好（编译时随机化）
```

### 1.2 Implant 识别特征

```
静态特征:
├─ 编译语言: Go → 大体积二进制（通常 > 5MB）
├─ Go build ID: 可通过 `go version` 命令或 strings 提取
├─ Section names: .text / .data / .bss / .symtab（Go 特有布局）
├─ 字符串:
│   ├─ "sliverpb" (protobuf 包名，混淆后可能不存在)
│   ├─ "sliver/" 路径残留
│   ├─ Go runtime 字符串 (runtime.goexit, runtime.main)
│   └─ mTLS 场景: 嵌入的证书数据
└─ 导入表: Go 二进制通常静态链接，导入表很短

网络特征:
├─ mTLS:
│   ├─ 默认使用 Sliver 自签 CA 签发的客户端+服务端证书
│   ├─ 证书 Subject/Issuer 可包含随机字符串
│   ├─ JARM 指纹: Go TLS 默认配置（非标准浏览器指纹）
│   └─ JA3: Go crypto/tls 默认 → 与浏览器差异明显
├─ WireGuard:
│   ├─ UDP 协议，默认端口 51820
│   ├─ 标准 WireGuard 握手 (Noise IK pattern)
│   └─ 与合法 VPN 流量难以区分（优势）
├─ HTTP(S):
│   ├─ 默认 nonce-based URL 路径 (随机字符串)
│   ├─ 可自定义 HTTP C2 Profile (类似 CS Malleable)
│   ├─ 默认 Content-Type 和 Response 结构
│   └─ Session cookie/header 中携带加密数据
└─ DNS:
    ├─ 子域名编码 (Base32/Base58)
    ├─ A/AAAA/TXT 记录组合
    └─ 查询频率和子域名长度可识别
```

### 1.3 配置提取方法

```bash
# Sliver implant 配置嵌入在二进制中，使用 AES-GCM 加密

# 方法 1: SliverC2-Config-Extractor
python3 sliver_config_extractor.py implant.exe

# 方法 2: 动态分析（运行时提取）
# 在调试器中断点 Go crypto/tls.Dial → 获取 C2 地址
# 或断点 net.Dial → 捕获连接目标

# 方法 3: 字符串分析（未混淆版本）
strings implant.exe | grep -E "https?://|:\d{4,5}|\.onion"
strings implant.exe | grep -i "mtls\|wg\|dns\|http"

# 方法 4: 流量捕获
# 沙箱运行 → 抓取 DNS/HTTP/TLS 连接目标
# mTLS: 提取证书 → 分析 CA 信息
```

---

## 2. Havoc C2

### 2.1 架构概述

```
Havoc 架构:
├─ TeamServer: 类似 CS TeamServer，GUI 管理
├─ Demon Agent:
│   ├─ 语言: C + ASM
│   ├─ 体积: < 100KB (shellcode 格式)
│   ├─ 反射加载: 内存执行，不落盘
│   └─ 模块化: BOF 兼容（可执行 CS BOF）
├─ 通信: HTTP(S)
└─ 特点: 免费开源，目标是 CS 替代品
```

### 2.2 Demon Agent 结构

```
Demon Implant 内部结构:
├─ Stage 0: Shellcode Loader (位置无关代码)
│   ├─ 解密 Demon core
│   ├─ 反射加载到内存
│   └─ 跳转到 DemonMain()
├─ Demon Core:
│   ├─ 配置解析: 从嵌入数据读取 C2/Sleep/Key 等
│   ├─ 通信模块: HTTP(S) 回调
│   ├─ 命令执行: 支持 BOF/PE/Shellcode 加载
│   └─ OPSEC 功能: Sleep obfuscation
└─ 配置区域: 加密存储在 shellcode 末尾或 PE .data 段
```

### 2.3 Sleep Obfuscation

```
Havoc 支持多种 Sleep 混淆技术:

Ekko:
├─ 原理: 使用 CreateTimerQueueTimer + ROP 链
├─ Sleep 时加密 Demon 内存（RWX → RW + 加密）
├─ 唤醒时解密恢复（解密 + RW → RWX）
├─ 目的: 内存扫描时看不到可执行的恶意代码
└─ 检测: 监控 CreateTimerQueueTimer + NtContinue 调用链

Zilean:
├─ 原理: 使用 NtApcSyscall + APC 队列
├─ 将加解密操作放入 APC 回调
├─ 更隐蔽的 ROP/gadget 使用
└─ 检测: 监控异常 APC 队列活动

Foliage:
├─ 原理: 使用 NtCreateThreadEx + APC
├─ 创建挂起线程 → 加密 → Sleep → 解密 → 恢复
└─ 检测: 挂起线程 + 内存权限频繁变化
```

### 2.4 配置提取

```bash
# Havoc Demon 配置通常在 shellcode/PE 末尾，XOR 加密

# 方法 1: 动态分析
# 在 x64dbg 中运行 → 断点 WinHTTP 函数 → 获取 C2 URL
# bp WinHttpConnect → 参数中包含 C2 服务器地址
# bp WinHttpOpenRequest → 参数中包含 URI 路径

# 方法 2: 内存 dump 后字符串搜索
# Demon 运行后配置在内存中解密
strings memdump.bin | grep -E "https?://|User-Agent:|Sleep:"

# 方法 3: 已知结构解析
# Havoc 配置格式:
# [4 bytes Magic] [4 bytes Size] [Config Data (XOR encrypted)]
# XOR key 从 TeamServer profile 中定义
```

### 2.5 网络特征

```
Havoc HTTP(S) 通信特征:
├─ 默认 User-Agent: 可配置（Profile 定义）
├─ 默认请求路径: 可配置
├─ 数据编码: AES 加密后 Base64
├─ Checkin 格式: 特定的 JSON/Binary 结构
├─ JA3: 取决于使用的 TLS 库（WinHTTP = Windows 原生指纹）
│   └─ 使用 WinHTTP → JA3 匹配 Windows 系统 → 难以基于 JA3 检测
├─ 心跳特征: 固定间隔 + Jitter（类似 CS）
└─ 响应特征: 特定的 HTTP Response 结构
```

---

## 3. Mythic C2

### 3.1 架构概述

```
Mythic 架构（最模块化的 C2）:
├─ Mythic Server: Docker 容器化部署
│   ├─ PostgreSQL 数据库
│   ├─ RabbitMQ 消息队列
│   ├─ Mythic UI (React)
│   └─ 各组件通过容器通信
├─ Agent 类型（独立开发，可替换）:
│   ├─ Apollo: C# (.NET) — Windows 专用
│   ├─ Athena: C# (.NET) — 跨平台 (.NET 6+)
│   ├─ Poseidon: Go — macOS/Linux
│   ├─ Medusa: Python — 跨平台
│   ├─ Merlin: Go — 跨平台
│   └─ 更多社区 agent...
├─ C2 Profile（独立模块）:
│   ├─ HTTP Profile
│   ├─ Websocket Profile
│   ├─ TCP Profile
│   └─ 自定义 Profile
└─ 特点: 高度模块化，每个组件可独立替换/开发
```

### 3.2 Agent 识别

```
Apollo (.NET Agent):
├─ 特征: .NET Assembly，可反编译
├─ 识别: dnSpy/ILSpy 打开 → 查找 Apollo 命名空间
├─ 配置: 嵌入在 Assembly 资源或硬编码字符串中
├─ 通信: 默认 HTTP(S)
└─ 检测: AMSI（.NET 加载触发 AMSI 扫描）

Athena (.NET 6+ Agent):
├─ 特征: 可编译为 Native AOT → 无 .NET 依赖
├─ 识别: 如果是 AOT 编译 → 类似原生二进制
├─ 如果是 .NET 托管 → 同 Apollo 分析方法
└─ 跨平台: Windows/Linux/macOS

Poseidon (Go Agent):
├─ 特征: 类似 Sliver 的 Go 二进制
├─ 识别: Go runtime 字符串 + 大体积
├─ 配置: 编译时嵌入
└─ 目标: macOS 和 Linux

通用识别方法:
├─ User-Agent / HTTP Header: Mythic profile 定义
├─ 通信模式: 特定的 checkin/tasking/response 三阶段
├─ 数据格式: JSON (Base64 编码的加密数据)
├─ UUID: Agent 首次 checkin 时注册的 UUID 格式
└─ 加密: 默认 AES-256-CBC + RSA 密钥交换
```

### 3.3 C2 Profile 分析

```bash
# Mythic C2 Profile 定义了通信格式
# 分析抓取的流量时关注:

# 1. Checkin (Agent 首次注册):
#    POST /api/v1.0/register
#    Body: {"action":"checkin","uuid":"xxx","ips":["..."],...}

# 2. Get Tasking (获取任务):
#    GET /api/v1.0/tasking/<uuid>

# 3. Post Response (返回结果):
#    POST /api/v1.0/response
#    Body: {"action":"post_response","responses":[...]}

# 通过 Profile 文件可以自定义上述所有路径和格式
# 但默认安装的特征是可识别的
```

---

## 4. Brute Ratel C4 (BRc4)

### 4.1 架构概述

```
BRc4 架构:
├─ 定位: 商业对手模拟工具（非开源）
├─ Badger Agent:
│   ├─ 语言: C
│   ├─ 体积: ~50KB (shellcode)
│   ├─ 无反射 DLL 注入 → 使用自定义加载器
│   └─ 内置高级 OPSEC 功能
├─ 通信:
│   ├─ HTTP(S)
│   ├─ DNS over HTTPS (DoH)
│   ├─ SMB (内网 pivot)
│   └─ TCP
└─ 特点: 作者为前 CrowdStrike 红队成员，专门设计绕 EDR
```

### 4.2 Badger Implant 特征

```
静态特征:
├─ Shellcode 格式: 位置无关代码
├─ 配置加密: RC4 加密，key 嵌入在 shellcode 中
├─ 无 PE header: 纯 shellcode 格式（不是 DLL/EXE）
├─ 体积小: 约 50-80KB
├─ 字符串: 运行时解密，静态分析看不到明文
└─ 导入: 动态 API 解析（hash-based）

与 Cobalt Strike 的关键差异:
├─ 无 Reflective DLL Injection → 不触发相关检测
├─ 无 BEACON magic bytes → CS 特征扫描无效
├─ 无 Watermark → 没有嵌入的 license ID
├─ Sleep 期间内存加密 → 内存扫描困难
├─ 使用 Indirect Syscalls → 绕过 ntdll hooks
└─ 自带 AMSI/ETW patch 功能
```

### 4.3 配置解密

```python
# BRc4 Badger 配置解密思路
# 1. 从 shellcode 中提取 RC4 key
#    - key 通常在 shellcode 开头附近
#    - 固定长度 (16-32 bytes)
# 2. 定位加密的配置块
#    - 在 shellcode 末尾或特定 offset
# 3. RC4 解密
#    - 解密后为 JSON 或自定义格式

# 已知分析工具:
# - BRc4 Configuration Extractor (Mandiant/Google)
# - 社区 YARA 规则
# - 沙箱动态分析提取 C2 配置

# 解密后的关键字段:
# - C2 Server (URI + Host)
# - Sleep Time
# - Jitter
# - User-Agent
# - URI paths (GET/POST)
# - Encryption keys (session key)
# - Kill date
```

---

## 5. 通用 C2 识别方法

### 5.1 JA3/JA3S 指纹

```
JA3 指纹用于识别 TLS 客户端:
├─ 原理: Hash(TLS版本+密码套件+扩展+椭圆曲线+点格式)
├─ C2 Agent 的 JA3 通常与真实浏览器不同
├─ 已知 C2 JA3 数据库: ja3er.com / trisul-ja3
├─ 对策（红队）: 使用 uTLS/WinHTTP 匹配真实浏览器

JA3S 指纹用于识别 TLS 服务器:
├─ 原理: Hash(TLS版本+密码套件+扩展)
├─ C2 Server 默认 TLS 配置有独特 JA3S
└─ 对策: 使用 Nginx/Cloudflare 前置
```

### 5.2 JARM 指纹

```bash
# JARM: 主动探测 TLS 服务器生成指纹
python3 jarm.py target_domain.com

# 已知 C2 JARM 指纹:
# Cobalt Strike: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
# Sliver:        2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5
# Havoc:         00000000000000000041d00000041d9535d505a1698c0a1303e90100000000
# Metasploit:    07d14d16d21d21d00007d14d07d21d9b2f5869a6985368a9f98571c65871ea

# 对策: 使用反代/CDN 隐藏真实 C2 的 JARM
```

### 5.3 Beacon Interval/Jitter 分析

```
通过网络流量分析识别 C2 心跳:
├─ 提取连接时间序列
├─ 计算间隔的均值和标准差
├─ 固定间隔 → 高度可疑（正常用户行为不固定）
├─ Jitter 低 (< 10%) → 机器行为
├─ 分析公式:
│   interval = mean(t[i+1] - t[i])
│   jitter = stdev(t[i+1] - t[i]) / interval
│   if interval 稳定且 jitter < 15% → 可能是 C2
└─ 工具: RITA (Real Intelligence Threat Analytics)
```

### 5.4 DNS Tunneling 模式识别

```
DNS C2 通道特征:
├─ 子域名长度: > 30 字符（编码数据）
├─ 查询类型: TXT/NULL/CNAME（非常规）
├─ 查询频率: 远高于正常 DNS（秒级）
├─ 编码方式: Base32/Base64/Hex 编码模式
├─ 唯一子域名数: 极大量唯一子域名
└─ NXDOMAIN 比例: 高（探测/传输失败）

检测查询:
# Splunk
index=dns | stats count dc(query) as unique_queries by src_ip
| where unique_queries > 500 AND count > 1000

# 工具: dnscat2-detect, dns-anomaly-detection
```

### 5.5 HTTP Profile 异常检测

```
C2 HTTP 通信的常见异常:
├─ URI 路径: 长期固定的 GET/POST 路径
├─ Response 大小: 空任务时响应大小固定
├─ Content-Type: 与实际内容不符
├─ Cookie: 异常长或结构化的 Cookie 值
├─ Host Header: 与 SNI 不匹配（Domain Fronting）
├─ 定时性: 高度规律的请求间隔
└─ 数据编码: Body 中 Base64/Hex 编码数据

蓝队检测思路:
├─ 统计同一域名的请求时间分布 → 识别 Beacon
├─ 分析 Response 大小分布 → 空任务固定大小
├─ 检查 URI entropy → 随机 URI 熵值高
└─ 对比已知 C2 Profile → Malleable Profile 库
```

---

## 6. 自动化分析工具

| 工具 | 用途 | 目标 C2 |
|------|------|---------|
| JARM (salesforce) | TLS 服务器指纹 | 所有 |
| BeaconEye | 内存实时扫描 Beacon | Cobalt Strike |
| 1768.py (JPCERT) | CS 配置解析 | Cobalt Strike |
| dissect.cobaltstrike | Python CS 解析库 | Cobalt Strike |
| SliverC2-Config-Extractor | Sliver 配置提取 | Sliver |
| RITA | 网络流量 Beacon 检测 | 所有 |
| Suricata + ET Rules | 网络签名检测 | 多种 C2 |
| Zeek + JA3 | TLS 指纹分析 | 所有 |
| Arkime (Moloch) | 全量流量捕获分析 | 所有 |
| Passer | 被动网络指纹 | 所有 |

---

## 关联参考

- **CS Beacon 手动解密与 TLV 解析** → `cs-beacon-decrypt.md`
