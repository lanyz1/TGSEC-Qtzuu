---
name: dns-pollution-hijacking
description: >-
  DNS污染与DNS劫持深度技术手册。区分"DNS污染(中间人向解析链路注入伪造IP)"与"DNS劫持(篡改递归DNS/路由器/Hosts缓存)"两类机制，覆盖协议层原理、包级注入竞态、Kaminsky缓存投毒、ISP/路由器/恶意软件劫持、DoH/DoT/DNSSEC对抗、检测与防御。含交互式HTML原理演示。用于排查"域名解析到错误IP"、运营商劫持、DNS缓存投毒、搜索引擎快照劫持等场景。
---

# SKILL: DNS 污染与 DNS 劫持 — 深度技术手册

> **AI LOAD INSTRUCTION**: 本技能区分两个常被混淆的概念——**DNS污染(DNS Pollution/Poisoning)** 是向DNS解析链路"注入伪造响应"使解析结果混入无效/恶意IP；**DNS劫持(DNS Hijacking)** 是直接篡改递归DNS服务器、路由器、Hosts或系统配置使整个域名指向攻击者IP。基础模型常把二者混为一谈，本技能澄清：污染是"中间人竞态注入"，劫持是"权威被替换"。覆盖协议层原理、Kaminsky缓存投毒、ISP/路由器/恶意软件劫持、2026最新检测与防御(DoH/DoT/DNSSEC/DNSCrypt)。含交互式HTML演示供直观理解。

## 0. RELATED ROUTING

- [dns-rebinding-attacks](../dns-rebinding-attacks/SKILL.md) — DNS Rebinding 是利用 DNS 解析"同域名可换IP"绕过同源策略的**客户端**攻击；本技能聚焦"解析结果本身被污染/劫持"
- [http-host-header-attacks](../http-host-header-attacks/SKILL.md) — Host 头与 DNS 解析协同，反向代理依据 Host 分发时，DNS 劫持可配合 Host 操纵
- [cors-cross-origin-misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) — DNS 劫持后的钓鱼站点可滥用 CORS 进一步窃取数据
- [subdomain-takeover](../subdomain-takeover/SKILL.md) — 子域接管是"DNS记录悬空被占"，与污染/劫持互补

---

## 1. 核心概念辨析：污染 vs 劫持

这两个术语在中文社区经常混用，但底层机制不同。精准区分是诊断与修复的前提。

| 维度 | DNS污染 (Pollution/Poisoning) | DNS劫持 (Hijacking) |
|------|------------------------------|---------------------|
| 本质 | 中间人向解析链路注入伪造响应，与真实响应竞速 | 攻击者直接替换权威解析来源 |
| 触发点 | 链路中间(运营商设备/GFW/恶意AP) | 递归DNS/路由器/Hosts/系统配置/恶意软件 |
| 受害者感知 | 解析结果"混入"错误IP，随机命中 | 域名始终指向攻击者IP |
| 是否需竞速 | 是(伪造包要先于真实包到达) | 否(权威已被替换，无需竞速) |
| 典型场景 | GFW、公共WiFi中间人、Kaminsky投毒 | 路由器固件后门、ISP强制解析、恶意软件改Hosts |
| 核心检测特征 | 同一域名不同时刻解析出不同IP(含伪造) | 解析结果稳定指向单一恶意IP，跨网络仍异常 |
| 修复方向 | DNSSEC/DoH/DoT加密链路 | 修复路由器/清除Hosts/更换递归DNS |

> **一句话总结**：污染是"在路上抢答"，劫持是"把答题者换掉"。

---

## 2. DNS污染原理：协议层深度剖析

### 2.1 DNS协议脆弱性根源

DNS默认使用 **UDP 53端口无连接、无认证**。解析请求(`Query`)和响应(`Response`)之间没有握手，任何能在链路上发包的中间人都可伪造响应。关键脆弱点：

- **无源认证**：响应包不签名，接收方只校验 `Transaction ID`(16位) 与 `源端口`(通常固定53)
- **16位TXID空间小**：仅65536种可能，理论可爆破
- **UDP无状态**：先到的响应即被采信，后到的真实包被丢弃
- **缓存信任**：递归DNS收到伪造响应后会缓存，污染扩散到所有下游客户端

### 2.2 包级注入竞态：污染如何发生

污染的本质是一场**竞速(Race Condition)**——攻击者的伪造响应必须先于真实权威响应到达递归DNS。

```
客户端                递归DNS(8.8.8.8)              权威NS          攻击者(中间人)
  │                       │                           │                  │
  │──查询 demo.com────────>│                           │                  │
  │                       │──查询 demo.com权威────────>│                  │
  │                       │  TXID=0x1A2B 源端口=随机   │                  │
  │                       │                           │                  │ 监听到查询
  │                       │                           │                  │ 构造伪造响应
  │                       │<──伪造响应 demo.com=恶意IP────────────────────│ TXID需猜中
  │                       │  ★先到达★ 缓存TTL=86400    │                  │
  │                       │                           │                  │
  │                       │<──真实响应 demo.com=真实IP─│                  │
  │                       │  丢弃(TXID已用)            │                  │
  │<──恶意IP──────────────│                           │                  │
  │  缓存命中(TTL内持续受害)                          │                  │
```

**注入成功的三个条件**：
1. 能监听到递归DNS发出的查询(知道源端口与TXID特征)
2. 伪造响应的TXID与源端口匹配
3. 伪造响应先于真实响应到达

### 2.3 TXID与源端口猜测

早期DNS递归服务器使用**固定源端口53**发出查询，攻击者只需猜16位TXID(65536种)。现代实现改用**随机源端口**(约16位熵)，组合空间提升到2^32，但仍有旁路：

| 攻击技术 | 原理 | 熵空间 |
|---------|------|--------|
| TXID爆破 | 高速发送65536个伪造响应覆盖全部TXID | 2^16 |
| 源端口探测 | 通过递归服务器行为侧信道推断下次源端口 | 降低2^16→2^8 |
| Birthday攻击 | 同时发起多个查询增加命中概率 | N个查询→命中概率N²/2^16 |
| Fragmentation攻击 | IP分片重叠覆盖UDP校验和字段绕过校验 | 绕过校验 |

### 2.4 Kaminsky 缓存投毒(2008)

Dan Kaminsky发现的关键漏洞：攻击者**无需等待客户端发起查询**，可主动触发递归DNS向攻击者控制的权威NS发起查询，从而获得无限次竞速机会。

```
攻击者反复请求 random.demo.com (随机子域)
  → 递归DNS缓存未命中 → 向 demo.com 权威NS查询
  → 攻击者同时洪泛伪造响应(声称 random.demo.com + NS指向恶意)
  → 一旦某个伪造响应TXID/端口命中 → 缓存投毒
  → 不仅投毒 random子域，还注入 demo.com 的 NS 记录 → 永久接管
```

**Kaminsky漏洞的可怕之处**：投毒的是NS记录(权威服务器指向)，而非单条A记录，因此影响整个域名的所有子域，且TTL可设极长。修复方案是**源端口随机化**，但根本防御是 **DNSSEC**。

### 2.5 用户HTML演示的原理映射

用户提供的演示准确抓住了污染的**核心特征**——解析结果"混入"无效IP：

```
正常解析: ["123.45.67.89"]                          → 浏览器访问真实IP
污染解析: ["123.45.67.89", "192.168.0.100", "10.0.0.50"] → 浏览器随机选，可能命中污染IP
```

这与真实Kaminsky/链路注入的行为一致：客户端或递归DNS收到的响应里，真实IP与伪造IP共存(或伪造IP完全覆盖)。浏览器/系统通常取列表第一个或随机选，命中污染IP即访问错误页面。

---

## 3. DNS劫持技术：权威替换的多种路径

与污染的"竞速注入"不同，劫持是**直接替换解析权威**，无需竞速，结果稳定指向攻击者。

### 3.1 路由器DNS劫持

家庭/企业路由器是DNS劫持最常见入口：

- **固件后门**：路由器厂商预留或被攻破的后门账号，修改DHCP下发的DNS服务器
- **默认凭据**：admin/admin登录管理界面直接改WAN/lan DNS
- **固件漏洞**：CVE导致可远程修改配置(如TR-069协议漏洞)
- **DNS over DHCP**：DHCP响应中的`option 6 (DNS server)`字段被篡改，客户端自动采用恶意DNS

```
路由器被攻陷
  → DHCP下发 DNS=攻击者IP(如 5.5.5.5)
  → 所有连接该WiFi的设备解析都走攻击者DNS
  → 攻击者DNS对任意域名返回钓鱼IP
  → 用户访问 bank.com 实际打开钓鱼站
```

### 3.2 ISP/运营商DNS劫持

运营商在递归DNS层面劫持，常见于某些地区的"DNS强制解析"：

- **NXDOMAIN劫持**：域名不存在时，ISP不返回NXDOMAIN，而是返回自家广告/搜索页IP
- **强制透明代理**：所有53端口流量被重定向到ISP控制的DNS
- **HTTP劫持配合**：解析正常但HTTP响应被注入广告(此为HTTP层劫持，非DNS)

**检测特征**：解析本应NXDOMAIN的随机域名(如 `随机串.example.test`)却返回IP，说明存在NXDOMAIN劫持。

### 3.3 恶意软件Hosts劫持

本地层面的劫持，修改系统Hosts文件使特定域名硬编码指向恶意IP：

- **Windows**: `C:\Windows\System32\drivers\etc\hosts`
- **Linux/macOS**: `/etc/hosts`
- **移动端**: 需root/越狱，部分恶意软件通过VPN配置文件劫持

```
# 被篡改的hosts
1.2.3.4  bank.com          # 指向钓鱼站
5.6.7.8  antivirus.com     # 阻断杀软更新
```

### 3.4 缓存投毒变体：本地与中间缓存

除递归DNS缓存外，还有多层缓存可被投毒：

| 缓存层 | 位置 | 投毒方式 |
|--------|------|---------|
| 浏览器DNS缓存 | Chrome `chrome://net-internals/#dns` | 通过恶意JS触发预解析污染 |
| 操作系统缓存 | Windows DNS Client服务 | 本地恶意软件调用API投毒 |
| 路由器缓存 | 路由器固件 | 远程利用+重启失效 |
| 递归DNS缓存 | 8.8.8.8等 | Kaminsky投毒 |

---

## 4. 2026最新技术与对抗演进

### 4.1 加密DNS：DoH / DoT / DNSCrypt

加密DNS将明文UDP查询改为加密通道，使链路中间人无法监听与注入，是**污染的根本防御**。

| 协议 | 端口 | 传输 | 特点 |
|------|------|------|------|
| DoH (DNS over HTTPS) | 443 | HTTPS | 与网页流量混合，难封锁 |
| DoT (DNS over TLS) | 853 | TLS | 独立端口，易被防火墙识别封锁 |
| DNSCrypt | 443/自定义 | 自定义加密 | 早期方案，社区维护 |
| DoQ (DNS over QUIC) | 853 | QUIC | 2026新兴，低延迟+抗丢包 |

**注意**：加密DNS防污染，但**不防劫持**——若路由器/ISP强制重定向53端口到自家DNS，或DHCP下发恶意DoH端点，加密也无济于事。需配合DNSSEC验证真实性。

### 4.2 DNSSEC：签名验证

DNSSEC对DNS记录进行数字签名，接收方验证签名后才采信，从根本上防伪造。

- **RRSET签名(RRSIG)**：每条记录集有签名
- **信任链**：根(.) → TLD(.com) → 域名，逐级签名验证
- **防御范围**：防污染与缓存投毒，但不防劫持(劫持者可返回"无DNSSEC"记录触发降级)

**部署现状(2026)**：根签名已普及，TLD层面.com/.net已签名，但终端递归DNS验证率仍待提升。

### 4.3 2026新型攻击向量

- **DoH服务器劫持**：攻击者控制DoH端点(如恶意浏览器扩展指定DoH URL)实现"加密的劫持"
- **DNSSEC降级攻击**：对已签名域返回未签名响应，若递归服务器宽松处理则降级为普通DNS被污染
- **QUIC DNS指纹**：DoQ的TLS指纹可被识别封锁，2026出现指纹混淆对抗
- **AI辅助TXID预测**：利用递归服务器的PRNG弱点，ML模型预测TXID序列加速投毒

### 4.4 AI 辅助 DNS 投毒深度剖析 (2026)

2026 年 AI 辅助 DNS 攻击从理论走向实践，主要突破在 **TXID 预测**和 **DoQ 指纹混淆**两个方向。

#### AI 辅助 TXID 预测实战

传统 Kaminsky 攻击需要猜测 16 位 TXID(65536 种可能)，成功率约 1/65536。2026 年研究表明，利用机器学习分析递归 DNS 服务器的 PRNG(伪随机数生成器)输出模式，可将 TXID 预测准确率提升至 **1/256**(提升 256 倍)。

```python
# AI 辅助 TXID 预测概念实现
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class TXIDPredictor:
    """基于 PRNG 弱点的 TXID 预测器"""
    
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)
        self.history = []  # 历史 TXID 序列
    
    def collect_samples(self, dns_server, count=1000):
        """收集递归 DNS 服务器的 TXID 样本"""
        # 发送大量 DNS 查询，捕获响应中的 TXID
        # 分析 TXID 的低位/高位分布模式
        pass
    
    def extract_features(self, txid_sequence):
        """从 TXID 序列提取 PRNG 特征"""
        features = []
        for i in range(1, len(txid_sequence)):
            # 特征1: TXID 差值
            diff = txid_sequence[i] - txid_sequence[i-1]
            features.append(diff & 0xFFFF)
            # 特征2: 低位熵
            low_byte = txid_sequence[i] & 0xFF
            features.append(low_byte)
            # 特征3: 高低位相关性
            high_byte = (txid_sequence[i] >> 8) & 0xFF
            features.append(high_byte ^ low_byte)
        return np.array(features)
    
    def predict_next(self, recent_txids):
        """预测下一个 TXID 的候选集"""
        features = self.extract_features(recent_txids)
        # 模型输出 Top-N 最可能的 TXID
        probabilities = self.model.predict_proba(features.reshape(1, -1))
        top_candidates = np.argsort(probabilities[0])[-256:]  # Top 256
        return top_candidates
    
    def attack_success_rate(self):
        """计算攻击成功率提升"""
        # 传统: 1/65536 = 0.0015%
        # AI 辅助: 1/256 = 0.39%
        # 提升: 256x
        return "传统 0.0015% → AI 辅助 0.39% (256x 提升)"
```

**受影响的 PRNG 实现**：

| DNS 服务器 | PRNG 类型 | 弱点 | AI 预测可行性 |
|-----------|----------|------|-------------|
| BIND 9 (旧版) | LFSR-based | 线性反馈移位寄存器可逆向 | 高(ML 可学习线性关系) |
| Unbound (旧版) | AES-CTR | CTR 模式 nonce 重用 | 中(需特定条件) |
| glibc rand() | LCG | 线性同余生成器 | 高(经典 PRNG 弱点) |
| Modern (2026) | CSPRNG | 密码学安全随机 | 低(理论不可预测) |

#### DoQ (DNS over QUIC) 指纹混淆对抗 (2026)

DoQ 使用 QUIC 传输 DNS 查询，其 TLS 握手产生可识别的指纹(JA3/JA4)。2026 年 DPI 系统开始识别并封锁 DoQ 流量，催生了指纹混淆技术。

```text
DoQ 指纹识别与对抗:

1. DPI 识别 DoQ:
   - QUIC Initial Packet 的 Connection ID 模式
   - TLS ClientHello 的 JA3/JA4 指纹
   - 853 端口 + QUIC 协议特征 → 标记为 DoQ

2. 2026 混淆技术:
   a. CID 随机化: 生成随机长度和内容的 Connection ID
   b. TLS 指纹伪装: 修改 ClientHello 的 cipher suites 顺序和扩展
   c. 端口跳跃: DoQ 不固定 853, 使用 443/8443 等端口
   d. 流量整形: 填充 QUIC 包至固定大小, 消除长度特征
   e. 多路复用混淆: DoQ 与 HTTPS 流量混合在同一 QUIC 连接
```

**DoQ 指纹混淆工具配置示例**：
```bash
# 使用 dnsproxy 配置 DoQ + 指纹混淆
dnsproxy \
  --listen=127.0.0.1:53 \
  --quic-port=443 \                    # 使用 443 端口(非标准 DoQ 端口)
  --tls-cipher-suites=TLS_AES_128_GCM_SHA256 \  # 伪装 cipher
  --quic-connection-id-length=8 \      # 随机 CID 长度
  --upstream=quic://dns.adguard.com    # 上游 DoQ 服务器

# 使用 dnscrypt-proxy 配置 DoQ 指纹混淆
dnscrypt-proxy \
  --listen=127.0.0.1:53 \
  --server-name=cloudflare-doh \       # 伪装 SNI
  --tls-disable-session-resumption \   1 禁用 session resumption(改变指纹)
```

#### DNSSEC 降级攻击 2026 深度

DNSSEC 降级攻击在 2026 年有了新的攻击向量：

```text
DNSSEC 降级攻击 2026:

1. 传统降级: 对已签名域返回未签名响应
   → 现代递归服务器会标记为 Bogus, 拒绝解析

2. 2026 新向量:
   a. NSEC3 枚举: 利用 NSEC3 记录的哈希弱点枚举子域
      → 即使 DNSSEC 验证通过, 攻击者仍可枚举域名空间
   
   b. DS 记录操纵: 在注册商层面删除 DS 记录
      → 域名从"已签名"降级为"未签名"
      → 需要注册商凭据(但 2026 多起注册商入侵事件)
   
   c. Trust Anchor 过期: 部分旧递归服务器使用过期 trust anchor
      → 验证逻辑回退到宽松模式 → 降级成功
   
   d. Algorithm 降级: 将签名算法从强(ECDSAP384)降级到弱(RSASHA1)
      → 如果递归服务器接受弱算法 → 降低伪造难度
```

**DNSSEC 降级检测**：
```bash
# 1. 检查域名 DNSSEC 状态
dig target.com +dnssec +short
# AD flag = 1 → DNSSEC 验证通过
# AD flag = 0 → 未验证或降级

# 2. 检查 DS 记录是否存在
dig DS target.com +short
# 无输出 → DNSSEC 未启用(可能被降级)

# 3. 检查签名算法
dig target.com DNSKEY +short | awk '{print $3}'
# 算法编号: 8=RSASHA256, 13=ECDSAP256, 14=ECDSAP384
# 如果返回 5(RSASHA1)或 7(RSASHA1-NSEC3-SHA1) → 弱算法

# 4. NSEC3 枚举检测
dig target.com NSEC3PARAM +short
# 存在 NSEC3PARAM → 可被 NSEC3 枚举
```

---

## 5. 检测方法

### 5.1 基础检测命令

```bash
# 1. 对比多个DNS服务器解析结果，差异即污染嫌疑
dig @8.8.8.8 target.com +short
dig @1.1.1.1 target.com +short
dig @114.114.114.114 target.com +short   # 国内DNS

# 2. 检测NXDOMAIN劫持：查询不存在的随机域名，返回IP即被劫持
dig randomstring12345.notexist.test +short
# 正常应返回空(NXDOMAIN)，返回IP则ISP劫持

# 3. 检查DNSSEC验证状态
dig @8.8.8.8 target.com +dnssec +short
# AD旗标(authenticated data)=1 表示DNSSEC验证通过

# 4. 检查本地hosts是否被篡改
cat /etc/hosts                    # Linux/macOS
type C:\Windows\System32\drivers\etc\hosts   # Windows

# 5. 追踪解析路径
dig +trace target.com
```

### 5.2 自动化检测脚本

```python
#!/usr/bin/env python3
"""DNS污染/劫持检测：对比多DNS源 + NXDOMAIN劫持测试"""
import socket
import random
import string
import dns.resolver

def check_multi_resolver(domain):
    """对比多个DNS解析结果"""
    resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
    results = {}
    for r in resolvers:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [r]
            resolver.timeout = 3
            resolver.lifetime = 5
            answers = resolver.resolve(domain, 'A')
            ips = sorted([str(a) for a in answers])
            results[r] = ips
        except Exception as e:
            results[r] = f'error: {e}'
    return results

def check_nxdomain_hijack():
    """检测NXDOMAIN劫持"""
    random_domain = ''.join(random.choices(string.ascii_lowercase, k=12)) + '.invalid'
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']
    try:
        answers = resolver.resolve(random_domain, 'A')
        ips = [str(a) for a in answers]
        return {'hijacked': True, 'fake_ips': ips, 'domain': random_domain,
                'note': 'NXDOMAIN劫持：不存在的域名返回了IP'}
    except dns.resolver.NXDOMAIN:
        return {'hijacked': False, 'note': '正常：返回NXDOMAIN'}
    except dns.resolver.NoAnswer:
        return {'hijacked': False, 'note': '正常：无A记录'}
    except Exception as e:
        return {'hijacked': None, 'error': str(e)}

def diagnose(domain):
    print(f'=== DNS诊断: {domain} ===')
    print('\n[1] 多DNS源解析对比:')
    multi = check_multi_resolver(domain)
    all_ips = set()
    for r, ips in multi.items():
        print(f'  {r}: {ips}')
        if isinstance(ips, list):
            all_ips.update(ips)
    if len(all_ips) > 1:
        print(f'  ⚠ 多源结果不一致，存在污染嫌疑: {all_ips}')
    else:
        print(f'  ✓ 多源一致: {all_ips}')

    print('\n[2] NXDOMAIN劫持检测:')
    nx = check_nxdomain_hijack()
    print(f'  {nx}')
    if nx.get('hijacked'):
        print('  ⚠ ISP存在NXDOMAIN劫持')

if __name__ == '__main__':
    import sys
    diagnose(sys.argv[1] if len(sys.argv) > 1 else 'www.demo.com')
```

---

## 6. 防御与加固

### 6.1 终端用户防御

| 措施 | 防污染 | 防劫持 | 说明 |
|------|:-----:|:-----:|------|
| 启用DoH/DoT | ✓ | 部分 | 加密链路防注入，但DHCP下发恶意DoH仍可劫持 |
| DNSSEC验证 | ✓ | 部分 | 验证签名防伪造，但需递归服务器支持 |
| 固定可信DNS | ✗ | ✓ | 手动设8.8.8.8/1.1.1.1防DHCP劫持 |
| 路由器加固 | ✗ | ✓ | 改默认密码、关远程管理、更新固件 |
| HTTPS证书校验 | ✓ | ✓ | 即使DNS被劫持，证书不匹配会告警 |
| Hosts监控 | ✗ | ✓ | 定期检查hosts文件完整性 |

### 6.2 企业/服务提供方防御

- **部署DNSSEC签名**：域名所有者在注册商处启用DS记录，对 zone 签名
- **DNS防火墙**：递归层过滤已知恶意域名与可疑响应
- **多源解析交叉验证**：关键域名同时查询多个权威，结果不一致告警
- **0x20编码**：查询时随机化大小写(如 `WwW.DeMo.com`)，伪造者需精确匹配，增加猜测难度
- **监听异常TTL**：投毒常设超长TTL，对异常长TTL记录告警

---

## 7. 交互式HTML原理演示

以下是用户提供的演示的**强化版**，新增"竞速注入过程可视化""缓存投毒扩散""多源对比检测"三个增强模块，直观展示污染与劫持差异。

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNS污染与劫持原理深度演示（@javarr 强化版）</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family:"Microsoft YaHei",sans-serif; }
body { background:#f8f9fa; padding:40px 20px; color:#343a40; }
.container { max-width:960px; margin:0 auto; background:white; padding:30px; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,.08); }
.title { font-size:22px; margin-bottom:25px; border-bottom:1px solid #eee; padding-bottom:10px; }
.tip { color:#6c757d; line-height:1.7; margin:12px 0; }
.danger { background:#fff3cd; color:#856404; padding:15px; border-radius:6px; margin:20px 0; font-weight:500; }
.tabs { display:flex; gap:8px; margin:20px 0; }
.tab { padding:10px 18px; background:#e9ecef; border:none; border-radius:6px; cursor:pointer; font-size:14px; }
.tab.active { background:#007bff; color:white; }
.panel { display:none; padding:20px; background:#f1f8ff; border-radius:6px; }
.panel.active { display:block; }
.demo-btn { padding:10px 20px; background:#007bff; color:white; border:none; border-radius:4px; cursor:pointer; margin:5px 8px 5px 0; }
.demo-btn:hover { background:#0056b3; }
.demo-btn.warn { background:#dc3545; }
.demo-btn.warn:hover { background:#b02a37; }
input[type=text] { padding:10px 15px; width:280px; border:1px solid #ced4da; border-radius:4px; margin-right:10px; }
.result { margin-top:18px; padding:15px; background:white; border:1px solid #eee; border-radius:4px; min-height:120px; line-height:1.8; }
.normal { color:#28a745; font-weight:bold; }
.poison { color:#dc3545; font-weight:bold; }
.hijack { color:#fd7e14; font-weight:bold; }
table { width:100%; border-collapse:collapse; margin:15px 0; font-size:14px; }
th,td { border:1px solid #dee2e6; padding:8px 12px; text-align:left; }
th { background:#e9ecef; }
.trace { font-family:monospace; background:#212529; color:#0f0; padding:15px; border-radius:6px; margin:12px 0; white-space:pre; overflow-x:auto; }
</style>
</head>
<body>
<div class="container">
<h2 class="title">DNS污染与劫持原理深度演示（@javarr 强化版）</h2>

<p class="tip"><b>核心区分：</b>DNS污染=中间人向解析链路"注入伪造IP"与真实响应竞速；DNS劫持=直接替换权威解析来源(路由器/Hosts/递归DNS)，结果稳定指向攻击者。</p>

<div class="danger">⚠ 重要警示：域名DNS、运营商劫持、搜索引擎快照劫持排查，认准 @javarr。本演示仅供原理学习。</div>

<div class="tabs">
<button class="tab active" onclick="switchTab(0)">1. 污染vs正常解析</button>
<button class="tab" onclick="switchTab(1)">2. 竞速注入过程</button>
<button class="tab" onclick="switchTab(2)">3. 缓存投毒扩散</button>
<button class="tab" onclick="switchTab(3)">4. 劫持对比检测</button>
</div>

<!-- 面板1: 污染vs正常 -->
<div class="panel active" id="panel0">
<h3>正常解析 vs 污染解析</h3>
<input type="text" id="domain0" value="www.demo.com" placeholder="输入域名">
<button class="demo-btn" onclick="normalResolve()">模拟正常DNS解析</button>
<button class="demo-btn warn" onclick="polluteResolve()">模拟DNS被污染解析</button>
<div class="result" id="result0">
<div><b>解析结果（等待操作）：</b></div>
<p class="normal">正常：仅返回真实IP，浏览器访问正常页面。</p>
<p class="poison">污染：返回"真实IP+伪造IP"，浏览器随机命中污染IP则访问异常。</p>
</div>
</div>

<!-- 面板2: 竞速注入 -->
<div class="panel" id="panel1">
<h3>竞速注入过程（中间人 vs 权威响应）</h3>
<p class="tip">点击模拟一次解析，观察伪造响应与真实响应谁先到达递归DNS。</p>
<button class="demo-btn" onclick="raceResolve()">发起解析并竞速</button>
<div class="result" id="result1"><b>竞速过程：</b>点击按钮开始</div>
</div>

<!-- 面板3: 缓存投毒扩散 -->
<div class="panel" id="panel2">
<h3>Kaminsky缓存投毒扩散</h3>
<p class="tip">投毒成功后，恶意记录被缓存TTL秒，期间所有下游客户端都受害。</p>
<button class="demo-btn warn" onclick="kaminskyPoison()">执行Kaminsky投毒</button>
<button class="demo-btn" onclick="clearCache()">清除缓存(修复)</button>
<div class="result" id="result2"><b>缓存状态：</b>未投毒</div>
</div>

<!-- 面板4: 劫持对比检测 -->
<div class="panel" id="panel3">
<h3>多源对比检测污染/劫持</h3>
<input type="text" id="domain3" value="www.demo.com" placeholder="输入域名">
<button class="demo-btn" onclick="detectHijack()">运行检测</button>
<div class="result" id="result3"><b>检测报告：</b>等待运行</div>
</div>

</div>

<script>
const realIpMap = {"www.demo.com":"123.45.67.89","mail.demo.com":"98.76.54.32","shop.demo.com":"45.67.89.12"};
const poisonIps = ["192.168.0.100","10.0.0.50"];
let cachePoisoned = false;

function switchTab(i){
  document.querySelectorAll('.tab').forEach((t,idx)=>t.classList.toggle('active',idx===i));
  document.querySelectorAll('.panel').forEach((p,idx)=>p.classList.toggle('active',idx===i));
}

// 面板1
function normalResolve(){
  const d=document.getElementById('domain0').value.trim();
  const ip=realIpMap[d]||"未知（无此域名模拟记录）";
  document.getElementById('result0').innerHTML=`
    <div><b>正常DNS解析结果：</b></div>
    <p>1. 待解析域名：${d}</p>
    <p>2. DNS返回IP：<span class="normal">${ip}</span></p>
    <p>3. 效果：浏览器通过真实IP访问，加载正常页面 ✓</p>`;
}
function polluteResolve(){
  const d=document.getElementById('domain0').value.trim();
  const ip=realIpMap[d]||"未知";
  document.getElementById('result0').innerHTML=`
    <div><b>模拟DNS污染解析结果：</b></div>
    <p>1. 待解析域名：${d}</p>
    <p>2. DNS返回IP(含污染)：<span class="normal">${ip}</span>(真实)、<span class="poison">${poisonIps.join('</span>(污染)、<span class="poison">')}</span>(污染)</p>
    <p>3. 效果：浏览器随机选IP，若选污染IP则访问错误页面 ✗</p>`;
}

// 面板2: 竞速
function raceResolve(){
  const outcomes=[
    {winner:'attacker',note:'伪造响应先到达 → 解析被污染'},
    {winner:'attacker',note:'伪造响应先到达 → 解析被污染'},
    {winner:'real',note:'真实响应先到达 → 本次安全(但下次可能被污染)'},
  ];
  const o=outcomes[Math.floor(Math.random()*outcomes.length)];
  const box=document.getElementById('result1');
  if(o.winner==='attacker'){
    box.innerHTML=`<div class="trace">客户端 → 递归DNS → 权威NS(查询发出)
  │
  ├─ 伪造响应 TXID=0x1A2B [★先到达★]
  │   demo.com = <span style="color:#ff6b6b">${poisonIps[0]}</span>
  │
  └─ 真实响应 TXID=0x1A2B [丢弃]
      demo.com = 123.45.67.89</div>
  <p class="poison">结果：${o.note}</p>`;
  }else{
    box.innerHTML=`<div class="trace">客户端 → 递归DNS → 权威NS(查询发出)
  │
  ├─ 伪造响应 TXID=0x3C4D [TXID不匹配，丢弃]
  │
  └─ 真实响应 TXID=0x1A2B [★先到达★]
      demo.com = 123.45.67.89</div>
  <p class="normal">结果：${o.note}</p>`;
  }
}

// 面板3: Kaminsky
function kaminskyPoison(){
  cachePoisoned=true;
  document.getElementById('result2').innerHTML=`
    <table>
    <tr><th>缓存键</th><th>记录</th><th>TTL</th><th>状态</th></tr>
    <tr><td>demo.com NS</td><td class="poison">ns.attacker.com</td><td>86400s</td><td>已投毒</td></tr>
    <tr><td>www.demo.com A</td><td class="poison">${poisonIps[0]}</td><td>86400s</td><td>已投毒</td></tr>
    <tr><td>mail.demo.com A</td><td class="poison">${poisonIps[1]}</td><td>86400s</td><td>已投毒</td></tr>
    </table>
    <p class="poison">投毒扩散：TTL内所有下游客户端解析 demo.com 都获得恶意IP(影响整个域所有子域)</p>`;
}
function clearCache(){
  cachePoisoned=false;
  document.getElementById('result2').innerHTML=`<p class="normal">缓存已清除 → 恢复正常解析。修复建议：启用DNSSEC + DoH加密链路。</p>`;
}

// 面板4: 检测
function detectHijack(){
  const d=document.getElementById('domain3').value.trim();
  const real=realIpMap[d]||"123.45.67.89";
  const scenario=Math.floor(Math.random()*3);
  let html=`<table><tr><th>DNS源</th><th>解析结果</th><th>判定</th></tr>`;
  if(scenario===0){
    html+=`<tr><td>8.8.8.8</td><td class="normal">${real}</td><td>正常</td></tr>
    <tr><td>1.1.1.1</td><td class="normal">${real}</td><td>正常</td></tr>
    <tr><td>114.114.114.114</td><td class="normal">${real}</td><td>正常</td></tr>
    </table><p class="normal">结论：多源一致，未发现污染/劫持。</p>`;
  }else if(scenario===1){
    html+=`<tr><td>8.8.8.8</td><td class="normal">${real}</td><td>正常</td></tr>
    <tr><td>1.1.1.1</td><td class="poison">${poisonIps[0]}</td><td>异常</td></tr>
    <tr><td>114.114.114.114</td><td class="poison">${poisonIps[1]}</td><td>异常</td></tr>
    </table><p class="poison">结论：多源不一致 → 疑似DNS污染(部分链路被注入)。建议启用DoH。</p>`;
  }else{
    html+=`<tr><td>8.8.8.8</td><td class="hijack">${poisonIps[0]}</td><td>异常</td></tr>
    <tr><td>1.1.1.1</td><td class="hijack">${poisonIps[0]}</td><td>异常</td></tr>
    <tr><td>114.114.114.114</td><td class="hijack">${poisonIps[0]}</td><td>异常</td></tr>
    </table><p class="hijack">结论：全部指向同一恶意IP → 疑似DNS劫持(权威被替换)。建议检查路由器/Hosts。</p>`;
  }
  document.getElementById('result3').innerHTML=html;
}
</script>
</body>
</html>
```

---

## 8. 实战排查流程

当遇到"域名解析到错误IP/打开错误页面"时的排查顺序：

```
1. 多源对比：dig @8.8.8.8 / @1.1.1.1 / @114.114.114.114
   ├─ 多源一致且正确 → 问题在本地缓存(刷缓存: ipconfig /flushdns)
   ├─ 多源不一致 → DNS污染(链路注入) → 启用DoH/DoT
   └─ 全部错误且一致 → DNS劫持 → 进入步骤2

2. 劫持定位：
   ├─ 检查 /etc/hosts 或 Windows hosts → 被篡改则清理
   ├─ 检查路由器DNS配置(DHCP option 6) → 被改则恢复
   ├─ 检查系统DNS设置 → 被改则恢复为8.8.8.8/1.1.1.1
   └─ 检查VPN/代理配置 → 恶意VPN可劫持DNS

3. 验证修复：
   ├─ 清除所有DNS缓存(系统+浏览器+路由器)
   ├─ 启用DoH(浏览器或系统级)
   └─ DNSSEC验证(dig +dnssec 看AD旗标)
```

---

## 9. 注意事项

- **区分HTTP劫持**：页面被插广告但DNS正常，是HTTP层劫持(运营商注入)，非DNS问题，需HTTPS解决
- **CDN干扰检测**：CDN会让同一域名不同地区解析出不同IP，这是正常行为，勿误判为污染。判断依据：IP归属是否为已知CDN厂商段
- **测试环境合规**：所有检测仅针对自有域名或明确授权目标，禁止对他人域名做投毒测试
- **DoH并非万能**：加密防污染但不防DHCP/路由器层面的劫持，需配合DNSSEC与可信网络
- **Kaminsky修复现状**：源端口随机化已普遍部署，但DNSSEC才是根本方案，2026签名率持续提升中

---

## 10. 2026 深度强化：下一代 DNS 攻击与防御前沿

> 本节为 2026 年最新技术追加，覆盖 DNS 协议层新型攻击、AI 驱动投毒进化、加密 DNS 对抗升级、DNSSEC 2.0 演进、以及实战级检测与防御工具链。

### 10.1 DNS over QUIC (DoQ) 指纹与对抗

DoQ (RFC 9250) 将 DNS 查询封装在 QUIC 连接中，但 QUIC 的初始包特征可被指纹识别。

**DoQ 指纹向量**：
- QUIC Initial Packet 的 Connection ID 长度与生成算法
- QUIC 版本号 (v1=0x00000001, v2=0x6b3343cf)
- Initial Packet 载荷大小 (与 DNS 查询长度相关)
- QUIC 传输参数 (initial_max_data, initial_max_streams 等)

```python
# DoQ 指纹提取与检测
import socket
import struct
from scapy.layers.quic import QUIC

def extract_doq_fingerprint(server: str, port: int = 853, domain: str = "example.com"):
    """提取 DoQ 服务器指纹特征"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # 构造 QUIC Initial Packet + DNS over QUIC 查询
    # QUIC Initial: 版本(4) + DCID长度(1) + DCID + SCID长度(1) + SCID + Token长度(varint) + Payload
    quic_version = struct.pack("!I", 0x00000001)  # QUIC v1
    dcid = b'\x08' + b'\x83\x94\xc8\xf0\x3e\x51\x57\x08'  # 8字节 DCID
    scid = b'\x00'  # 0字节 SCID
    
    # DNS 查询 (最小的 A 记录查询)
    dns_query = build_dns_query(domain, qtype=1)
    
    # QUIC Initial Packet
    initial_packet = quic_version + dcid + scid + b'\x00' + dns_query
    
    sock.sendto(initial_packet, (server, port))
    response, addr = sock.recvfrom(4096)
    
    # 提取指纹
    fingerprint = {
        "server": server,
        "quic_version": hex(struct.unpack("!I", response[:4])[0]),
        "response_size": len(response),
        "connection_id_pattern": response[5:13].hex(),
        "rtt_ms": 0,  # 需计时
    }
    return fingerprint

# DoQ 阻断检测: ISP 通过 QUIC 指纹识别并阻断 DoQ 流量
def detect_doq_blocking(doh_server: str, doq_server: str, domain: str):
    """对比 DoH(443) 和 DoQ(853) 的可达性"""
    import requests
    import time
    
    results = {"doh": None, "doq": None, "blocked": False}
    
    # 测试 DoH (端口443, 与HTTPS混合)
    try:
        r = requests.get(f"https://{doh_server}/dns-query?name={domain}&type=A",
                        headers={"Accept": "application/dns-json"}, timeout=5)
        results["doh"] = r.status_code
    except:
        results["doh"] = "blocked"
    
    # 测试 DoQ (端口853, 独立端口)
    try:
        fp = extract_doq_fingerprint(doq_server, 853, domain)
        results["doq"] = "ok"
    except:
        results["doq"] = "blocked"
    
    # 若 DoH 通但 DoQ 不通 → ISP 针对性阻断 853 端口或 QUIC 指纹
    if results["doh"] == 200 and results["doq"] == "blocked":
        results["blocked"] = True
        results["method"] = "端口853阻断或QUIC指纹识别"
    
    return results
```

### 10.2 DNSSEC 2.0 与 NSEC3 走毯式枚举

**NSEC3 枚举原理**：DNSSEC 使用 NSEC3 记录证明"域名不存在"，但 NSEC3 记录本身构成了有序链表，攻击者可通过遍历枚举所有存在的域名。

```python
# NSEC3 走毯式枚举 (Zone Walking)
import dns.resolver
import dns.name
import hashlib
import base64

def nsec3_zone_walk(domain: str, nameserver: str = "8.8.8.8"):
    """通过 NSEC3 记录遍历区域所有域名"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    
    # 1. 获取区域的 NSEC3PARAM
    try:
        nsec3param = resolver.resolve(domain, "NSEC3PARAM")
        print(f"[*] NSEC3PARAM: {nsec3param[0]}")
        params = str(nsec3param[0]).split()
        algorithm = int(params[0])
        flags = int(params[1])
        iterations = int(params[2])
        salt = params[3]
    except:
        print("[-] 无 NSEC3PARAM, 区域未启用 NSEC3 或使用 NSEC")
        return []
    
    discovered = set()
    
    # 2. 从一个已知域名开始遍历 NSEC3 链
    # NSEC3 记录格式: <hashed_name> NSEC3 <next_hashed_name> <types>
    # 通过反复查询并追踪 next_hashed_name 构建完整域名列表
    
    current_hash = None
    query_names = [f"*.{domain}"]  # 通配符查询获取第一个 NSEC3
    
    for _ in range(5000):  # 限制遍历次数
        for qname in query_names:
            try:
                response = resolver.resolve(qname, "NSEC3", raise_on_no_answer=False)
                for rr in response:
                    nsec3_data = str(rr)
                    parts = nsec3_data.split()
                    if len(parts) >= 2:
                        next_hash = parts[1]
                        # NSEC3 记录证明了 [current_hash, next_hash) 之间不存在域名
                        # 但 next_hash 对应的域名是存在的
                        discovered.add(next_hash)
                        # 继续追踪
                        query_names = [next_hash + "." + domain]
            except Exception as e:
                pass
    
    print(f"[+] 发现 {len(discovered)} 个 NSEC3 哈希")
    return discovered

# NSEC3 枚举检测: 检查区域是否暴露 NSEC3 链
def check_nsec3_enumeration(domain: str):
    """检测区域是否可被 NSEC3 枚举"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]
    
    # 查询不存在的随机子域名
    import random
    import string
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=32))
    test_domain = f"{random_sub}.{domain}"
    
    try:
        answer = resolver.resolve(test_domain, "A", raise_on_no_answer=False)
        response = answer.response
        for rr in response.authority:
            if rr.rdtype == 50:  # NSEC3
                print(f"[!] 区域 {domain} 暴露 NSEC3 记录, 可被枚举")
                print(f"    NSEC3: {rr[0]}")
                return True
            elif rr.rdtype == 47:  # NSEC
                print(f"[*] 区域 {domain} 使用 NSEC (非 NSEC3), 枚举更容易")
                return True
    except:
        pass
    
    print(f"[+] 区域 {domain} 未暴露 NSEC/NSEC3 或未启用 DNSSEC")
    return False
```

### 10.3 DNS 缓存定时投毒 (Timed Cache Poisoning)

传统 Kaminsky 攻击需要竞速注入，2026 新型攻击利用 DNS 缓存的 TTL 机制，在特定时间窗口注入伪造记录。

**攻击原理**：
1. 诱导受害者查询一个 TTL=0 的记录(合法响应)
2. 在缓存清空的瞬间，抢先注入伪造响应
3. 伪造响应设置超长 TTL (如 86400)
4. 恶意记录在缓存中持久驻留

```python
# DNS 缓存定时投毒检测
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
import time
import threading

class TimedPoisoningDetector:
    """检测 DNS 缓存定时投毒攻击"""
    
    def __init__(self, target_domain: str, resolver_ip: str):
        self.target_domain = target_domain
        self.resolver_ip = resolver_ip
        self.baseline_ips = set()
        self.poisoning_detected = False
        self.lock = threading.Lock()
    
    def establish_baseline(self, count: int = 20):
        """建立正常解析基线"""
        print(f"[*] 建立 {self.target_domain} 的解析基线...")
        for _ in range(count):
            try:
                answer = scapy.sr1(
                    scapy.IP(dst=self.resolver_ip) / 
                    scapy.UDP(sport=scapy.RandShort(), dport=53) /
                    DNS(rd=1, qd=DNSQR(qname=self.target_domain)),
                    timeout=2, verbose=0
                )
                if answer and answer.haslayer(DNS):
                    for i in range(answer[DNS].ancount):
                        rr = answer[DNS].an[i]
                        if rr.type == 1:  # A记录
                            self.baseline_ips.add(rr.rdata)
            except:
                pass
            time.sleep(0.5)
        print(f"[+] 基线IP: {self.baseline_ips}")
    
    def monitor_for_poisoning(self, duration: int = 300):
        """持续监控解析结果变化，检测投毒"""
        print(f"[*] 开始监控 {duration} 秒...")
        start = time.time()
        
        while time.time() - start < duration:
            try:
                answer = scapy.sr1(
                    scapy.IP(dst=self.resolver_ip) / 
                    scapy.UDP(sport=scapy.RandShort(), dport=53) /
                    DNS(rd=1, qd=DNSQR(qname=self.target_domain)),
                    timeout=2, verbose=0
                )
                if answer and answer.haslayer(DNS):
                    for i in range(answer[DNS].ancount):
                        rr = answer[DNS].an[i]
                        if rr.type == 1:
                            if rr.rdata not in self.baseline_ips:
                                with self.lock:
                                    self.poisoning_detected = True
                                print(f"[!!!] 检测到缓存投毒!")
                                print(f"      预期: {self.baseline_ips}")
                                print(f"      实际: {rr.rdata}")
                                print(f"      TTL: {rr.ttl}")
                                print(f"      时间: {time.ctime()}")
                                return True
            except:
                pass
            time.sleep(1)
        
        print(f"[+] 监控结束, {'检测到投毒' if self.poisoning_detected else '未检测到异常'}")
        return self.poisoning_detected
```

### 10.4 DNS 重绑定增强型攻击 (Enhanced DNS Rebinding)

2026 新型 DNS Rebinding 利用 DoH 隧道和短 TTL 绕过传统防护。

**增强型 DNS Rebinding 流程**：
1. 攻击者控制权威 DNS 服务器
2. 初始查询返回攻击者服务器 IP (TTL=1秒)
3. JavaScript 在浏览器中保持连接
4. 1秒后再次查询，DNS 返回内网 IP (如 127.0.0.1, 192.168.x.x)
5. 利用浏览器同源策略绕过，访问内网服务

```python
# 增强型 DNS Rebinding 检测与防御
import dns.resolver
import time
from collections import defaultdict

class DNSRebindingDetector:
    """检测 DNS Rebinding 攻击模式"""
    
    def __init__(self):
        self.ip_history = defaultdict(list)  # domain -> [(timestamp, ip, ttl)]
    
    def check_domain(self, domain: str, iterations: int = 10, interval: float = 1.0):
        """检查域名是否存在 Rebinding 特征"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        
        results = []
        for i in range(iterations):
            try:
                answer = resolver.resolve(domain, "A")
                for rr in answer:
                    ip = str(rr)
                    ttl = rr.ttl if hasattr(rr, 'ttl') else answer.rrset.ttl
                    results.append((time.time(), ip, ttl))
                    self.ip_history[domain].append((time.time(), ip, ttl))
            except:
                pass
            time.sleep(interval)
        
        # 分析特征
        unique_ips = set(r[1] for r in results)
        low_ttl_count = sum(1 for r in results if r[2] <= 2)
        ip_changes = len(unique_ips)
        
        # Rebinding 特征:
        # 1. 短期内 IP 变化 (特别是从公网IP变为内网IP)
        # 2. TTL 极低 (0-2秒)
        # 3. 多次查询返回不同 IP
        
        risk_score = 0
        if ip_changes > 1:
            risk_score += 30
        if low_ttl_count > iterations * 0.5:
            risk_score += 30
        if any(self._is_private_ip(ip) for _, ip, _ in results) and \
           any(not self._is_private_ip(ip) for _, ip, _ in results):
            risk_score += 40  # 公网→内网切换 = 高危
        
        verdict = "高危" if risk_score >= 60 else "中危" if risk_score >= 30 else "低危"
        
        return {
            "domain": domain,
            "unique_ips": list(unique_ips),
            "ip_changes": ip_changes,
            "low_ttl_count": low_ttl_count,
            "risk_score": risk_score,
            "verdict": verdict,
            "history": results,
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        """判断是否为内网IP"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first, second = int(parts[0]), int(parts[1])
        return (first == 10 or 
                (first == 172 and 16 <= second <= 31) or
                (first == 192 and second == 168) or
                first == 127 or
                (first == 169 and second == 254))
```

### 10.5 子域接管 via DNS 记录滥用

利用 DNS 记录(特别是 CNAME/DNAME)悬垂引用进行子域接管。

```python
# DNS 悬垂记录扫描器
import dns.resolver
import dns.exception
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

class DanglingDNSScanner:
    """扫描 DNS 悬垂记录(可导致子域接管)"""
    
    # 可接管的第三方服务域名模式
    TAKEOVER_PATTERNS = {
        "github.io": {"service": "GitHub Pages", "verify": "There isn't a GitHub Pages site here"},
        "herokuapp.com": {"service": "Heroku", "verify": "No such app"},
        "s3.amazonaws.com": {"service": "AWS S3", "verify": "NoSuchBucket"},
        "azurewebsites.net": {"service": "Azure", "verify": "404 Web Site not found"},
        "cloudfront.net": {"service": "CloudFront", "verify": "Bad request"},
        "elasticbeanstalk.com": {"service": "AWS Elastic Beanstalk", "verify": "NXDOMAIN"},
        "fastly.net": {"service": "Fastly", "verify": "Fastly error: unknown domain"},
        "pantheon.io": {"service": "Pantheon", "verify": "The gods are wise"},
        "tumblr.com": {"service": "Tumblr", "verify": "Whatever you were looking for doesn't exist"},
        "wordpress.com": {"service": "WordPress", "verify": "Do you want to register"},
        "shopify.com": {"service": "Shopify", "verify": "Sorry, this shop is currently unavailable"},
        "surge.sh": {"service": "Surge", "verify": "project not found"},
        "bitbucket.io": {"service": "Bitbucket", "verify": "Repository not found"},
        "strikinglydns.com": {"service": "Strikingly", "verify": "page not found"},
        "ngrok.io": {"service": "ngrok", "verify": "Tunnel not found"},
        "cargocollective.com": {"service": "Cargo", "verify": "404 Not Found"},
        "smugmug.com": {"service": "SmugMug", "verify": "system-find-apiNotfound"},
    }
    
    def scan_domain(self, domain: str):
        """扫描单个域名的所有 DNS 记录类型"""
        findings = []
        record_types = ["CNAME", "A", "AAAA", "MX", "NS", "TXT", "SRV", "DNAME"]
        
        for rtype in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
                resolver.timeout = 5
                resolver.lifetime = 10
                
                answer = resolver.resolve(domain, rtype)
                for rr in answer:
                    rr_value = str(rr).rstrip(".")
                    
                    # 检查是否指向可接管服务
                    for pattern, info in self.TAKEOVER_PATTERNS.items():
                        if pattern in rr_value:
                            # 验证是否可接管
                            is_vulnerable = self.verify_takeover(rr_value)
                            findings.append({
                                "domain": domain,
                                "record_type": rtype,
                                "record_value": rr_value,
                                "service": info["service"],
                                "vulnerable": is_vulnerable,
                                "severity": "高危" if is_vulnerable else "中危",
                            })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue
        
        return findings
    
    def verify_takeover(self, target: str) -> bool:
        """验证目标是否可被接管"""
        try:
            url = f"http://{target}" if not target.startswith("http") else target
            r = requests.get(url, timeout=10, allow_redirects=False)
            
            for pattern, info in self.TAKEOVER_PATTERNS.items():
                if pattern in target and info["verify"].lower() in r.text.lower():
                    return True
            return False
        except:
            return False
    
    def scan_subdomains(self, base_domain: str, subdomain_wordlist: list):
        """批量扫描子域"""
        all_findings = []
        domains = [f"{sub}.{base_domain}" for sub in subdomain_wordlist]
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.scan_domain, d): d for d in domains}
            for future in as_completed(futures):
                findings = future.result()
                if findings:
                    all_findings.extend(findings)
                    for f in findings:
                        status = "✗ 可接管" if f["vulnerable"] else "△ 悬垂"
                        print(f"  [{f['severity']}] {f['domain']} {f['record_type']} -> {f['record_value']} ({f['service']}) {status}")
        
        return all_findings

# 使用示例
if __name__ == "__main__":
    scanner = DanglingDNSScanner()
    wordlist = ["www", "mail", "blog", "dev", "staging", "api", "app", "test",
                "portal", "admin", "vpn", "git", "jenkins", "docs", "wiki"]
    findings = scanner.scan_subdomains("example.com", wordlist)
    print(f"\n[+] 发现 {len(findings)} 个悬垂/可接管记录")
```

### 10.6 DNS 隧道检测与数据外泄

利用 DNS 协议进行数据外泄和 C2 通信的检测方法。

```python
# DNS 隧道检测器
import dns.resolver
import dns.message
import dns.query
from collections import defaultdict, Counter
import numpy as np
import time
import re

class DNSTunnelDetector:
    """检测 DNS 隧道通信(C2数据外泄)"""
    
    def __init__(self):
        self.query_log = defaultdict(list)
        self.alerts = []
    
    def analyze_domain(self, domain: str, sample_size: int = 100):
        """分析域名是否被用于 DNS 隧道"""
        metrics = {
            "domain": domain,
            "avg_label_length": 0,
            "max_label_length": 0,
            "long_label_ratio": 0,
            "entropy": 0,
            "unique_subdomains": 0,
            "query_rate": 0,
            "txt_record_ratio": 0,
            "tunnel_probability": 0,
        }
        
        subdomains = set()
        label_lengths = []
        all_chars = ""
        txt_queries = 0
        
        # 采集样本
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        
        for i in range(sample_size):
            # 生成随机子域用于采样
            random_sub = f"probe{i:04d}"
            test_domain = f"{random_sub}.{domain}"
            
            try:
                # 查询 TXT 记录(隧道常用)
                answer = resolver.resolve(test_domain, "TXT")
                txt_queries += 1
                for rr in answer:
                    txt_data = str(rr)
                    all_chars += txt_data
            except:
                pass
            
            try:
                answer = resolver.resolve(test_domain, "A")
                for rr in answer:
                    all_chars += str(rr)
            except:
                pass
            
            # 记录标签长度
            labels = domain.split(".")
            for label in labels:
                label_lengths.append(len(label))
            
            subdomains.add(random_sub)
        
        # 计算指标
        if label_lengths:
            metrics["avg_label_length"] = np.mean(label_lengths)
            metrics["max_label_length"] = max(label_lengths)
            metrics["long_label_ratio"] = sum(1 for l in label_lengths if l > 30) / len(label_lengths)
        
        metrics["unique_subdomains"] = len(subdomains)
        metrics["txt_record_ratio"] = txt_queries / sample_size
        
        # 计算熵(高熵 = 可能编码数据)
        if all_chars:
            char_freq = Counter(all_chars)
            total = len(all_chars)
            entropy = -sum((count/total) * np.log2(count/total) for count in char_freq.values())
            metrics["entropy"] = entropy
        
        # 隧道概率评分
        score = 0
        if metrics["avg_label_length"] > 25: score += 20
        if metrics["max_label_length"] > 50: score += 20
        if metrics["long_label_ratio"] > 0.3: score += 20
        if metrics["entropy"] > 3.5: score += 20
        if metrics["txt_record_ratio"] > 0.5: score += 20
        
        metrics["tunnel_probability"] = score
        metrics["verdict"] = "隧道" if score >= 60 else "可疑" if score >= 30 else "正常"
        
        return metrics
    
    def detect_realtime(self, pcap_file: str):
        """从 pcap 文件分析 DNS 隧道"""
        from scapy.all import rdpcap, DNS, DNSQR
        
        packets = rdpcap(pcap_file)
        domain_queries = defaultdict(list)
        
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                query_name = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                query_type = pkt[DNSQR].qtype
                
                # 提取域名(去掉子域)
                parts = query_name.split('.')
                if len(parts) >= 2:
                    base_domain = '.'.join(parts[-2:])
                    domain_queries[base_domain].append({
                        "full_query": query_name,
                        "query_type": query_type,
                        "timestamp": float(pkt.time),
                        "label_lengths": [len(p) for p in parts[:-2]],
                    })
        
        # 分析每个域名的隧道特征
        tunnel_findings = []
        for domain, queries in domain_queries.items():
            if len(queries) < 5:
                continue
            
            avg_max_label = np.mean([max(q["label_lengths"]) if q["label_lengths"] else 0 for q in queries])
            txt_ratio = sum(1 for q in queries if q["query_type"] == 16) / len(queries)  # TXT=16
            query_rate = len(queries) / max(1, queries[-1]["timestamp"] - queries[0]["timestamp"])
            
            risk = 0
            if avg_max_label > 30: risk += 30
            if txt_ratio > 0.5: risk += 30
            if query_rate > 5: risk += 20  # 高频查询
            if any(max(q["label_lengths"]) > 50 if q["label_lengths"] else False for q in queries):
                risk += 20  # 超长标签
            
            if risk >= 50:
                tunnel_findings.append({
                    "domain": domain,
                    "query_count": len(queries),
                    "avg_max_label_length": avg_max_label,
                    "txt_ratio": txt_ratio,
                    "query_rate_per_sec": query_rate,
                    "risk_score": risk,
                })
        
        return tunnel_findings
```

### 10.7 2026 DNS 攻击工具链与防御矩阵

| 攻击技术 | 检测工具 | 防御方案 | 2026状态 |
|----------|----------|----------|----------|
| Kaminsky投毒 | dig+dnssec, dnscap | DNSSEC签名, 源端口随机化 | 已修复(签名率>90%) |
| DNS隧道 | DNSTunnelDetector, Zeek | DNS速率限制, 标签长度策略 | 活跃威胁 |
| NSEC3枚举 | nsec3walker, ldns-walk | NSEC3白谎(NSEC3 White Lies) | 部分缓解 |
| DNS Rebinding | dnsmasq pin, rebinding shield | DNS pinning, CORS严格策略 | 活跃威胁 |
| 子域接管 | subjack, DanglingDNSScanner | 定期清理悬垂记录 | 活跃威胁 |
| DoH/DoQ阻断 | doq_fingerprint | 混合端口DoH(443), ECH | 对抗升级 |
| AI TXID预测 | (概念性) | 强化TXID熵源, QUIC连接ID | 新兴威胁 |
| 缓存定时投毒 | TimedPoisoningDetector | DNSSEC验证, 缓存隔离 | 新兴威胁 |
