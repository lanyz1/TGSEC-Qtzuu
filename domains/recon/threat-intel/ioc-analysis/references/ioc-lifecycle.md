# IOC 生命周期管理与分析方法

> IOC 不是静态的数据库条目。每个 IOC 都有生命周期、衰减曲线和情报价值。红队需要理解蓝队如何利用 IOC 进行枢轴分析和归因，才能设计不可追踪的基础设施。

---

## 1. IOC 类型与生命周期

### 1.1 Pyramid of Pain 各层 IOC

```
各层 IOC 的更换成本与生命周期:

┌─────────────────────────────────────────────────────┐
│ TTPs (战术/技术/过程)                                 │
│ 更换成本: 极高（需要完全改变攻击方法论）              │
│ 生命周期: 年级别 → 组织不会频繁改变 TTP              │
│ 情报价值: 最高 → 可识别同一组织跨年度活动             │
├─────────────────────────────────────────────────────┤
│ Tools (工具特征: Imphash/YARA/PDB)                   │
│ 更换成本: 高（需要重新编译/重写工具）                 │
│ 生命周期: 季度级别                                    │
│ 情报价值: 高 → 工具重用可关联多次行动                 │
├─────────────────────────────────────────────────────┤
│ Host Artifacts (注册表/Mutex/文件路径/服务名)         │
│ 更换成本: 中（修改配置即可）                          │
│ 生命周期: 月级别                                      │
│ 情报价值: 中 → 可识别同一工具的不同部署               │
├─────────────────────────────────────────────────────┤
│ Network Artifacts (JA3/User-Agent/URI 模式/C2协议)   │
│ 更换成本: 中（修改 Profile/配置）                     │
│ 生命周期: 周级别                                      │
│ 情报价值: 中 → 网络签名可规模化检测                   │
├─────────────────────────────────────────────────────┤
│ Domain Names (C2/钓鱼域名)                           │
│ 更换成本: 低-中（需要注册+养老+分类）                 │
│ 生命周期: 天-周级别                                   │
│ 情报价值: 中低 → 可 pivot 到注册信息/基础设施         │
├─────────────────────────────────────────────────────┤
│ IP Addresses (C2/VPS/代理 IP)                        │
│ 更换成本: 极低（新建 VPS 几分钟）                     │
│ 生命周期: 小时-天级别                                 │
│ 情报价值: 低 → 云 IP 被多个租户复用                   │
├─────────────────────────────────────────────────────┤
│ Hash Values (MD5/SHA256)                             │
│ 更换成本: 极低（改一个字节即变化）                    │
│ 生命周期: 即时 → 每次编译/修改都变                    │
│ 情报价值: 最低 → 只能匹配完全相同的文件               │
└─────────────────────────────────────────────────────┘
```

### 1.2 IOC 老化 (Aging) 与失效判断

```
IOC 老化模型:

新鲜 IOC (0-72小时):
├─ 高置信度，高价值
├─ 立即可用于检测和阻断
├─ 来源: 实时事件响应、沙箱分析、蜜罐
└─ 行动: 立即封锁/检测

活跃 IOC (3-30天):
├─ 中高置信度
├─ 仍可用于检测，但可能已被更换
├─ C2 域名/IP 可能仍在使用
└─ 行动: 保持检测，降低封锁优先级

衰减 IOC (1-6个月):
├─ 中低置信度
├─ 攻击者可能已轮换基础设施
├─ Hash 和 IP 最先失效
├─ 域名和 Host artifact 可能仍有效
└─ 行动: 保留用于历史分析和猎杀

历史 IOC (> 6个月):
├─ 低置信度（作为封锁依据）
├─ 高价值（作为情报分析依据）
├─ 可用于: 长期趋势分析、归因、基础设施关联
├─ IP 可能已被分配给新租户 → 误报风险高
└─ 行动: 转入情报数据库，不用于实时封锁
```

### 1.3 历史 IOC 的情报价值

```
过期的 IOC 不应删除，而应用于:

1. 归因分析:
   ├─ 同一注册邮箱注册的历史域名
   ├─ 同一 IP 段上的历史恶意服务
   └─ 工具特征的演变追踪

2. 基础设施模式识别:
   ├─ 攻击者偏好的 VPS 提供商
   ├─ 域名注册的 naming pattern
   ├─ SSL 证书的签发 CA 偏好
   └─ 地理位置分布模式

3. 威胁猎杀:
   ├─ 回溯搜索历史日志
   ├─ 发现之前未检测到的入侵
   └─ 确认 dwell time（驻留时间）
```

---

## 2. IOC 分析方法

### 2.1 单 IOC 枢轴分析 (Pivoting)

```
从单个 IOC 出发，通过枢轴关联发现更多基础设施:

=== IP → 域名 → 注册信息 → 更多域名 ===

1. IP 地址枢轴:
   IP: 192.168.1.100
   │
   ├─ Passive DNS → 查找历史解析到该 IP 的域名
   │   工具: PassiveTotal, VirusTotal, SecurityTrails
   │   $ curl "https://api.passivetotal.org/v2/dns/passive?query=192.168.1.100"
   │
   ├─ Shodan/Censys → 该 IP 上运行的服务
   │   $ shodan host 192.168.1.100
   │   关注: HTTP 标题/证书/开放端口/Banner
   │
   ├─ 反向 WHOIS → 同一注册者的其他 IP/域名
   │
   └─ 证书透明度 → 该 IP 关联的 SSL 证书
       $ curl "https://crt.sh/?q=192.168.1.100"

2. 域名枢轴:
   Domain: c2.evil-domain.com
   │
   ├─ WHOIS → 注册信息（邮箱/姓名/地址）
   │   └─ 反向 WHOIS → 同一注册者的所有域名
   │
   ├─ Passive DNS → 历史 A/AAAA/MX/NS 记录
   │   └─ 发现其他使用同一 IP 的域名
   │
   ├─ 子域名枚举 → 发现更多子域名和服务
   │
   ├─ SSL 证书 → crt.sh 查询证书历史
   │   └─ 证书中的 SAN (Subject Alternative Name) 包含其他域名
   │
   └─ URL/URI 分析 → 如果有 C2 路径，搜索相同路径特征

3. Hash 枢轴:
   Hash: SHA256_of_malware
   │
   ├─ VirusTotal → 沙箱报告 → 提取 C2 地址
   │   └─ C2 IP/域名 → 继续枢轴
   │
   ├─ MalwareBazaar → 相同家族的其他样本
   │   └─ 提取所有样本的 C2 → 基础设施图谱
   │
   ├─ Hybrid Analysis → 行为报告 → 网络 IOC
   │
   └─ YARA → 编写 YARA 规则搜索相似样本
```

```bash
# 枢轴分析实战命令

# VirusTotal IP 信息
curl -s -H "x-apikey: $VT_KEY" \
  "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4" | \
  jq '.data.attributes.last_https_certificate.extensions.subject_alternative_name'

# PassiveTotal 被动 DNS
curl -s -u "user:key" \
  "https://api.passivetotal.org/v2/dns/passive?query=evil.com" | \
  jq '.results[] | {resolve: .resolve, firstSeen: .firstSeen, lastSeen: .lastSeen}'

# Shodan 主机信息
curl -s "https://api.shodan.io/shodan/host/1.2.3.4?key=$SHODAN_KEY" | \
  jq '{ports: .ports, hostnames: .hostnames, http_title: .data[].http.title}'

# crt.sh 证书搜索
curl -s "https://crt.sh/?q=%.evil.com&output=json" | \
  jq '.[].name_value' | sort -u
```

### 2.2 关联分析 (Correlation)

```
多维度关联:

1. 时间相关性:
   ├─ 同一时间段注册的域名 → 同一批次基础设施
   ├─ 同一时间段的 C2 活动 → 同一行动
   ├─ 证书签发时间聚类 → 基础设施搭建时间点
   └─ 工具: 时间线分析（Timeline Analysis）

2. 基础设施重叠:
   ├─ 共享 IP: 多个域名解析到同一 IP
   ├─ 共享 NS: 使用同一 Name Server
   ├─ 共享注册商: 同一账户注册多个域名
   ├─ 共享证书 CA: 统一使用 Let's Encrypt / 同一商业 CA
   ├─ 共享 SSH Key: 多个 VPS 使用同一 SSH 密钥
   └─ 共享 JARM: 相同的 TLS 服务器配置

3. 代码相似度:
   ├─ Imphash 相同 → 相同的导入表布局
   ├─ SSDEEP/TLSH 近似 → 代码结构相似
   ├─ Rich Header 匹配 → 相同编译环境
   ├─ PDB 路径 → 开发环境路径泄露
   └─ 字符串重用 → 共享代码片段
```

### 2.3 归因线索 (Attribution Indicators)

```
归因分析中的弱信号:

语言 Artifacts:
├─ PE 资源中的 Language ID
├─ 代码注释中的语言
├─ PDB 路径中的用户名/路径
├─ Error message 的语言
└─ 键盘布局偏好

时区 Patterns:
├─ PE 编译时间 → 推断工作时区
│   (注意: 编译时间可伪造)
├─ C2 活动时间分布 → 工作时间推断
├─ Git commit 时间（如有源码泄露）
├─ 域名注册时间
└─ 文件创建/修改时间

Victimology:
├─ 目标行业和地区 → 缩小动机范围
├─ 攻击时机 → 与地缘政治事件关联
├─ 数据窃取类型 → 经济/情报/军事
└─ 后续利用方式 → 破坏/间谍/犯罪

⛔ 归因注意事项:
├─ 所有弱信号都可以被伪造（False Flag）
├─ 编译时间可修改
├─ 语言 artifact 可植入
├─ 需要多个独立线索交叉验证
└─ 归因结论应标注置信度
```

---

## 3. 红队 OPSEC 视角

### 3.1 避免产生可 Pivot 的 IOC

```
红队基础设施 OPSEC 清单:

域名注册:
├─ ⛔ 不要用同一邮箱注册多个行动的域名
├─ ⛔ 不要用同一注册商账户
├─ ✓ 每个行动使用独立的一次性邮箱
├─ ✓ 每个行动使用不同的注册商
├─ ✓ 启用 Whois Privacy
└─ ✓ 域名命名不要有可识别模式

VPS/IP:
├─ ⛔ 不要在不同行动中复用 IP
├─ ⛔ 不要用同一云账户
├─ ✓ 每次行动新建云账户
├─ ✓ 使用不同 VPS 提供商
├─ ✓ 行动结束销毁（不是停止）
└─ ✓ IP 使用前检查历史信誉

SSL 证书:
├─ ⛔ 不要在证书中泄露关联信息
├─ ✓ 使用 Let's Encrypt（最常见）
├─ ✓ 或 Cloudflare Universal SSL
└─ ✓ 不要用自签名证书

工具/Payload:
├─ ⛔ 不要在不同行动中复用同一编译版本
├─ ⛔ 不要留下 PDB 路径
├─ ✓ 每次行动重新编译
├─ ✓ 修改 Rich Header / 编译时间
├─ ✓ 清理代码中的唯一标识
└─ ✓ 使用不同的 C2 Profile
```

### 3.2 基础设施隔离原则

```
不同行动的基础设施必须完全隔离:

行动 A                    行动 B
├─ 域名 A1, A2           ├─ 域名 B1, B2
├─ IP: a.a.a.a           ├─ IP: b.b.b.b
├─ 云账户: AcctA         ├─ 云账户: AcctB
├─ 注册邮箱: mailA       ├─ 注册邮箱: mailB
├─ 支付方式: CryptoA     ├─ 支付方式: CryptoB
├─ C2 Profile: ProfileA  ├─ C2 Profile: ProfileB
└─ SSH Key: keyA          └─ SSH Key: keyB

如果行动 A 的任何一个 IOC 被发现:
├─ 蓝队可以 pivot 到行动 A 的其他 IOC
├─ 但绝不能 pivot 到行动 B 的任何 IOC
└─ 这就是隔离的目标
```

### 3.3 Indicator 过期策略

```
基础设施生命周期管理:

Staging (初始访问):
├─ 生命周期: 24-48 小时
├─ 钓鱼域名/链接 → 投递成功后立即弃用
├─ Payload 托管 → 目标下载后关闭
└─ 不关联到 Long-Haul 基础设施

Long-Haul (持久驻留):
├─ 生命周期: 行动期间（周-月）
├─ 每 2 周检查 VT/AbuseIPDB 检出状态
├─ 域名被标记 → 切换到备用
├─ IP 被标记 → 更换 Redirector
└─ 保持 2+ 备用 C2 通道

Exfiltration (数据外传):
├─ 生命周期: 单次使用
├─ 每次外传使用不同的通道/域名
├─ 外传完成 → 立即销毁
└─ 使用云存储 API → 更难追踪
```

### 3.4 域名注册 OPSEC

```
域名购买最佳实践:

Aged Domains (推荐):
├─ 购买已过期的老域名（expireddomains.net）
├─ 检查历史: Wayback Machine 无恶意内容
├─ 检查信誉: VT/URLhaus 无恶意标记
├─ 检查分类: 已被 Bluecoat/PA 归类为合法
├─ 成本高但 OPSEC 最好
└─ 已有历史 = 不像新注册的 C2

新注册域名:
├─ 至少提前 30 天注册
├─ 部署合法网站内容
├─ 申请分类（Business/Technology/Education）
├─ 等待搜索引擎收录
├─ 建立正常的 DNS 历史
└─ 然后才用于 C2

Privacy Protection:
├─ 所有域名启用 Whois Privacy
├─ 使用一次性 ProtonMail/Tutanota
├─ 不使用真实姓名/地址/电话
├─ 不同域名使用不同注册信息
└─ 支付使用 Monero > Bitcoin > 预付卡
```

---

## 4. 工具速查

| 工具 | 用途 | 红队/蓝队 |
|------|------|----------|
| VirusTotal | 文件/IP/域名多引擎扫描 | 双方 |
| AlienVault OTX | 开源威胁情报平台 | 蓝队 |
| MISP | 威胁情报共享平台 | 蓝队 |
| PassiveTotal/RiskIQ | 被动 DNS + WHOIS 分析 | 蓝队 |
| Shodan | 互联网设备搜索 | 双方 |
| Censys | TLS 证书和主机搜索 | 双方 |
| crt.sh | 证书透明度搜索 | 双方 |
| SecurityTrails | DNS 历史和域名情报 | 蓝队 |
| Maltego | 可视化关联分析 | 蓝队 |
| ThreatConnect | 威胁情报平台 | 蓝队 |
| YARA | 文件模式匹配 | 蓝队 |
| expireddomains.net | 过期域名搜索 | 红队 |
| GreyNoise | IP 噪声/扫描情报 | 双方 |

---

## 关联参考

- **C2 基础设施 OPSEC 清单** → `c2-infra-opsec.md`
