# P0–P4 成本分级打法（源站溯源执行流水线）

先跑 `scripts/cdn_quick_trace.py <domain>`；本文件是自动化无果后的手动穷尽流水线。
统一原则：**P0 全并行 → 有候选即验证 → 无候选升级**。P0–P2 覆盖 80%+ 场景；CDN 特定绕过与 P3/P4 是兜底。

## 核心原则（7 条）

1. **最小成本优先**：严格按优先级执行，P0 命中即进验证，不命中升一级
2. **早停**：P0/P1 已有 2+ 独立来源交叉确认同一 IP → 直接验证收工
3. **晚停兜底**：到 P2 仍无候选 → 全量跑 P3
4. **死磕兜底**：全失败 → P4 穷尽非常规手段
5. **证据分级**：每个候选标注 S/A/B/C/X 强度，禁止把 C 级当结论
6. **误判排除**：每个候选必须过验证协议（§验证），排除共享来源误报
7. **并行执行**：同优先级步骤并行发起，缩短爆破时间

| 优先级 | 类别 | 成本 | 预期命中率 | 内容 |
|--------|------|------|-----------|------|
| P0 | 快速低成本 | 极低 | 高 | SPF/MX/TXT、IPv6、历史 DNS 回溯、CNAME/响应头指纹 |
| P1 | 中级 | 中 | 中高 | SSL 证书指纹、CT 日志、子域枚举、CDN 节点行为基线 |
| P2 | 较高级 | 较高 | 中 | 空间搜索引擎、favicon hash、多端口、IP 反查、页面特征 |
| P3 | 高级/手动 | 高 | 低 | 邮件触发、源码审计、Archive、AXFR/NSEC、GA/AdSense、横幅探测 |
| P4 | 深度穷尽 | 极高 | 不定 | Archive 考古、泄露路径、被动情报、云元数据、WAF 穿透、时间窗、社工、拓扑、地域差异 |

---

## P0：快速命中（全并行）

### P0-1 SPF / MX / TXT 泄露

```bash
dig TXT <root> +short          # v=spf1 ip4:x.x.x.x —— 直接暴露发信源 IP
dig MX <root> +short           # 邮件服务器常与源站在同机房
dig TXT _dmarc.<root> +short
dig TXT _spf.<root> +short     # 子域 SPF 常泄内部段
```
解析：SPF 里的 ip4/ip6/include 段与主站 A 记录比对；MX 主机 IP 反查历史。

### P0-2 IPv6 探测

```bash
dig AAAA <root> +short
dig AAAA www.<root> +short
```
很多 CDN 只代理 IPv4，AAAA 如直出即源站（海外站高发）。

### P0-3 历史 DNS 回溯（单点最高命中率）

免费网站（CN 优选）：

- `https://ipchaxun.com/<domain>/` — 历史 A 记录全量（含最早记录）
- `https://site.ip138.com/<domain>/` — 域名历史 IP + 子域
- 备选：ViewDNS `viewdns.info/iphistory/`、SecurityTrails、VirusTotal

分析方法：
- **最早 A 记录** = 接入 CDN 之前 = 源站候选
- **IP 数拐点**：1–2 个 → 突然 10+ 个 = 接入 CDN 时间点；拐点前的 IP 都是候选
- **长期稳定 1–2 个** = 疑似未换过源站

### P0-4 基础 DNS + CDN 识别

```bash
dig <root> +short ; dig www.<root> +short ; dig <root> CNAME +short
curl -sI https://<root> | head -30
```

**CNAME 指纹表（关键 30 条）**

| CNAME 特征 | 厂商 |
|---|---|
| eo.dnse5.com / *.edgeone.* | 腾讯 EdgeOne |
| cdn.dnsv1.com / tlivecdn | 腾讯云 CDN |
| kunlun*.com / *.kunluncdn.* / aligl* / *.w.cdngslb.com | 阿里云 CDN |
| tx.kcdnvip / *.kcdnvip.* | 金山云 |
| wscloudcdn.com / txwsglb0.com | 网宿 |
| lxdns.com / chinacache | 蓝汛 |
| bsclink / *.bsgslb.* | 白山云 |
| jiashule.com / *.jiashule.* | 加速乐 |
| yundun* / yundunddos | 云盾 |
| nscloudwaf / *.nscloud.* | 创宇盾 |
| 365cyd / *.365cyd.* | 安全宝/知道创宇 |
| cloudfront.net | AWS CloudFront |
| cloudflare.net / cloudflare.com | Cloudflare |
| akamai*.net / akamaiedge / edgesuite / edgekey | Akamai |
| azureedge.net / azurefd.net | Azure |
| fastly.net / fastlylb.net | Fastly |
| impervadns.* / incapsula.* | Imperva |
| sucuri.net | Sucuri |
| huaweicloud / hwcdn / *.hwclouds | 华为云 |
| cdn77.org | CDN77 |
| stackpathdns.com | StackPath |
| keycdn.com / kxcdn.com | KeyCDN |
| bunnycdn.com | BunnyCDN |
| gcorelabs.com / gcdn.co | Gcore |
| googleusercontent / googlehosted | Google Cloud CDN |

**响应头指纹表**

| 头特征 | 厂商 |
|---|---|
| cf-ray / server: cloudflare | Cloudflare |
| server: TencentEdgeOne / X-EO-* | 腾讯 EdgeOne |
| via: *.kunlun / server: Tengine + eagleeye | 阿里云 |
| via: cache*.wscloudcdn / X-Cache: 网宿 | 网宿 |
| X-HW-Via | 华为云 |
| x-amz-cf-id / x-amz-cf-pop / via: *.cloudfront.net | CloudFront |
| X-Azure-Ref / X-Azure-ClientIP | Azure |
| X-Served-By / X-Cache / via: varnish | Fastly |
| server: AkamaiGHost / X-Akamai-* | Akamai |
| X-Iinfo / X-CDN: Incapsula | Imperva |
| X-Sucuri-Cache / X-Sucuri-ID | Sucuri |
| server: BCE / X-Bce-* | 百度云 |
| server: CDN77 / X-Edge-Location | CDN77 / KeyCDN |
| via: google / server: Google Frontend | Google Cloud |

**泄露头清单**（出现即直接回源证据）：`X-Real-IP` `X-Forwarded-For` `X-Originating-IP` `X-Remote-IP` `X-Remote-Addr` `X-Client-IP` `X-Host` `X-Original-URL`；`Location`/`Link` 回显内网地址；`Server` 带源站版本号。

---

## P1：证书与行为分析

### P1-1 证书指纹提取（核心：serial）

```bash
echo | openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null | \
  openssl x509 -noout -serial -fingerprint -sha256 -dates -subject -ext subjectAltName
```
记录 **serial**（后续决定性比对用）+ SHA256 + SAN。海外站常暴露 Let's Encrypt 真实证书链差异。

### P1-2 CT 日志

```bash
curl -s "https://crt.sh/?q=%.<domain>&output=json" | jq -r '.[].name_value' | sort -u
# 另: censys.io CT 搜索; 证书里出现的 非 CDN 主机名 = 源站候选
```

### P1-3 子域名枚举（高优先前缀）

```bash
for s in www mail ftp api admin test dev staging beta app m web portal direct origin backend server host node ip ipv4 ipv6 ns1 ns2 dns dns1 dns2 mx smtp pop imap ssh vpn git gitlab jenkins ci cdn static assets img media upload download cms blog shop store ftp2 db mysql redis mongo ldap sso oa erp crm mail2; do
  dig +short $s.<domain> A; done
```
**通配符检测**：先 dig 随机子域，若泛解析 → 浏览法失效，改历史 DNS/CT 源。

### P1-4 CDN 节点行为基线

```bash
for i in 1 2 3; do curl -sI https://<domain> | grep -iE 'server|via|x-cache|cf-ray'; sleep 1; done
```
节点行为差异：EdgeOne 拦截 **567**=WAF 拦截 / **418**=未匹配域名；CF 无 cf-ray 直连=候选源站。拿这个基线对比候选 IP 的响应。

---

## P2：深度搜索

### P2-1 空间搜索引擎（有 key 优先）

```bash
# FOFA: domain="x" / cert="x" / cert=".x" / header 排除 CDN
curl "https://fofa.info/api/v1/search/all?email=<EMAIL>&key=<KEY>&qbase64=$(echo -n 'cert="target.com"' | base64)"
# Shodan: ssl.cert.subject.CN:target.com
# Censys v2: services.tls.certificates.leaf_data.subject.common_name: target.com
# ZoomEye: ssl:"target.com"
# Quake(360): cert: target.com
# Hunter(奇安信): cert="target.com"
# SecurityTrails: /v1/domain/target.com + /v1/history/target.com/dns/a
# VirusTotal: /api/v3/domains/target.com/resolutions
```
**无 key 替代**：各官网网页版 / viewdns / hackertarget / dnsdumpster。

### P2-2 Favicon hash 关联

```python
import base64, mmh3, requests
ico = requests.get('https://target.com/favicon.ico', timeout=10).content
print('mmh3:', mmh3.hash(base64.encodebytes(ico)))
```
拿到 hash 后 FOFA `icon_hash="..."` 全互联网找同图标服务器（含源站、兄弟站、测试机）。

### P2-3 多端口扫描（24 常用）

`80 81 443 444 8080 8081 8088 8443 8880 8888 9000 9090 9443 3000 5000 8000 8001 9200 6379 3306 21 22 2222 3389`

### P2-4 IP 反查

- `https://ipchaxun.com/<ip>/` — 同 IP 历史绑定域名
- `https://site.ip138.com/<ip>/` — 同 IP 域名列表
- 命中带品牌词的兄弟域名 = 同源站集群线索

### P2-5 页面特征提取

```bash
curl -sk https://target.com/ | grep -oiE 'generator[^>]*|powered by[^<]*' | head
curl -sk https://target.com/robots.txt ; curl -sk https://target.com/sitemap.xml | head -20
```
独特字符串/站点 ID/统计代码 = 跨域关联锚点（接 GA/AdSense 法）。

---

## P3：高级 / 手动

- **P3-1 邮件触发法**：订阅 newsletter / 注册 / 找回密码 → 收信看 `Received:` 链（最底部条目=发信服务器）与 Message-ID 域名；自建邮件服务器常与源站同机房。
- **P3-2 源码审计**：`.git/HEAD` `.git/config` `.env` `config.php.bak` `www.zip` `backup.zip` `docker-compose.yml` `phpinfo.php` `.well-known/`；JS 注释/`sourceMappingURL`/`.map` 文件。
- **P3-3 Web Archive**：`web.archive.org/cdx` 抓全量快照，找旧 IP/预 CDN 子域（→P4-1 展开）。
- **P3-4 AXFR**：`dig axfr @<ns> <domain>` 遍历所有 NS。
- **P3-5 DNSSEC NSEC walking**：`dig +dnssec` 拿到 NSEC 链枚举子域；`nsec3walker` 思路。
- **P3-6 同组织关联**：ICP 备案主体反查其他域名 / whois registrant / 同 GA-ID / 同 IP 段。
- **P3-7 GA / AdSense ID**：`grep -oE 'UA-\d+-\d+|G-[A-Z0-9]{6,}|ca-pub-\d+'` 全站搜；把 ID 丢公共 www 源站或搜索平台反查（同 ID = 同运营）。
- **P3-8 SSH / FTP banner**：22 / 21 / 2222 端口 banner 比对，识别源站主机指纹。
- **P3-9 WebSocket 探测**：`/ws` `/socket.io` 握手头常泄露内网地址。
- **P3-10 CORS / CSP 分析**：Origin 反射探测 ACAO；CSP report 端点常指源站。
- **P3-11 /24 邻居**：FOFA `ip="x.x.x.0/24"` 找同段服务器（排除 CDN 段）。

---

## CDN 特定绕过（先 P0-4 识别厂商，再对号）

### Cloudflare

- **非代理端口**：HTTP 仅 80/8080/8880/2052/2082/2086/2095；HTTPS 仅 443/2053/2083/2087/2096/8443。其余端口（8888/9090/8081/21/22/3306 等）**不过 CF**，直连源站
- **CrimeFlare**：`crimeflare.org` CF 源站数据库
- **direct 子域**：`direct.` `direct-connect.` `ftp.` `backup.` `mail.`
- 非 HTTP 协议直连 / SOA 老 DNS / CF Partner 泄露

### 腾讯 EdgeOne

- 响应码判定：**567**=WAF 拦截 / **418**=域名未匹配（源站也可能返 418，需换信号）
- CVM 网段速查（腾讯云 ip ranges JSON）过滤候选
- EdgeOne 证书为自动同步 → 候选 IP 的证书**序列号比对法仍有效**

### 阿里云 CDN / DCDN

- **回源 HOST ≠ 加速域名** 时源站直接响应 → `curl -H "Host: 内部名" http://<candidate>/` 绕过
- ECS 网段速查（aliyun ip ranges）
- 无固定 IP 场景：OSS / 函数计算 FC（找 bucket 域名而非 IP）

### AWS CloudFront

- 源站=S3/ELB/EC2 混用；`ip-ranges.json` 过滤
- 旧证书/ACM 验证记录反查；S3 bucket 直连

### Azure

- `*.cloudapp.azure.com` 起源；Front Door health probe；非标端口常全开

### Fastly

- anycast；`X-Served-By` 泄露 POP；Shield 配置；直连行为差异

### Akamai

- **SureRoute test object**：`/akamai/sureroute-test-object.html`（含 'Origin' 行为揭示）
- **Ghost 绕过**：请求加 `Pragma: akamai-x-get-true-cache-key, akamai-x-cache-on, akamai-x-get-extracted-values` 读内部值
- staging 网络（akamaihd staging 主机）；archive.org 老记录

### Imperva / Sucuri

- 仅代理 80/443；**Imperva 回源不验 Host**（直接 IP + 任意 Host 拿源站响应）；`X-Iinfo` / `X-Sucuri-Cache` 识别

### 华为云 / 网宿 / 百度云

- 华为：`X-HW-Via`；ECS 网段
- 网宿：历史配置泄露 + 非标端口
- 百度云：BCE 头；BCH/BOS 直连；历史 DNS 泄露

### 未知厂商兜底（4+5 步）

识别 4 步：CNAME 链全展开 → 响应头全面指纹 → ASN/ipinfo 归属 → 在线检测工具交叉。
绕过 5 步：①24 非标端口逐个 `curl -H "Host: <domain>"` ②直连行为差异对比 ③协议层（HTTP/HTTPS/FTP/WS）各自试 ④EDNS Client Subnet 换解析视角 ⑤历史 DNS 老配置。

---

## P4：深度挖掘（穷尽兜底）

- **P4-1 Archive 时间线考古**：`web.archive.org/cdx/search/cdx?url=*.target.com&output=json&limit=...` 找旧 IP、旧域名、预 CDN 子域；对每个快照扫表单/接口老地址。
- **P4-2 泄露路径全表（40+）**：`.env .git/HEAD .git/config .svn/entries backup.zip backup.tar.gz www.zip wwwroot.zip web.zip website.zip db.sql database.sql dump.sql backup.sql config.php.bak config.php~ config.old .htaccess~ .DS_Store phpinfo.php info.php test.php debug.log access.log error.log composer.json composer.lock package.json Dockerfile docker-compose.yml .dockerignore .well-known/security.txt sitemap.xml robots.txt crossdomain.xml server-status server-info jmx-console admin/` — 循环探测，出现任何回显即分析。
- **P4-3 被动情报 8 源**：DNSDumpster、ThreatCrowd、AlienVault OTX、RiskIQ、BGP.he.net、Netcraft、BuiltWith、URLScan.io。
- **P4-4 云厂商内网域名 + IP 段**：枚举 `*.myqcloud.com *.aliyuncs.com *.amazonaws.com.cn`；下载各云 ip ranges（AWS ip-ranges.json / Azure ServiceTags / GCP cloud.json / 腾讯阿里官方段）做归属判定。
- **P4-5 WAF 穿透 5 法**：HTTP 方法扫描（GET/POST/PUT/OPTIONS/HEAD 找不拦的方法）；路径混淆（`//admin`、`/%2f`、分段）；Host 头注入（`X-Forwarded-Host`、多重 Host）；XFF 欺骗回显探测；大 body / 慢速发送打绕过。
- **P4-6 时间维度 3 法**：ACME 续期窗口（按证书到期时间倒推，HTTP-01 验证前源站对挑战路径开放）；配置变更监控（正文/头 hash 定时 diff）；新子域监控（crt.sh 增量）+ 新 A 记录监控。
- **P4-7 社工辅助 5 类**：GitHub commit/搜索泄露；pastebin；search engine 缓存；行业论坛；漏洞披露平台（HackerOne/Bugcrowd 报告里蹭老信息）。
- **P4-8 网络拓扑推断**：traceroute/MTR、TTL 基线、ICMP 探测、BGP 路径 → 压最后一跳。
- **P4-9 地域差异**：`whatsmydns.net` 多地解析、境外 DNS（8.8.8.8/1.1.1.1）差异、IPv6 覆盖、`check-host.net` 多节点 curl。

---

## 验证协议（每个候选必须过）

### V-1 证书序列号精确比对（决定性）

```bash
# CDN 面
S1=$(echo | openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null | openssl x509 -noout -serial)
# 候选 IP 面
S2=$(echo | openssl s_client -connect <ip>:443 -servername <domain> 2>/dev/null | openssl x509 -noout -serial)
[ "$S1" = "$S2" ] && echo MATCH
```

| 观察 | 判定 |
|---|---|
| 序列号完全一致 + 候选默认证书不同 | ✅ 确定性命中 |
| 序列号一致 + 同为默认证书（如 CDN 统一下发） | ⚠️ 需更多信号（头/体/行为） |
| 序列号不同 | ❌ 非源站（或换过证书的旧节点） |

### V-2 HTTP 行为对比

CDN 面 vs 候选面：`Server` 头差异、正文 sha256、unique 字符串、404 页面样式、robots.txt —— 吻合 ≥2 项记 A 级。

### V-3 IP 归属反查

ipinfo/ASN 判断是否 CDN 厂商段；历史绑定域名列表是否有同组织域名。

### V-4 多端口/服务确认

22/3306/6379 banner、21 FTP、其他业务端口 —— 源站常开，CDN 节点全关。

---

## 证据分级与置信度

| 级别 | 依据 |
|---|---|
| S | 证书序列号精确匹配 + 行为吻合 + 默认证书不同 |
| A | 2+ 独立方法交叉确认 |
| B | 单方法命中 + 行为吻合 |
| C | 仅头部/历史单点 |
| X | 出现矛盾证据 |

置信度：S=99%；A=85–95%；B=60–80%；C=<50%（不可当结论）。

**报告模板**：目标 → 识别 CDN → 候选表（IP/来源/证据级）→ 验证记录（serial/行为）→ 结论置信度 → 未解决项与去向（WAF/纯 CDN 无暴露/仅内网）→ 后续建议。

未能确定时的收尾：列明已尝试方法 + 各类证据 + 排除原因，给下一步方向，禁止硬凑结论。

---

## 执行控制（7 条）

1. **Token 节省**：先跑纯 DNS 步骤再动 API/网页抓取
2. **并行**：同优先级全并行
3. **跨平台**：Win 用 curl.exe/PowerShell，Linux 用 bash 原生命令
4. **容错**：单点失败不中断，记录后继续
5. **频率控制**：对目标 API/服务加 sleep/随机化，防封
6. **Key 安全**：API key 不进报告与日志
7. **合规**：仅授权目标执行

---

## 与既有能力的关系

- 自动化优先：`scripts/cdn_quick_trace.py`（本套技能）+ `scripts/cdn_ranges.py`
- 方法大典：`full-handbook-v5.1.md`（50 方法深度版）
- 快速排名：`method-matrix.md`；分支决策：`decision-tree.md`
- 本文件 = 成本分级流水线（P0→P4）与厂商绕过矩阵，补齐「什么时候用哪招」的执行顺序层。
