---
name: information-gathering
description: 信息收集深度渗透测试专业技能（v3.0 高级版）：被动侦察全维度（证书透明度CT新来源/DNS历史/泄露数据库/暗网社工数据）、主动侦察与隐蔽性（代理池/指纹伪装/低频扫描）、子域名接管检测与利用、云资产发现（对象存储/云函数/未绑定域名）、小程序与App移动端资产、关联信息图谱（员工/组织架构/供应链）、AI大模型辅助OSINT自动化、信息收集到攻击面优先级评估的决策方法论
version: 3.0.0
---

# 信息收集深度测试技能（高级版）

## 概述

信息收集是攻击链（Kill Chain）的第一步，其质量直接决定后续漏洞发现、利用与横向移动的成败。在实战攻防（红队）与渗透测试中，信息收集的定位已从"找到几个漏洞入口"升级为**攻击面测绘与高价值目标研判**：先把目标"看全"（全资产、全暴露面、全关联），再"看准"（哪些资产最脆弱、最值钱、最容易打穿）。

本技能（v3.0）在 v2.0 全量核心内容（子域名/端口/指纹/WAF/CDN/证书/邮箱/GitHub/备案/敏感信息）基础上，按资深攻防专家实战视角新增：被动侦察全维度、主动侦察与隐蔽性、子域名接管、云资产发现、移动端资产、关联信息图谱、暗网与泄露数据库情报、AI 大模型辅助 OSINT、攻击面优先级评估决策方法论。

### 核心概念
- **攻击面（Attack Surface）**：目标组织暴露在互联网上的一切可被触达的资产总和，包括域名、IP、端口、Web 服务、API、云资源、移动端、第三方供应链
- **影子资产（Shadow IT）**：未纳入资产清单的测试环境、废弃系统、个人搭建服务——红队最高价值目标
- **被动 vs 主动 vs 半被动**：被动=不触达目标（第三方数据源）；半被动=间接触达（如向公共 DNS/CT 日志发起查询）；主动=直接向目标发送流量
- **资产关联（Pivoting）**：通过证书、备案、邮箱、指纹等"连接点"从已知资产横向扩散发现未知资产
- **隐蔽性（OPSEC）**：主动侦察阶段所有流量必须可控、可解释、低风险，避免打草惊蛇
- **信息噪音**：自动工具产出的海量结果需去重、验证、按风险排序，否则无法指导后续攻击

## 一、信息收集方法论

### 1.1 攻防视角的信息收集哲学
```
1. 全量测绘 → 2. 关联扩散 → 3. 去重验证 → 4. 风险排序 → 5. 打点决策
```
- **以攻为导**：每个收集动作都必须回答"这个信息能转化为哪种攻击？"（凭据→撞库、新子域→未加固环境、影子资产→无防护入口）
- **广度优先**：先穷尽一切被动手段，再逐步增加主动强度；被动收集 0 成本、0 暴露、0 法律风险，永远先做
- **关联为王**：单点信息价值有限，把域名、IP、证书、邮箱、员工、供应链编织成图谱才能发现隐藏通路

### 1.2 信息收集分层模型
```
Layer 1: 企业/组织层（工商信息、备案、股权、子公司、供应链）
Layer 2: 人员层（员工邮箱、账号、社交、泄露凭证）
Layer 3: 域名/DNS 层（主域名、子域名、历史DNS、CT日志）
Layer 4: 网络层（ASN/IP段、端口、服务）
Layer 5: Web 层（指纹、目录、JS、API、敏感文件）
Layer 6: 云资产层（对象存储、云函数、CDN、容器）
Layer 7: 移动端层（小程序、App）
Layer 8: 历史/第三方层（Wayback、泄露库、暗网、空间引擎）
Layer 9: 情报整合层（AI聚合、攻击面评估、打点决策）
```

### 1.3 三类收集手段对比
| 手段 | 是否触达目标 | 隐蔽性 | 典型动作 |
|------|------------|--------|---------|
| 被动 OSINT | 否 | 极高 | Whois/CT/GitHub/泄露库/空间引擎/暗网 |
| 半被动 | 间接 | 高 | 公共DNS查询、证书查询、第三方API |
| 主动 | 是 | 低（需伪装） | 端口扫描、目录fuzz、漏洞探测 |

### 1.4 实战原则
- **被动穷尽原则**：主动扫描前，必须把被动手段全部跑完（常见资产 80% 以上被动即可发现）
- **单点验证原则**：任何资产必须先探活（httpx）再深挖，避免在死资产上浪费弹药
- **优先级原则**：时间有限时，优先处理"新出现"（CT刚签发）、"被遗忘"（影子资产）、"有凭据"（泄露库命中）三类资产

## 二、被动侦察全维度（OSINT·企业/人员/泄露）

### 2.1 Whois 与注册信息
```bash
# 基础查询
whois target.com
whois target.com | grep -E "Registrant|Email|Phone|Name Server"

# RDAP（新一代标准化接口，支持结构化输出）
curl -s https://rdap.org/domain/target.com | jq .
curl -s https://rdap.arin.net/registry/entity/ORGNAME | jq .

# 在线数据源
# who.is / whois.domaintools.com（历史Whois） / viewdns.info / rdap.org
# 反查：同注册人邮箱/名称反查全部域名（Domaintools Reverse WHOIS、whoisxmlapi）
```

**关键动作（红队必做）：**
- **注册邮箱/电话反查**：`@"域名注册邮箱"` 在空间引擎/WhoisXML 中反查同一主体其他域名
- **历史 Whois**：注册人变更记录可暴露目标真实身份、旧联系邮箱（可入社工库）
- **隐私保护识别**：whoisguard/domainprivacy 等隐私服务 + 历史记录可还原真实注册人

### 2.2 企业工商信息与 ICP 备案（国内攻防核心）
```bash
# 备案查询（ICP/IP地址/域名信息备案管理系统）
https://beian.miit.gov.cn
# 备案号反查：同一备案主体下全部域名 → 扩展资产
site:beian.miit.gov.cn "公司名"
# 工具：无影 多引擎备案反查；ICP备案查询API（如 fofa/hunter 集成）

# 企业工商信息
# 天眼查 / 企查查 / 爱企查 / 国家企业信用信息公示系统(gsxt.gov.cn)
# 重点维度：
#  - 对外投资/控股子公司（>50% 可能内网互通）
#  - 分支机构、关联企业（品牌/法定代表人关联）
#  - 软件著作权（登记名可反查系统名→搜"系统名"找入口）
#  - 商标、专利（暴露产品线、新技术方向）
#  - 年报/联系方式（泄露邮箱格式、电话段）
```

**实战要点：**
- 攻防演练中"备案号→主体→所有备案域名"是扩展攻击面的第一梯队手段
- 子公司/控股公司资产经常与母公司内网互通或共用 VPN/SSO，是横向突破口
- 软件著作权名称 = 系统名称，用 `site:目标.com "系统名"` 或空间引擎直接定位该系统

### 2.3 搜索引擎 Dorks
```
# 通用语法（Google/Bing/百度/360 语法略有差异）
site:target.com inurl:admin|login|dashboard
site:target.com filetype:sql|bak|conf|env|log|zip|rar
site:target.com inurl:.git|.svn|.DS_Store|phpinfo.php
site:target.com "Index of /"
site:target.com "password"|"api_key"|"aws_secret"|"accessKeyId"
site:s3.amazonaws.com "target.com"
site:pastebin.com "target.com"
site:*.target.com -www

# 人员/组织
"@target.com" site:linkedin.com            # 员工邮箱格式
"@target.com" site:github.com              # 员工GitHub
"公司名" "工资表|通讯录|花名册" filetype:xls|doc|pdf   # 公示文档泄露

# 多引擎联动（国内目标必须覆盖百度/搜狗/360）
# 百度：site:target.com 后台 | 管理 | 测试
# 搜狗微信搜索：搜索目标公众号/小程序泄露信息
```

### 2.4 代码托管平台泄露（GitHub/GitLab/Gitee）
```bash
# GitHub 搜索（2023+ 需登录；Gitee 无需）
"target.com" password|secret|api_key|token
"公司名" 密码|密钥|内网|数据库
filename:.env target
filename:wp-config.php|config.php target
filename:.git-credentials target
path:.ssh/id_rsa target
filename:config.json password

# Gitee（国内开发者常忽略安全）
# gitee.com 搜索 "公司名" + 敏感关键字
# GitLab 自建实例：常见 8080/9090 端口 + /explore 公开项目

# 工具链
- gitdorks_go / GitDorker / GitRob / GitGot
- trufflehog / gitleaks（深扫历史提交中的密钥）
- GitHack / dvcs-ripper（提取泄露的 .git/.svn 完整源码）
- shhgit（实时监控全球公开代码提交）
```

### 2.5 网盘/文库/公开文档泄露（国内特色）
```bash
# 网盘搜索（员工常传敏感资料）
# 凌风云 / 猪猪盘 / 云盘狗 / 小马盘 / 超能搜
# 关键词：公司名+拓扑图/台账/密码/账号/花名册/巡检表

# 文库泄露
# 百度文库 / 搜文库 / 360文库
# 关键词：公司名+运维手册/实施方案/投标文件（含拓扑、IP、账号）

# 其他公开文档
# 招投标网站（中国政府采购网等）：实施方案常含网络拓扑、系统清单、IP规划
# 官网"供应商/合作伙伴"栏目 → 供应链线索
```

## 三、证书透明度（CT）与 DNS 历史

### 3.1 CT 日志原理与新数据源
证书透明度（RFC 6962/9162）要求所有公开可信 CA 将签发的每张证书写入公开可验证日志。**证书的 SAN 字段列出全部覆盖域名**，等于目标自己"投喂"子域名清单，且零触达。

**2025-2026 新趋势：**
- 自 2013 年以来已累计记录 **25 亿+ 张证书**，Let's Encrypt 每天签发约 1000 万张
- Chrome（2018）、Apple（系统级）、**Firefox 135（2025-02）** 三大浏览器全部强制 CT
- 蜜罐研究：证书签发后平均 **73 秒** 内即被扫描流量触达——CT 是攻击者发现新资产的第一时效来源
- 证书内嵌邮箱（CA 邮箱）可用于反查同一申请者

**核心查询源：**
```bash
# crt.sh（Sectigo 维护，PostgreSQL 全文索引，最常用）
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Censys 证书搜索（支持更精确字段过滤）
# https://search.censys.io/certificates?q=names%3A+target.com

# Entrust CT 搜索 / Google Transparency Report / certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u
```

### 3.2 CT 聚合与监控工具
```bash
# CTFR（纯 CT 收集，秒级）
python3 ctfr.py -d target.com -o subs.txt

# Sublert（CT 持续监控：新签发域名 → Slack 推送，抢占新资产第一落点）
python3 sublert.py --domains target.com --slack_api_token xxx
# 实战价值：目标刚部署的 staging/内测环境，未加固且未暴露，是高危打点入口

# 与主动枚举互补：CT 发现的是"真实使用过"的域名，字典爆破发现的是"可能使用"的域名
```

### 3.3 DNS 历史记录
```bash
# 历史解析记录（CDN 上线前的真实 IP、旧服务器）
# SecurityTrails / DNSDB（Farsight）/ ViewDNS.info / 微步在线(威胁情报社区)
# 场景：某域名解析到 Cloudflare 之前直连源站 IP → 该 IP 可绕过 CDN

# 微步在线 API（国内数据全）
curl -s "https://api.threatbook.cn/v3/domain/query?apikey=KEY&domain=target.com" | jq .

# passive DNS（被动 DNS 数据，覆盖历史解析对）
# RiskIQ PassiveTotal / 微步 PDNS / DNSGrep
curl -s "https://dns.bufferover.run/dns?q=.target.com" | jq -r '.FDNS_A[]' | head
```

### 3.4 DNS 记录深度解析
```bash
# 全记录类型（每个都可能是攻击入口）
dig target.com A AAAA MX NS TXT CNAME SOA SRV CAA
dig _autodiscover._tcp.target.com SRV     # 邮件自动发现
dig _ldap._tcp.target.com SRV             # 域控线索
dig _sip._tcp.target.com SRV              # VoIP
dig _vlmcs._tcp.target.com SRV            # KMS激活服务器（可刷授权）

# TXT 记录高风险点
# SPF/DKIM 泄露邮件基础设施；verification token（Google/Apple/Bing）可用于冒充验证
# "v=spf1 include:spf.xxx.com" 反查第三方邮件服务商

# CNAME 指向云服务 = 子域名接管候选
dig cname staging.target.com
# 返回 .s3.amazonaws.com / .blob.core.windows.net / .cloudfront.net / .herokuapp.com 等 → 见第五章

# AXFR 区域传送（老而有效）
dig axfr target.com @ns1.target.com
dnsrecon -d target.com -t axfr
```

## 四、子域名枚举（被动+主动全维度）

### 4.1 被动数据源与聚合
```bash
# 主流被动源
# VirusTotal / SecurityTrails / Censys / Shodan / ThreatCrowd / AlienVault OTX
# 国内：FOFA / Hunter(奇安信) / Quake(360) / 微步 / ZoomEye
# ProjectDiscovery Chaos（聚合数千赏金项目数据，含独有域名）

# 工具（多源聚合）
subfinder -d target.com -silent | anew subs.txt          # 40+ 被动源
amass enum -passive -d target.com -o amass.txt           # 最全面（含图谱输出）
assetfinder target.com
findomain -t target.com
# 新一代：subdominator（73 个被动源，Python3.13+，异步高性能）
subdominator -d target.com -o subs.txt

# 空间引擎语法（国内目标必备）
# FOFA: domain="target.com" || cert="target.com" || icp="目标备案号"
# Hunter: domain="target.com" && web.title="目标"
# Quake: domain: "target.com"
# 空间引擎还能直接给出：IP、端口、指纹、国家、ASN → 一步到位
```

### 4.2 字典爆破（主动）
```bash
# 高质量词表
# seclists/Discovery/DNS/（best-dns-wordlist.txt、deepmagic 等）
# bitquark-subdomains-top100000.txt
# 六位数/行业定制：按目标行业生成（dev/staging/test/uat/oa/vpn/mail/sso）

dnsx 解析验证：
puredns bruteforce subdomains-top100000.txt target.com -r resolvers.txt

gobuster dns -d target.com -w subdomains.txt
dnsrecon -d target.com -D subdomains.txt -t brt
```

### 4.3 变体生成（Permutation）
基于已知子域自动衍生新词（红队效率倍增器）：
```bash
# alterx（ProjectDiscovery）：根据已有子域生成排列变体
cat subs.txt | alterx -silent | dnsx -silent | anew final-subs.txt

# 语义变体：api→api-dev→api-test→api-uat→api-staging
# 品牌变体：公司英文名/拼音/缩写 + dev/test/内网 等后缀
```

### 4.4 解析验证与资产归一
```bash
# 全部候选 → 解析 → 探活 → 去重
cat subs.txt | dnsx -silent -a -resp -cdn | tee resolved.txt
cat resolved.txt | awk '{print $1}' | httpx -silent -title -tech-detect -status-code -cdn -json | tee alive.json

# 通配符过滤：*.target.com 解析到同一 IP 时需过滤泛解析噪音
dnsx -w wildcard-check.txt 对比解析结果

# 注意：先验证再扫描，避免对 CNAME 指向第三方（GitHub Pages/云存储）的域名做无意义扫描
```

## 五、子域名接管检测与利用

### 5.1 接管原理（Dangling DNS/CNAME 劫持）
子域名解析（CNAME）指向已注销的第三方资源（S3 桶、Azure 应用、GitHub Pages、Heroku、Zendesk 等），攻击者注册该资源即可完全控制子域名内容，继承父域名信誉，用于钓鱼、投放恶意内容、窃取 Cookie。

**2025 典型案例：** 印尼 `.ac.id`/`.go.id` 等高校与政府域名被接管后投放在线赌博广告——信誉借壳攻击已成为主流滥用方式。

### 5.2 主流服务接管指纹（Fingerprint）
| 云服务 | CNAME/解析特征 | 错误指纹 |
|--------|---------------|---------|
| AWS S3 | `*.s3.amazonaws.com` | `NoSuchBucket` |
| Azure 应用 | `*.azurewebsites.net` | 404 页面 `Azure Web Apps` |
| Azure Blob | `*.blob.core.windows.net` | `ContainerNotFound` |
| GitHub Pages | `*.github.io` | 404 `There isn't a GitHub Pages site here` |
| CloudFront | `*.cloudfront.net` | 403 `Bad request` |
| Heroku | `*.herokuapp.com` | `no-such-app` |
| Fastly | `*.fastly.net` | 502/未知 |
| Shopify | `*.myshopify.com` | 无商店页面 |
| 腾讯云 COS | `*.cos.ap-*.myqcloud.com` | `NoSuchBucket` |
| 阿里云 OSS | `*.oss-cn-*.aliyuncs.com` | `NoSuchBucket` |

### 5.3 检测工具链
```bash
# 自动化指纹匹配（首选 nuclei 模板，签名持续更新）
subfinder -d target.com -silent | nuclei -t ~/nuclei-templates/http/takeovers/ -o takeover.txt

# 专用工具
subjack -w subs.txt -t 100 -ssl -o takeover.txt
subzy run --targets subs.txt
dnsReaper file -f subs.txt -o takeover.txt
# BadDNS（2025 新发布，自动同步 nuclei + dnsReaper 签名库）

# 半自动复核
# 对每个 CNAME 记录发起 HTTP 请求，观察指纹错误响应（见 5.2 表）
```

### 5.4 利用与影响评估
```
1. 注册被废弃资源（S3 桶名/Heroku 应用名/GitHub Pages 仓库）
2. 在接管域上托管钓鱼页/恶意 JS（继承目标信誉）
3. 窃取通过该子域名的 Cookie（父域 Cookie 范围攻击）
4. 影响评估：接管域是否用于邮件（MX 子域→邮件伪造）、是否位于 WAF 白名单
```
**注意：** 接管验证用"无害指纹探测"，实际注册资源须在授权范围与规则允许内，并提前与甲方确认。

## 六、主动侦察与隐蔽性

### 6.1 代理池与出口 IP 轮换
```bash
# 目的：多出口 IP 分散流量特征，避免单一 IP 被封/被溯源
# 方案：商业代理池（按国家/城市选出口） / 住宅代理（更隐蔽） / 自建跳板 VPS
# 工具：proxychains / httpx -proxy / nuclei -proxy / ffuf -x

httpx -l targets.txt -proxy http://proxy:8080
nuclei -l alive.txt -proxy http://proxy:8080 -rl 5

# DNS 层隐蔽：使用公共/第三方 resolver，不直接向目标 NS 发包（dnsx -r 8.8.8.8,1.1.1.1）
```

### 6.2 指纹伪装
```bash
# HTTP 头伪装（模拟真实浏览器）
# 统一 UA 池：Chrome/Edge/Safari 常见版本轮换
httpx -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/126.0"
# 补全常见头：Accept/Accept-Language/Referer 与浏览器一致，避免畸形请求特征

# TLS 指纹（JA3）与 HTTP2 指纹（部分高级 WAF 检测）
# 使用 curl-impersonate / 浏览器自动化（无头 Chrome）规避 TLS 指纹识别

# 扫描工具本身特征（masscan/nmap 的默认 payload 可被 IDS 特征库识别）
# 重要目标改用自研/改造扫描器或降低发包特征
```

### 6.3 低频扫描与速率控制
```bash
# 原则：总量可控、速率低调、时间拉长
nmap -sS -p- -T2 --min-rate 200 target.com        # 低速率全端口
nuclei -l alive.txt -rl 10 -c 5 -pause 30s        # 每秒10请求上限
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 20   # 限速

# 扫描窗口避开业务高峰（白天上班时间流量混杂，夜晚扫描特征明显）
# 先小样本验证再全面铺开；每个目标之间随机暂停，避免机械节奏
```

### 6.4 端口扫描策略
```bash
# 两段式：masscan 快速定位开放端口 → nmap 精准识别
masscan -p1-65535 --rate=10000 target.com -oL ports.txt
ports=$(awk -F' ' '{print $3}' ports.txt | cut -d'/' -f1 | tr '\n' ',')
nmap -sV -sC -p $ports target.com -oN nmap.txt

# 常见高风险端口（直接对应漏洞面）
# 6379 Redis / 9200 ES / 27017 Mongo / 11211 Memcached / 7001 WebLogic
# 2375 Docker / 10250 kubelet / 6443 k8s / 9090 Prometheus / 2181 Zookeeper
# 5601 Kibana / 8161 ActiveMQ / 4848 GlassFish / 10000 Webmin
# UDP 重点：53/161(SNMP)/123(NTP反射)/500(IPsec)/623(IPMI)
nmap -sU -p 53,161,162,500,623 --top-ports 20 target.com

# 内网资产常映射到外网非常规端口 → 全端口扫描是红队标配（很多"少见的端口"=内网系统）
```

### 6.5 服务识别与漏洞预判
```bash
# Nmap 脚本批量（信息面优先）
nmap --script=http-title,http-headers,ssl-enum-ciphers,http-enum -sV target.com
nmap --script=dns-zone-transfer,smb-enum-shares,snmp-info target.com

# 指纹→漏洞预判：识别出版本后立即关联 CVE/EXP
# 服务版本 → nuclei 模板 / searchsploit 匹配 → 打点清单
nuclei -l alive.txt -severity critical,high -t ~/nuclei-templates/ -rl 20

# 注意：漏洞扫描阶段已属高暴露动作，务必在授权+隐蔽性评估后执行
```

## 七、Web 指纹与内容识别

### 7.1 技术栈识别
```bash
# httpx 批量指纹（信息收集标配）
httpx -l subs.txt -status-code -title -tech-detect -server -ip -cname -cdn -web-server -json

# whatweb 单点深扫
whatweb -a 3 https://target.com

# 指纹维度
# Server 头 / X-Powered-By / Cookie 特征 / 静态资源路径 / 报错页面特征
# favicon hash（空间引擎万能钥匙：同一图标=同一产品）
python3 favihash.py -u https://target.com/favicon.ico
# → 拿 hash 去 FOFA: icon_hash="xxx" / Shodan: http.favicon.hash:xxx → 发现同产品全部暴露资产
```

### 7.2 CMS/框架/中间件指纹特征库
| 产品 | 关键特征 |
|------|---------|
| WordPress | `/wp-content/` `/wp-includes/` `wp-login.php` |
| ThinkPHP | `/?s=/`、`X-Powered-By: ThinkPHP`、TP 报错页 |
| Spring Boot | `/actuator`、`/swagger-ui`、`/v3/api-docs`、whitelabel 报错页 |
| Shiro | `rememberMe=deleteMe` Cookie（→ 反序列化链） |
| 通达OA/泛微/致远 | 特定登录页+版本号（OA 0day 高发） |
| Jenkins | `/manage`、`X-Jenkins` 头（未授权脚本控制台） |
| Nacos | `/nacos/` 未授权（配置泄露→凭据） |
| 若依(RuoYi) | `/prod-api/`、`ruoyi` 标识（默认弱口令高发） |
| Fastjson | 畸形 JSON 报错泄露版本（详见 fastjson-exploitation 技能） |

### 7.3 目录与敏感文件扫描
```bash
# 常规扫描（多引擎交叉验证，减少误报）
ffuf -u https://target.com/FUZZ -w wordlist.txt -t 30 -mc 200,301,302,403 -o ffuf.json
gobuster dir -u https://target.com -w wordlist.txt -x php,asp,aspx,jsp,html,json,bak,zip,sql
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js,json,bak,zip

# 备份文件专项（红队高收益：源码=审计金矿）
# www.zip / backup.zip / web.zip / site.zip / 域名.zip / 域名.tar.gz / dump.sql / db.sql
# 工具：Test404备份文件扫描器 / ihoneyBakFileScan

# 版本控制目录（完整源码提取）
# .git/（GitHack 提取） .svn/ .hg/ .DS_Store（泄露文件列表）

# 配置文件
# .env / .env.bak / config.php / config.inc.php / web.config / .htaccess / .user.ini
# application.yml / bootstrap.yml（Spring 配置可能含数据库口令、AK/SK）

# 管理入口
# admin/ manager/ manage/ backend/ system/ oa/ sso/ /phpmyadmin/ /actuator/ /console/
```

### 7.4 JavaScript 分析（API 与密钥挖掘）
```bash
# 收集 JS：当前页面 + 历史归档 + JS 目录枚举
echo "target.com" | waybackurls | grep -E "\.js" | sort -u > js.txt
cat subs.txt | getJS --complete

# 分析：LinkFinder / SecretFinder / JSFinder / Burp JS Miner
python3 LinkFinder.py -i https://target.com/js/app.js -o cli
python3 SecretFinder.py -i https://target.com/js/app.js -o cli

# 从 JS 提取的核心情报
# - 未公开 API 端点（/api/v2/internal/...）
# - AK/SK、JWT 密钥、加密密钥
# - 内部域名/内网 IP（→ 直接访问或 SSRF 目标）
# - 云配置：Firebase/Supabase/Cognito/OSS 桶名
# - 前端路由（React/Vue 路由 → 未公开页面）
# - 注释中的测试账号/开发接口

# 批量自动化：转子（Windows，爬取+提取AK/SK/手机号/邮箱+漏洞分类）
```

### 7.5 Source Map 源码还原
```bash
# 生产环境误发布 .js.map → 可还原几乎完整的前端源码
curl https://target.com/js/app.js.map -o app.js.map
# 工具：source-map-restore / unwebpack-sourcemap / SourceMapReader
# 还原后可审计：加密算法、签名逻辑、硬编码密钥、接口鉴权逻辑
```

### 7.6 403/401 绕过与认证页面
```bash
# 403 绕过（访问控制缺陷，红队常规动作）
# 路径变形：/secret → /secret/ /secret/. /./secret/./ %2f / //secret // /SECRET
# 方法切换：GET→POST→PUT→OPTIONS（部分 WAF/规则只拦 GET）
# 头部伪造：X-Forwarded-For: 127.0.0.1  X-Original-URL: /admin  X-Rewrite-URL: /admin
# Referer: https://target.com/admin（部分访问控制按 Referer 判断）
# 附加扩展：/admin.json /admin%00 /admin/..;/admin（Tomcat/Spring 路径解析差异）

# 401 页面：抓取 WWW-Authenticate 头判断认证类型（Basic/表单/SSO/OAuth）
# 常见默认口令：admin/admin、admin/123456、test/test（结合泄露情报撞库）
```

## 八、WAF/CDN 识别与真实 IP 溯源

### 8.1 WAF 识别
```bash
wafw00f https://target.com

# 手动验证：发送无害探测包观察拦截特征
curl -X POST https://target.com/ -d "id=1' AND '1'='1"
# 观察：拦截页特征 / 响应头变化 / 状态码突变 / 内容差异

# 常见 WAF 特征
# Cloudflare: server: cloudflare + cf-ray 头
# 阿里云WAF / 腾讯云WAF / 安全狗 / D盾 / 云锁 / 长亭雷池(SafeLine) / 创宇盾
# 识别到 WAF → 调整扫描策略（见 6.3）→ 后续利用需 WAF 绕过（参考各漏洞利用技能）
```

### 8.2 CDN 识别
```bash
# CNAME 检查
dig cname www.target.com
# *.cloudfront.net / *.cdn.cloudflare.net / *.kunlun*.com(阿里CDN) / 腾讯云CDN / 网宿

# 多节点对比：同一域名解析结果是否多地不同（是→CDN）
# 工具：17CE 超级Ping / IPIP.net / 站长工具
# 老牌：CloudFail / CloudUnflare（已部分失效，配合历史DNS使用）
```

### 8.3 真实 IP 溯源全手段（红队核心技能）
```
1. 历史 DNS：SecurityTrails/DNSDB/微步，CDN 上线前的 A 记录（最高效）
2. 子域名排查：未接入 CDN 的子域（mail/oa/ftp/vpn/测试域）直连源站
3. 邮件头：发送邮件到目标，查 Received: 字段中的源 IP
4. 证书关联：Censys/crt.sh 按证书指纹反查所有托管该证书的 IP（含源站）
5. 空间引擎：FOFA "cert=目标域" 按证书找 IP；Shodan ssl.cert.subject.cn
6. 错误页/功能点：SSRF、文件包含、网站地图、报错日志泄露内网 IP
7. 特定技术特征：F5 LTM Cookie / Citrix NSC / 部分负载均衡头可解码真实 IP
8. 云存储回源：对象存储的 CNAME 常暴露存储桶区域与真实存储节点
9. 移动端直连：App/小程序常直接请求源站 IP（见第十章）
10. 验证：用候选 IP 直接 HTTP 访问，对比页面内容/证书/Server 头是否与域名一致
```

## 九、云资产发现

### 9.1 对象存储（S3/OSS/COS/Blob/GCS）
```bash
# Bucket 命名规律（红队生成式枚举）
# target-prod / target-dev / target-backup / target-upload / target-images
# target-数据 / target-备份 / 拼音/英文名+环境

# 工具
- S3Scanner（批量检测）
- bucket-stream
- grayhatwarfare.com（公共桶搜索）
- 空间引擎：FOFA "target.com" 关联存储域名

# 权限验证（无签名直接列举）
aws s3 ls s3://target-prod --no-sign-request
aws s3api get-bucket-acl --bucket target-prod --no-sign-request
# 阿里云：ossutil ls oss://bucket --no-sign-request
# 腾讯云：cosbrowser / coscmd 无签名列举
# 错误语义：AccessDenied(存在但拒绝) / NoSuchBucket(不存在) / AllAccessDisabled
```

### 9.2 云函数与 Serverless 资产
```bash
# 云函数 API 网关：/api/v1/xxx、/prod/xxx 形态，常暴露内网调用接口
# 微信云开发/腾讯云开发环境指纹
curl -i "https://xxx.app.tcloudbase.com/_/cloudbaserun"
# 响应头 X-TCB-Source 暴露云环境存在
# 阿里云 FC / AWS Lambda API 网关 / GCP Cloud Run

# 云函数常见问题：未授权调用（无鉴权）、调试日志泄露、环境变量注入
# 空间引擎语法：FOFA "app.tcloudbase.com" && 目标关键词
```

### 9.3 未绑定域名与影子资产
```
# 已注册但未接入 DNS/未部署服务的域名（NS 指向无效）
# 方法：CT 日志中找到的域名 → 无法解析 → 可注册或接管（见第五章）
# 已解绑的 CDN/存储域名 → 悬空 CNAME → 接管

# 影子资产画像（红队甜点区）
# - 开发者自建测试站（VPS 上跑 Jupyter/phpMyAdmin/Grafana）
# - 员工个人 GitHub Pages/网盘/云主机绑定目标域名
# - 未纳入采购的云资源（AWS 账号/新租户）
# 发现渠道：空间引擎按公司名/邮箱/证书关联、员工社交主页、招聘 JD 中的技术栈
```

### 9.4 容器与编排（K8s/Docker）
```bash
# 暴露面
# 2375/2376 Docker API（未授权 = 直接 RCE）
# 6443 Kubernetes API、10250 kubelet（未授权 pod 管理）
# 9090 Prometheus / 3000 Grafana / 8080 Harbor Registry
# 空间引擎：FOFA "protocol=docker" && 目标IP段 / "kubelet" "10250"
nmap -sV -p 2375,2376,6443,10250,9090,3000 target.com
```

## 十、移动端资产（小程序/App）

### 10.1 小程序发现
```bash
# 入口：微信搜索公司名（全部小程序列表）、公众号关联小程序
# 资产查询平台：爱企查/天眼查关联小程序、七麦数据/点点
# 每个小程序 = 一组完整 API 面（往往比 Web 端更少防护）
```

### 10.2 小程序抓包与反编译
```bash
# 抓包（PC 微信 + Proxifier 转发到 Burp；或模拟器 + 抓包工具）
# 低版本微信/Android 7 模拟器可绕过证书校验；高版本需系统证书挂载
openssl x509 -in cacert.der -out cacert.pem
# 将证书放入模拟器 /system/etc/security/cacerts/ 并 chmod 644

# 获取小程序包（本地缓存）
# Windows: C:\Users\<user>\AppData\Roaming\Tencent\xwechat\radium\Applet\packages
# Mac: ~/Library/Containers/com.tencent.xinWeChat/Data/.wxapplet/packages/

# 反编译（主包+分包）
node wuWxapkg.js __APP__.wxapkg        # wxappUnpacker 主包
unveilr "小程序目录"                    # 自动处理分包，输出源码

# 源码分析重点
# - app.js / config.js：AK/SK、云环境ID、API 域名
# - request 封装：BaseURL、加密签名逻辑（sign 参数生成）
# - 分包路径：未授权模块、隐藏功能页
# - WXSS 注释：测试账号、开发信息
```

### 10.3 小程序专属风险点
```
- 云函数未授权调用（wx.cloud.callFunction 任意函数）
- API 越权：JWT 签名不校验/算法混淆（alg:none）
- 敏感参数明文传输（路由 URL 带 token/用户ID）
- 内网地址直连：小程序后端常部署在办公网，请求头 X-Forwarded-For 伪造
- 加密算法逆向：硬编码密钥提取 → 重放/构造合法请求
```

### 10.4 APK 分析（Android App）
```bash
# 获取：小蓝本 / 点点 / Apple Store / 七麦数据 / 应用市场

# 静态分析
jadx -d output app.apk                      # 反编译为 Java 源码
apktool d app.apk                           # 资源与 smali
# AppInfoScanner / ApkAnalyser / bytecode-viewer
# 提取：URL/域名、AK/SK、证书文件、SQLite 数据库、硬编码凭据

# 字符串全量提取
strings -n 8 app.apk | grep -iE "http|api|key|secret|token"

# 脱壳（加固应用）
# BlackDex / fdex2 / 反射大师 / 微脱壳
# 绕过抓包：JustTrustMe++ / HttpCanary / 小黄鸟 / Frida SSL Pinning 绕过

# iOS：爱思助手提取 IPA → class-dump / Hopper 分析（方法论同上）
```

### 10.5 移动端与 Web 资产联动
```
1. 从 App/小程序提取的 API 域名/内网 IP 合并进攻击面清单
2. 移动端接口往往绕过 WAF/CDN（直连源站）→ 真实 IP 溯源捷径
3. 移动端参数构造（版本号/设备指纹）可能绕过 Web 端风控
4. 云端配套（OSS/COS/云函数）与 Web 端共享存储 → 横向
```

## 十一、关联信息图谱：员工/组织/供应链

### 11.1 员工信息收集
```bash
# 邮箱格式确认（钓鱼/撞库基础）
theHarvester -d target.com -b all
# 在线：Hunter.io / snov.io / email-format / skymem
# 常见格式：firstname.lastname / first.last / flast / f.last+数字

# 社交平台（脉脉/领英/微博/知乎/贴吧）
"@target.com" site:linkedin.com
"公司名" "工号" site:xxx.com
# 招聘信息：HR 联系方式、JD 中的技术栈、薪资范围（社工素材）

# 人员信息聚合（国内）
# SGK 工具 / 天眼查高管信息 / 企查查法人+联系方式
# 注意：人员信息仅用于授权范围内社工/口令喷洒研判，严禁滥用
```

### 11.2 组织架构与子公司
```
# 股权关系（天眼查/企查查"股权穿透"）
# 全资/控股子公司 → 资产纳入攻击面（内网常互通）
# 法定代表人/高管关联企业 → 独立资产但共享人员习惯（口令复用）

# 官网线索
# "组织机构"页面 → 部门列表（IT/运维/研发命名习惯）
# "领导简介" → 高管姓名（社工/口令猜测素材）
# 年报/社会责任报告 → 分支机构、供应商名单
```

### 11.3 供应链关联（红队扩展攻击面高价值维度）
```
# 三类关键供应商
1. 系统开发商/外包商：同一套源码交付多家客户 → 代码审计可复用、0day 通用
   （官网"供应商/中标公告"、系统页脚/源码注释中的开发商标识）
2. 运维商/驻场商：掌握多客户运维账号 → 供应链突破口
3. 硬件/云供应商：设备默认口令、云租户配置错误

# 采集途径
# 招投标网站（政府采购网等）→ 中标单位名单
# 官网"合作伙伴"、系统备份文件中的供应商模板
# 招聘信息中"负责XX系统运维"→ 定位驻场商
```

### 11.4 邮箱/账号泄露检查
```bash
# 免费：Have I Been Pwned（域名级：输入 @target.com 查看员工泄露账号）
https://haveibeenpwned.com/DomainSearch

# 聚合检索
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "https://api.dehashed.com/search?query=email:@target.com"

# 泄露命中后的攻击转化：
# 泄露密码 → 撞库 VPN/OA/邮箱（需确认在授权范围内）
# 泄露邮箱 → 钓鱼、密码喷洒名单
# 泄露会话 Cookie → 直接登录（MFA 绕过）
```

## 十二、泄露数据库与暗网情报

### 12.1 2025-2026 泄露态势（情报背景）
- 2025-06 Cybernews 披露 **160 亿条凭证** 暴露于未加密存储，92% 来自 2024-2025 活跃攻击，61% 密码仍有效，34% 附带会话令牌
- 2025 年 Infostealer（窃密木马）新增 **15.6 亿条凭证**，平均每台感染设备 547 条密码，86% 为明文
- AI 工具凭证进入黑市：2025 年超 102 万条 OpenAI 账号凭证、HuggingFace 凭证 +18%
- 凭证从感染到上架 <48 小时，勒索部署通常 <4 天——时效性决定数据价值
- 54% 的勒索受害者在攻击前其企业凭证已出现在 stealer 日志中（Hudson Rock 等研究）

### 12.2 查询数据源分层
| 层级 | 数据源 | 覆盖范围 | 成本 |
|------|--------|---------|------|
| 免费公开 | HIBP、IntelX、LeakCheck 免费档、Pastebin | 已公开披露泄露 | 免费 |
| 聚合商业 | Dehashed、Snusbase、LeakCheck、Scylla | 多来源聚合+明文密码 | 付费 |
| 威胁情报 | SOCRadar、Recorded Future、CloudSEK XVigil、MicroCTI | stealer log、暗网论坛、IAB 情报 | 企业级 |
| 暗网监控 | 自有爬虫 + Telegram 频道监控 | 实时一手数据 | 高成本 |

### 12.3 暗网/Telegram 监控方法论
```bash
# 原则：监控 ≠ 主动购买/交互。仅收集公开可访问的泄露数据用于安全评估

# Telegram 频道（Telethon 只读抓取公开频道中目标关键词）
# 关键词：目标域名/公司名/邮箱后缀/系统名

# 暗网索引（Tor 环境，仅访问合法可索引站点）
# DarkSearch / Ahmia / 已索引的泄露数据库镜像
torsocks curl -s "http://darksearch.io/api/search?query=target.com"

# Stealer log 平台（Hudson Rock 免费查询接口）
curl -s "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=@target.com"
# → 返回受感染设备、窃取凭证 → 直接关联企业泄露面

# 评估命中数据价值（见 12.1）：新鲜度/明文性/会话令牌/访问级别（VPN、邮件、云控制台）
```

## 十三、AI 大模型结合

### 13.1 AI 辅助 OSINT 自动化（实体提取）
```
场景：LLM 分析网页/报告/文档，自动提取结构化实体
输入：目标年报、招投标文件、官网页面、泄露文档、扫描报告
输出：组织实体（人/部门/系统名）、技术实体（IP/域名/端口/框架/API）、
      关系实体（子公司/供应商/运维商）、敏感实体（邮箱/电话/账号）

示例 Prompt：
"从以下招投标文档中提取：1)所有系统名称和对应开发商 2)网络拓扑相关IP/网段
 3)运维人员姓名与联系方式 4)默认口令或测试账号线索，输出JSON格式："

# 效率点：手工 2 小时通读文档 → LLM 2 分钟提取，再人工核验
# 应用：批量分析数百个子域名首页、批量提取 JS 中的接口与密钥、分析源码仓库
```

### 13.2 AI 驱动的信息聚合与攻击面评估
```
1. 聚合层：多工具输出（subfinder/httpx/nuclei/CT/空间引擎）原始 JSON 喂给 LLM
2. 去噪层：LLM 根据上下文判断哪些是死资产/泛解析/CDN/无价值页面
3. 研判层：LLM 输出"高概率目标+理由+建议动作"排序清单
   Prompt："以下是我方资产清单，请标注：最可能被攻破的3个资产及理由、
           疑似影子资产的域名、应优先验证的接管候选、需人工复核的可疑项"
4. 报告层：自动生成信息收集报告初稿（攻击面图、资产清单、风险分级）

# 代表性平台/工具（2025-2026）
- FullHunt Agentic AI（MCP 协议，自然语言调用 40+ 情报工具）
- SpiderFoot HX / Maltego AI / Recon-NG AI / Shodan AI
- osint-cli / local LLM 方案（Ollama + Mistral/Llama/Qwen 本地跑，数据不出境）
```

### 13.3 大模型辅助社工信息分析
```
1. 邮件/文档分析：识别撰写人风格、时间习惯（钓鱼时机研判）
2. 人员关系推理：从公开社交信息推断部门/职级/权限（口令喷洒优先级）
3. 密码习惯预测：从泄露数据+公开信息推断密码构造规律（限授权口令评估）
4. 话术生成：针对目标人员的钓鱼话术（仅限授权的社工演练）
```

### 13.4 本地 LLM 私有化与 MCP 工具链
```bash
# 本地部署（OPSEC：目标数据不出境、无第三方日志）
ollama pull qwen2.5:7b            # 或 llama3.1/mistral
ollama serve

# MCP（Model Context Protocol）接入情报工具
# FullHunt MCP / 自建工具服务：LLM 可调用的子域/证书/端口/泄露查询接口
# Claude Desktop / Cline 等客户端配置 mcpServers 即可

# 自动化流水线示例（recon → LLM triage）
subfinder -d target.com -silent | httpx -json | jq . > recon.json
llm-triage recon.json > prioritized.txt   # 自研脚本：调本地 LLM 输出优先级清单
```

### 13.5 幻觉与误报控制（AI 使用纪律）
- **LLM 输出绝不直接执行**：所有 AI 给出的域名/IP/凭据必须二次验证（dnsx/httpx/接口实测）
- **上下文裁剪**：长文档分段喂入，避免关键信息被截断
- **交叉验证**：AI 聚合结果与空间引擎/CT 等权威源比对
- **敏感数据隔离**：目标数据优先本地模型处理；云端 API 不清洗数据时禁用
- **结论留痕**：AI 判断保留原始依据，便于报告追溯与复核

## 十四、信息收集 → 攻击面优先级评估决策方法论

### 14.1 资产归一与分类
```
汇总所有渠道 → 统一资产模型
├── Web 资产（域名+端口+指纹+状态）
├── 网络资产（IP/C段/ASN/服务）
├── 云资产（存储桶/云函数/CDN源站）
├── 移动资产（小程序/App/API）
├── 人员资产（邮箱/账号/泄露凭证）
└── 供应链资产（开发商/外包商系统）
规则：域名→解析→IP→服务→指纹，四级归一，去重；标注数据来源（可追溯）
```

### 14.2 风险评分模型（示例）
```
得分 = 可达性(30) + 技术脆弱性(25) + 暴露面(20) + 情报命中(15) + 业务价值(10)

- 可达性：公网直连=高；需凭证/条件触发=中；仅内网=低
- 技术脆弱性：版本已知 CVE / 存在公开 EXP / 默认口令 / 高危组件=高
- 暴露面：暴露端口数、管理端口、调试接口、API 文档
- 情报命中：泄露库命中凭据 / stealer log 命中 / 暗网提及
- 业务价值：核心业务系统、OA/邮箱/VPN（边界突破价值最高）

输出：按分数排序的攻击目标清单 + 每条的攻击路径建议
```

### 14.3 高价值目标识别清单（红队甜点区）
```
□ 新签发证书域名（CT 30 天内）→ 未加固环境
□ 影子资产（测试/开发/废弃系统）→ 无监控无防护
□ 泄露库命中账号可登录的系统（VPN/OA/邮箱/云控制台）
□ 悬空 CNAME（子域名接管）→ 信誉借壳
□ 未接入 CDN/WAF 的直连源站 → 绕过防护
□ 移动端直连的内网 API → 绕过边界设备
□ 供应链开发商系统 → 一套源码/账号通吃
□ 管理后台/调试接口（actuator/console/swagger）
□ 高危组件版本（Fastjson/Log4j/Shiro/通达OA 等）
```

### 14.4 攻击链规划与打点决策
```
1. 选择最小阻力路径：优先"凭据类"（泄露/弱口令）> "配置类"（未授权/接管）> "漏洞类"（CVE）
2. 先验证后深入：每个目标用最低噪音动作验证（httpx/单个请求/DNSlog）
3. 保持多条备选路径：A 目标失败立即切换 B/C（信息收集阶段已备好 3+ 攻击路径）
4. 打点后信息回流：拿到权限后的内部信息 → 反哺攻击面清单（二次信息收集）
5. 全过程留痕：每次动作的时间/目标/结果记录，供报告与复盘
```

## 十五、工具链总表

| 分类 | 工具 | 用途 |
|------|------|------|
| 企业/人员 OSINT | 天眼查/企查查/爱企查、工信部备案、Hunter.io、theHarvester、teemo | 工商/备案/邮箱/人员 |
| 证书透明度 | crt.sh、CTFR、Sublert、certspotter、Censys | 子域/新资产监控 |
| DNS 历史 | SecurityTrails、DNSDB、ViewDNS、微步在线、bufferover | 历史解析/真实IP |
| 子域枚举 | subfinder、amass、subdominator、assetfinder、findomain、OneForAll、灯塔ARL | 被动+主动枚举 |
| DNS 解析 | dnsx、puredns、dig、dnsrecon、fierce | 验证/爆破/AXFR |
| 子域接管 | nuclei(takeover模板)、subjack、subzy、dnsReaper、BadDNS | 接管检测 |
| 端口扫描 | masscan、nmap、naabu、zmap | 全端口/服务识别 |
| Web 指纹 | httpx、whatweb、wappalyzer、favihash | 技术栈/CMS |
| 目录扫描 | ffuf、gobuster、dirsearch、feroxbuster、御剑、7kbscan | 目录/备份文件 |
| JS 分析 | LinkFinder、SecretFinder、getJS、JSFinder、转子、Burp JS Miner | API/密钥提取 |
| 云资产 | S3Scanner、bucket-stream、ossutil、coscmd、grayhatwarfare | 存储桶检测 |
| 移动端 | wxappUnpacker、unveilr、jadx、apktool、AppInfoScanner、BlackDex、JustTrustMe++ | 小程序/APK |
| 泄露情报 | HIBP、Dehashed、Snusbase、LeakCheck、IntelX、Hudson Rock | 凭据泄露查询 |
| 空间引擎 | FOFA、Hunter、Quake、Shodan、Censys、ZoomEye | 全网资产检索 |
| 自动化编排 | reconftw、recon-ng、SpiderFoot、osmedeus、NocturneRecon、ENscan、无影 | 一键信息收集 |
| AI 辅助 | FullHunt Agentic AI、SpiderFoot HX、Ollama(本地LLM)、MCP工具链 | 智能聚合研判 |
| 报告输出 | 自研整合脚本、maltego、amass viz | 图谱可视化/报告 |

## 十六、信息收集检查清单

### 16.1 被动阶段
- [ ] Whois/注册人/邮箱/电话反查、历史 Whois
- [ ] 企业工商信息：股权穿透、子公司、分支机构、软件著作权
- [ ] ICP 备案查询与备案号反查（国内目标）
- [ ] 搜索引擎 Dorks（Google/Bing/百度/搜狗微信）多引擎覆盖
- [ ] GitHub/GitLab/Gitee 代码泄露搜索
- [ ] 网盘/文库/招投标文件泄露搜索
- [ ] 证书透明度（crt.sh/Censys/certspotter）子域提取
- [ ] CT 新证书监控（Sublert，新部署资产）
- [ ] DNS 历史记录查询（真实 IP/旧资产）
- [ ] 被动子域枚举（subfinder/amass/subdominator）
- [ ] 空间引擎检索（FOFA/Hunter/Quake，域名/证书/备案/公司名四路并进）
- [ ] 邮箱格式与员工账号收集
- [ ] 泄露数据库查询（HIBP/Dehashed/Hudson Rock）
- [ ] 暗网/Telegram/stealer log 关键词监控

### 16.2 主动阶段
- [ ] DNS 记录全类型枚举（含 SRV/TXT/CNAME 云关联）
- [ ] AXFR 区域传送尝试
- [ ] 子域名字典爆破 + 变体生成（alterx）
- [ ] DNS 解析验证与通配符过滤、HTTP 探活
- [ ] 子域名接管指纹检测（CNAME 悬空）
- [ ] 全端口 TCP 扫描（masscan→nmap 两段式）
- [ ] 重点 UDP 端口扫描
- [ ] 服务版本识别与高危端口排查
- [ ] Web 指纹识别（技术栈/CMS/框架/中间件）
- [ ] 目录/敏感文件/备份文件扫描
- [ ] .git/.svn/.DS_Store 泄露检查
- [ ] JS 文件分析（API/密钥/路由/内网IP）
- [ ] Source Map 源码还原
- [ ] 403/401 绕过测试、认证页面识别
- [ ] favicon hash 关联扩展

### 16.3 云与移动端
- [ ] 对象存储桶枚举与权限检测（S3/OSS/COS/Blob/GCS）
- [ ] 云函数/Serverless API 网关探测
- [ ] 悬空 CNAME / 未绑定域名检查
- [ ] 容器暴露面（Docker/K8s API）
- [ ] 小程序发现、抓包、反编译、源码分析
- [ ] App 下载、反编译、字符串提取、脱壳
- [ ] 移动端 API/内网地址合并入资产清单

### 16.4 整合与研判
- [ ] 全渠道资产归一去重、数据来源可追溯
- [ ] 风险评分与优先级排序（14.2 模型）
- [ ] 高价值目标标记（影子资产/新资产/凭据命中/接管候选）
- [ ] 攻击路径规划（≥3 条备选）
- [ ] AI 辅助聚合与交叉验证
- [ ] 输出信息收集报告（资产清单+攻击面图+风险分级）

## 十七、修复建议

### 17.1 攻击面收敛（甲方视角）
- **资产清单化**：建立权威资产台账（域名/IP/端口/指纹/负责人），对接 CAASM 平台持续发现影子资产
- **备案/子公司治理**：定期核对备案主体下全部域名，注销废弃域名与备案
- **存储桶最小权限**：对象存储默认私有，禁止公共读；统一生命周期策略清理冗余桶
- **CT 监控**：订阅 crt.sh/Sublert 监控自有域名新证书，识别未申报资产
- **Dangling DNS 治理**：周期性核查 CNAME 指向资源的存活性，注销前先删 DNS 记录

### 17.2 泄露数据响应
- **凭据轮换**：泄露库命中后立即强制重置相关账号口令（VPN/OA/邮箱/云控制台优先）
- **会话令牌失效**：stealer log 命中的会话 Cookie 全部失效并重新认证
- **暗网监控**：对域名/邮箱后缀/系统名建立持续暗网监测（参考第十二章）
- **MFA 全覆盖**：凭证泄露时代 MFA 是最后防线，重点覆盖 VPN/邮箱/云控制台
- **Infostealer 治理**：员工终端防病毒覆盖、浏览器密码管理器审计

### 17.3 服务暴露收敛
- 关闭非必要公网端口（管理端口走 VPN/堡垒机），高危组件（Redis/MongoDB/ES/Docker）禁止裸奔公网
- 管理后台/调试接口（actuator/console/swagger）公网下线或强认证
- 移除生产环境 Source Map、备份文件、.git 目录
- 统一加固边界：CDN+WAF 全量接入，源站 IP 不暴露（见 8.3 溯源手段逐项反制）
- 移动端 AK/SK/密钥服务端化，禁止硬编码于客户端

### 17.4 开发与供应链
- 代码扫描（gitleaks/trufflehog）纳入 CI，阻止密钥进仓库
- 开发商/外包商签署安全条款，交付代码做安全审计（供应链通用源码风险）
- 小程序/App 上线前安全测试，云函数全部鉴权

## 十八、注意事项

- **仅限授权测试**：所有信息收集动作必须在目标书面授权的范围内执行；超出授权范围的行为（含被动收集某些敏感数据）可能违法
- **合规声明**：本技能所述技术仅用于授权渗透测试、红队演练、CTF 与安全研究。依据《中华人民共和国网络安全法》《数据安全法》《个人信息保护法》，未授权收集个人信息、入侵他人系统将承担法律责任；泄露数据查询与暗网访问仅在合法合规且获取授权的前提下进行
- **被动优先**：先 OSINT 被动收集，后主动扫描；能被动解决的绝不主动发包
- **隐蔽至上**：主动侦察全程控制速率、伪装指纹、轮换出口，避免触发 WAF 封禁与溯源
- **数据保护**：收集到的个人/企业信息严格保密，测试结束即销毁，不写入报告之外的文件
- **授权边界**：Whois/CT/空间引擎等公开数据合法，但主动扫描、接管验证、口令测试均需授权
- **社会工程边界**：人员信息仅用于授权社工演练与口令风险评估，禁止骚扰、泄露或滥用
- **记录留痕**：全部动作时间/目标/命令/结果存档，供报告编写、复盘与纠纷自证
- **CDN 提醒**：先确认 CDN 再扫描，扫 CDN 节点 IP 无意义且浪费弹药；真实 IP 溯源后再深入
- **时效性**：工具与数据源变化快（2025-2026 已出现 subdominator/BadDNS/FullHunt Agentic AI 等新工具），定期更新本技能；AI 辅助输出必须人工二次验证
- **情报版本**：暗网泄露数据时效极强（48 小时窗口），命中数据须注明发现时间与来源置信度

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
