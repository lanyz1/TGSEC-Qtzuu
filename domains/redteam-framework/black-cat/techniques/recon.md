---
name: pentest-recon
description: "信息收集：通用资产发现 + 国内特有拓线（测绘引擎/小程序/APP/股权穿透）——假设驱动的信号→动作速查表"
allowed-tools: Read,Grep,Glob,Bash,WebFetch
---

# Recon（信息收集）

> 仅在根路由选择本目录后读取。每个条目都是待验证的检查假设；执行前用当前一手证据确认适用性。

**触发**: 目标是 Web/API/域名/企业，需最大化发现资产、域名、IP、子域、APP、小程序、云存储，尤其在初始范围只有一个公司名或一个主站时。

---

## 通用信息收集

### CDN 绕过 → 真实源站 IP + 内部主机名泄露
- **信号**: CNAME 指向 Cloudflare/Akamai/阿里云CDN/腾讯云CDN
- **假设**: 源站 IP 隐藏但可通过证书/DNS 历史/特征反查；内部主机名（jenkins/staging/admin-portal）也可能通过 CT 日志泄露
- **验证**: `curl -H "Host: target.com" https://<候选IP>` 返回目标内容
- **找 IP 管线**: SecurityTrails DNS 历史 A 记录时间线 → FOFA `cert.serial_number="<hex>"` + Shodan `ssl.cert.serial:<dec>` + Censys 三引擎 SSL 证书反查 → Favicon MurmurHash3 跨引擎反查(shodan `http.favicon.hash:<mmh3>` / fofa `icon_hash=<mmh3>`) → DNS Cache Snooping massdns `--norecurse` 非递归查询权威 NS → **CT 日志全量采样**：监控 CA 全量签发流，企业经常为内部主机（jenkins.internal.corp.com/admin-portal.staging.int）签发公网证书，这些出现在 SAN 字段但不属于目标查询范围
- **证实**: 两个以上引擎指向同一 IP + HTTP 直接访问响应内容匹配；或发现未公开的内部主机名
- **证伪**: 所有候选 IP 返回 CDN 错误页或超时 → 源站可能有 IP 白名单
- **升级**: 拿到源站 IP 后跳过 WAF，直接端口扫描 + 漏洞探测；内部主机名 → ASL 追加 → 定向测试

### JS Source Map → 源码还原 + 端点提取
- **信号**: 目标使用 Webpack/Vite 打包且 `.map` 文件可访问
- **假设**: Source map 包含原始目录结构、变量名、注释和隐藏端点
- **验证管线**: `unwebpack-sourcemap` 还原完整目录结构 → `LinkFinder` 提取 API 路由/WebSocket endpoint → `SecretFinder` 提取 20+ 种凭证类型 → headless browser 渲染 SPA 用 paramFuzzer 提取动态参数 → SubDomainizer 提取云存储 URL + 隐藏子域名
- **证实**: 发现未文档化的 API 端点或硬编码凭证
- **升级**: 新端点 → ASL 追加 → 进入 API Fuzzing 流程

### 企业拓线 → 关联资产发现
- **信号**: 目标为企业，需扩大攻击面到子公司/供应商
- **假设**: GA/Facebook Pixel/Hotjar 追踪 ID 可跨域关联同一组织
- **验证管线**: GA/Hotjar 追踪 ID 反向查询关联域名 → ICP 备案反查（ENScan_GO 同一主体/手机号/邮箱）→ WHOIS 历史 + 注册邮箱 + Name Server + SPF 交叉关联 → Crunchbase/OpenCorporates 母子关系 + 高管关联 → CrossLinked 抓 LinkedIn 员工邮箱反推命名规则
- **证实**: 发现未在初始范围内的关联域名或资产
- **升级**: 新域名 → RECON 状态重启（独立 ASL 条目）

### 云存储资产发现
- **信号**: 目标使用 AWS/Azure/GCP/阿里云/腾讯云
- **假设**: 存在公开或可枚举的对象存储桶
- **验证**: `cloud_enum` 多云关键词变异爆破（企业名+缩写+产品名+环境名组合）→ GCP `TestIamPermissions` API 未认证检测 → s3recon 逐位爆破利用 IAM 条件键 s3:ResourceAccount 确定 12 位 Account ID → SubDomainizer 从 JS 自动提取云存储 URL
- **证实**: Bucket 可以未认证读取/写入/列目录
- **升级**: Bucket 内容分析 → 敏感信息提取 → 云身份横向

### 版本控制 / 备份文件泄露 → 源码还原
- **信号**: 目标可能残留 `.git`/`.svn`/`.DS_Store` 目录或备份/临时文件
- **假设**: 泄露目录可还原服务端源码、配置、DB 口令、目录结构
- **验证**: `.git`→GitHack/GitHacker（GitHacker 能挖已删 commit 与分支/stash）；`.svn`→dvcs-ripper `rip-svn.pl`；`.DS_Store`→ds_store_exp 递归下载引用文件；备份/临时文件 fuzz `www.zip`/`网站名.zip`/`.bak`/`.swp`/`.orig`；Java 站测 `WEB-INF/web.xml`、`WEB-INF/classes`（class 反编译）
- **证实**: 拿到整站源码/配置或接口映射
- **升级**: 源码转白盒审计（配置/硬编码凭据/后门）→ 新端点 ASL 追加

### 被动归档 → 历史 URL + 隐藏子域
- **信号**: 目标有历史资产、旧端点、下线接口
- **假设**: Wayback/Common Crawl 归档了历史 URL 与参数，含已下线端点和带参 URL（`redirect=`/`file=`/`url=` → SSRF/开放重定向线索）
- **验证**: `gau target.com`（一次拉 Wayback+Common Crawl+OTX+URLScan）/ `echo target.com | waybackurls`；Common Crawl CDX `https://index.commoncrawl.org/` 用 `*.target.com` 通配挖子域，全程不触达目标
- **证实**: 发现现役枚举漏掉的旧端点/子域/敏感参数
- **升级**: 旧端点 → 参数 Fuzzing；子域 → ASL 追加

### 被动 DNS → IP↔域名双向反查
- **信号**: 需从一个已知 IP 反查其历史绑过的全部域名，或补充非 SecurityTrails 的解析源
- **假设**: 被动 DNS 记录了 IP 上过 CDN 之前的真实解析和历史绑定域名（带 first/last-seen）
- **验证**: 微步在线 x.threatbook.com / PassiveDNS.cn / DNSDB rdata 反向搜索（IP→域名）/ CIRCL / `amass enum -passive -d target.com`
- **证实**: 一个 IP 反查出多个关联域名，或发现旧解析暴露的源站
- **升级**: 新域名/源站 IP → RECON 重启 / 直连探测

### 邮件认证记录 → 关联域名 + 自有 IP 段
- **信号**: 目标有企业邮箱（几乎所有企业域都配 SPF/DMARC/MX）
- **假设**: SPF include 链、DMARC rua、MX/DKIM 泄露第三方 SaaS、兄弟/子公司域名，`ip4/ip6` 机制直接列自有 IP 段（SPF flattening 会拍平成裸 IP 列表）
- **验证**: `dig txt target.com`（递归展开 `include:`/`redirect=`/`ip4:`）；`dig txt _dmarc.target.com`（读 `rua=`/`ruf=` 收件域）；`dig mx`/`dig txt selector._domainkey.target.com`
- **证实**: 发现关联域名或企业自持 IP 段
- **升级**: IP 段 → ASN/C 段扩面；关联域 → ASL 追加

### ASN / BGP → 企业整段 IP → C 段反查
- **信号**: 大目标需界定地址空间（高校/集团常自持 B/C 段）
- **假设**: 企业 BGP 宣告的 CIDR 内有未上 CDN 的真实资产与旁站
- **验证**: `asnmap -org "COMPANY"` / `asnmap -d target.com`（输出全部 CIDR）→ C 段落地：DomainClassCIPScan（C 段域名反查）+ `nmap -sn` 探活 + PTR 反向解析
- **证实**: 同段内发现子域枚举覆盖不到的旁站/兄弟系统
- **升级**: 新资产 → 端口扫描 + 指纹 → ASL 追加

### 邮件头 Received 链 → 真实源站 IP（绕 CDN）
- **信号**: 目标接 CDN 隐藏源站，但会主动发信（注册激活/找回密码/订阅确认/退订）
- **假设**: CDN 只加速 Web，邮件多从源站直发；邮件头暴露源站真实 IP 与内网信息
- **验证**: 触发目标发信 → 看邮件"原始/源代码" → 读 `Received:` 链最底部（最早）一跳 + `X-Originating-IP`/`X-Sender-IP`（HELO/EHLO 握手常带客户端 LAN IP）
- **证伪**: 目标用 SendGrid/Mailgun/阿里云邮件推送 → 拿到的是服务商 IP
- **证实**: `curl -H "Host: target.com"` 验证候选 IP 返回目标内容
- **升级**: 拿到源站 IP → 跳过 WAF 直接探测

---

## 国内特有手法

### 测绘引擎：进阶语法

> FOFA/Quake/Hunter/ZoomEye 数据互补：Quake 非 Web/工控/未授权指纹最细；Hunter/SUMAP 备案关联最强；FOFA 亚洲 Web 覆盖广且有 fid/is_honeypot 独有字段。精确 pivot 用 `==`，跨平台换字段名。

#### ICP 备案号反查全主体资产
- **信号**: 已拿到目标一个资产，需从企业主体维度反向扩面（国内引擎独有能力，Shodan/ZoomEye 没有）
- **假设**: 同一 ICP 主体名下常备案大量域名/资产，通过备案号可一键捞全
- **验证**: 从已知站提取备案号 → Hunter `icp.number="京ICP备XXX号"`，可叠加 `&& ip.port="8080"` 收敛暴露服务；Quake/SUMAP 有同类字段
- **证实**: 返回该主体名下未在初始范围的域名/IP
- **升级**: 新域名 → RECON 重启（独立 ASL 条目）→ 二次子域名收集

#### fid 站点结构聚类
- **信号**: 目标把同一套 Web 应用部署在多个分散 IP/域名（镜像、负载节点、SaaS 多租户）
- **假设**: `fid` 基于站点整体结构生成，比 `icon_hash` 更精细，能聚出整个集群
- **验证**: 先查一个已知站拿 `fid` → FOFA `fid="<值>"` 全网 pivot
- **证实**: 捞出跨 IP/域名的同源站集群
- **升级**: 集群内逐个探测，找防护最弱节点打点

#### 蜜罐/欺诈数据净化（HVV 必备）
- **信号**: 批量拉取某框架资产准备打点，需避免踩蜜罐触发告警
- **验证**: FOFA 查询追加 `&& is_honeypot=false && is_fraud=false`（国内引擎独有字段）
- **证实**: 结果集剔除蜜罐节点与仿冒数据后更干净
- **升级**: 净化后的资产进入指纹叠加打点流程

#### 降噪三件套（精确 pivot 基础）
- **信号**: 做证书/标题/指纹 pivot 时误报多（多数引擎默认分词模糊匹配）
- **验证**:
  - `==` 强制精确大小写敏感匹配（FOFA `domain=="qq.com"` / ZoomEye `title=="XXX后台"`），把"包含"收敛为"等于"
  - `!=` 排跳转空壳（`body!="Object moved" && title!="302"`），剔除 CDN/WAF 的 302 空壳页
  - `ip_ports="80,161"` 多端口共开特征，精确定位特定设备/源站（如同时开 Web+SNMP 的网络设备）
- **证实**: 结果噪声显著下降，pivot 命中率提升

#### body 特征串全网找裸奔源站（绕 CDN 补充）
- **信号**: 源站接 CDN，前端 IP 隐藏，但源站在 80/8080/8443 等端口可能仍原样返回同一 body
- **假设**: 页面里独一无二的字符串（内联 JS 版本、构建 hash、后台标识）在源站未接 CDN 时全网可搜到；比 favicon 更抗改（有些站改了图标但没改 body）
- **验证**: 提取页面唯一特征串 → FOFA `body="<唯一串>"`（去掉 host/domain 限制全网搜）→ 候选 IP 用 `curl -H "Host: target.com"` 验证
- **证实**: 命中未接 CDN 的真实源站 IP
- **升级**: 拿到源站 IP → 跳过 WAF 直接端口扫描 + 漏洞探测

#### 测试/预发布/内部系统定向发现
- **信号**: 目标存在测试/预发布环境（防护薄弱、鉴权缺失、带真实数据，且常不接 CDN 直暴源站）
- **假设**: 环境命名习惯 + 内部系统 body 标识可批量捞出
- **验证**: FOFA `domain="target.com" && (host="uat"||host="dev"||host="pre"||host="staging"||title="测试"||body="内部系统"||body="仅供内部使用")`；Hunter `domain.suffix="target.com" && web.title="测试环境"`
- **证实**: 发现打点突破口——弱防护的非生产环境
- **升级**: 定向测试鉴权缺失/默认口令 → ASL 追加

---

### 企业拓线：小程序 / APP / 股权穿透

> 国内目标核心增量。推荐主链路：企业名 → 股权穿透枚举全部关联主体 → 每主体分别做 ICP/APP/公众号/小程序反查 → 拿到的 APP/小程序做静态提取挖后端接口与 AK/SK → 后端域名/IP 回测绘引擎 icon_hash+cert+C段横向扩面。

#### 微信小程序 wxapkg 反编译提取接口/域名/密钥
- **信号**: 目标有微信小程序（后端 API 往往比主站防护弱、暴露隐藏域名）
- **假设**: 小程序包内硬编码后端 API host、隐藏域名、OSS/云密钥、未授权接口
- **验证**:
  1. 微信打开目标小程序使其缓存到本地。新版微信缓存约在 `AppData\Roaming\Tencent\xwechat\radium\Applet\packages`；旧版在 `WeChat Files\Applet\wx{appid}\`
  2. 判断结构：只有 `__APP__.wxapkg`=主包；多个 `.wxapkg`=分包，需全部反编译
  3. 反编译：`unveilr <文件夹>`（自动处理分包，最推荐）或 wedecode（活跃维护）或 wxappUnpacker
  4. 导入结果搜索：域名、API 接口、`ossAccessKeyId`/AK-SK、电话、邮箱
- **证实**: 提取到未公开的后端域名/接口或可用 AK/SK
- **升级**: 新域名 → 测绘扩面；AK/SK → aksk_tool 反拉云资产（见 cloud.md）

#### APP 资产反查 + 静态提取
- **信号**: 目标企业有移动 APP（含被遗忘的老旧/子品牌 APP）
- **假设**: 同主体名下多个 APP 各自有独立后端资产；APK/IPA 内硬编码域名/IP/AK-SK
- **验证**:
  - 反查全部 APP：七麦(qimai.cn)/点点(app.diandian.com)按开发者反查该主体名下所有 iOS/安卓 APP；爱企查从软著维度补充
  - 静态提取：`AppInfoScanner`（apk/ipa 批量提域名/IP/URL/AK-SK）、`apkleaks`（正则扫 URI/endpoints/secrets）、MobSF（综合）
- **证实**: 发现独立后端接口、第三方服务域名、云密钥
- **升级**: 后端域名/IP → 测绘扩面；接口 → API Fuzzing（web.md）

#### 股权穿透 + 多维聚合拓线
- **信号**: 根域名/主体都找不全，需从组织架构维度破局（国内 SRC 起手式）
- **假设**: 资产常藏在子公司/关联公司名下；沿股权关系下钻可拉全域名+APP+小程序+公众号
- **验证**:
  - 股权底座：`EquityInfoer` 拉天眼查股权穿透（母子公司/实控人链路，关注 100% 控股）
  - 一键聚合：`ENScan_GO`（狼组）聚合爱企查/天眼查/快查 API，一次输出 ICP备案+APP+小程序+公众号+控股关系
  - 官方去噪：`ICP_Query_Batch` 直连工信部对一批主体批量查备案（含 APP/小程序备案）
- **证实**: 发现关联主体名下未在初始范围的资产
- **升级**: 每个新主体/域名 → RECON 重启，喂给 OneForAll/水泽做二次子域名收集
