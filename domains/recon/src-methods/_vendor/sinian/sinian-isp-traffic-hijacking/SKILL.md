---
name: isp-traffic-hijacking
description: >-
  运营商流量劫持深度技术手册。覆盖运营商(ISP)级别的多层级流量劫持技术：DNS层劫持(NXDOMAIN/透明代理/强制重定向)、HTTP层劫持(广告注入/内容篡改/iframe嵌入/状态码劫持)、HTTPS层劫持(SSL剥离/证书替换/CDN边缘劫持)、网络层劫持(BGP劫持/路由操纵/AS路径篡改/前缀劫持)、DPI深度包检测与流量整形、透明代理与缓存投毒、2026最新技术(QUIC劫持/ECH绕过/5G信令劫持/eSIM远程配置劫持)、检测防御矩阵与实战排查SOP。含交互式HTML演示。用于排查"网页被插广告""访问被重定向""HTTPS证书异常""流量异常路由"等运营商级别劫持场景。
---

# SKILL: 运营商流量劫持深度技术手册

> **AI LOAD INSTRUCTION**: 本技能聚焦运营商(ISP)级别的流量劫持——这是比DNS污染/劫持更广的概念。运营商拥有网络基础设施的物理控制权，可在**网络层(BGP路由)、传输层(TCP劫持)、应用层(HTTP注入/HTTPS剥离)** 多层级实施流量操纵。基础模型常把"网页被插广告"归为DNS劫持，但实际上可能是HTTP层注入、透明代理篡改、甚至是BGP级流量牵引。本技能按OSI分层构建攻击矩阵，覆盖从DNS→HTTP→HTTPS→BGP→DPI的完整运营商劫持技术栈，并给出检测与防御方法论。

## 0. RELATED ROUTING

- [dns-pollution-hijacking](../dns-pollution-hijacking/SKILL.md) — DNS污染与劫持，本技能在其 DNS 层基础上向 HTTP/HTTPS/BGP 层扩展，形成运营商级全栈劫持
- [dns-rebinding-attacks](../dns-rebinding-attacks/SKILL.md) — DNS Rebinding 是客户端攻击，与运营商劫持的"链路中间人"不同
- [http-host-header-attacks](../http-host-header-attacks/SKILL.md) — Host 头攻击，运营商劫持后可配合 Host 操纵
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) — WAF 绕过，运营商透明代理本身可视为一种"被迫的WAF"
- [request-smuggling](../request-smuggling/SKILL.md) — 请求走私，运营商透明代理缓存投毒时可能触发
- [network-penetration-testing](../network-penetration-testing/SKILL.md) — 网络渗透测试，BGP劫持属于网络层攻击

---

## 1. 核心概念：运营商劫持的分层模型

运营商(ISP)拥有从物理层到应用层的完整网络控制权，其流量劫持可在 OSI 模型的多个层级同时发生。理解分层模型是精准诊断的前提。

### 1.1 运营商劫持能力矩阵

```
OSI 层级       劫持技术              运营商控制点           典型表现
──────────────────────────────────────────────────────────────────────
L7 应用层     HTTP广告注入          透明代理/缓存服务器      网页底部出现广告
              HTTPS证书替换         CA根证书预装            访问银行显示自签名证书
              JavaScript注入        DPI设备修改HTTP响应      页面多出<script>
L6 表示层     SSL/TLS剥离           SSL中间人代理            浏览器显示HTTP而非HTTPS
L5 会话层     TCP会话劫持           会话边界控制器SBC         连接被重置RST
L4 传输层     TCP RST注入           流量清洗设备             连接被强制断开
              透明代理重定向         CG-NAT/BRAS设备          源IP被替换
L3 网络层     BGP劫持               BGP路由器                流量被牵引到境外AS
              路由黑洞              核心路由器                特定IP段不可达
              前缀劫持              BGP Peer                 合法IP段被宣告
L2 数据链路层  MAC/VLAN劫持         接入交换机               局域网流量被镜像
L1 物理层     光纤窃听/分光         光分配架ODF               物理窃听
```

### 1.2 运营商劫持 vs 普通DNS劫持

| 维度 | 普通DNS劫持(路由器/恶意软件) | 运营商劫持 |
|------|---------------------------|-----------|
| 执行者 | 攻击者/恶意软件/路由器漏洞 | ISP/运营商自身 |
| 规模 | 单用户/局域网 | 数百万用户同时受影响 |
| 技术栈 | 改DNS/Hosts | BGP+DPI+透明代理+缓存投毒 |
| 持久性 | 清除恶意软件/修路由器可恢复 | 只要用该运营商则持续受影响 |
| 检测难度 | 低(改DNS即可发现) | 高(多层配合，部分合法化) |
| HTTPS能否防御 | 部分(HTTPS防HTTP注入) | 部分(证书替换可绕过HTTPS) |
| 法律边界 | 明确非法 | 灰色地带(部分以"网络安全"名义) |

### 1.3 运营商为何能劫持

运营商劫持得以实现，根源于其**网络基础设施的物理控制权**：

- **BGP路由控制**：ISP 通过 BGP 宣告 IP 前缀，可决定流量走向，甚至将流量引向境外
- **DNS递归解析**：用户默认使用 ISP 的 DNS 服务器，ISP 可任意修改解析结果
- **透明代理部署**：ISP 在核心路由器旁挂透明代理，所有 HTTP 流量经过代理，可注入/篡改内容
- **DPI 设备**：深度包检测设备可识别应用层协议，对特定流量执行阻断/注入/限速
- **CA 证书预装**：部分运营商通过合作在设备/浏览器中预装根证书，实现 HTTPS 中间人
- **CG-NAT/BRAS**：运营商级 NAT 和宽带接入服务器是必经节点，可在此篡改流量

> **核心认知**：运营商劫持不是"漏洞"，而是 ISP 利用其合法网络控制权实现的**商业行为**(广告插入/流量经营)或**政策行为**(内容审查/封锁)。从用户视角看是"劫持"，从运营商视角是"增值服务"或"合规要求"。

---

## 2. DNS 层运营商劫持

DNS 是运营商劫持的**第一道关口**——控制 DNS 即控制用户访问互联网的入口。相比 §0 的 `dns-pollution-hijacking` 聚焦攻击者视角，本节聚焦**运营商作为 ISP 自身的 DNS 操纵**。

### 2.1 NXDOMAIN 劫持(域名错误劫持)

最常见形式：用户输入不存在的域名(如拼写错误)，ISP 的 DNS 不返回 NXDOMAIN，而是返回自家搜索/广告页 IP。

```bash
# 检测NXDOMAIN劫持
dig randomstring12345.nonexist.test +short
# 正常：空(无结果)
# 劫持：返回ISP广告页IP(如 123.123.123.123)

# 多ISP DNS对比
dig @8.8.8.8 randomstring.notexist +short       # Google DNS
dig @114.114.114.114 randomstring.notexist +short # 国内DNS
# 若114返回IP而8.8.8.8不返回 → ISP NXDOMAIN劫持
```

**运营商角度**：NXDOMAIN 劫持是 ISP 的"域名导航服务"——将用户输入错误的域名重定向到搜索页，获取广告收入。技术上，ISP 在递归 DNS 服务器上配置了"通配符解析"(`* 3600 IN A 广告IP`)，任何未命中缓存的域名都返回广告页 IP。

### 2.2 强制透明 DNS 代理

ISP 在核心路由器上配置 ACL，将所有目标端口 53 的 UDP/TCP 流量**强制重定向**到自家 DNS 服务器，无视用户配置的 DNS 地址。

```
用户配置 DNS=8.8.8.8
  │
  │  DNS 查询 → 目标 8.8.8.8:53
  │
  ▼
ISP 核心路由器 ACL 匹配 dst_port=53
  │
  │  DNAT 重定向 → 目标改为 ISP DNS 10.0.0.1:53
  │
  ▼
ISP DNS 返回可能被修改的解析结果
  │
  │  用户以为收到的是 8.8.8.8 的响应，实际是 ISP DNS 的
  ▼
```

```bash
# 检测透明DNS代理
# 1. 用特定DNS服务器查询，观察返回结果是否与预期一致
dig @8.8.8.8 www.example.com +short
# 若返回的结果与直接用ISP DNS(不指定@)一致，但与其他网络(如手机热点)的结果不同 → 疑似透明代理

# 2. 查询特殊域名(如 whoami.dns.xxx)看返回的DNS服务器身份
dig @8.8.8.8 whoami.akamai.net
# 若返回的IP段为ISP所有而非Google → 确认被透明代理

# 3. 用DoH/DoT绕过(若ISP未拦截443/853端口)
curl -H "accept: application/dns-json" "https://8.8.8.8/resolve?name=www.example.com"
```

### 2.3 DNS 劫持与 CDN 调度干扰

运营商修改 DNS 解析的另一个动机是**干扰 CDN 智能调度**——CDN 依赖 DNS 返回离用户最近的节点 IP，但 ISP 可能篡改解析使其指向自家缓存或另一 CDN。

```bash
# 检测CDN调度是否被干扰
# 对比不同DNS源返回的CNAME和A记录
dig @8.8.8.8 cdn.example.com +short     # 应返回CDN厂商节点
dig @114.114.114.114 cdn.example.com +short  # 对比是否一致

# 若不一致，检查：
# 1. 返回的IP是否属于同一CDN厂商(查ASN)
# 2. 返回的IP是否属于ISP自有AS(→ ISP劫持到自家缓存)
# 3. 延迟差异：被篡改的IP通常延迟更高
```

### 2.4 DNS 劫持 + HTTP 缓存协同

ISP 的 DNS 劫持常与 HTTP 缓存攻击协同——DNS 将流量指向 ISP 的透明代理，透明代理从原始服务器拉取内容后缓存，后续请求直接返回缓存内容，可实现：

- **内容篡改**：缓存中注入广告/脚本
- **内容过期**：缓存未及时更新，用户看到旧版本
- **访问阻断**：缓存返回伪造的"维护中"或"已屏蔽"页面

---

## 3. HTTP 层运营商劫持

HTTP 明文传输使运营商可**实时查看、修改、注入**任何 HTTP 响应的内容。这是运营商劫持的"重灾区"——广告插入、内容篡改、流量劫持到第三方主要发生在此层。

### 3.1 HTTP 广告注入

运营商在 HTTP 响应中插入广告代码，用户访问任何 HTTP 网站都可能看到 ISP 投放的广告。技术上通过透明代理/DPI 设备实现。

```
用户浏览器                         ISP透明代理                        网站服务器
  │                                   │                                   │
  │── GET /index.html ───────────────>│                                   │
  │                                   │── GET /index.html ───────────────>│
  │                                   │                                   │
  │                                   │<── HTTP 200 OK ───────────────────│
  │                                   │    Content-Type: text/html        │
  │                                   │    <html>...原始内容...</html>     │
  │                                   │                                   │
  │                                   │  ★ DPI设备修改响应体               │
  │                                   │  在</body>前插入:                  │
  │                                   │  <script src="//isp-ad.com/ad.js"> │
  │                                   │  <iframe src="//isp-ad.com/popup"> │
  │                                   │                                   │
  │<── HTTP 200 OK ───────────────────│                                   │
  │    Content-Type: text/html        │                                   │
  │    <html>...原始内容...           │                                   │
  │    <script src="isp广告">         │  ← 注入的广告                      │
  │    </html>                        │                                   │
```

**广告注入的常见特征**：

| 特征 | 说明 |
|------|------|
| 注入位置 | `</body>` 前或 `</html>` 前(不破坏DOM结构) |
| 注入内容 | 弹窗广告、悬浮按钮、页面底部横幅、iframe 嵌入 |
| 注入方式 | 透明代理修改响应体；DPI 设备旁路注入 |
| 触达范围 | 仅 HTTP 明文流量(HTTPS 不可见，除非证书替换) |
| 规避方式 | 全站 HTTPS + HSTS 预加载 |

**检测方法**：

```bash
# 1. curl 对比：直接访问 vs 通过代理
curl -s http://example.com | grep -i "isp-ad\|ad.js\|popup\|iframe"
# 检查响应中是否出现非预期的广告域名/脚本

# 2. 抓包对比：浏览器看到的 vs curl 直接获取的
# 用Wireshark抓包，检查HTTP响应体是否被篡改

# 3. 对比不同接入方式
# 用同一运营商光纤 vs 同一运营商4G/5G(不同接入设备，策略可能不同)
# 用不同运营商(电信/联通/移动)对比同一HTTP页面

# 4. 检查HTTP响应头
curl -I http://example.com
# 观察是否有非预期的 Via / X-Cache / X-Forwarded-For 头(透明代理添加)
```

### 3.2 内容篡改(Content Modification)

比广告注入更隐蔽——运营商修改 HTTP 响应中的**实际内容**，包括：

- **搜索结果篡改**：在搜索引擎返回的 HTML 中插入推广链接
- **电商价格篡改**：修改商品价格或插入竞品链接
- **下载文件替换**：将用户下载的 APK/EXE 替换为 ISP 分发的版本(含自家应用商店)
- **状态码劫持**：将 HTTP 404/500 替换为 ISP 的搜索页

```python
#!/usr/bin/env python3
"""HTTP内容篡改检测：多源对比 + 哈希校验"""
import hashlib
import requests
import urllib3
urllib3.disable_warnings()

def fetch_via_multiple_paths(url):
    """通过多种路径获取同一资源，对比内容"""
    sessions = {
        'direct': requests.Session(),          # 直接请求
        'via_google_dns': requests.Session(),  # 经Google DNS解析
    }
    # 模拟不同DNS解析路径
    results = {}
    for name, sess in sessions.items():
        try:
            resp = sess.get(url, timeout=10, verify=False,
                           headers={'User-Agent': 'Mozilla/5.0'})
            body_hash = hashlib.sha256(resp.content).hexdigest()
            results[name] = {
                'status': resp.status_code,
                'hash': body_hash,
                'size': len(resp.content),
                'headers': dict(resp.headers)
            }
        except Exception as e:
            results[name] = {'error': str(e)}
    return results

def detect_tampering(results):
    """对比多路径结果，检测内容篡改"""
    hashes = [r['hash'] for r in results.values() if 'hash' in r]
    if len(set(hashes)) > 1:
        return {
            'tampered': True,
            'detail': f'内容不一致: {len(set(hashes))}种不同哈希',
            'results': results
        }
    return {'tampered': False, 'detail': '内容一致'}

if __name__ == '__main__':
    results = fetch_via_multiple_paths('http://httpbin.org/html')
    tamper_check = detect_tampering(results)
    print(f'检测结果: {tamper_check}')
```

### 3.3 HTTP 302 劫持(流量重定向)

运营商在 HTTP 响应中插入 `302 Found` 状态码或 `Location` 头，将用户重定向到第三方页面。常见于：

- **域名过期页面**：域名已过期但用户仍访问，ISP 返回 302 跳转到广告页
- **网站无法访问**：目标服务器故障，ISP 返回 302 跳转到"导航页"
- **恶意流量劫持**：将电商流量重定向到带 ISP 返利链接的 URL

```bash
# 检测302劫持
curl -v http://可能被劫持的域名 2>&1 | grep -E "< HTTP|< Location|< Via"
# 观察是否出现非预期的302 + Location头

# 对比正常网络(手机热点)下的响应
# 若运营商网络返回302而手机热点返回200 → 运营商302劫持
```

### 3.4 iframe 劫持与弹窗注入

运营商在 HTTP 页面中嵌入 `<iframe>` 或注入 JavaScript 弹窗：

```html
<!-- 运营商注入的典型代码 -->
<!-- 底部iframe广告 -->
<iframe src="http://isp-ad.com/banner" width="100%" height="80" frameborder="0"></iframe>

<!-- 悬浮弹窗 -->
<script>
(function(){
  var d=document.createElement('div');
  d.innerHTML='<div style="position:fixed;bottom:0;z-index:99999;">ISP广告</div>';
  document.body.appendChild(d);
})();
</script>

<!-- 整页遮罩层 -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:99999;
  background:rgba(0,0,0,0.5);" onclick="location.href='http://isp-ad.com'">
  <div style="margin:20% auto;width:400px;background:white;padding:20px;">
    温馨提示：请点击领取流量包
  </div>
</div>
```

---

## 4. HTTPS 层运营商劫持

HTTPS 设计目标就是防中间人篡改，但运营商有多种手段绕过。这是运营商劫持最危险也最隐蔽的层面。

### 4.1 SSL/TLS 剥离(SSL Stripping)

运营商将用户的 HTTPS 请求**降级为 HTTP**，从而恢复明文可见性。用户浏览器地址栏显示 `http://` 而非 `https://`，但大部分用户不会注意。

```
用户                     ISP透明代理                  网站
  │                         │                           │
  │── https://bank.com ──>│                           │
  │                         │  降级为 HTTP              │
  │                         │── http://bank.com ──────>│
  │                         │                           │
  │                         │<── HTTP 301 → HTTPS ─────│
  │                         │   (网站要求升级)           │
  │                         │                           │
  │                         │── https://bank.com ──────>│
  │                         │<── TLS 握手，运营商有证书  │
  │                         │                           │
  │<── HTTP 200 OK ────────│                           │
  │    用户侧是HTTP         │  运营商侧是HTTPS            │
  │    内容可被篡改         │  内容加密传输              │
```

**SSL 剥离的防护**：HSTS(HTTP Strict Transport Security)预加载。浏览器内置 HSTS 列表，对已知域名**强制 HTTPS**，不先尝试 HTTP，从根本上阻断剥离。

```bash
# 检测SSL剥离
# 1. 手动访问 http:// 知名网站(如 http://google.com)
# 若浏览器未自动跳转到 https:// → 可能在SSL剥离中
# 正确行为：浏览器用HSTS自动升级到https://

# 2. 检查HSTS状态
curl -I https://google.com 2>&1 | grep -i strict-transport
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### 4.2 证书替换(HTTPS中间人)

比 SSL 剥离更隐蔽——运营商**替换 HTTPS 证书**，使用自己的证书与用户建立 TLS 连接，再用另一条 TLS 连接与真实服务器通信。用户看到的是 HTTPS，但证书是 ISP 的。

```
用户                      ISP MITM代理                   网站
  │                          │                             │
  │── TLS ClientHello ────>│                             │
  │                          │── TLS ClientHello ────────>│
  │<── ISP证书(ISP-CA签发)──│<── 真实网站证书 ──────────────│
  │                          │                             │
  │── 数据(ISP密钥加密) ──>│── 数据(网站密钥加密) ──────>│
  │                          │                             │
  ★ 用户看到HTTPS + 锁图标    ★ 但证书是ISP的
  ★ ISP可以解密、查看、篡改所有"加密"流量
```

**证书替换的前提条件**：
- 运营商 CA 根证书**预装**在用户设备/浏览器信任存储中
- 或通过**企业 MDM/设备管理**推送根证书
- 或利用**用户习惯**——点击"继续访问"绕过证书警告

**检测方法**：

```bash
# 1. 检查证书颁发者
openssl s_client -connect www.example.com:443 -servername www.example.com 2>&1 | \
  openssl x509 -noout -issuer -subject -fingerprint

# 2. 对比不同网络下的证书指纹
# 同一域名在运营商网络 vs 手机热点下的证书指纹应一致
# 若不一致(且非正常证书轮换) → 疑似证书替换

# 3. 证书透明度(Certificate Transparency)验证
# 在 crt.sh 查询域名的证书日志，看是否出现非预期的ISP证书
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq '.[].issuer_name'

# 4. 浏览器检查
# Chrome: F12 → Security → View Certificate → 查看颁发者
# 若颁发者是未知CA且非公共CA(Firefox/Chrome内置的) → 可能是运营商证书
```

### 4.3 CDN 边缘节点劫持

运营商与 CDN 厂商合作或自建 CDN 节点，在边缘节点上篡改内容。由于 CDN 节点本身拥有合法的 SSL 证书(CDN 厂商持有)，用户侧无法检测到证书异常。

现实中的"CDN 劫持"场景：
- **CDN 节点被入侵**：攻击者控制 CDN 节点后篡改内容，用户看到的是"合法 CDN 节点"的篡改内容
- **CDN 内部人**：CDN 员工在节点上注入广告/挖矿脚本
- **运营商伪 CDN**：运营商声称自己是 CDN 合作节点，但实际在篡改内容

```bash
# 检测CDN劫持
# 1. 对比不同CDN边缘节点的响应
# 用不同地区的代理/VPN访问同一CDN资源，对比哈希

# 2. 检查CDN节点的IP归属
# 若CDN域名的解析IP属于运营商AS而非CDN厂商AS → 疑似伪CDN
dig cdn.example.com +short | xargs -I {} whois {} | grep -i "netname\|org-name"

# 3. 子资源完整性(SRI)校验
# 在HTML中用integrity属性校验JS/CSS文件的哈希
# <script src="//cdn.example.com/lib.js" integrity="sha384-xxx"></script>
# 若CDN返回的内容被篡改，浏览器会拒绝加载
```

### 4.4 2026 QUIC/HTTP3 劫持

QUIC(HTTP3 底层协议)强制加密，理论上比 TCP+TLS 更难劫持。但 2026 年已出现多种绕过：

- **QUIC 降级攻击**：运营商阻断 UDP 443(QUIC 端口)，强制浏览器回退到 TCP+TLS，再执行 TLS 劫持
- **QUIC 版本协商劫持**：在 QUIC 握手阶段伪造版本协商包，降级到有已知漏洞的旧版本
- **ECH(加密ClientHello)绕过**：ECH 加密了 SNI 域名，但运营商可通过 IP 地址/流量特征推断目标域名，选择性阻断

---

## 5. BGP 劫持与路由操纵

BGP(Border Gateway Protocol)是互联网的"导航系统"——自治系统(AS)之间通过 BGP 宣告 IP 前缀的可达性。BGP 劫持是运营商级别最底层、影响范围最大的劫持方式。

### 5.1 BGP 劫持基础

BGP 劫持(前缀劫持)：攻击者(或恶意 ISP)向 BGP 对等体宣告**不属于自己**的 IP 前缀，使互联网流量被牵引到攻击者控制的 AS。

```
正常路由:
  用户 → ISP-A → 中转AS → ISP-B → 目标(1.2.3.0/24)
  
BGP劫持:
  用户 → ISP-A → 中转AS → 恶意AS(宣告了1.2.3.0/24) → 攻击者服务器
                                        ↓
                               目标(1.2.3.0/24) 流量被窃取
```

**BGP 劫持的三种类型**：

| 类型 | 说明 | 影响范围 | 持续性 |
|------|------|---------|--------|
| 前缀劫持 | 宣告不属于自己的更具体前缀(如 /25 而非 /24) | 全网 | 直到路由撤回 |
| 路径篡改 | 修改 AS_PATH 使自家路径看起来更短，吸引流量 | 部分网络 | 持续 |
| 路由泄露 | 将内部路由错误宣告到公网(如 2021年 Facebook 宕机) | 全网 | 直到修复 |

### 5.2 运营商 BGP 劫持的"合法外衣"

运营商 BGP 劫持与恶意攻击不同，常披着"合法"外衣：

- **流量工程**：运营商声称"优化路由"将流量经自家网络传输，实际实现了流量监控
- **政府要求**：以"网络安全"名义封锁特定 IP 段，通过 BGP 黑洞路由实现
- **内容审查**：将特定域名的 IP 段路由到审查设备，经审查后再转发(或直接丢弃)
- **商业竞争**：将竞争对手的流量路由到自家服务，获取商业利益

### 5.3 BGP 劫持检测

```bash
# 1. 查看当前路由路径
traceroute -n 目标IP
mtr -r -n 目标IP

# 2. 对比不同网络的路径
# 从不同AS发起traceroute，观察路径是否一致
# 若某网络路径异常经过非预期AS → 可能BGP劫持

# 3. 使用BGP监控服务
# RouteViews / RIPE RIS 提供全球BGP路由表快照
# 查询某IP前缀的BGP宣告历史
whois -h whois.radb.net -- "-i origin AS12345"   # 查询某AS宣告的前缀

# 4. BGP劫持检测工具
# BGPStream: 实时BGP事件监控
# Is BGP Safe Yet?: 检测特定AS的RPKI/ROV部署状态
```

### 5.4 RPKI 与路由安全

RPKI(Resource Public Key Infrastructure)是 BGP 劫持的根本防御——IP 前缀持有者通过数字签名声明"只有我授权宣告这个前缀"，路由器验证签名后拒绝未授权的宣告。

```bash
# 检查某前缀的ROA(Route Origin Authorization)
# 使用RIPE NCC的RPKI验证器
curl -s "https://stat.ripe.net/data/rpki-validation/data.json?resource=1.2.3.0/24" | jq

# 查看某AS的RPKI部署状态
# https://isbgpsafeyet.com/
```

---

## 6. DPI 深度包检测与流量操纵

DPI(Deep Packet Inspection)是运营商实现精细化流量劫持的核心设备——不仅识别 IP/端口，更深入解析**应用层协议**(HTTP/DNS/TLS/QUIC)，对特定流量执行阻断、注入、限速、重定向。

### 6.1 DPI 工作原理

```
正常路由器(无DPI):
  查看 IP 头 + TCP/UDP 端口 → 转发

DPI设备:
  查看 IP 头 + TCP/UDP 端口
  + 重组 TCP 流
  + 解析应用层协议(HTTP头/DNS查询/TLS SNI/QUIC连接ID)
  + 匹配规则库(URL关键词/IP黑名单/协议特征)
  + 执行动作(放行/阻断/注入/限速/重定向/记录)
```

### 6.2 DPI 实现的劫持能力

| 能力 | 实现方式 | 典型场景 |
|------|---------|---------|
| URL 过滤 | 解析 HTTP Host 头/SNI，匹配黑名单 | 网站封锁 |
| 关键词过滤 | 解析 HTTP 响应体，匹配敏感词 | 内容审查 |
| 协议识别 | 通过流量特征识别协议(P2P/VPN/游戏) | 限速/阻断 |
| 应用层注入 | 在 HTTP 响应中插入 JavaScript/广告 | 广告投放 |
| 流量重定向 | 将特定流量 DNAT 到审查/缓存服务器 | 强制缓存 |
| TLS 指纹 | 通过 JA3/JA4 指纹识别客户端 | 阻断特定浏览器/TLS库 |
| 会话劫持 | 注入 TCP RST 包强制断开连接 | 阻断特定网站 |
| 深度限速 | 对特定应用(视频/下载)实施差异化限速 | 流量经营 |

### 6.3 DPI 检测与绕过

```bash
# 1. 检测TCP RST注入(DPI阻断)
# 用tcpdump抓包，观察是否收到非预期的RST包
tcpdump -i eth0 'tcp[tcpflags] & (tcp-rst) != 0' -n

# 2. 检测TLS SNI阻断
# 对比不同SNI的TLS握手成功率
# 若特定域名的TLS握手失败但用IP直接访问成功 → SNI阻断
openssl s_client -connect 目标IP:443 -servername 被封域名  # 测试SNI

# 3. 绕过DPI的常见方式
# VPN/代理(全流量加密，DPI无法识别内容)
# ECH/ESNI(加密SNI，DPI无法识别域名)
# 协议混淆(如Shadowsocks/VMess/VLESS伪装成HTTPS流量)
# 域前置(Domain Fronting，SNI=CDN域名，Host=真实域名)
```

---

## 7. 透明代理与缓存投毒

透明代理是运营商劫持的"执行引擎"——对用户透明(无需配置代理)地拦截、缓存、修改 HTTP/HTTPS 流量。

### 7.1 透明代理部署架构

```
用户                      ISP核心路由器                      互联网
  │                          │                                │
  │── HTTP请求 ───────────>│                                │
  │                          │  ★ 策略路由匹配                 │
  │                          │  dst_port=80 → 旁路到透明代理   │
  │                          │  dst_port=443 → 正常转发        │
  │                          │                                │
  │                          │── 转发到透明代理 ──>│            │
  │                          │                    │ 缓存命中?  │
  │                          │                    │ → 是: 返回缓存(可能过期/篡改)
  │                          │                    │ → 否: 向源站请求
  │                          │<── 返回响应 ───────│            │
  │<── HTTP响应(可能被篡改)──│                                │
```

### 7.2 透明代理的劫持能力

| 能力 | 说明 |
|------|------|
| 缓存投毒 | 返回过期/篡改的缓存内容 |
| 内容注入 | 在 HTTP 响应中插入广告/脚本 |
| 流量复制 | 将流量镜像到监控/审计系统 |
| 访问控制 | 阻断特定 URL/IP |
| 数据压缩 | 压缩图片/视频(同时降低质量) |

### 7.3 检测透明代理

```bash
# 1. 检查响应头中的Via/X-Forwarded-For/X-Cache头
curl -v http://example.com 2>&1 | grep -iE "Via:|X-Cache:|X-Forwarded-For:"

# 2. 检查HTTP响应中的异常
# 透明代理可能修改Content-Length，导致响应体与声明长度不一致
curl -s -o /tmp/response http://example.com
actual=$(wc -c < /tmp/response)
declared=$(curl -sI http://example.com | grep -i Content-Length | awk '{print $2}' | tr -d '\r')
echo "声明: $declared, 实际: $actual"

# 3. 用不同的TTL值探测缓存行为
# 向同一URL发多次请求，观察响应是否一致
# 若响应始终相同(即使源站已更新) → 缓存投毒
```

---

## 8. 2026 最新技术：下一代运营商劫持与对抗

### 8.1 5G 信令劫持

5G 核心网(5GC)基于服务化架构(SBA)，信令面与控制面分离。运营商可利用 5G 信令实现更精细的流量劫持：

- **NEF(Network Exposure Function)** 滥用：运营商通过 NEF 向第三方开放用户位置/流量信息，可被滥用于定向劫持
- **NWDAF(网络数据分析功能)** 辅助：AI 驱动的流量分析，识别用户行为模式，实现个性化劫持(如对特定用户画像投放广告)
- **5G 切片劫持**：在同一物理网络上创建多个虚拟切片，将特定流量引导到受控切片

### 8.2 eSIM 远程配置劫持

eSIM 允许运营商远程推送配置文件到设备。若运营商被攻破或恶意，可推送篡改的配置文件，使设备使用攻击者控制的 APN/代理/DNS。

### 8.3 QUIC/HTTP3 深度劫持

2026 年 QUIC 普及率已超过 40%，运营商开始部署 QUIC 感知的 DPI 设备：

- **QUIC 连接迁移劫持**：QUIC 支持连接迁移(切换 IP 不中断)，攻击者可劫持迁移过程
- **QUIC 0-RTT 重放**：0-RTT 数据可被重放，运营商可重放用户的 QUIC 请求
- **HTTP3 QPACK 注入**：HTTP3 使用 QPACK 头压缩，DPI 设备在解压后注入头部

### 8.4 ECH 绕过与对抗

ECH(Encrypted ClientHello)加密了 TLS 握手中的 SNI 域名，使 DPI 无法识别目标域名。2026 年运营商的对抗手段：

- **IP 地址关联**：即使 SNI 加密，IP 地址仍暴露。运营商维护 IP→域名映射数据库，通过目标 IP 反推域名
- **流量指纹**：通过数据包大小、时序、连接模式等特征识别目标服务(如 YouTube 的流量模式独特)
- **ECH 降级**：在 DNS 层面阻断 ECH 所需的 HTTPS/SVCB DNS 记录，使客户端回退到明文 SNI

### 8.5 2026 运营商劫持检测的新思路

```python
#!/usr/bin/env python3
"""2026 运营商流量劫持综合检测"""
import hashlib
import time
import socket
import ssl
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class HijackDetectionResult:
    layer: str          # 检测层(DNS/HTTP/HTTPS/BGP)
    hijacked: bool
    evidence: str
    confidence: float   # 置信度 0-1

class ISPHijackDetector:
    """运营商流量劫持综合检测器"""
    
    def __init__(self, target_domain: str, target_ip: Optional[str] = None):
        self.domain = target_domain
        self.target_ip = target_ip
        self.results: List[HijackDetectionResult] = []
    
    def run_all_checks(self):
        self._check_dns_layer()
        self._check_http_layer()
        self._check_https_layer()
        self._check_bgp_layer()
        return self._summarize()
    
    def _check_dns_layer(self):
        """DNS层检测：多源对比 + NXDOMAIN劫持"""
        resolvers = {
            'google': '8.8.8.8',
            'cloudflare': '1.1.1.1',
            'quad9': '9.9.9.9'
        }
        ips = {}
        for name, ns in resolvers.items():
            try:
                result = socket.getaddrinfo(self.domain, 80, socket.AF_INET)
                ips[name] = sorted(set(r[4][0] for r in result))
            except Exception as e:
                ips[name] = [f'error: {e}']
        
        unique = set(tuple(v) for v in ips.values())
        if len(unique) > 1:
            self.results.append(HijackDetectionResult(
                layer='DNS', hijacked=True, confidence=0.7,
                evidence=f'多源DNS不一致: {ips}'
            ))
        else:
            self.results.append(HijackDetectionResult(
                layer='DNS', hijacked=False, confidence=0.3,
                evidence=f'多源DNS一致: {ips}'
            ))
    
    def _check_http_layer(self):
        """HTTP层检测：检查响应中是否有注入的广告/脚本"""
        try:
            import urllib.request
            req = urllib.request.Request(f'http://{self.domain}',
                headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read().decode('utf-8', errors='ignore')
            headers = dict(resp.headers)
            
            # 检测广告注入特征
            ad_patterns = ['isp-ad', 'popup_ad', 'traffic_package', '流量包',
                          'iframe.*ad', 'suspension.*ad']
            evidence = []
            for p in ad_patterns:
                import re
                if re.search(p, body, re.IGNORECASE):
                    evidence.append(f'发现广告注入特征: {p}')
            
            if evidence:
                self.results.append(HijackDetectionResult(
                    layer='HTTP', hijacked=True, confidence=0.8,
                    evidence='; '.join(evidence)
                ))
            else:
                self.results.append(HijackDetectionResult(
                    layer='HTTP', hijacked=False, confidence=0.4,
                    evidence='未发现广告注入特征'
                ))
        except Exception as e:
            self.results.append(HijackDetectionResult(
                layer='HTTP', hijacked=False, confidence=0.1,
                evidence=f'HTTP检测失败: {e}'
            ))
    
    def _check_https_layer(self):
        """HTTPS层检测：证书指纹对比"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((self.domain, 443), timeout=10)
            with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                serial = cert.get('serialNumber', '')
                
                self.results.append(HijackDetectionResult(
                    layer='HTTPS', hijacked=False, confidence=0.4,
                    evidence=f'颁发者: {issuer.get("CN", "unknown")}, '
                           f'序列号: {serial}'
                ))
        except Exception as e:
            self.results.append(HijackDetectionResult(
                layer='HTTPS', hijacked=False, confidence=0.1,
                evidence=f'HTTPS检测失败: {e}'
            ))
    
    def _check_bgp_layer(self):
        """BGP层检测：traceroute路径分析"""
        try:
            result = subprocess.run(
                ['traceroute', '-n', '-m', '15', '-q', '2', self.target_ip or self.domain],
                capture_output=True, text=True, timeout=30
            )
            self.results.append(HijackDetectionResult(
                layer='BGP', hijacked=False, confidence=0.2,
                evidence=f'路由路径:\n{result.stdout[:500]}'
            ))
        except Exception as e:
            self.results.append(HijackDetectionResult(
                layer='BGP', hijacked=False, confidence=0.1,
                evidence=f'BGP检测失败: {e}'
            ))
    
    def _summarize(self):
        hijacked_layers = [r for r in self.results if r.hijacked]
        return {
            'domain': self.domain,
            'total_checks': len(self.results),
            'hijacked_count': len(hijacked_layers),
            'hijacked_layers': [r.layer for r in hijacked_layers],
            'details': [{'layer': r.layer, 'hijacked': r.hijacked,
                         'evidence': r.evidence} for r in self.results]
        }

if __name__ == '__main__':
    detector = ISPHijackDetector('www.example.com')
    result = detector.run_all_checks()
    print(f'检测结果: {result}')
```

---

## 9. 检测与防御

### 9.1 分层检测矩阵

| 劫持层 | 检测方法 | 工具 | 置信度 |
|--------|---------|------|--------|
| DNS | 多DNS源对比+DoH对比 | dig/kdig/curl DoH | 高 |
| DNS | NXDOMAIN劫持测试 | dig 随机域名 | 高 |
| HTTP | 响应体哈希对比 | curl + sha256 | 中 |
| HTTP | 广告注入特征匹配 | curl + grep | 中 |
| HTTP | Via/X-Cache头检测 | curl -v | 中 |
| HTTPS | 证书指纹跨网络对比 | openssl s_client | 高 |
| HTTPS | 证书透明度日志查询 | crt.sh | 高 |
| HTTPS | HSTS状态检测 | curl -I | 中 |
| BGP | 多网络traceroute对比 | mtr/traceroute | 中 |
| BGP | BGP路由表监控 | RouteViews/RIPE RIS | 高 |
| DPI | TLS指纹/SNI阻断测试 | openssl + 自定义JA3 | 中 |
| 透明代理 | 响应体与Content-Length一致性 | curl | 中 |

### 9.2 防御矩阵

| 防御措施 | 防御层级 | 效果 | 部署难度 |
|---------|---------|------|---------|
| 全站HTTPS + HSTS预加载 | HTTP/HTTPS | 防HTTP劫持/SSL剥离 | 低 |
| DoH/DoT加密DNS | DNS | 防DNS劫持/透明代理 | 低 |
| DNSSEC验证 | DNS | 防DNS伪造 | 低 |
| 证书透明度监控 | HTTPS | 发现证书替换 | 中 |
| SRI子资源完整性 | HTTP/HTTPS | 防CDN劫持 | 低 |
| VPN/代理(全流量加密) | 所有层 | 防所有层劫持(绕过DPI) | 中 |
| ECH加密SNI | HTTPS | 防SNI阻断/识别 | 中 |
| RPKI路由验证 | BGP | 防BGP劫持 | 高(ISP侧) |
| 多网络对比验证 | 所有层 | 发现劫持 | 低(检测用) |
| 端到端加密(应用层) | 所有层 | 即使BGP劫持也防窃听 | 中 |

### 9.3 终端用户防护清单

```text
[优先级1 — 立即生效]
├─ 浏览器启用DoH (Chrome: chrome://settings/security → 使用安全DNS)
├─ 操作系统启用DoH (Windows 11: 网络设置 → DNS → 首选加密DNS)
├─ 安装HTTPS Everywhere或启用浏览器"始终使用HTTPS"
└─ 检查系统证书信任存储，移除未知CA

[优先级2 — 持续监控]
├─ 定期用 crt.sh 检查所管理域名的证书透明度日志
├─ 对关键网站用SRI校验第三方资源
├─ 对比不同网络(运营商+手机热点+境外VPN)下的访问结果
└─ 关注BGP劫持事件(如通过BGPStream订阅)

[优先级3 — 企业/服务方]
├─ 部署DNSSEC签名
├─ 启用HSTS预加载(提交到 hstspreload.org)
├─ 部署RPKI ROA保护IP前缀
├─ CDN选择支持SRI和证书透明度
└─ 监控CDN节点的内容一致性
```

---

## 10. 交互式HTML原理演示

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>运营商流量劫持原理演示</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family:"Microsoft YaHei","Noto Sans CJK SC",sans-serif; }
body { background:#f0f2f5; padding:30px; color:#2c3e50; }
.container { max-width:1000px; margin:0 auto; }
h1 { font-size:24px; margin-bottom:10px; color:#1a1a2e; }
.subtitle { color:#6c757d; margin-bottom:25px; line-height:1.6; }
.tabs { display:flex; gap:6px; margin-bottom:0; flex-wrap:wrap; }
.tab { padding:12px 18px; background:#dee2e6; border:none; border-radius:8px 8px 0 0; cursor:pointer; font-size:13px; transition:all .2s; }
.tab.active { background:#1a1a2e; color:#fff; }
.panel { display:none; background:#fff; padding:24px; border-radius:0 0 10px 10px; min-height:420px; }
.panel.active { display:block; }
.btn { padding:10px 22px; border:none; border-radius:6px; cursor:pointer; font-size:14px; margin:6px 8px 6px 0; transition:all .2s; }
.btn-primary { background:#007bff; color:#fff; }
.btn-primary:hover { background:#0056b3; }
.btn-danger { background:#dc3545; color:#fff; }
.btn-danger:hover { background:#b02a37; }
.btn-warn { background:#fd7e14; color:#fff; }
.btn-warn:hover { background:#d6690e; }
.btn-success { background:#28a745; color:#fff; }
.btn-success:hover { background:#1e7e34; }
.result { margin-top:18px; padding:16px; background:#f8f9fa; border:1px solid #e9ecef; border-radius:6px; min-height:80px; line-height:1.8; font-size:14px; }
.log { font-family:"Courier New",monospace; background:#1a1a2e; color:#0f0; padding:14px; border-radius:6px; margin:10px 0; white-space:pre; overflow-x:auto; font-size:13px; }
.normal { color:#28a745; font-weight:bold; }
.danger { color:#dc3545; font-weight:bold; }
.warn { color:#fd7e14; font-weight:bold; }
table { width:100%; border-collapse:collapse; margin:12px 0; font-size:13px; }
th,td { border:1px solid #dee2e6; padding:8px 12px; text-align:left; }
th { background:#e9ecef; }
.tag { display:inline-block; padding:4px 10px; border-radius:12px; font-size:12px; margin:3px; }
.tag-dns { background:#cce5ff; color:#004085; }
.tag-http { background:#d4edda; color:#155724; }
.tag-https { background:#fff3cd; color:#856404; }
.tag-bgp { background:#f8d7da; color:#721c24; }
.flow { display:flex; align-items:center; gap:10px; margin:15px 0; flex-wrap:wrap; }
.flow-node { background:#e9ecef; padding:10px 16px; border-radius:6px; text-align:center; font-size:13px; }
.flow-arrow { font-size:18px; color:#6c757d; }
.badge { background:#dc3545; color:#fff; padding:2px 8px; border-radius:10px; font-size:11px; }
</style>
</head>
<body>
<div class="container">
<h1>运营商流量劫持原理演示</h1>
<p class="subtitle">运营商(ISP)可在DNS、HTTP、HTTPS、BGP多层对流量实施劫持。本演示可视化各层劫持原理，帮助理解劫持机制与检测方法。</p>

<div class="tabs">
<button class="tab active" onclick="switchTab(0)">1. DNS劫持</button>
<button class="tab" onclick="switchTab(1)">2. HTTP注入</button>
<button class="tab" onclick="switchTab(2)">3. HTTPS剥离</button>
<button class="tab" onclick="switchTab(3)">4. BGP劫持</button>
<button class="tab" onclick="switchTab(4)">5. 综合检测</button>
</div>

<!-- 面板1: DNS劫持 -->
<div class="panel active" id="panel0">
<h3>DNS层 — NXDOMAIN劫持 · 透明代理 · CDN调度干扰</h3>
<div class="flow">
  <div class="flow-node">用户输入<br>不存在的域名</div>
  <span class="flow-arrow">→</span>
  <div class="flow-node">ISP DNS<br>递归查询</div>
  <span class="flow-arrow">→</span>
  <div class="flow-node" style="background:#f8d7da;border:2px solid #dc3545;">不返回NXDOMAIN<br>返回广告页IP <span class="badge">劫持</span></div>
  <span class="flow-arrow">→</span>
  <div class="flow-node">用户看到<br>ISP搜索/广告页</div>
</div>
<button class="btn btn-primary" onclick="simNormalDNS()">模拟正常DNS</button>
<button class="btn btn-danger" onclick="simNXDhijack()">模拟NXDOMAIN劫持</button>
<button class="btn btn-warn" onclick="simTransparentDNS()">模拟透明DNS代理</button>
<div class="result" id="result0"><b>等待操作：</b>点击按钮模拟DNS层劫持场景</div>
</div>

<!-- 面板2: HTTP注入 -->
<div class="panel active" id="panel1" style="display:none">
<h3>HTTP层 — 广告注入 · 内容篡改 · iframe嵌入</h3>
<button class="btn btn-primary" onclick="simNormalHTTP()">模拟正常HTTP响应</button>
<button class="btn btn-danger" onclick="simAdInject()">模拟广告注入</button>
<button class="btn btn-warn" onclick="simContentTamper()">模拟内容篡改</button>
<button class="btn btn-success" onclick="simDetectHTTP()">运行检测</button>
<div class="result" id="result1"><b>原始响应：</b>点击按钮模拟HTTP层劫持</div>
</div>

<!-- 面板3: HTTPS剥离 -->
<div class="panel active" id="panel2" style="display:none">
<h3>HTTPS层 — SSL剥离 · 证书替换 · CDN边缘劫持</h3>
<div class="flow">
  <div class="flow-node">用户请求<br>https://bank.com</div>
  <span class="flow-arrow">→</span>
  <div class="flow-node" style="background:#f8d7da;border:2px solid #dc3545;">ISP SSL剥离<br>降级为HTTP <span class="badge">劫持</span></div>
  <span class="flow-arrow">→</span>
  <div class="flow-node">用户侧HTTP<br>内容可被篡改</div>
  <span class="flow-arrow">→</span>
  <div class="flow-node">ISP侧HTTPS<br>与真实服务器通信</div>
</div>
<button class="btn btn-primary" onclick="simNormalHTTPS()">模拟正常HTTPS</button>
<button class="btn btn-danger" onclick="simSSLStrip()">模拟SSL剥离</button>
<button class="btn btn-warn" onclick="simCertReplace()">模拟证书替换</button>
<div class="result" id="result2"><b>证书信息：</b>点击按钮模拟HTTPS层劫持</div>
</div>

<!-- 面板4: BGP劫持 -->
<div class="panel active" id="panel3" style="display:none">
<h3>BGP层 — 前缀劫持 · 路由操纵 · 流量牵引</h3>
<div class="flow">
  <div class="flow-node">用户<br>AS-A</div>
  <span class="flow-arrow">→</span>
  <div class="flow-node" style="background:#f8d7da;border:2px solid #dc3545;">恶意AS<br>宣告1.2.3.0/24 <span class="badge">劫持</span></div>
  <span class="flow-arrow">→</span>
  <div class="flow-node">攻击者<br>服务器</div>
</div>
<p style="margin-top:10px;color:#6c757d;">正常路由：用户→AS-A→AS-B→目标(1.2.3.0/24) | 劫持路由：恶意AS宣告更具体前缀(/25)，流量被牵引</p>
<button class="btn btn-primary" onclick="simNormalBGP()">正常BGP路由</button>
<button class="btn btn-danger" onclick="simBGPHijack()">BGP前缀劫持</button>
<button class="btn btn-warn" onclick="simRouteLeak()">路由泄露</button>
<div class="result" id="result3"><b>路由表：</b>点击按钮模拟BGP层劫持</div>
</div>

<!-- 面板5: 综合检测 -->
<div class="panel active" id="panel4" style="display:none">
<h3>综合检测 — 多层级扫描</h3>
<button class="btn btn-primary" onclick="runFullScan()">运行全层扫描</button>
<button class="btn btn-success" onclick="runDefenseCheck()">运行防御评估</button>
<div class="result" id="result4"><b>检测报告：</b>等待运行</div>
</div>

</div>

<script>
function switchTab(i){
  document.querySelectorAll('.tab').forEach((t,idx)=>t.classList.toggle('active',idx===i));
  document.querySelectorAll('.panel').forEach((p,idx)=>p.classList.toggle('active',idx===i));
}

// 面板1: DNS
function simNormalDNS(){
  document.getElementById('result0').innerHTML=`
  <table><tr><th>域名</th><th>查询结果</th><th>状态</th></tr>
  <tr><td>www.demo.com</td><td class="normal">123.45.67.89</td><td>正常</td></tr>
  <tr><td>random123.notexist</td><td class="normal">NXDOMAIN</td><td>正常</td></tr>
  </table><p class="normal">✓ DNS正常：不存在的域名返回NXDOMAIN</p>`;
}
function simNXDhijack(){
  document.getElementById('result0').innerHTML=`
  <table><tr><th>域名</th><th>查询结果</th><th>状态</th></tr>
  <tr><td>random123.notexist</td><td class="danger">ISP广告页 58.xx.xx.xx</td><td>被劫持</td></tr>
  <tr><td>another456.notexist</td><td class="danger">ISP搜索页 58.xx.xx.xx</td><td>被劫持</td></tr>
  </table><p class="danger">⚠ NXDOMAIN劫持：不存在的域名返回ISP广告/搜索页IP。互联网标准要求返回NXDOMAIN，ISP的行为违反DNS协议。</p>
  <p style="color:#6c757d;">检测方法：dig randomstring.notexist +short → 返回IP=劫持，返回空=正常</p>`;
}
function simTransparentDNS(){
  document.getElementById('result0').innerHTML=`
  <div class="log">用户配置DNS: 8.8.8.8
  实际DNS查询: 被ISP路由器DNAT重定向到 10.0.0.1 (ISP DNS)
  
  查询 www.sensitive.com:
    用户期望(8.8.8.8): 返回真实IP
    实际收到(ISP DNS):   返回修改后的IP(或被封锁)
  
  检测: 用DoH查询绕过透明代理
    curl -H "accept: application/dns-json" "https://8.8.8.8/resolve?name=www.sensitive.com"</div>
  <p class="warn">⚠ 透明DNS代理：即使用户配置了第三方DNS，ISP仍可将53端口流量强制重定向到自家DNS</p>`;
}

// 面板2: HTTP
function simNormalHTTP(){
  document.getElementById('result1').innerHTML=`
  <div class="log">HTTP/1.1 200 OK
  Content-Type: text/html
  Content-Length: 512
  
  &lt;html&gt;
  &lt;head&gt;&lt;title&gt;正常页面&lt;/title&gt;&lt;/head&gt;
  &lt;body&gt;
  &lt;h1&gt;欢迎访问&lt;/h1&gt;
  &lt;p&gt;这是原始内容，未被篡改。&lt;/p&gt;
  &lt;/body&gt;
  &lt;/html&gt;</div>
  <p class="normal">✓ 正常HTTP响应：无广告注入，无内容篡改</p>`;
}
function simAdInject(){
  document.getElementById('result1').innerHTML=`
  <div class="log">HTTP/1.1 200 OK
  Content-Type: text/html
  Content-Length: 712  <span class="danger">← ISP修改了Content-Length</span>
  Via: ISP-Transparent-Proxy/2.0  <span class="danger">← ISP透明代理标记</span>
  
  &lt;html&gt;
  &lt;head&gt;&lt;title&gt;正常页面&lt;/title&gt;&lt;/head&gt;
  &lt;body&gt;
  &lt;h1&gt;欢迎访问&lt;/h1&gt;
  &lt;p&gt;这是原始内容。&lt;/p&gt;
  <span class="danger">&lt;script src="//isp-ad.com/ad.js"&gt;&lt;/script&gt;</span>
  <span class="danger">&lt;iframe src="//isp-ad.com/popup"&gt;&lt;/iframe&gt;</span>
  &lt;/body&gt;
  &lt;/html&gt;</div>
  <p class="danger">⚠ HTTP广告注入：ISP在响应体 &lt;/body&gt; 前插入广告脚本和iframe。注入点在原始内容之后，不破坏页面结构。仅影响HTTP明文流量。</p>`;
}
function simContentTamper(){
  document.getElementById('result1').innerHTML=`
  <div class="log">原始响应:          ISP篡改后:
  &lt;title&gt;下载站&lt;/title&gt;   &lt;title&gt;下载站&lt;/title&gt;
  &lt;a href="apk"&gt;下载&lt;/a&gt;   &lt;a href="<span class="danger">ISP-apk</span>"&gt;下载&lt;/a&gt;
  &lt;span&gt;100元&lt;/span&gt;       &lt;span&gt;<span class="danger">80元(ISP渠道)</span>&lt;/span&gt;
  HTTP/1.1 404 Not Found    <span class="danger">HTTP/1.1 302 Found → ISP搜索页</span></div>
  <p class="danger">⚠ 内容篡改：ISP修改下载链接为自家分发、篡改价格、将404劫持为302重定向到搜索页</p>`;
}
function simDetectHTTP(){
  document.getElementById('result1').innerHTML=`
  <table><tr><th>检测项</th><th>结果</th><th>判定</th></tr>
  <tr><td>Via/X-Cache头</td><td class="danger">Via: ISP-Proxy</td><td>疑似透明代理</td></tr>
  <tr><td>Content-Length匹配</td><td class="danger">声明512实际712</td><td>响应体被注入</td></tr>
  <tr><td>广告特征匹配</td><td class="danger">发现isp-ad.com</td><td>确认广告注入</td></tr>
  <tr><td>多网络对比</td><td class="danger">运营商网络≠VPN</td><td>确认运营商劫持</td></tr>
  </table>
  <p class="danger">结论：HTTP层存在运营商广告注入，建议启用全站HTTPS+HSTS</p>`;
}

// 面板3: HTTPS
function simNormalHTTPS(){
  document.getElementById('result2').innerHTML=`
  <div class="log">TLS 1.3 握手成功
  颁发者: CN=DigiCert Global CA
  主题:   CN=*.bank.com
  有效期: 2025-01-01 ~ 2026-01-01
  指纹:   SHA256: a1b2c3d4...</div>
  <p class="normal">✓ 正常HTTPS：证书由公共CA签发，指纹与预期一致</p>`;
}
function simSSLStrip(){
  document.getElementById('result2').innerHTML=`
  <div class="log">用户访问: https://bank.com
  ISP操作: 拦截https请求，降级为http
  用户看到: http://bank.com <span class="danger">(地址栏无锁图标)</span>
  
  ISP侧: ISP与bank.com建立TLS连接(ISP有合法证书)
  用户侧: 用户与ISP间是HTTP明文，内容可被ISP查看/篡改
  
  防御: HSTS预加载 → 浏览器强制HTTPS，不尝试HTTP</div>
  <p class="danger">⚠ SSL剥离：ISP将HTTPS降级为HTTP，用户侧明文传输，ISP可查看/篡改所有内容</p>`;
}
function simCertReplace(){
  document.getElementById('result2').innerHTML=`
  <div class="log">正常证书:           ISP替换证书:
  颁发者: DigiCert      颁发者: <span class="danger">ISP-CA Root</span>
  主题:   *.bank.com     主题:   *.bank.com
  指纹:   a1b2c3d4...    指纹:   <span class="danger">x9y8z7...</span>
  
  用户浏览器: 显示HTTPS + 锁图标 <span class="danger">(但证书是ISP签发的)</span>
  检测: 对比不同网络下的证书指纹 → 不一致则存在证书替换</div>
  <p class="danger">⚠ 证书替换：ISP用自家CA证书替换真实证书。用户看到HTTPS锁图标，但ISP可解密所有流量。前提是ISP根证书预装在用户设备信任存储中。</p>`;
}

// 面板4: BGP
function simNormalBGP(){
  document.getElementById('result3').innerHTML=`
  <div class="log">正常BGP路由:
  AS 用户 → AS 骨干网 → AS 目标ISP → 1.2.3.4 (目标)
  
  AS_PATH: 64500 64501 64502
  跳数: 3
  延迟: 15ms</div>
  <p class="normal">✓ 正常路由：流量沿最短路径到达目标，AS_PATH合理</p>`;
}
function simBGPHijack(){
  document.getElementById('result3').innerHTML=`
  <div class="log">BGP劫持路由:
  AS 用户 → AS 骨干网 → <span class="danger">AS 恶意(宣告了1.2.3.0/25)</span> → 攻击者服务器
  
  AS_PATH: 64500 <span class="danger">64999</span>
  跳数: 2 <span class="danger">(更短→BGP优先选择)</span>
  延迟: <span class="danger">200ms (流量绕到境外)</span>
  
  劫持原理: 恶意AS宣告了更具体的1.2.3.0/25前缀
  BGP选路规则: 最长前缀匹配 → 更具体的/25优先于/24</div>
  <p class="danger">⚠ BGP前缀劫持：恶意AS宣告不属于自己的IP前缀，全球流量被牵引到攻击者。影响范围可能覆盖整个互联网。</p>`;
}
function simRouteLeak(){
  document.getElementById('result3').innerHTML=`
  <div class="log">路由泄露:
  AS内部路由误宣告到公网
  AS_PATH: 64500 64501 64502 64503 64504 64505...
  跳数: 异常长
  
  后果: 流量绕路、延迟增加、部分区域不可达
  案例: 2021年Facebook全球宕机 = BGP路由被撤回</div>
  <p class="warn">⚠ 路由泄露：AS将内部路由错误宣告到公网，导致流量异常绕路或全网不可达</p>`;
}

// 面板5: 综合检测
function runFullScan(){
  const results=[
    {layer:'DNS',status:'hijacked',detail:'NXDOMAIN劫持: 不存在的域名返回ISP广告IP',tag:'tag-dns'},
    {layer:'HTTP',status:'hijacked',detail:'广告注入: 响应体发现isp-ad.com脚本',tag:'tag-http'},
    {layer:'HTTPS',status:'normal',detail:'证书指纹与预期一致',tag:'tag-https'},
    {layer:'BGP',status:'normal',detail:'路由路径正常，AS_PATH=3跳',tag:'tag-bgp'},
    {layer:'DPI',status:'suspicious',detail:'TCP RST注入: 特定域名连接被强制断开',tag:'tag-bgp'},
  ];
  let html='<table><tr><th>检测层</th><th>状态</th><th>详情</th></tr>';
  for(const r of results){
    const cls=r.status==='hijacked'?'danger':r.status==='suspicious'?'warn':'normal';
    html+=`<tr><td><span class="${r.tag}">${r.layer}</span></td><td class="${cls}">${r.status==='hijacked'?'❌ 劫持':r.status==='suspicious'?'⚠ 可疑':'✅ 正常'}</td><td>${r.detail}</td></tr>`;
  }
  html+='</table>';
  html+='<p class="danger">总结：检测到DNS+HTTP层劫持，DPI层可疑。建议：启用DoH+全站HTTPS+HSTS+更换网络对比验证。</p>';
  document.getElementById('result4').innerHTML=html;
}
function runDefenseCheck(){
  document.getElementById('result4').innerHTML=`
  <table><tr><th>防御措施</th><th>状态</th><th>效果</th></tr>
  <tr><td>DoH加密DNS</td><td class="danger">未启用</td><td>启用可防DNS劫持</td></tr>
  <tr><td>全站HTTPS</td><td class="warn">部分启用</td><td>全站HTTPS+HSTS预加载可防HTTP注入</td></tr>
  <tr><td>HSTS预加载</td><td class="danger">未启用</td><td>可防SSL剥离，提交到hstspreload.org</td></tr>
  <tr><td>证书透明度监控</td><td class="danger">未配置</td><td>crt.sh可发现证书替换</td></tr>
  <tr><td>SRI子资源完整性</td><td class="danger">未配置</td><td>防CDN边缘劫持</td></tr>
  <tr><td>RPKI路由验证</td><td class="danger">未部署</td><td>ISP侧防BGP劫持</td></tr>
  </table>
  <p class="danger">防御评分: 2/6 — 建议优先启用DoH+HTTPS+HSTS</p>`;
}
</script>
</body>
</html>
```

---

## 11. 实战排查流程

遇到"网页异常"时的分层排查 SOP：

```text
[步骤1] 判断劫持层级
  ├─ 地址栏是 http:// 还是 https://？ → HTTP可能是注入，HTTPS可能是证书替换
  ├─ 访问多个网站都有问题？ → 运营商劫持(全局) vs 单站问题(网站被黑)
  └─ 换个网络(手机热点)是否正常？ → 是=运营商劫持，否=网站/设备问题

[步骤2] DNS层检测
  ├─ dig 不存在的域名 → 返回IP=NXDOMAIN劫持
  ├─ dig @8.8.8.8 vs @114.114.114.114 → 不一致=DNS挟持
  └─ DoH查询对比：curl DoH API vs 普通dig → 不一致=透明DNS代理

[步骤3] HTTP层检测
  ├─ curl -v 查看响应头 Via/X-Cache → 存在=透明代理
  ├─ 对比Content-Length与实际响应体大小 → 不一致=注入
  └─ curl + grep 搜索广告特征(isp-ad/iframe/popup) → 命中=广告注入

[步骤4] HTTPS层检测
  ├─ openssl s_client 查看证书颁发者 → 非公共CA=证书替换
  ├─ 证书指纹跨网络对比 → 不一致=证书替换
  └─ crt.sh 查询证书透明度日志 → 出现非预期证书=被替换

[步骤5] BGP层检测
  ├─ traceroute 目标IP，对比不同网络路径
  ├─ BGP路由表查询(RouteViews/RIPE RIS)
  └─ 延迟异常增大(>200ms绕路) → 可能BGP劫持

[步骤6] 证据收集与报告
  ├─ 截图+抓包+日志保存
  ├─ 向运营商投诉(附证据)
  └─ 向工信部/通管局举报(运营商不处理时)
```

---

## 12. 注意事项

- **法律边界**：本技能仅用于理解运营商劫持机制与**防御**，检测自身网络是否被劫持。对他人网络实施劫持属违法行为
- **运营商差异**：不同运营商(电信/联通/移动)、不同地区、不同接入方式(光纤/4G/5G)的劫持策略不同，需具体分析
- **HTTPS 不是万能药**：HTTPS 防 HTTP 注入但防不了证书替换(若 ISP 根证书预装)或 SSL 剥离(若无 HSTS)
- **DoH 局限性**：DoH 防 DNS 劫持但防不了 HTTP/HTTPS 层劫持，需配合全站 HTTPS + HSTS
- **VPN 是最终手段**：若运营商劫持严重且无法通过技术手段规避，VPN/代理将全流量加密是最终解决方案
- **与 CDN 劫持的区分**：CDN 正常的多节点调度会导致不同地区解析不同 IP，勿误判为劫持。判断依据：IP 归属 AS 是否为 CDN 厂商或 ISP
- **证据保全**：发现劫持后保留完整的抓包日志、截图、时间戳，作为向运营商/监管机构投诉的证据

---

## 13. 2026 深度强化：运营商劫持下一代技术

> 本节覆盖 2026 年最新运营商级劫持技术演进，包括 AI 驱动的智能 DPI、6G 预研劫持、卫星互联网劫持、量子安全对抗、以及全栈检测工具链。

### 13.1 AI 驱动的智能 DPI (Intelligent Deep Packet Inspection)

2026 运营商 DPI 系统引入机器学习模型，实现协议识别与流量分类的智能化，传统混淆手段面临失效。

**AI-DPI 工作原理**：
- 流量特征提取：包大小序列、到达时间间隔、TLS指纹、TCP窗口行为
- ML 模型分类：随机森林/XGBoost/LSTM 网络流量分类器
- 实时决策：识别 VPN/代理/翻墙协议并触发阻断

```python
# AI-DPI 对抗: 流量指纹混淆器
import numpy as np
from scapy.all import *
import time
import struct

class TrafficObfuscator:
    """对抗 AI-DPI 的流量混淆器"""
    
    def __init__(self):
        self.padding_strategies = {
            "random": lambda: np.random.randint(1, 64),
            "fixed_64": lambda: 64,
            "fixed_128": lambda: 128,
            "mtu_align": lambda: 1500 - np.random.randint(0, 100),
        }
    
    def obfuscate_tls_fingerprint(self, tls_hello_bytes: bytes) -> bytes:
        """混淆 TLS Client Hello 指纹(JA3/JA4)"""
        # 1. 随机化 Cipher Suites 顺序(不影响功能)
        # TLS Hello 中 Cipher Suites 是列表，顺序不影响选择(服务端按优先级选)
        # 但 JA3 指纹依赖顺序，打乱顺序可绕过指纹检测
        
        # 2. 添加 GREASE 扩展(Google Randomized Extensions)
        grease_values = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 
                         0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a]
        
        # 3. 随机化 Extensions 顺序
        # 4. 添加无用扩展填充
        
        return tls_hello_bytes  # 简化示意
    
    def timing_obfuscation(self, packets: list, target_pattern: str = "normal"):
        """混淆包时间间隔模式"""
        if target_pattern == "normal":
            # 模拟正常浏览流量模式
            intervals = np.random.exponential(0.5, len(packets))
        elif target_pattern == "video":
            # 模拟视频流模式(稳定间隔)
            intervals = np.random.normal(0.033, 0.005, len(packets))  # ~30fps
        elif target_pattern == "random":
            # 完全随机化
            intervals = np.random.uniform(0, 2, len(packets))
        
        result = []
        for pkt, interval in zip(packets, intervals):
            result.append(pkt)
            time.sleep(interval)
        return result
    
    def packet_padding(self, packet: bytes, strategy: str = "random") -> bytes:
        """对数据包进行填充，打破包大小指纹"""
        pad_size = self.padding_strategies[strategy]()
        # 使用 TLS Record Layer 的 padding 或 TCP Options 填充
        padding = b'\x00' * pad_size
        return packet + padding

class AIDPIEvader:
    """AI-DPI 规避策略矩阵"""
    
    STRATEGIES = {
        # 策略1: 多路复用混淆 - 将翻墙流量与其他合法流量混合
        "multiplex": {
            "description": "将目标流量与视频流/大文件下载混合",
            "effectiveness": 0.85,
            "overhead": "high",
            "technique": "使用 yamux/smux 多路复用, 将代理通道嵌入正常HTTPS会话中",
        },
        # 策略2: 流量整形 - 模拟特定应用模式
        "shape_to_video": {
            "description": "将流量整形为视频流模式",
            "effectiveness": 0.75,
            "overhead": "medium",
            "technique": "固定包大小(1316字节=HLS分片)+稳定间隔(33ms)",
        },
        # 策略3: 协议伪装 - TLS-in-TLS 隧道
        "tls_in_tls": {
            "description": "在合法TLS连接中嵌套代理TLS连接",
            "effectiveness": 0.90,
            "overhead": "high",
            "technique": "ShadowTLS v3 / XTLS-Reality, 使用真实站点证书作为前置",
        },
        # 策略4: 域前置增强 - ECH + Domain Fronting
        "ech_fronting": {
            "description": "ECH加密SNI + CDN域前置",
            "effectiveness": 0.95,
            "overhead": "low",
            "technique": "ClientHello ECH扩展隐藏真实SNI + CDN Host头指向真实后端",
        },
        # 策略5: 分片与重组
        "fragmentation": {
            "description": "TLS Hello 分片传输，破坏DPI重组",
            "effectiveness": 0.70,
            "overhead": "low",
            "technique": "将ClientHello分为多个TCP段, 在SNI字段边界分片",
        },
    }
    
    def select_strategy(self, detected_dpi_type: str, bandwidth: str = "high"):
        """根据检测到的DPI类型选择最优规避策略"""
        scores = {}
        for name, strat in self.STRATEGIES.items():
            score = strat["effectiveness"]
            if bandwidth == "low" and strat["overhead"] == "high":
                score *= 0.5
            scores[name] = score
        
        best = max(scores, key=scores.get)
        return {
            "recommended": best,
            "strategy": self.STRATEGIES[best],
            "all_scores": scores,
        }
```

### 13.2 卫星互联网劫持 (Satellite Internet Hijacking)

Starlink/Kuiper/OneWeb 等卫星互联网引入新的劫持向量。

```python
# 卫星互联网劫持检测
class SatelliteHijackDetector:
    """检测卫星互联网链路中的劫持行为"""
    
    def __init__(self):
        self.satellite_prefixes = [
            # Starlink IP段 (示例)
            "204.12.0.0/16", "23.134.0.0/16",
            # OneWeb IP段
            "45.135.0.0/16",
        ]
        self.ground_station_hops = []
    
    def detect_satellite_mitm(self, target: str):
        """检测卫星链路中间人"""
        import subprocess
        
        # 1. traceroute 分析卫星跳数
        result = subprocess.run(
            ["traceroute", "-n", "-q", "3", "-w", "5", target],
            capture_output=True, text=True, timeout=60
        )
        
        hops = []
        for line in result.stdout.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 2:
                hop_num = int(parts[0])
                ip = parts[1] if parts[1] != "*" else None
                rtt = [float(p) for p in parts[2:] if p != "*"]
                hops.append({"hop": hop_num, "ip": ip, "rtt": rtt})
        
        # 卫星链路特征: 某跳RTT突然跳升到100ms+ (低轨) 或 600ms+ (高轨)
        satellite_hop = None
        for i, hop in enumerate(hops):
            if hop["rtt"] and any(r > 100 for r in hop["rtt"]):
                # 检查前一跳是否为地面站
                if i > 0 and hops[i-1]["rtt"] and all(r < 50 for r in hops[i-1]["rtt"]):
                    satellite_hop = i
                    break
        
        # 2. 检测卫星链路中的流量注入
        # 卫星ISP可能在卫星网关处注入内容
        findings = {
            "target": target,
            "hops": hops,
            "satellite_hop_detected": satellite_hop is not None,
            "satellite_hop": satellite_hop,
            "potential_hijack": False,
            "evidence": [],
        }
        
        # 3. 对比卫星链路与地面链路的响应差异
        # 在卫星链路中请求HTTP页面, 检查是否被注入额外内容
        try:
            import requests
            r = requests.get(f"http://{target}", timeout=30)
            
            # 检查注入标记
            injection_markers = [
                "<!-- injected", "<script>var _sat", "iframe src=\"http",
                "document.write('<script", "eval(atob(",
            ]
            for marker in injection_markers:
                if marker in r.text:
                    findings["potential_hijack"] = True
                    findings["evidence"].append(f"HTTP响应中发现注入标记: {marker}")
        except:
            pass
        
        return findings
```

### 13.3 BGP 劫持实时检测系统

```python
# BGP 劫持实时监控
import requests
import json
from datetime import datetime, timedelta
from collections import defaultdict

class BGPHijackMonitor:
    """基于公开 BGP 数据源的实时劫持监控"""
    
    def __init__(self):
        self.sources = {
            "routeviews": "http://routeviews.org/bgpdata/",
            "ripe_ris": "https://stat.ripe.net/data/looking-glass/data.json",
            "bgpstream": "https://bgpstream.caida.org/api/v1/",
            "isbgpsafe": "https://isbgpsafeyet.com/api/",
        }
        self.baseline_origins = defaultdict(set)
    
    def check_prefix_hijack(self, prefix: str):
        """检查特定前缀是否被劫持"""
        findings = {
            "prefix": prefix,
            "legitimate_origin": None,
            "current_origins": set(),
            "hijacked": False,
            "hijack_type": None,
            "evidence": [],
        }
        
        # 1. 查询 RIPEstat 获取当前宣告源
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={prefix}"
            r = requests.get(url, timeout=30)
            data = r.json()
            
            if data["status"] == "ok":
                prefixes = data["data"]["prefixes"]
                for p in prefixes:
                    asns = p.get("origin_asn", [])
                    for asn in asns:
                        findings["current_origins"].add(asn)
        except:
            pass
        
        # 2. 查询历史基线
        try:
            url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={prefix}"
            r = requests.get(url, timeout=30)
            data = r.json()
            
            if data["status"] == "ok":
                asns = data["data"]["asns"]
                for asn_info in asns:
                    findings["legitimate_origin"] = asn_info["asn"]
        except:
            pass
        
        # 3. 判断劫持
        if findings["legitimate_origin"] and findings["current_origins"]:
            if findings["legitimate_origin"] not in findings["current_origins"]:
                # 源被完全替换 → 前缀劫持
                findings["hijacked"] = True
                findings["hijack_type"] = "prefix_hijack"
                findings["evidence"].append(
                    f"合法源 AS{findings['legitimate_origin']} 不在当前宣告源中"
                )
            elif len(findings["current_origins"]) > 1:
                # 多源宣告 → 子前缀劫持或路由泄露
                findings["hijacked"] = True
                findings["hijack_type"] = "subprefix_hijack"
                findings["evidence"].append(
                    f"多源宣告: {findings['current_origins']} (合法: AS{findings['legitimate_origin']})"
                )
        
        # 4. 检查 RPKI/ROV 状态
        try:
            url = f"https://stat.ripe.net/data/rpki-validation/data.json?resource={prefix}"
            r = requests.get(url, timeout=30)
            data = r.json()
            if data["status"] == "ok":
                validating = data["data"]["validating_roas"]
                if validating:
                    roa_status = validating[0].get("status", "unknown")
                    findings["rpki_status"] = roa_status
                    if roa_status == "invalid":
                        findings["evidence"].append("RPKI 验证失败: ROA 不匹配")
        except:
            pass
        
        return findings
    
    def monitor_bgp_events(self, watch_prefixes: list, alert_callback=None):
        """持续监控 BGP 事件"""
        print(f"[*] 开始监控 {len(watch_prefixes)} 个前缀的 BGP 状态...")
        
        # 建立基线
        for prefix in watch_prefixes:
            result = self.check_prefix_hijack(prefix)
            if result["legitimate_origin"]:
                self.baseline_origins[prefix] = {result["legitimate_origin"]}
            print(f"  基线: {prefix} → AS{result.get('legitimate_origin', '?')}")
        
        # 持续监控
        import time
        while True:
            for prefix in watch_prefixes:
                result = self.check_prefix_hijack(prefix)
                if result["hijacked"]:
                    alert = {
                        "timestamp": datetime.now().isoformat(),
                        "prefix": prefix,
                        "type": result["hijack_type"],
                        "evidence": result["evidence"],
                        "current_origins": list(result["current_origins"]),
                    }
                    print(f"[!!!] BGP 劫持告警: {json.dumps(alert, indent=2)}")
                    if alert_callback:
                        alert_callback(alert)
            time.sleep(300)  # 每5分钟检查一次

# 使用示例
if __name__ == "__main__":
    monitor = BGPHijackMonitor()
    # 监控 Google DNS 的前缀
    result = monitor.check_prefix_hijack("8.8.8.0/24")
    print(json.dumps(result, indent=2, default=str))
```

### 13.4 证书透明度监控与劫持检测

```python
# 证书透明度日志监控
import requests
import json
from datetime import datetime, timedelta
import hashlib

class CTLogMonitor:
    """通过证书透明度日志检测运营商证书替换劫持"""
    
    def __init__(self):
        self.ct_sources = [
            "https://crt.sh/?q={}&output=json",
            "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        ]
        self.known_cas = set()  # 已知的合法CA列表
        self.baseline_certs = {}  # domain -> [cert_fingerprints]
    
    def establish_baseline(self, domain: str):
        """为域名建立证书基线"""
        certs = self._query_ct_logs(domain)
        self.baseline_certs[domain] = {
            "fingerprints": set(),
            "issuers": set(),
            "valid_from": datetime.now().isoformat(),
        }
        
        for cert in certs:
            fp = hashlib.sha256(cert.get("raw", "").encode()).hexdigest()
            self.baseline_certs[domain]["fingerprints"].add(fp)
            issuer = cert.get("issuer_name", cert.get("issuer_ca_id", "unknown"))
            self.baseline_certs[domain]["issuers"].add(str(issuer))
        
        print(f"[+] {domain} 基线: {len(self.baseline_certs[domain]['fingerprints'])} 个证书, "
              f"签发者: {self.baseline_certs[domain]['issuers']}")
        return self.baseline_certs[domain]
    
    def detect_hijack(self, domain: str):
        """检测域名是否被签发了未授权证书(运营商中间人)"""
        current_certs = self._query_ct_logs(domain)
        
        if domain not in self.baseline_certs:
            self.establish_baseline(domain)
        
        baseline = self.baseline_certs[domain]
        new_certs = []
        suspicious_certs = []
        
        for cert in current_certs:
            fp = hashlib.sha256(cert.get("raw", "").encode()).hexdigest()
            issuer = str(cert.get("issuer_name", cert.get("issuer_ca_id", "unknown")))
            
            if fp not in baseline["fingerprints"]:
                new_certs.append(cert)
                # 检查签发者是否为已知合法CA
                if baseline["issuers"] and issuer not in baseline["issuers"]:
                    suspicious_certs.append({
                        "domain": domain,
                        "fingerprint": fp,
                        "issuer": issuer,
                        "not_before": cert.get("not_before"),
                        "reason": "签发者不在基线CA列表中",
                    })
        
        # 检查运营商特定CA模式
        isp_ca_indicators = [
            "China Telecom", "China Mobile", "China Unicom",
            "CNNIC", "CFCA", "GDCA", "SZCA",  # 国内CA
        ]
        for cert in new_certs:
            issuer = str(cert.get("issuer_name", ""))
            for indicator in isp_ca_indicators:
                if indicator.lower() in issuer.lower():
                    suspicious_certs.append({
                        "domain": domain,
                        "fingerprint": hashlib.sha256(cert.get("raw", "").encode()).hexdigest(),
                        "issuer": issuer,
                        "not_before": cert.get("not_before"),
                        "reason": f"证书由运营商相关CA签发: {indicator}",
                    })
        
        return {
            "domain": domain,
            "total_certs": len(current_certs),
            "new_certs": len(new_certs),
            "suspicious_certs": suspicious_certs,
            "hijack_indicated": len(suspicious_certs) > 0,
        }
    
    def _query_ct_logs(self, domain: str):
        """查询证书透明度日志"""
        try:
            url = self.ct_sources[0].format(domain)
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                return r.json()
        except:
            pass
        try:
            url = self.ct_sources[1].format(domain)
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                return r.json()
        except:
            pass
        return []
```

### 13.5 全栈劫持检测综合工具

```python
# 运营商劫持综合检测器
import subprocess
import requests
import socket
import ssl
import json
import time
from datetime import datetime
from collections import defaultdict

class ISPHijackScanner:
    """运营商劫持全栈综合扫描器"""
    
    def __init__(self):
        self.results = defaultdict(list)
        self.test_domains = [
            "example.com", "google.com", "baidu.com",
            "github.com", "cloudflare.com", "mozilla.org",
        ]
    
    def full_scan(self, target_domain: str = None):
        """执行全栈劫持检测"""
        domains = [target_domain] if target_domain else self.test_domains
        report = {
            "scan_time": datetime.now().isoformat(),
            "tests": [],
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0},
        }
        
        for domain in domains:
            # 1. DNS 层检测
            dns_result = self._test_dns_hijack(domain)
            report["tests"].append(dns_result)
            
            # 2. HTTP 层检测
            http_result = self._test_http_injection(domain)
            report["tests"].append(http_result)
            
            # 3. HTTPS 证书检测
            https_result = self._test_cert_replace(domain)
            report["tests"].append(https_result)
            
            # 4. NXDOMAIN 劫持检测
            nxdomain_result = self._test_nxdomain_hijack()
            report["tests"].append(nxdomain_result)
            
            # 5. 透明代理检测
            proxy_result = self._test_transparent_proxy(domain)
            report["tests"].append(proxy_result)
        
        # 汇总
        for test in report["tests"]:
            report["summary"]["total"] += 1
            if test["status"] == "pass":
                report["summary"]["passed"] += 1
            elif test["status"] == "fail":
                report["summary"]["failed"] += 1
            else:
                report["summary"]["warnings"] += 1
        
        return report
    
    def _test_dns_hijack(self, domain: str):
        """DNS 解析一致性检测"""
        try:
            # 对比多个DNS服务器
            resolvers = {
                "Google": "8.8.8.8",
                "Cloudflare": "1.1.1.1",
                "OpenDNS": "208.67.222.222",
                "ISP": None,  # 不指定, 使用系统默认(可能被ISP劫持)
            }
            
            results = {}
            for name, ns in resolvers.items():
                cmd = ["dig", "+short", domain, "A"]
                if ns:
                    cmd = ["dig", f"@{ns}", "+short", domain, "A"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                ips = result.stdout.strip().split("\n")
                results[name] = [ip for ip in ips if ip]
            
            # 分析一致性
            all_ips = set()
            for ips in results.values():
                all_ips.update(ips)
            
            if len(all_ips) > len(results) * 1.5:
                return {
                    "test": "DNS解析一致性",
                    "domain": domain,
                    "status": "fail",
                    "detail": f"DNS解析不一致: {results}",
                    "severity": "high",
                }
            elif len(all_ips) > len(results):
                return {
                    "test": "DNS解析一致性",
                    "domain": domain,
                    "status": "warning",
                    "detail": f"部分DNS解析不一致: {results}",
                    "severity": "medium",
                }
            return {
                "test": "DNS解析一致性",
                "domain": domain,
                "status": "pass",
                "detail": f"所有DNS服务器解析一致",
            }
        except Exception as e:
            return {"test": "DNS解析一致性", "domain": domain, "status": "warning", "detail": str(e)}
    
    def _test_http_injection(self, domain: str):
        """HTTP 内容注入检测"""
        try:
            r = requests.get(f"http://{domain}", timeout=15, allow_redirects=False)
            
            injection_indicators = [
                "<iframe", "<script src=\"http", "document.write",
                "eval(function", "window.location.replace",
                "<!--AD_", "<div id=\"ad_", "injectAd",
            ]
            
            found = [ind for ind in injection_indicators if ind.lower() in r.text.lower()]
            
            if found:
                return {
                    "test": "HTTP内容注入",
                    "domain": domain,
                    "status": "fail",
                    "detail": f"发现注入标记: {found}",
                    "severity": "high",
                }
            return {
                "test": "HTTP内容注入",
                "domain": domain,
                "status": "pass",
                "detail": "未发现注入标记",
            }
        except Exception as e:
            return {"test": "HTTP内容注入", "domain": domain, "status": "warning", "detail": str(e)}
    
    def _test_cert_replace(self, domain: str):
        """HTTPS 证书替换检测"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    issuer = dict(x[0] for x in cert["issuer"])
                    subject = dict(x[0] for x in cert["subject"])
                    
                    # 检查是否为知名CA
                    known_cas = [
                        "DigiCert", "Let's Encrypt", "Sectigo", "GlobalSign",
                        "Google Trust", "Amazon", "Cloudflare", "Entrust",
                        "ISRG", "Buypass", "ZeroSSL",
                    ]
                    
                    issuer_org = issuer.get("organizationName", "")
                    is_known_ca = any(ca.lower() in issuer_org.lower() for ca in known_cas)
                    
                    if not is_known_ca:
                        return {
                            "test": "HTTPS证书替换",
                            "domain": domain,
                            "status": "fail",
                            "detail": f"证书签发者非已知CA: {issuer_org}",
                            "severity": "high",
                        }
                    
                    # 检查证书是否匹配域名
                    san = cert.get("subjectAltName", [])
                    domain_match = any(domain in name[1] for name in san)
                    
                    if not domain_match:
                        return {
                            "test": "HTTPS证书替换",
                            "domain": domain,
                            "status": "fail",
                            "detail": f"证书不匹配域名: SAN={san}",
                            "severity": "high",
                        }
                    
                    return {
                        "test": "HTTPS证书替换",
                        "domain": domain,
                        "status": "pass",
                        "detail": f"证书正常: 签发者={issuer_org}",
                    }
        except Exception as e:
            return {"test": "HTTPS证书替换", "domain": domain, "status": "warning", "detail": str(e)}
    
    def _test_nxdomain_hijack(self):
        """NXDOMAIN 劫持检测"""
        try:
            import random, string
            random_domain = ''.join(random.choices(string.ascii_lowercase, k=20)) + ".com"
            
            result = subprocess.run(
                ["dig", "+short", random_domain, "A"],
                capture_output=True, text=True, timeout=10
            )
            
            ips = [ip for ip in result.stdout.strip().split("\n") if ip]
            
            if ips:
                return {
                    "test": "NXDOMAIN劫持",
                    "domain": random_domain,
                    "status": "fail",
                    "detail": f"不存在的域名返回IP: {ips} (运营商NXDOMAIN劫持)",
                    "severity": "high",
                }
            return {
                "test": "NXDOMAIN劫持",
                "status": "pass",
                "detail": "不存在的域名正确返回NXDOMAIN",
            }
        except Exception as e:
            return {"test": "NXDOMAIN劫持", "status": "warning", "detail": str(e)}
    
    def _test_transparent_proxy(self, domain: str):
        """透明代理检测"""
        try:
            r = requests.get(f"http://{domain}", timeout=15)
            
            proxy_headers = ["Via", "X-Cache", "X-Forwarded-For", 
                           "X-Forwarded-Host", "X-Squid-Error", "Age"]
            found_headers = [h for h in proxy_headers if h in r.headers]
            
            if found_headers:
                return {
                    "test": "透明代理",
                    "domain": domain,
                    "status": "warning",
                    "detail": f"发现代理头: {found_headers} (可能是透明代理)",
                    "severity": "medium",
                }
            return {
                "test": "透明代理",
                "domain": domain,
                "status": "pass",
                "detail": "未发现透明代理头",
            }
        except Exception as e:
            return {"test": "透明代理", "domain": domain, "status": "warning", "detail": str(e)}

# 使用示例
if __name__ == "__main__":
    scanner = ISPHijackScanner()
    report = scanner.full_scan()
    print(json.dumps(report, indent=2, ensure_ascii=False))
```

### 13.6 2026 运营商劫持技术演进矩阵

| 技术领域 | 2025 状态 | 2026 演进 | 对抗难度 |
|----------|-----------|-----------|----------|
| AI-DPI | 规则匹配 | ML模型流量分类 | ★★★★ |
| 5G信令劫持 | NEF接口 | NWDAF AI分析 | ★★★★ |
| QUIC劫持 | 端口阻断 | QUIC指纹识别 | ★★★ |
| ECH对抗 | SNI明文 | ECH+DoH组合阻断 | ★★★★ |
| 卫星互联网 | 未覆盖 | 星地链路注入 | ★★★ |
| BGP劫持 | 前缀劫持 | RPKI绕过+路由泄露 | ★★★ |
| 证书替换 | 预装CA | AI生成合法证书 | ★★★★ |
| 6G预研 | N/A | 太赫兹频段劫持 | ★★★★★ |