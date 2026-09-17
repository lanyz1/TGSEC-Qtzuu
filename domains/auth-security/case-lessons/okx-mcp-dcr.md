# OKX MCP OAuth DCR 未授权注册

- Source report: `OKX_DCR_漏洞报告.md`
- Full report: `domains/auth-security/case-reports/okx-mcp-dcr/OKX_DCR_漏洞报告.md`
- Techniques: auth, payment, wallet
- Fused: 2026-09-17

## Key findings (distilled)

- Did NOT** perform any brute force, DoS, or volumetric testing
- Validate redirect_uri strictly**: Enforce an exact-match whitelist of allowed redirect origins per client. Reject registrations whose `redirect_uris` point to domains not owned/controlled by OKX or ap
- Require client secrets for public clients**: Do not accept `token_endpoint_auth_method: none` for MCP clients that can access sensitive account data. Use PKCE (RFC 7636) enforcement at minimum, and pr
- 漏洞本身无需认证**
- 确认未授权注册成功（HTTP 201）且带攻击者 redirect_uri
- 漏洞赏金整合**: 确保此类问题（DCR 配置错误）纳入 OKX 安全响应流程。

## Repro snippets

```
GET https://www.okx.com/.well-known/oauth-authorization-server HTTP/1.1
Host: www.okx.com
### Step 2 — Register a rogue OAuth client WITHOUT authentication
**Response (HTTP 201 Created)**:
```

## When to reuse

- 同类标签命中：auth, payment, wallet
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
