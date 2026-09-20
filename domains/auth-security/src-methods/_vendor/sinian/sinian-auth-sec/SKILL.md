---
name: auth-sec
description: >-
  Entry P1 category router for authentication and authorization. Use when
  testing login flows, sessions, object authorization, JWT, OAuth, CORS, CSRF,
  and enterprise SSO weaknesses before any deeper auth topic skill.
---

# Authentication and Authorization Router

This is the routing entry point for authentication, sessions, and authorization boundaries.

Use it to decide whether the issue is mainly login mechanics, object-level authorization, browser trust boundaries, or identity protocols such as OAuth/JWT/SAML before going deeper.

## When to Use

- The target includes login, registration, password reset, 2FA, sessions, JWT, OAuth, or SSO
- You suspect object authorization flaws, cross-tenant access, cross-origin reads, CSRF, or protocol misconfiguration
- You need to decide whether to test authentication or authorization first

## Skill Map

- [Authentication Bypass](../authbypass-authentication-flaws/SKILL.md): login bypass, password reset, 2FA, enumeration, brute-force protections
- [IDOR Broken Object Authorization](../idor-broken-object-authorization/SKILL.md): IDOR, BOLA, BFLA, missing object permissions
- [JWT OAuth Token Attacks](../jwt-oauth-token-attacks/SKILL.md): algorithm confusion, key trust issues, claim abuse, token forgery
- [OAuth OIDC Misconfiguration](../oauth-oidc-misconfiguration/SKILL.md): redirect URI, state, nonce, PKCE, account binding
- [CSRF Cross Site Request Forgery](../csrf-cross-site-request-forgery/SKILL.md): CSRF tokens, SameSite, JSON CSRF, login CSRF
- [CORS Cross Origin Misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md): reflected Origin, credentialed cross-origin reads, allowlist bypass
- [SAML SSO Assertion Attacks](../saml-sso-assertion-attacks/SKILL.md): assertion wrapping, signature validation, audience, ACS boundaries

### 2026 新增攻击面路由

- [401/403 Bypass Techniques](../401-403-bypass-techniques/SKILL.md): HTTP/3 QUIC绕过、边缘/Serverless 403绕过、API网关授权不一致 (2026)
- [Open Redirect](../open-redirect/SKILL.md): OAuth/SSO链CNAME链式接管、AI Agent→SSRF→凭证窃取 (2026)
- [AI/LLM Attack Surface](../ai-llm-attack-surface/SKILL.md): OAuth在AI Agent框架中的攻击面、MCP认证缺失(1,862服务器)、Passkey API认证滥用 (2026)
- [Security Awareness Training](../security-awareness-training/SKILL.md): MFA疲劳攻击(Push Bombing)、AiTM代理钓鱼、Deepfake Vishing (2026)
- [Telegram Mini App & Bot Security](../telegram-mini-app-bot-security/SKILL.md): initData签名伪造、Bot Token泄露、TON Connect钓鱼、Telegram Stars退款欺诈 (2026)

## Recommended Flow

1. First confirm the authentication model and session boundaries
2. Then confirm object-level and function-level authorization
3. Then move to token, cross-origin, and protocol details
4. If enterprise federation exists, continue with OAuth, OIDC, or SAML topics

## Related Categories

- [api-sec](../api-sec/SKILL.md)
- Default credentials, username variants, wordlist sizing, and port focus are consolidated in [authbypass-authentication-flaws](../authbypass-authentication-flaws/SKILL.md)