# Chinese 发卡 (Card Issuance) Frameworks — Vulnerability Research Report

**Date:** 2026-07-23
**Scope:** 独角数卡, 异次元发卡, 风铃发卡, 云尚发卡
**Sources:** NVD/CVE Database, GitHub repos, source code analysis, security advisories

---

## 1. 独角数卡 (dujiaoka)

### Overview
- **Repository:** `assimon/dujiaoka` (12,146 ★, 2.8k forks)
- **Tech Stack:** Laravel 6.x + PHP 7.4 + dcat-admin (admin panel)
- **Latest Version:** 2.0.4 (final release)
- **Status:** **ARCHIVED** (March 12, 2026) — read-only, replaced by [Dujiao-Next](https://dujiao-next.com)
- **License:** MIT
- **Language:** PHP

### Known CVEs
No direct CVEs registered against `dujiaoka` itself, but it **inherits all dcat-admin vulnerabilities** since dcat-admin is its admin panel framework.

### Inherited dcat-admin CVEs (Critical)

| CVE ID | Severity | Description | CVSS | Affected Versions |
|--------|----------|-------------|------|-------------------|
| **CVE-2026-11621** | HIGH | Unrestricted file upload via `editorMDUpload()` in `/admin/dcat-api/editor-md/upload`. Manipulation of `editormd-image-file` argument allows remote attackers to upload arbitrary files. | N/A | ≤ 2.2.3-beta |
| **CVE-2025-65656** | HIGH | File inclusion vulnerability in `admin/src/Extend/VersionManager.php`. | N/A | ≤ 2.2.3-beta |
| **CVE-2024-54775** | MEDIUM | Stored XSS via `/admin/auth/menu` and `/admin/auth/extensions`. | N/A | 2.2.0-beta, 2.2.2-beta |
| **CVE-2025-0709** | MEDIUM | XSS on Roles page (`/admin/auth/roles`). | N/A | 2.2.1-beta |
| **CVE-2024-29644** | MEDIUM | XSS via user login box. | N/A | ≤ 2.1.3 |
| **CVE-2023-33736** | MEDIUM | Stored XSS via URL parameter injection. | 5.4 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N) | 2.1.3-beta |

### Common Vulnerabilities

1. **Default/Weak Credentials:**
   - dcat-admin default: `admin` / `admin`
   - Installation wizard sets admin credentials — users often use weak passwords
   - No brute-force protection on admin login

2. **Information Disclosure:**
   - `.env.example` has `APP_DEBUG=true` — many deployments leave debug mode on
   - Debug mode exposes stack traces, DB queries, environment variables
   - Laravel debug mode can leak `APP_KEY` via error pages

3. **Admin Panel Exposure:**
   - `ADMIN_ROUTE_PREFIX` is configurable but often left as default (`/admin`)
   - Admin panel is the full dcat-admin interface exposed to the internet

4. **File Upload:**
   - Editor.md image upload endpoint (`/admin/dcat-api/editor-md/upload`) has unrestricted upload
   - Can lead to RCE via PHP shell upload if file extension validation is bypassed

5. **XSS:**
   - Multiple stored/reflected XSS vectors in admin panel (menus, roles, login, URL params)
   - Can lead to admin session hijacking

6. **Payment Gateway Issues:**
   - Payment notify callbacks (`notify_url`) are largely GET-based, increasing CSRF risk
   - Multiple payment gateways (支付宝, 微信, Paypal, Stripe, USDT, etc.) each with own callback handling
   - Payment verification bypass possible if signature checking is weak

7. **Dependency Vulnerabilities:**
   - Uses Laravel 6.x (EOL since Sept 2022) — no security patches
   - Multiple dependency bumps in PRs suggest unpatched known vulns (guzzlehttp/psr7, symfony/http-kernel, league/flysystem)

### Default Credentials
- **Admin:** Set during installation (dcat-admin default: `admin`/`admin`)
- **Admin Path:** Configurable via `ADMIN_ROUTE_PREFIX` (default: `/admin`)
- **Admin HTTPS:** `ADMIN_HTTPS=false` by default (credentials sent in cleartext)

### Common Attack Paths

```
1. Recon:
   → Identify /admin or custom admin path
   → Check APP_DEBUG (error pages leak info)
   → Fingerprint dcat-admin version via JS/CSS assets

2. Initial Access:
   → Default credentials (admin/admin)
   → Brute force login (no rate limiting in dcat-admin)
   → CVE-2024-29644: XSS via login box → credential theft

3. Post-Auth Exploitation:
   → CVE-2026-11621: Upload PHP shell via editor.md upload
   → CVE-2025-65656: File inclusion to LFI/RFI
   → CVE-2023-33736/2024-54775/2025-0709: XSS → session hijacking

4. Unauthenticated Paths:
   → Payment callback endpoints (various notify_url routes)
   → /pay-gateway/{handle}/{payway}/{orderSN} — order enumeration
```

---

## 2. 异次元发卡 (yiciyuan-faka / acg-faka)

### Overview
- **Repository:** `lizhipay/acg-faka` (5,316 ★, 1k forks)
- **Tech Stack:** PHP 8.0+ custom framework (Eloquent ORM via Illuminate/Database)
- **Latest Version:** 3.5.5 (active development — commit 13 hours ago)
- **License:** MIT
- **Also Known As:** 二次元发卡系统, ACG-FAKA

### Known CVEs

| CVE ID | Severity | Description | CVSS | Affected Versions |
|--------|----------|-------------|------|-------------------|
| **CVE-2023-43971** | MEDIUM | Reflected XSS via `encode` parameter in `Index.php`. | 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) | 1.1.7 |

### Common Vulnerabilities

1. **Default/Weak Credentials:**
   - Demo admin: `demo@demo.com` / `123456` (documented in README)
   - Demo user: `为了明天美好而战斗` / `123456`
   - Many production deployments use identical weak passwords
   - Email-based login (not username)

2. **XSS / Input Validation:**
   - CVE-2023-43971: `encode` parameter in Index.php is not sanitized
   - Route-based parameter injection via `$_GET['s']` parsing
   - `Firewall::inst()->xssKiller()` is applied to route parameters but may have bypasses

3. **Authentication:**
   - Cookie-based session (`ACG-SHOP` session name)
   - Admin path: `/admin` (redirects to `/admin/authentication/login`)
   - Session token stored in cookie `ManageConst::SESSION`
   - No visible CSRF protection on admin forms

4. **Route/URL Manipulation:**
   - Custom router parses `$_GET['s']` for controller routing
   - Pattern-based URL rewriting for `/item/{id}` and `/cat/{id}`
   - Potential for path traversal if `$controller` concatenation is not properly validated

5. **Plugin System:**
   - Supports third-party plugins loaded dynamically
   - Plugin namespace: `App\Controller` → potentially allows loading arbitrary classes
   - Plugin store for templates and payment gateways

6. **File Permissions:**
   - Installation lock file at `kernel/Install/Lock`
   - Re-installation possible if lock file is deleted

7. **Payment Gateway:**
   - Extensible plugin-based payment system
   - Supports 全网任意平台 (any payment platform)
   - Callback verification depends on individual plugin implementation

### Default Credentials
- **Admin Login:** `demo@demo.com` / `123456` (documented demo)
- **Admin Path:** `/admin` → redirects to `/admin/authentication/login`
- **Demo Server:** `http://203.0.113.15:91/admin`

### Common Attack Paths

```
1. Recon:
   → Fingerprint via /admin path and page structure
   → Check /install for setup page (if Lock file missing)
   → Version detection via README or changelog

2. Initial Access:
   → Default/weak credentials (demo@demo.com / 123456 or variants)
   → CVE-2023-43971: XSS via encode parameter → credential theft
   → Session cookie manipulation if session secrets are weak

3. Post-Auth Exploitation:
   → Plugin upload → arbitrary code execution
   → Template modification → PHP code injection
   → Payment gateway plugin abuse
   → Database access via admin panel features

4. Unauthenticated Paths:
   → Payment notify callbacks (plugin-dependent)
   → API endpoints for goods/category queries
   → Install wizard if /install accessible
```

---

## 3. 风铃发卡 (Fengling Faka)

### Overview
- **Repository:** `utgpay2/card-system-usdtpay` (26 ★)
- **Tech Stack:** PHP (unknown framework)
- **Description:** USDT direct payment card issuance system — payments go directly to personal wallet address without third-party intermediaries
- **Status:** Low popularity, minimal community

### Known CVEs
**None found.** No CVEs registered in NVD. No security advisories published.

### Common Vulnerabilities (Inferred from Architecture)

1. **USDT Payment Integration:**
   - Direct USDT payments to personal addresses
   - Payment verification logic may be spoofable if not checking confirmations
   - No third-party escrow — transaction verification is self-implemented

2. **Default Credentials:**
   - Unknown (no documentation found)
   - Likely similar patterns to other faka frameworks

3. **Limited Code Review:**
   - Small codebase with 287 commits on main sister repo (acg-faka)
   - Less scrutiny = potentially more undiscovered vulnerabilities

### Common Attack Paths

```
1. Recon:
   → Identify framework via page structure/fingerprinting
   → Check for exposed admin panels

2. USDT Payment Manipulation:
   → Transaction confirmation spoofing
   → Double-spend attacks if confirmation depth is low
   → Race conditions in payment verification

3. Standard Web Vectors:
   → SQL injection in search/order functions
   → File upload via product image upload
   → Default/weak admin credentials
```

---

## 4. 云尚发卡 (Yunshang Faka)

### Overview
- **Repository:** `sjkgames/yearysfk` (6 ★) — "云尚发卡年度版（商业版）"
- **Alternative Source:** `oyokojapan-del/xi_tong_kai_yuan_wu` — "php系统开源无加密版云尚发卡系统1.5.7"
- **Tech Stack:** PHP (version 1.5.7 known)
- **Status:** Very low visibility, primarily circulated on Chinese forums

### Known CVEs
**None found.** No CVEs registered in NVD.

### Common Vulnerabilities (Inferred)

1. **Unencrypted Distribution:**
   - "无加密版" (unencrypted version 1.5.7) circulating openly
   - Source code fully available for vulnerability research
   - Encrypted commercial versions may have backdoors

2. **Default Credentials:**
   - Unknown (no documentation found)
   - Commercial version may have hardcoded credentials

3. **Version 1.5.7:**
   - Old version — likely has unpatched vulnerabilities
   - No evidence of security updates/maintenance

### Common Attack Paths

```
1. Recon:
   → Identify version via page source/comments
   → Check for /admin, /install paths

2. Source Code Analysis:
   → Unencrypted version allows full static analysis
   → Search for hardcoded credentials, SQL injection points
   → Check for eval()/assert()/system() calls

3. Exploitation:
   → Default credentials
   → Unpatched PHP vulnerabilities (if old PHP version used)
   → Standard web app attack vectors
```

---

## 5. Cross-Framework Common Attack Patterns

### Universal Attack Surface for Chinese Faka Frameworks

1. **Default/Weak Admin Credentials:**
   - Most frameworks use simple defaults or allow weak passwords
   - `admin/admin`, `admin/123456`, `demo@demo.com/123456` are common
   - No brute-force protection on login forms

2. **Admin Panel Exposure:**
   - `/admin` is the universal admin path across all frameworks
   - Admin panels are internet-facing with full CRUD capabilities
   - Often no IP whitelisting or 2FA

3. **Payment Callback Manipulation:**
   - All frameworks handle payment notify callbacks
   - Inadequate signature verification can lead to order fraud
   - Race conditions between payment verification and card issuance
   - Common endpoints: `notify_url`, `return_url`, `callback`

4. **File Upload Vulnerabilities:**
   - Product image upload
   - Editor/rich text upload (especially via dcat-admin)
   - Plugin/theme upload
   - Potential path: upload → PHP shell → RCE

5. **SQL Injection:**
   - Search functionality (goods, orders)
   - Order/category ID parameters
   - Admin panel query builders

6. **XSS (Cross-Site Scripting):**
   - Product descriptions (stored XSS)
   - Search queries (reflected XSS)
   - Admin panel input fields
   - Can lead to admin credential theft

7. **Information Disclosure:**
   - Debug mode left enabled (APP_DEBUG=true)
   - Error pages exposing DB credentials, file paths
   - `.env` file exposure via misconfiguration
   - `.git` directory exposure

8. **API Endpoint Abuse:**
   - Goods query APIs (card enumeration)
   - Order status APIs
   - Merchant/distributor APIs
   - Often lack authentication or rate limiting

### Recommended Testing Methodology

```
Phase 1 — Recon:
  ├── Fingerprint framework (HTTP headers, page structure, JS/CSS)
  ├── Discover admin path (/admin, custom prefix)
  ├── Check for debug mode, .env exposure, .git exposure
  └── Identify version via changelog, README, or error messages

Phase 2 — Auth Testing:
  ├── Try default credentials (admin/admin, demo@demo.com/123456)
  ├── Brute force admin login
  └── Test session management (token predictability, logout CSRF)

Phase 3 — Input Validation:
  ├── XSS in search, product descriptions, admin forms
  ├── SQL injection in order/product ID parameters
  ├── File upload → PHP shell (product images, editor uploads)
  └── Path traversal in file operations

Phase 4 — Business Logic:
  ├── Payment callback manipulation (signature bypass)
  ├── Order price manipulation
  ├── Card/key enumeration (sequential IDs)
  └── Race conditions (double-spend, concurrent purchases)

Phase 5 — Post-Exploitation:
  ├── Privilege escalation to admin
  ├── Database extraction
  └── Persistence (cron jobs, backdoored plugins)
```

---

## 6. References

- **独角数卡 (dujiaoka):** https://github.com/assimon/dujiaoka (ARCHIVED)
- **异次元发卡 (acg-faka):** https://github.com/lizhipay/acg-faka
- **风铃发卡:** https://github.com/utgpay2/card-system-usdtpay
- **云尚发卡:** https://github.com/sjkgames/yearysfk
- **CVE-2023-33736:** https://nvd.nist.gov/vuln/detail/CVE-2023-33736
- **CVE-2024-29644:** https://nvd.nist.gov/vuln/detail/CVE-2024-29644
- **CVE-2024-54775:** https://nvd.nist.gov/vuln/detail/CVE-2024-54775
- **CVE-2025-0709:** https://nvd.nist.gov/vuln/detail/CVE-2025-0709
- **CVE-2025-65656:** https://nvd.nist.gov/vuln/detail/CVE-2025-65656
- **CVE-2026-11621:** https://nvd.nist.gov/vuln/detail/CVE-2026-11621
- **CVE-2023-43971:** https://nvd.nist.gov/vuln/detail/CVE-2023-43971
- **dcat-admin:** https://github.com/jqhph/dcat-admin
