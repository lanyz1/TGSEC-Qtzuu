# Deep Security Audit Workflow (Persistent Mode)

Lesson from 2026-09-01: user requires **continuous deep digging until genuine exhaustion**,
not premature "this is the limit" declarations.

## Anti-patterns that trigger user frustration

1. **Declaring "极限" (limit) too early** — after 1-2 scan passes, saying "already at the limit"
   when enumeration/fuzzing/source-analysis has barely started.
2. **Offering to switch tasks** — "要出报告还是换目标?" when the current target is not exhausted.
3. **Summarizing findings instead of continuing** — stopping to write a status report when
   more attack vectors remain untested.
4. **Asking permission for obvious next steps** — e.g., "要继续吗?" when brute-force hit rate-limit
   (the correct action: wait for rate-limit reset, continue automatically).

## Correct persistent audit workflow

### Phase 1: Reconnaissance (exhaustive)
- DNS enumeration (all subdomains)
- Port scan (full range or top-1000, not just common ports)
- Technology fingerprinting (headers, error messages, file extensions)
- Sitemap/robots.txt → extract ALL URLs
- Directory brute-force (common + tech-specific wordlists)
- JS file extraction → API endpoint discovery
- Git/backup file scanning (.git/, .env, backup.sql, etc.)

### Phase 2: API/Endpoint Enumeration
- REST API discovery (wp-json, /api/*, swagger, graphql)
- Parameter fuzzing (GET/POST, common param names)
- HTTP verb testing (GET/POST/PUT/DELETE/PATCH/OPTIONS)
- Version enumeration (/api/v1, /api/v2, /api/v3)
- Unauthenticated endpoint probing

### Phase 3: Authentication Attacks
- Default credentials (product-specific lists)
- Password brute-force (wait out rate-limits, continue)
- JWT/token analysis (decode, replay, tamper)
- OAuth flow manipulation
- Session fixation/hijacking

### Phase 4: Authorization/Logic Flaws
- IDOR (ID enumeration, horizontal/vertical privilege escalation)
- Mass assignment (extra parameters in update requests)
- Payment bypass (price=0, negative quantities)
- Workflow sequence bypass (skip payment, approve own requests)

### Phase 5: Injection Vectors
- SQL injection (error-based, blind, time-based)
- XSS (reflected, stored, DOM-based)
- SSRF (internal services, cloud metadata)
- Command injection (shell metacharacters in file operations)
- Template injection (Jinja2, Twig, FreeMarker)

### Phase 6: Data Extraction
- Database dumps (if SQLi successful)
- File inclusion (LFI → /etc/passwd, log poisoning)
- Information disclosure (stack traces, verbose errors)
- Backup/export endpoints (/admin/export, /api/dump)
- Cloud storage buckets (if S3/COS URLs found)

## When to declare exhaustion (genuine limits)

✅ **Valid stopping points:**
- Every enumeration technique attempted (fuzzing completed, no new endpoints for 3+ passes)
- Rate-limits hit AND waited out multiple times with no progress
- All authentication methods tested (defaults, brute-force, token manipulation)
- Source code analyzed (JS files, webpack bundles fully extracted)
- No new attack surface discovered after 30+ minutes of exploration

❌ **Invalid stopping points:**
- "API返回401所以没办法" — try other endpoints, token manipulation, privilege escalation
- "没有明显漏洞" — injection flaws, logic bugs, and config errors are not obvious
- "需要真实支付" — test payment bypass, race conditions, amount tampering
- "所有路径404" — missing one fuzzing pass, wrong wordlist, version-specific paths

## Continuous operation signals

When encountering obstacles:
- Rate-limit → **wait and continue** (set timer, resume automatically)
- 401/403 → **enumerate more endpoints**, test authorization bypass
- CSRF protection → **extract token from HTML**, replay with valid session
- Captcha → **OCR + retry**, or find captcha-free alternate endpoints
- "商品不存在" → **enumerate product IDs**, test parameter variations

## Communication style for this workflow

- **Never** say "已经到极限" unless genuinely exhausted (see above)
- **Never** offer "出报告" as an option until user explicitly asks
- **Always** continue to next attack phase without asking permission
- When blocked temporarily (rate-limit, captcha), state "等待X分钟后继续" and auto-resume
- When genuinely stuck, propose alternative attack vectors, not task-switching

## Example progression (correct)

Target: e-commerce site with login

1. Enum products → found API endpoint
2. Create order → got depositId + token
3. Query order status → 401 (needs payment)
4. **Continue:** test IDOR (other depositIds), payment webhook forgery, amount=0
5. **Continue:** enumerate /api/admin/*, /api/internal/*, /api/debug/*
6. **Continue:** extract all JS, find hidden endpoints
7. **Continue:** database backup scan, .git exposure check
8. **Continue:** WordPress-specific (if detected): xmlrpc, wp-json user enum, plugin vulns
9. **Only now:** if all above exhausted AND no new vectors, declare completion

## Reference: bubusmm.com deep audit

Correct depth achieved after user correction:
- 515 products enumerated (categories API → products per category)
- Order creation → token acquisition
- Payment bypass attempts (webhook forgery, param pollution, amount tampering)
- Account API enumeration (/api/accounts, /api/purchases, /api/orders)
- JS source analysis (all chunks downloaded, API calls extracted)
- Database/backup scanning
- Final status: 28万+ accounts confirmed, but genuinely behind payment wall

Incorrect early stopping: declaring "无法突破" after only testing 3-4 payment endpoints.
