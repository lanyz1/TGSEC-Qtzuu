# Chinese CMS/Web Framework Vulnerabilities Research Report

**Date:** 2026-07-23  
**Sources:** NVD (NIST), GitHub Advisory Database, Exploit-DB (searchsploit), CVE Details

---

## 1. 织梦 DedeCMS (DedeCMS)

**Summary:** DedeCMS is one of the most targeted Chinese CMS. 171+ GitHub advisories. Heavy exploitation history.

### Known CVEs
| CVE | Severity | Type | Description |
|-----|----------|------|-------------|
| CVE-2015-4553 | Critical | RFI → GetShell | Variable coverage in `/install/index.php` / `.bak` allows remote file inclusion leading to code execution |
| CVE-2020-27533 | Medium | XSS | Stored XSS via `_keyword_` parameter in search feature |
| CVE-2024-* (multiple) | Critical | RCE | `file_manage_control.php` command execution, `setup` code injection |
| Multiple | Critical | File Upload | Arbitrary code execution via file upload in backend |
| Multiple | High | CSRF | Cross-site request forgery in various admin endpoints |

### Known Exploits (Exploit-DB)
| EDB-ID | Type | Version | Description |
|--------|------|---------|-------------|
| 9876 | SQL Injection | 5.1 | `plus/feedback_js.php` - UNION-based SQLi to extract admin credentials |
| 33685 | Auth Bypass | 5.5 | `_SESSION[dede_admin_id]` spoofing via multipart form → arbitrary file upload |
| 37423 | RFI → RCE | <5.7-sp1 | `install/index.php` variable coverage → getshell (CVE-2015-4553) |
| 48326 | Stored XSS | 7.5 SP2 | Persistent XSS via multiple backend fields |
| 48974 | XSS | 5.8 | Reflected XSS via `_keyword_` in search (CVE-2020-27533) |

### Common Attack Vectors
1. **`/install/index.php` or `.bak`** — Variable coverage → remote file inclusion (pre-5.7-sp1)
2. **`/plus/feedback_js.php`** — SQL injection via `arcurl` parameter
3. **`include/dialog/select_soft_post.php`** — Auth bypass via `_SESSION[dede_admin_id]` + file upload → shell
4. **`file_manage_control.php`** — Command execution (5.7.115+)
5. **Backend file upload** — Unrestricted file upload → arbitrary code execution
6. **CSRF** — Admin action forging (add admin, modify config)

### Default Credentials / Paths
- Admin path: `/dede/` (default), `/admin/`
- Default admin: `admin` / `admin` (historically common)
- Install lock file: `/install/install_lock.txt`
- Database config: `/data/common.inc.php`

### Typical Exploitation Path
1. Enumerate target → find DedeCMS install (check `/dede/`, `/include/`, `/plus/`, `/install/`)
2. Check for `/install/index.php.bak` → CVE-2015-4553 RFI
3. Attempt SQLi on `plus/feedback_js.php` → extract admin hash
4. Attempt auth bypass via `select_soft_post.php` with forged session → upload webshell
5. Brute-force `/dede/` login (admin/admin)
6. Post-auth: upload template-based webshell via template editor

---

## 2. 帝国 EmpireCMS (EmpireCMS)

**Summary:** 18 GitHub advisories. Multiple critical RCE and SQLi. Still actively maintained.

### Known CVEs
| CVE | Severity | Type | Description |
|-----|----------|------|-------------|
| CVE-2006-4354 | High | RFI | `checklevel.php` remote file inclusion |
| Multiple | Critical | SQL Injection | `ftppassword` parameter, `AdClass.php` |
| Multiple | Critical | RCE | `e/install/index.php` remote code execution |
| Multiple | High | File Upload | `LoadInMod` function arbitrary file upload |
| Multiple | High | Code Injection | `ReplaceListVars` eval injection in template parser |
| Multiple | Critical | Directory Traversal | `..%2F` path traversal in file upload → RCE |
| Multiple | High | CSRF | `enews=AddUser` action for adding admin accounts |

### Known Exploits (Exploit-DB)
| EDB-ID | Type | Version | Description |
|--------|------|---------|-------------|
| 2239 | RFI | 3.7 | `checklevel.php` remote file inclusion (CVE-2006-4354) |
| 10069 | SQL Injection | 47 | Guestbook CLIENT-IP header SQLi to extract admin credentials |

### Common Attack Vectors
1. **`e/install/index.php`** — RCE if install directory not removed (similar to DedeCMS)
2. **`e/class/connect.php`** — SQL injection points
3. **Guestbook (`e/enews/index.php`)** — SQLi via CLIENT-IP/X-Forwarded-For headers
4. **File upload in admin** — `..%2F` directory traversal → arbitrary path write
5. **Template parser** — `ReplaceListVars` eval injection
6. **`admin/db/DoSql.php`** — SQL execution → PHP code injection
7. **CSRF** — Add admin user via `enews=AddUser`

### Default Credentials / Paths
- Admin path: `/e/admin/`
- Install path: `/e/install/`
- Default admin credentials: `admin` / `admin` (often unchanged)
- Database config: `/e/class/config.php`

### Typical Exploitation Path
1. Identify EmpireCMS → check `/e/admin/`, `/e/install/`
2. Check `/e/install/index.php` still accessible → RCE
3. SQLi via guestbook CLIENT-IP header → extract `phome_enewsuser` credentials
4. Brute-force admin panel
5. Post-auth: file upload with path traversal → webshell
6. Post-auth: template editing → eval injection

---

## 3. PHPCMS

**Summary:** 20 GitHub advisories. Extensive history of RFI, SQLi, and file upload issues. Older versions very vulnerable.

### Known CVEs
| CVE | Severity | Type | Description |
|-----|----------|------|-------------|
| Multiple | High | RFI | Remote file inclusion in 1.1.7 (multiple class files) |
| Multiple | Critical | SQL Injection | `data.php`, `model_field.class.php`, `yp/job.php` |
| Multiple | Critical | File Upload → RCE | `attachment.class.php` in 9.6.0 |
| Multiple | Moderate | XSS | Multiple endpoints in 9.6.3 |
| Multiple | Moderate | Directory Traversal | 9.1.13 `q` parameter, 1.2.2 `class.cache_phpcms.php` |
| CVE-2020-* | Critical | Code Injection | `/type.php` arbitrary content write |

### Known Exploits (Exploit-DB)
| EDB-ID | Type | Version | Description |
|--------|------|---------|-------------|
| 29343-29352 | RFI | 1.1.7 | 10 different RFI vulnerabilities (class files + parser/counter) |
| 5006 | File Disclosure | 1.2.2 | `?file=` parameter arbitrary file read |
| 32873 | SQL Injection | 2008 | `search_ajax.php` SQLi |
| 16019 | SQL Injection | 2008 | General SQLi |
| 35239 | SQL Injection | 2008 V2 | `data.php` SQLi |
| 16027 | Blind SQLi | 9.0 | Blind SQL injection |
| 24782 | XSS | 1.1/1.2 | Cross-site scripting |

### Common Attack Vectors
1. **RFI in 1.1.7** — 10+ different class files allow remote file inclusion
2. **SQLi** — `data.php`, `search_ajax.php`, `yp/job.php`, `model_field.class.php`
3. **File upload** — `attachment.class.php` in 9.6.0 → unrestricted upload
4. **`type.php` code injection** — Write arbitrary content to files (2008)
5. **Directory traversal** — `q` parameter, `class.cache_phpcms.php`

### Default Credentials / Paths
- Admin path: `/admin.php` or `/index.php?m=admin`
- Database config: `/caches/configs/database.php`
- Upload directory: `/uploadfile/`

### Typical Exploitation Path
1. Fingerprint PHPCMS version (check `/api.php?op=phpcms` or version files)
2. If 1.1.7 → direct RFI in multiple class files
3. If 2008 → SQLi on `data.php` or `search_ajax.php`
4. If 9.x → check `attachment.class.php` upload, brute admin
5. Post-auth: template editing, cache file writing

---

## 4. Discuz! (Discuz)

**Summary:** 27 GitHub advisories. One of China's most popular forum platforms. Historic RCE, modern LFI/XSS.

### Known CVEs
| CVE | Severity | Type | Description |
|-----|----------|------|-------------|
| CVE-2008-6958 | Critical | RCE | `wap/index.php` remote code execution (6.x/7.x) |
| Multiple | High | SQL Injection | `admincp.php`, `index.php` (searchid), plugin SQLi |
| Multiple | Critical | RCE | Discuz!ML 3.2-3.4 arbitrary PHP code via modified request |
| Multiple | High | Auth Bypass | `member.php` arbitrary password reset |
| Multiple | Critical | Access Bypass | WeChat login bypass (X3.4) |
| Multiple | High | LFI | X5.0 local file inclusion (2026 CVE) |
| Multiple | Critical | Auth Bypass | X5.0 authentication bypass (2026 CVE) |
| Multiple | Moderate | XSS | Numerous reflected/stored XSS across versions |

### Known Exploits (Exploit-DB)
| EDB-ID | Type | Version | Description |
|--------|------|---------|-------------|
| 7119 | RCE | 6.x/7.x | `wap/index.php` WAP registration → `creditsformula` eval injection → webshell |
| 7185 | Password Reset | * | `member.php` arbitrary password reset (user+mail+uid known) |
| 2859 | SQLi/Admin | 4.x | SQL injection → admin credential extraction |
| 2644 | SQLi | 5.0.0 GBK | SQL injection → admin creation |
| 6214 | SQLi | 6.0.1 | `searchid` parameter SQL injection |
| 10861 | SQLi | 1.03 | SQL injection |
| 9529/9576 | Plugin SQLi | * | Crazy Star, JiangHu plugin SQLi |

### Common Attack Vectors
1. **`wap/index.php`** RCE (6.x/7.x) — Register via WAP, inject `creditsformula` → `eval()` → write webshell
2. **Discuz!ML 3.2-3.4** — Language pack manipulation → arbitrary PHP code execution
3. **`member.php` password reset** — Requires known username/email/UID
4. **SQLi in `index.php`** — `searchid` parameter (6.0.1)
5. **WeChat login bypass** (X3.4) — Bypass disabled account restrictions
6. **Modern X5.0** — Auth bypass, CAPTCHA bypass, LFI (2026 CVEs)
7. **Database backup** — `admincp_db.php` allows arbitrary backup download

### Default Credentials / Paths
- Admin path: `/admin.php`
- Default admin: `admin` / `admin` (historically)
- UCenter path: `/uc_server/`
- Config: `/config/config_global.php`
- WAP: `/wap/index.php`

### Typical Exploitation Path
1. Identify Discuz version (footer, `/source/discuz_version.php`)
2. If 6.x/7.x → exploit `wap/index.php` RCE (CVE-2008-6958)
3. If ML 3.x → language pack RCE
4. If credentials known → password reset via `member.php`
5. SQLi via plugin or `searchid`
6. Brute-force admin → template edit → eval webshell
7. Modern X5.0 → LFI + auth bypass chain

---

## 5. ThinkPHP

**Summary:** 35 GitHub advisories, 31 NVD CVEs. Most-vulnerable Chinese framework. Deserialization is the #1 attack vector.

### Known CVEs (NVD - 31 total)
| CVE | Severity | Type | Affected |
|-----|----------|------|----------|
| CVE-2025-63888 | Critical | RCE | 5.0.24 `File.php` read function |
| CVE-2025-63889 | High | Arbitrary File Read | 5.0.24 `Template.php` fetch function |
| CVE-2025-50707 | Critical | RCE | 3.2.5 `index.php` |
| CVE-2025-50706 | Critical | RCE | 5.1 `routecheck` function |
| CVE-2024-48112 | Critical | Deserialization → RCE | 6.1.3-8.0.4 `Index.php` |
| CVE-2024-44902 | Critical | Deserialization → RCE | 6.1.3-8.0.4 |
| CVE-2024-34467 | Moderate | XSS | 8.0.3 `think_exception.tpl` |
| CVE-2022-47945 | Critical | LFI → RCE | <6.0.14 `lang` parameter + pearcmd.php |
| CVE-2022-45982 | Critical | Deserialization | 6.0.0-6.1.1 |
| CVE-2022-44289 | Critical | File Upload → RCE | 5.1.41, 5.0.24 |
| CVE-2022-38352 | Critical | Deserialization | 6.0.13 `Psr6Cache` |
| CVE-2022-33107 | Critical | Deserialization | 6.0.12 `AbstractCache.php` |
| CVE-2021-44892 | Critical | RCE | 3.x `value[_filename]` |
| CVE-2021-44350 | High | SQL Injection | 5.0.x-5.1.22 `parseOrder` |
| CVE-2021-36567 | Critical | Deserialization | 6.0.8 `AbstractCache` |
| CVE-2021-36564 | Critical | Deserialization | 6.0.8 `Adapter.php` |
| CVE-2019-9082 | Critical | RCE | <3.2.4 `invokefunction` |
| CVE-2018-20062 | Critical | RCE | NoneCMS using ThinkPHP `filter` parameter |
| CVE-2018-25270 | Critical | RCE | 5.0.23 routing parameter |
| CVE-2020-21865 | Critical | RCE | ThinkPHP50-CMS `?s=captcha` |
| CVE-2020-20120 | High | SQLi | 3.2.3 and below `where`/`query` |

### Known Exploits (Exploit-DB)
| EDB-ID | Type | Version | Description |
|--------|------|---------|-------------|
| 46150 | RCE | 5.X | Comprehensive RCE PoC collection (25+ payloads) |
| 45978 | RCE | <5.0.23/5.1.31 | `invokefunction` → `call_user_func_array` → system commands |
| 48333 | RCE (Metasploit) | Multiple | MSF module for PHP injection RCE |
| 33933 | XSS | 2.0 | `index.php` XSS |

### Critical Attack Vectors

#### A. Pre-5.0.23 RCE (Most Famous)
```
# Method 1: invokefunction
http://target/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id

# Method 2: Request input filter
http://target/?s=index/\think\Request/input&filter=system&data=whoami

# Method 3: Template file write → webshell
http://target/?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=<?php phpinfo();?>

# Method 4: POST (5.0.23)
POST /index.php?s=captcha
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
```

#### B. Deserialization (6.x - 8.x)
- **CVE-2024-44902 / CVE-2024-48112**: Deserialization in `vendor/league/flysystem-cached-adapter`
- **CVE-2022-45982 / CVE-2022-38352 / CVE-2022-33107**: Multiple deserialization chains

#### C. LFI → RCE (CVE-2022-47945)
- `lang` parameter when `lang_switch_on=true` → include pearcmd.php → RCE

#### D. SQL Injection
- **CVE-2021-44350**: `parseOrder` in Builder.php (5.0.x-5.1.22)
- **CVE-2020-20120**: Missing array sanitization in `where`/`query` (3.2.3)

### Default Paths
- Entry point: `/index.php`, `/public/index.php`
- Runtime/log: `/runtime/log/`
- Config: `/config/`, `/application/config.php`
- Upload: `/public/uploads/`

### Typical Exploitation Path
1. Identify ThinkPHP version → check debug mode output
2. If <5.0.23 → direct `invokefunction` RCE
3. If 5.0.23 → POST `_method=__construct` RCE
4. If 6.x → try deserialization via `vendor/league/flysystem-cached-adapter`
5. If lang_switch_on → CVE-2022-47945 LFI→RCE
6. SQLi via `parseOrder` or search parameters
7. Check `/runtime/log/` for exposed credentials

---

## 6. FastAdmin

**Summary:** 12 GitHub advisories. ThinkPHP-based admin builder. Moderately targeted.

### Known Exploits/Vulnerabilities
| Reference | Severity | Type | Description |
|-----------|----------|------|-------------|
| GHSA | Critical | File Upload | v1.2.1 arbitrary file upload → RCE |
| GHSA | High | SQL Injection | `app/admin/controller/Ajax.php` `table` parameter |
| GHSA | High | CSRF | v1.0.0.20190111 CSRF to add admin user |
| GHSA | High | SSRF | Member center SSRF vulnerability |
| GHSA | High | Auth Bypass | `public/index.php/admin/auth` authentication bypass |
| GHSA | Moderate | XSS | Multiple XSS vulnerabilities |

### Common Attack Vectors
1. **File upload** → `Ajax.php` unrestricted upload → code execution
2. **SQLi** in `Ajax.php` `table` parameter → data extraction
3. **Auth bypass** in admin authentication
4. **CSRF** to add admin accounts
5. Inherited ThinkPHP vulnerabilities (deserialization, LFI)

### Default Paths
- Admin: `/admin/` → `/index.php/admin/`
- Login: `/index.php/admin/index/login.html`
- Upload: `/uploads/`

### Typical Exploitation Path
1. Identify FastAdmin (check for `/index.php/admin/` paths)
2. Check inherited ThinkPHP vulnerabilities
3. Attempt auth bypass on admin endpoints
4. SQLi via `Ajax.php?table=`
5. CSRF to add admin account
6. Post-auth: file upload or template editing

---

## 7. Typecho

**Summary:** 19 GitHub advisories. Lightweight blog engine. Notable install.php RCE in older versions.

### Known CVEs
| CVE | Severity | Type | Description |
|-----|----------|------|-------------|
| CVE-2024-35539 | Moderate | Race Condition | 1.3.0 race condition in comment posting |
| CVE-2024-35540 | High | Stored XSS | 1.3.0 stored XSS via post content |
| CVE-2018-18753 | Critical | RCE | 1.1 install.php unserialize → RCE |
| Multiple | High | File Upload | 1.2.1 arbitrary file upload → RCE |
| Multiple | Moderate | XSS | Multiple XSS in 1.2.0, 1.2.1, 1.3.0 |
| Multiple | High | XML Bomb | XML Quadratic Blowup DoS in 1.2.1 |
| Multiple | Moderate | Clickjacking | 1.2.1 |
| Multiple | Moderate | Client IP Spoofing | 1.3.0 |
| Multiple | Moderate | Open Redirect | 1.1 Login.php `referer` parameter |

### Known Exploits (Exploit-DB)
| EDB-ID | Type | Version | Description |
|--------|------|---------|-------------|
| 52161 | Race Condition | 1.3.0 | Comment race condition (CVE-2024-35539) |
| 52162 | Stored XSS | 1.3.0 | Stored XSS via blog post (CVE-2024-35540) |

### Critical: Typecho 1.1 install.php RCE (CVE-2018-18753)
The most famous Typecho vulnerability: The installer unserializes user-controlled data from the `__typecho_config` cookie, allowing arbitrary object injection leading to remote code execution.

### Common Attack Vectors
1. **`install.php` unserialize** → RCE (v1.1, if install not removed)
2. **File upload** → arbitrary code execution (v1.2.1)
3. **Stored XSS** → admin session hijacking (v1.2.0 - v1.3.0)
4. **Race condition** → duplicate actions (v1.3.0)
5. **XML bomb** → DoS

### Default Credentials / Paths
- Admin: `/admin/`
- Install: `/install.php`
- Config: `/config.inc.php`
- Upload: `/usr/uploads/`

### Typical Exploitation Path
1. Identify Typecho (check meta generator, `/admin/`, `/install.php`)
2. If `/install.php` accessible and version ≤1.1 → unserialize RCE
3. If 1.2.1 → attempt file upload vulnerability
4. Stored XSS in blog comments/posts → steal admin cookies
5. Brute-force admin panel
6. Post-auth: template/plugin editing for code execution

---

## 8. 齐博CMS (QiboCMS) & 科汛CMS (KesionCMS)

**Summary:** No results in Exploit-DB or GitHub advisories. These are older/less common CMS.

### Notes
- No CVEs found in NVD or GitHub Advisory Database
- No exploits in Exploit-DB
- Likely used in legacy/internal Chinese deployments
- Common to find default installations with weak credentials
- Attack surface similar to other Chinese CMS: admin panels, install directories, upload paths

---

## Cross-Cutting Attack Patterns (Chinese CMS)

### 1. Install Directory Left Behind
Almost all Chinese CMS share this risk: `/install/` directory is not deleted after installation, allowing:
- DedeCMS: CVE-2015-4553 (variable coverage → getshell)
- EmpireCMS: `install/index.php` RCE
- Typecho: CVE-2018-18753 (unserialize → RCE)

### 2. Template-Based Code Execution
Most Chinese CMS allow template editing from admin panel. Post-auth → edit template → inject PHP → webshell.

### 3. Backup File Exposure
- `/install/index.php.bak` (DedeCMS)
- Database backups in web-accessible directories
- Config file backups (`.bak`, `.old`, `.php~`)

### 4. Weak Admin Credentials
Common defaults: `admin/admin`, `admin/123456`, `admin/admin888`

### 5. ThinkPHP Inheritance
FastAdmin and many other Chinese CMS are built on ThinkPHP → inherit all ThinkPHP RCE/deserialization vulns.

---

## Quick Reference: Vulnerability Counts

| Framework | GitHub Advisories | NVD CVEs | Exploit-DB |
|-----------|-------------------|----------|------------|
| DedeCMS | 171+ | Multiple | 5 |
| ThinkPHP | 35 | 31 | 4 |
| Discuz | 27 | Multiple | 11+ |
| PHPCMS | 20 | Multiple | 10+ |
| Typecho | 19 | Multiple | 2 |
| EmpireCMS | 18 | Multiple | 2 |
| FastAdmin | 12 | Multiple | 0 |
| QiboCMS | 0 | 0 | 0 |
| KesionCMS | 0 | 0 | 0 |

---

## Methodology & Sources

1. **NVD NIST API**: Used for CVE enumeration (NVD website browser for ThinkPHP)
2. **GitHub Advisory Database**: `github.com/advisories?query=<framework>` for each framework
3. **Exploit-DB via searchsploit**: Local exploit database queries for each framework
4. **In-scope frameworks**: DedeCMS, EmpireCMS, PHPCMS, Discuz, ThinkPHP, FastAdmin, Typecho
5. **Out-of-scope but checked**: QiboCMS (齐博), KesionCMS (科汛) — no results found
