# Chinese OA/ERP Frameworks — Vulnerability Research Report

**Generated:** 2026-07-23
**Scope:** Comprehensive vulnerability research covering known CVEs, exploits, attack vectors, and attack paths for major Chinese OA/ERP frameworks.

---

## Table of Contents
1. [通达OA (Tongda)](#1-通达oa-tongda)
2. [泛微OA (Weaver/Fanwei)](#2-泛微oa-weaverfanwei)
3. [致远OA (Seeyon/Zhiyuan)](#3-致远oa-seeyonzhiyuan)
4. [用友 (Yonyou/UFIDA)](#4-用友-yonyouufida)
5. [蓝凌OA (Landray/Lanling)](#5-蓝凌oa-landraylanling)
6. [万户OA (Wanhu)](#6-万户oa-wanhu)
7. [Cross-Framework Attack Patterns](#7-cross-framework-attack-patterns)
8. [Default Credentials](#8-default-credentials)
9. [Sources & References](#9-sources--references)

---

## 1. 通达OA (Tongda)

**Vendor:** Beijing Tongda Xinke Technology Co., Ltd.
**Versions affected:** 2017 through v11.10
**Total CVEs found:** ~55 on cve.org

### Critical/High-Impact CVEs

| CVE | Severity | Type | Affected File/Endpoint | Description |
|-----|----------|------|----------------------|-------------|
| CVE-2024-4903 | Critical | SQL Injection | `/general/meeting/manage/delete.php` (M_ID_STR) | SQLi leading to data exfiltration |
| CVE-2024-25320 | Critical | SQL Injection | `/affair/delete.php` ($AFF_ID) | SQL injection in v2017 up to v11.9 |
| CVE-2024-1252 | Critical | SQL Injection | `/general/attendance/manage/ask_duty/delete.php` | SQLi up to v11.9 |
| CVE-2024-1251 | Critical | SQL Injection | `/general/email/outbox/delete.php` (DELETE_STR) | SQLi up to v11.10 |
| CVE-2024-10732 | Critical | SQL Injection | `/module/word_model/view/index.php` | SQLi up to v11.10 |
| CVE-2024-10731 | Critical | SQL Injection | `/pda/appcenter/check_seal.php` (ID) | SQLi up to v11.10 |
| CVE-2024-10730 | Critical | SQL Injection | `/pda/appcenter/web_show.php` | SQLi up to v11.6 |
| CVE-2024-10658 | Critical | SQL Injection | `/pda/approve_center/check_seal.php` | SQLi up to v11.10 |
| CVE-2024-10657 | Critical | SQL Injection | `/pda/approve_center/prcs_info.php` (RUN_ID) | SQLi up to v11.10 |
| CVE-2024-10656 | Critical | SQL Injection | `/pda/meeting/apply.php` | SQLi up to v11.9 |
| CVE-2024-10655 | Critical | SQL Injection | `/pda/reportshop/new.php` | SQLi up to v11.9 |
| CVE-2024-10619 | Critical | SQL Injection | `/pda/reportshop/next_detail.php` | SQLi up to v11.10 |
| CVE-2024-10618 | Critical | SQL Injection | `/pda/reportshop/record_detail.php` | SQLi up to v11.10 |
| CVE-2024-10617 | Critical | SQL Injection | `/pda/workflow/check_seal.php` (ID) | SQLi up to v11.10 |
| CVE-2024-10616 | Critical | SQL Injection | `/pda/workflow/webSignSubmit.php` (saleId) | SQLi up to v11.9 |
| CVE-2024-10615 | Critical | SQL Injection | `/general/approve_center/query/list/input_form/delete_data_attach.php` | SQLi up to v11.10 |
| CVE-2024-10602 | Critical | SQL Injection | `/general/approve_center/list/input_form/data_picker_link.php` | SQLi up to v11.9 |
| CVE-2024-10601 | Critical | SQL Injection | `/general/address/private/address/query/delete.php` | SQLi up to v11.10 |
| CVE-2024-10600 | Critical | SQL Injection | `/pda/appcenter/submenu.php` | SQLi up to v11.6 |
| CVE-2024-10598 | Critical | SQL Injection | `/general/hr/setting/attendance/leave/data.php` | SQLi v11.2-v11.6 |
| CVE-2024-0938 | Critical | SQL Injection | `/general/email/inbox/delete_webmail.php` | SQLi up to v11.9 |
| CVE-2023-7180 | Critical | SQL Injection | `/general/project/proj/delete.php` | SQLi up to v11.9 |
| CVE-2023-7023 | Critical | SQL Injection | `/general/vehicle/query/delete.php` | SQLi up to v11.9 |
| CVE-2023-7022 | Critical | SQL Injection | `/general/work_plan/manage/delete_all.php` | SQLi up to v11.9 |
| CVE-2023-7021 | Critical | SQL Injection | `/general/vehicle/checkup/delete_search.php` | SQLi up to v11.9 |
| CVE-2023-7020 | Critical | SQL Injection | `/general/wiki/cp/ct/view.php` | SQLi up to v11.9 |
| CVE-2024-10599 | Medium | Path Traversal | `/inc/package_static_resources.php` | Info disclosure up to v11.7 |

### Common Attack Vectors

1. **SQL Injection (PRIMARY)** — The overwhelming majority of Tongda OA vulnerabilities are SQL injection in `delete.php` endpoints across various modules (meeting, affair, email, attendance, vehicle, project, work_plan, wiki, approve_center, address). The pattern is consistent: unsanitized GET/POST parameters passed directly to SQL queries.

2. **RCE via File Upload** — GitHub repository `admintony/TongdaRCE` documents RCE exploits for versions < v11.5 and v11.6, achieved through file upload bypass leading to webshell deployment.

3. **Path Traversal** — Less common but present in resource loading endpoints.

### Typical Exploitation Path

```
1. Fingerprint: Look for Tongda OA login page (typically /general/ or /logincheck.php)
2. SQLi: Test delete.php endpoints with sqlmap (e.g., /general/meeting/manage/delete.php?M_ID_STR=1)
3. Dump credentials from SQLi: Extract admin hashes from the database
4. Login: Use cracked credentials to access admin panel
5. RCE: Upload webshell through file upload endpoints or use known RCE chain
```

### Default Credentials
- `admin` / `admin` (common default)
- `admin` / `123456`
- `admin` / `tongda`

---

## 2. 泛微OA (Weaver/Fanwei)

**Vendor:** Shanghai Weaver Network Technology Co., Ltd.
**Products:** E-cology, E-office, E-mobile, E-bridge
**Total CVEs found:** ~16 across product lines

### 2a. Weaver E-cology (核心产品)

| CVE | Severity | Type | Affected Component | Description |
|-----|----------|------|-------------------|-------------|
| **CVE-2026-22679** | **Critical** | **RCE** | `/papi/esearch/data/devops/dubboApi/debug/method` | **Unauthenticated RCE** via exposed Dubbo debug endpoint in v10.0 prior to 20260312. Attackers invoke arbitrary commands through the debug method endpoint. |
| **CVE-2025-34038** | **Critical** | **SQL Injection** | `getdata.jsp` (sql parameter) | SQLi in E-cology 8.0: unsanitized sql parameter passed directly to database query. |
| CVE-2024-48070 | Critical | **RCE** | Unknown endpoint | Remote code execution via specially crafted requests |
| CVE-2024-48069 | Critical | File Upload Bypass | Unknown | Race condition allowing malicious file upload and server privilege control |
| CVE-2023-51892 | Critical | **RCE** | `FrameworkShellController` | Remote code execution via crafted script in E-cology v10.0.2310.01 |
| CVE-2023-3793 | Critical | **Arbitrary File Read** | `filelFileDownloadForOutDoc.class` | Arbitrary file read via HTTP POST handler |
| **CVE-2022-50992** | **Critical** | **Arbitrary File Read** | `XmlRpcServlet` XML-RPC endpoint | **Unauthenticated** arbitrary file read via XML-RPC interface in E-cology < 10.52 |
| CVE-2024-7704 | Medium | Source Code Disclosure | `/cloudstore/ecode/setup/ecology_dev.zip` | Source code leak |
| CVE-2023-2806 | Medium | XXE | API component (`RequestInfoByXml`) | XML External Entity injection up to v9.0 |
| CVE-2019-10272 | Medium | CRLF Injection | `/workflow/request/ViewRequestForwardSPA.jsp` | CRLF/header injection via `isintervenor` parameter |

### 2b. Weaver E-office

| CVE | Severity | Type | Affected Endpoint | Description |
|-----|----------|------|-------------------|-------------|
| **CVE-2022-50993** | **Critical** | **Unauth File Upload** | `OfficeServer.php` | **Unauthenticated arbitrary file upload** via multipart POST in versions prior to 10.0_20221201 |
| CVE-2023-2648 | Critical | File Upload | `/inc/jquery/uploadify/uploadify.php` (Filedata) | Authenticated file upload in E-Office 9.5 |
| CVE-2023-2647 | Critical | File Upload | `/webroot/inc/utility_all.php` | File upload vulnerability |
| CVE-2023-2523 | Critical | File Upload | `App/Ajax/ajax.php?action=mobile_upload_save` | File upload via mobile upload handler |

### 2c. Weaver OA (generic)

| CVE | Severity | Type | Affected Endpoint | Description |
|-----|----------|------|-------------------|-------------|
| CVE-2023-2766 | Medium | File Disclosure | `/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini` | Configuration file exposure in v9.5 |
| CVE-2023-2765 | Medium | File Download | `/E-mobile/App/System/File/downfile.php` (url parameter) | Arbitrary file download |

### Common Attack Vectors

1. **XML-RPC Interface (XmlRpcServlet)** — CRITICAL. The `/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet` endpoint in unpatched E-cology allows unauthenticated file read. This is one of the most commonly exploited endpoints in the wild.

2. **BeanShell / Dubbo Debug Endpoints** — CVE-2026-22679 exposes Dubbo debug method endpoint allowing unauthenticated RCE. This is the most recent critical vulnerability.

3. **File Upload** — Multiple endpoints across E-office accept unauthenticated file uploads (OfficeServer.php, uploadify.php, mobile_upload_save).

4. **SQL Injection** — `getdata.jsp` passes user input directly to database without sanitization.

5. **FrameworkShellController** — Remote code execution via crafted requests to this controller.

### Typical Exploitation Path (E-cology)

```
1. Fingerprint: Look for /weaver/, /ecology/, /e-mobile/ paths
2. XML-RPC file read: Exploit CVE-2022-50992 on XmlRpcServlet to read config files
   → Extract database credentials, API keys, service passwords
3. Configuration leak: Download /cloudstore/ecode/setup/ecology_dev.zip (CVE-2024-7704)
4. SQL Injection: Use getdata.jsp SQLi to dump user credentials (CVE-2025-34038)
5. RCE: Exploit CVE-2026-22679 (Dubbo debug) or CVE-2023-51892 (FrameworkShellController)
   or upload webshell through CVE-2024-48069 (race condition file upload)
```

### Default Credentials
- `sysadmin` / `1` (E-cology)
- `admin` / `admin`
- `admin` / `123456`
- `admin` / `ecology`

---

## 3. 致远OA (Seeyon/Zhiyuan)

**Vendor:** Beijing Seeyon Internet Technology Co., Ltd.
**Products:** A8, A6, M3, Zhiyuan OA Web Application System
**Total CVEs found:** ~13

| CVE | Severity | Type | Affected Endpoint | Description |
|-----|----------|------|-------------------|-------------|
| **CVE-2025-34040** | **Critical** | **Unauth File Upload → RCE** | `/seeyon/wpsAssistServlet` | **Unauthenticated arbitrary file upload** via path traversal in `realFileType`/`fileId` parameters. Upload JSP to webroot → RCE. Affects v5.0-v8.0SP2. |
| **CVE-2025-5140** | **Critical** | **Deserialization** | `ThirdMenuController.class` | Deserialization vulnerability in `oursNetService.getData` up to v8.1 SP2 |
| **CVE-2025-4531** | **Critical** | **RCE** | Unknown (postData function) | Remote code execution in v8.1 SP2 |
| **CVE-2019-25714** | **Critical** | **Unauth File Write** | `/seeyon/htmlofficeservlet` | **Unauthenticated arbitrary file write** to webroot via specially crafted requests. Pre-RCE. |
| CVE-2021-4461 | High | Session Manipulation | `thirdpartyController.do` (enc parameter) | Improper decoding of `enc` parameter allows influencing session attributes up to v7.0 SP1 |
| CVE-2025-4529 | Medium | Path Traversal | `M3CoreController.class` Download | Path traversal in file download up to v8.1 SP2 |
| CVE-2025-4000 | Medium | Open Redirect/SSRF | `ssoproxy.jsp` | SSO proxy vulnerability in v8.1 SP2 |
| CVE-2025-3999 | Medium | XSS | `/common/js/addDate/date.jsp` | Reflected XSS in v8.1 SP2 |
| CVE-2025-56451 | Medium | XSS | `seeyon/main.do` (topValue) | Cross-site scripting in A8+ v7.0 |

### Key Exploit Details

**CVE-2025-34040 (wpsAssistServlet):**
```
POST /seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/Hello.jsp&fileId=2
Content-Type: multipart/form-data; boundary=----

------WebKitFormBoundary
Content-Disposition: form-data; name="upload"; filename="123.xls"

<% out.println("HelloWorld");%>
------WebKitFormBoundary--
```
- FOFA fingerprint: `app="致远互联-OA" && title="V8.0SP2"`
- Exploit available in exploit-db (EDB-ID: 52490)

### Common Attack Vectors

1. **wpsAssistServlet File Upload (CVE-2025-34040)** — PRIMARY entry point. Unauthenticated JSP upload to webroot via path traversal. The most commonly exploited vulnerability in the wild.

2. **htmlofficeservlet File Write (CVE-2019-25714)** — Another unauthenticated file write to web application root. Combined with the above, file write is the dominant attack vector for Seeyon.

3. **Deserialization (CVE-2025-5140)** — Java deserialization in `ThirdMenuController` allowing code execution.

4. **Session Manipulation (CVE-2021-4461)** — `thirdpartyController.do` can be used to influence session attributes, potentially leading to privilege escalation.

### Typical Exploitation Path

```
1. Fingerprint: Check for /seeyon/, seeyon/main.do, seeyon/login.jsp
2. File Upload: Exploit CVE-2025-34040 (wpsAssistServlet) to upload JSP webshell
   OR: Exploit CVE-2019-25714 (htmlofficeservlet) to write malicious files
3. Access Webshell: Navigate to uploaded JSP file in webroot
4. Persist/PrivEsc: Use the webshell for further access
5. Deserialization: Optionally, CVE-2025-5140 for code execution on patched systems
```

### Default Credentials
- `admin` / `123456`
- `system` / `system`
- `seeyon` / `123456`

---

## 4. 用友 (Yonyou/UFIDA)

**Vendor:** Yonyou Network Technology Co., Ltd. (formerly UFIDA)
**Products:** NC (ERP-NC), U8 Cloud, NC Cloud, PLM, U8+
**Total CVEs found:** ~12

### 4a. Yonyou UFIDA NC

| CVE | Severity | Type | Affected Endpoint | Description |
|-----|----------|------|-------------------|-------------|
| **CVE-2025-34039** | **Critical** | **Code Injection (BeanShell)** | `bsh.servlet.BshServlet` | **Unauthenticated code injection** via exposed BeanShell testing servlet in NC v6.5 and prior. Allows arbitrary Java code execution. |
| **CVE-2023-4748** | **Critical** | **Arbitrary File Read** | `PrintTemplateFileServlet.java` | Arbitrary file read up to 20230807 |
| CVE-2025-2712 | Medium | Open Redirect | `/help/top.jsp` | Open redirect in ERP-NC 5.0 |
| CVE-2025-2711 | Medium | XSS | `/help/systop.jsp` (langcode) | Reflected XSS in ERP-NC 5.0 |
| CVE-2025-2710 | Medium | XSS | `/menu.jsp` (flag) | Reflected XSS in ERP-NC 5.0 |
| CVE-2025-2709 | Medium | Open Redirect | `/login.jsp` (key/redirect) | Open redirect |

### 4b. Yonyou U8 Cloud

| CVE | Severity | Type | Affected Endpoint | Description |
|-----|----------|------|-------------------|-------------|
| CVE-2025-14185 | Critical | SQL Injection | `nc/pubitf/erm/mobile/appservice/AppServletService.class` (usercode) | SQLi in U8 Cloud 5.0/5.0sp/5.1/5.1sp |
| CVE-2025-12344 | High | Vulnerability | `/service/NCloudGatewayServlet` | Request header manipulation vulnerability |
| CVE-2022-26263 | Low | DOM XSS | `/u8sl/WebHelp` | DOM-based XSS in U8 v13.0 |

### 4c. Yonyou PLM

| CVE | Severity | Type | Affected | Description |
|-----|----------|------|----------|-------------|
| CVE-2021-41744 | Critical | Command Injection | All versions | Command injection in Product Lifecycle Management |

### Key Exploit Details

**CVE-2025-34039 (BeanShell RCE) — MOST CRITICAL:**
```
Unauthenticated access to /servlet/~ic/bsh.servlet.BshServlet
Allows execution of arbitrary Java code via BeanShell interpreter

Example:
POST /servlet/~ic/bsh.servlet.BshServlet
bsh.script=exec("whoami");
```
- This is the direct equivalent of the Java `Runtime.getRuntime().exec()` exposed without auth.
- Extremely trivial to exploit — commonly found in unpatched NC deployments.

### Common Attack Vectors

1. **BeanShell Servlet (CVE-2025-34039)** — The single most critical vulnerability across all Chinese ERPs. An unauthenticated BeanShell interpreter exposed on the web. Trivial RCE.

2. **SQL Injection** — `AppServletService.class` SQLi in the `usercode` parameter, common in U8 Cloud mobile interfaces.

3. **Arbitrary File Read** — `PrintTemplateFileServlet` allows reading arbitrary files from the server.

4. **Command Injection** — PLM product has known command injection.

5. **XSS** — Multiple reflected XSS across help/login pages, useful for phishing/session hijacking.

### Typical Exploitation Path

```
1. Fingerprint: Look for /nc/, /u8sl/, /portal/, /service/, Yonyou-specific paths
2. BeanShell RCE: Hit /servlet/~ic/bsh.servlet.BshServlet directly
   → If accessible, game over — execute arbitrary commands
3. SQL Injection: If BeanShell is patched, try SQLi via mobile endpoints
4. File Read: Exploit CVE-2023-4748 to read config files → extract DB credentials
5. Login: Use extracted credentials to access admin panels
```

### Default Credentials
- `admin` / `admin`
- `admin` / `1`
- `system` / `system`
- `root` / `root`
- `yonyou` / `yonyou`
- `nc` / `nc`

---

## 5. 蓝凌OA (Landray/Lanling)

**Vendor:** Shenzhen Landray Software Co., Ltd.
**Total CVEs found:** 2 (likely many more known in Chinese vulnerability databases like CNVD/CNNVD)

| CVE | Severity | Type | Affected Endpoint | Description |
|-----|----------|------|-------------------|-------------|
| **CVE-2024-58352** | **Critical** | **Unauth HQL Injection** | Unknown (uid POST parameter) | **Unauthenticated Hibernate HQL injection** allowing query of arbitrary Hibernate entity classes. Can extract all database data. |
| CVE-2022-34924 | High | Arbitrary File Read | `/sys/ui/extend/varkind/custom.jsp` | Arbitrary file read via patch #133383/#137780 |

### Common Attack Vectors

1. **HQL Injection** — CVE-2024-58352 is particularly dangerous because HQL injection can access all mapped entity classes, not just raw tables. This can expose user credentials, system configurations, and business data.

2. **Arbitrary File Read** — `custom.jsp` endpoint allows reading server files.

### Typical Exploitation Path

```
1. Fingerprint: Look for /sys/, /landray/, /ekp/ paths
2. HQL Injection: Exploit CVE-2024-58352 with crafted uid parameter to extract user data
3. File Read: Use /sys/ui/extend/varkind/custom.jsp to read configuration files
4. Extract credentials from database or config files
5. Login and escalate
```

### Default Credentials
- `admin` / `admin`
- `sysadmin` / `123456`
- `admin` / `landray`

---

## 6. 万户OA (Wanhu)

**Vendor:** Wanhu Network Technology Co., Ltd.
**Total CVEs found:** 0 on cve.org (but known vulnerabilities exist in Chinese databases)

**Note:** While no CVEs were found in the CVE.org database, Chinese vulnerability databases (CNVD, CNNVD) and Chinese security communities frequently report Wanhu OA vulnerabilities including:
- SQL injection vulnerabilities
- File upload bypasses
- Default credential issues

### Default Credentials
- `admin` / `admin`
- `admin` / `123456`
- `admin` / `wanhu`

---

## 7. Cross-Framework Attack Patterns

### Common Vulnerability Classes Across All Frameworks

| Vulnerability Class | Tongda | Weaver | Seeyon | Yonyou | Landray |
|---------------------|--------|--------|--------|--------|---------|
| SQL Injection | ✅ (50+) | ✅ | ❌ | ✅ | ✅ (HQL) |
| File Upload (→ RCE) | ✅ | ✅ (4+) | ✅ (2) | ❌ | ❌ |
| Unauthenticated RCE | ✅ | ✅ (2) | ✅ (1) | ✅ (1) | ❌ |
| Deserialization | ❌ | ❌ | ✅ | ❌ | ❌ |
| Arbitrary File Read | ✅ | ✅ (2) | ✅ (1) | ✅ | ✅ |
| XXE | ❌ | ✅ | ❌ | ❌ | ❌ |
| Code Injection | ❌ | ❌ | ❌ | ✅ (BeanShell) | ❌ |
| Source Code Leak | ❌ | ✅ | ❌ | ❌ | ❌ |

### Common Attack Surface

1. **`delete.php` pattern** — Particularly in Tongda OA: nearly every module has a `delete.php` that's vulnerable to SQL injection via unsanitized ID parameters.

2. **Unprotected servlets** — Seeyon (wpsAssistServlet, htmlofficeservlet), Yonyou (BshServlet) expose critical functionality without authentication.

3. **Mobile API endpoints** — `/pda/`, `/mobile/`, `/m/` paths often have weaker authentication and more injected code.

4. **File upload handlers** — Multiple frameworks accept file uploads without proper validation, enabling webshell deployment.

5. **XML-RPC / RPC endpoints** — Weaver's XmlRpcServlet is a major attack surface for information disclosure.

### Chained Exploitation (Multi-Framework)

In large Chinese enterprises, multiple OA/ERP systems coexist. A typical APT/red team chain:

```
1. External Recon: FOFA/Shodan fingerprinting for Chinese OA systems
2. Initial Access: Exploit public-facing OA (most likely Seeyon or Weaver)
   e.g., CVE-2025-34040 (Seeyon) → JSP webshell
3. Internal Discovery: From webshell, scan internal network for:
   - Yonyou NC ERP (port 80/8080, /nc/, /servlet/)
   - Database servers (MySQL port 3306, Oracle 1521, SQL Server 1433)
4. Lateral Movement: Use OA credentials from first foothold
   OR: Exploit BeanShell on Yonyou NC for code execution
5. Data Exfiltration: SQLi chains across frameworks to dump all business data
```

---

## 8. Default Credentials

| Framework | Username | Password |
|-----------|----------|----------|
| Tongda OA | admin | admin |
| Tongda OA | admin | 123456 |
| Tongda OA | admin | tongda |
| Weaver E-cology | sysadmin | 1 |
| Weaver E-office | admin | admin |
| Seeyon OA | admin | 123456 |
| Seeyon OA | system | system |
| Seeyon OA | seeyon | 123456 |
| Yonyou NC | admin | admin |
| Yonyou NC | system | system |
| Yonyou NC | root | root |
| Yonyou NC | nc | nc |
| Yonyou U8 | admin | 1 |
| Landray OA | admin | admin |
| Landray OA | sysadmin | 123456 |
| Wanhu OA | admin | admin |
| Wanhu OA | admin | 123456 |

---

## 9. Sources & References

### CVE Sources
- **cve.org** — Primary CVE database (searched for each framework)
- **NVD (NIST)** — National Vulnerability Database
- **CNVD** — China National Vulnerability Database (www.cnvd.org.cn)
- **CNNVD** — China National Information Security Vulnerability Database

### Exploit Repositories
- **Exploit-DB** — Local searchsploit, EDB-ID 52490 (Seeyon/Zhiyuan OA file upload)
- **GitHub** — `admintony/TongdaRCE` (Tongda OA RCE exploit)

### Advisories
- **VulnCheck** — advisories for CVE-2025-34040, CVE-2025-34039, CVE-2026-22679, CVE-2024-58352, CVE-2022-50992, CVE-2022-50993
- **VulDB** — Multiple CVEs across all frameworks

### FOFA / Shodan Dorking
```
# Tongda OA
app="Tongda-OA"

# Weaver E-cology
app="泛微-协同办公OA"

# Seeyon
app="致远互联-OA"

# Yonyou NC
app="用友-NC"
title="Yonyou NC"

# Landray
app="蓝凌OA"
```

### Additional Notes
- Many more vulnerabilities exist in Chinese vulnerability databases (CNVD/CNNVD) that are not assigned CVEs.
- Chinese APT groups (e.g., APT27, APT41) are known to target these OA/ERP frameworks for supply chain and enterprise access.
- Most exploitation happens within hours of vulnerability disclosure due to active scanning by both security researchers and threat actors.
