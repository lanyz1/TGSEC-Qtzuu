#!/usr/bin/env python3
"""CDN quick origin tracer — passive discovery + Host-header verify.

Stages: CDN header detect → crt.sh → resolve → history DNS → MX/SPF →
filter CDN ranges → Host verify + body hash. Stdlib first; uses requests if present.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    from cdn_ranges import filter_candidates, get_vendor, is_cdn
except Exception:  # pragma: no cover
    def is_cdn(ip: str) -> bool:
        return False

    def get_vendor(ip: str) -> Optional[str]:
        return None

    def filter_candidates(ips):
        return list(ips)

BYPASS_LABELS = [
    "mail", "smtp", "pop3", "imap", "webmail", "mx", "cpanel", "whm", "admin",
    "ftp", "ftps", "sftp", "direct", "origin", "backend", "real", "unprotected",
    "bypass", "no-cdn", "raw", "vpn", "ns1", "ns2", "dev", "staging", "test",
    "uat", "beta", "api", "api2", "m", "mobile", "www1", "www2", "git", "ssh",
]


def http_get(url: str, timeout: int = 20) -> bytes:
    try:
        import requests  # type: ignore

        r = requests.get(url, timeout=timeout, headers={"User-Agent": "cdn-quick-trace/0.1"})
        return r.content
    except Exception:
        req = urllib.request.Request(url, headers={"User-Agent": "cdn-quick-trace/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()


def dig(name: str, rtype: str = "A") -> List[str]:
    try:
        out = subprocess.check_output(
            ["dig", "+short", name, rtype],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        )
        vals = []
        for line in out.splitlines():
            line = line.strip().rstrip(".")
            if not line:
                continue
            if rtype in ("A", "AAAA") and re.match(r"^[\d.:a-fA-F]+$", line):
                vals.append(line)
            elif rtype in ("MX", "CNAME", "TXT"):
                vals.append(line)
        return vals
    except Exception:
        try:
            if rtype == "A":
                return sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET)})
            if rtype == "AAAA":
                return sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET6)})
        except Exception:
            return []
        return []


def detect_cdn(host: str) -> Dict:
    info = {"host": host, "headers": {}, "vendor_hints": []}
    try:
        import requests  # type: ignore

        r = requests.get(f"https://{host}/", timeout=15, allow_redirects=True)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
    except Exception:
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(f"https://{host}/", context=ctx, timeout=15) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as e:
            info["error"] = str(e)
            return info
    info["headers"] = {k: hdrs[k] for k in hdrs if k in (
        "server", "cf-ray", "cf-cache-status", "via", "x-cache", "x-amz-cf-id",
        "x-amz-cf-pop", "x-sucuri-id", "x-akamai-transformed",
    )}
    blob = " ".join(f"{k}:{v}" for k, v in hdrs.items()).lower()
    if "cf-ray" in hdrs or "cloudflare" in blob:
        info["vendor_hints"].append("Cloudflare")
    if "x-amz-cf" in blob or "cloudfront" in blob:
        info["vendor_hints"].append("CloudFront")
    if "akamai" in blob:
        info["vendor_hints"].append("Akamai")
    if "fastly" in blob:
        info["vendor_hints"].append("Fastly")
    return info


def crtsh_names(domain: str) -> Set[str]:
    names: Set[str] = set()
    try:
        raw = http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=40)
        data = json.loads(raw.decode("utf-8", "ignore") or "[]")
        for row in data if isinstance(data, list) else []:
            for part in str(row.get("name_value", "")).split("\n"):
                part = part.strip().lower().lstrip("*.")
                if part.endswith(domain) or part == domain:
                    names.add(part)
    except Exception as e:
        names.add(f"__crt_error__:{e}")
    return names


def history_ips(domain: str) -> Set[str]:
    ips: Set[str] = set()
    try:
        raw = http_get(f"https://api.hackertarget.com/iphistory/?q={domain}", timeout=20).decode()
        for line in raw.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                ips.add(m.group(1))
    except Exception:
        pass
    try:
        raw = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20).decode()
        for line in raw.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                ips.add(m.group(1))
    except Exception:
        pass
    return ips


def resolve_host(host: str) -> Set[str]:
    return set(dig(host, "A") + dig(host, "AAAA"))


def mail_ips(domain: str) -> Set[str]:
    ips: Set[str] = set()
    for mx in dig(domain, "MX"):
        # "10 mail.example.com"
        host = mx.split()[-1] if mx.split() else mx
        ips |= resolve_host(host)
    for txt in dig(domain, "TXT"):
        # include:ip4:
        for m in re.finditer(r"ip4:([\d.]+)", txt):
            ips.add(m.group(1))
        for m in re.finditer(r"include:([^\s\"]+)", txt):
            # not resolving includes recursively here
            pass
    return ips


def fetch_with_host(ip: str, host: str, timeout: int = 12) -> Dict:
    out = {"ip": ip, "ok": False}
    try:
        import requests  # type: ignore

        r = requests.get(
            f"https://{ip}/",
            headers={"Host": host, "User-Agent": "cdn-quick-trace/0.1"},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        body = r.content
        out.update({
            "ok": True,
            "status": r.status_code,
            "server": r.headers.get("Server"),
            "title": (re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S) or [b"", b""])[1][:120].decode("utf-8", "ignore"),
            "sha256": hashlib.sha256(body).hexdigest(),
            "len": len(body),
        })
        return out
    except Exception as e:
        out["error"] = str(e)[:160]
        return out


def baseline_hash(host: str) -> Optional[str]:
    try:
        import requests  # type: ignore

        r = requests.get(f"https://{host}/", timeout=15)
        return hashlib.sha256(r.content).hexdigest()
    except Exception:
        try:
            raw = http_get(f"https://{host}/", timeout=15)
            return hashlib.sha256(raw).hexdigest()
        except Exception:
            return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CDN quick origin tracer")
    ap.add_argument("domain")
    ap.add_argument("-o", "--output", help="JSON report path")
    ap.add_argument("--passive-only", action="store_true", help="No Host-header probes")
    ap.add_argument("--threads", type=int, default=20)
    args = ap.parse_args(argv)
    domain = args.domain.strip().lower().lstrip("http://").lstrip("https://").split("/")[0]

    report: Dict = {"domain": domain, "ts": int(time.time()), "cdn": {}, "candidates": [], "verified": []}
    print(f"[*] detect CDN: {domain}")
    report["cdn"] = detect_cdn(domain)
    print(f"    hints={report['cdn'].get('vendor_hints')} headers={report['cdn'].get('headers')}")

    print("[*] crt.sh")
    crt_raw = crtsh_names(domain)
    names = {n for n in crt_raw if not n.startswith("__crt_error__")}
    err = [n for n in crt_raw if n.startswith("__crt_error__")]
    if err:
        print(f"    crt warn: {err[0][:80]}")
    names |= {domain, f"www.{domain}"}
    for lab in BYPASS_LABELS:
        names.add(f"{lab}.{domain}")
    print(f"    names={len(names)}")

    print("[*] resolve + history + mail")
    cand: Set[str] = set()
    cand |= resolve_host(domain)
    cand |= history_ips(domain)
    cand |= mail_ips(domain)

    def _res(n: str) -> Set[str]:
        return resolve_host(n)

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(_res, n): n for n in sorted(names)[:400]}
        for fut in as_completed(futs):
            try:
                cand |= fut.result()
            except Exception:
                pass

    report["raw_ips"] = sorted(cand)
    non_cdn = filter_candidates(sorted(cand))
    report["candidates"] = [{"ip": ip, "cdn": get_vendor(ip)} for ip in sorted(cand)]
    report["non_cdn"] = non_cdn
    print(f"    raw={len(cand)} non_cdn={len(non_cdn)} → {non_cdn[:20]}")

    if not args.passive_only and non_cdn:
        print("[*] Host-header verify")
        base = baseline_hash(domain)
        report["baseline_sha256"] = base
        verified = []
        with ThreadPoolExecutor(max_workers=min(10, args.threads)) as ex:
            futs = {ex.submit(fetch_with_host, ip, domain): ip for ip in non_cdn[:40]}
            for fut in as_completed(futs):
                res = fut.result()
                if not res.get("ok"):
                    continue
                res["hash_match"] = bool(base and res.get("sha256") == base)
                verified.append(res)
                mark = "MATCH" if res["hash_match"] else "resp"
                print(f"    {mark} {res['ip']} status={res.get('status')} len={res.get('len')} title={res.get('title','')[:40]}")
        report["verified"] = sorted(verified, key=lambda x: (not x.get("hash_match"), x.get("ip")))
        hits = [v for v in verified if v.get("hash_match")]
        print(f"[+] hash matches: {len(hits)}")
    else:
        print("[*] skip verify (passive-only or no candidates)")

    out = args.output or f"/tmp/cdn_report_{domain.replace('.', '_')}.json"
    Path(out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] report → {out}")
    return 0


if __name__ == "__main__":
    # quiet urllib3 if requests present
    try:
        import urllib3

        urllib3.disable_warnings()
    except Exception:
        pass
    sys.exit(main())
