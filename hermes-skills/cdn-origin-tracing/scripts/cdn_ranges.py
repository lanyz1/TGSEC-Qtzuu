#!/usr/bin/env python3
"""Minimal CDN IP range classifier + candidate filter (stdlib only)."""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from typing import Iterable, List, Optional, Tuple

# Compact high-signal static ranges (not exhaustive). Prefer refreshing from
# vendor feeds for long engagements — see full handbook.
STATIC_RANGES: List[Tuple[str, str]] = [
    ("Cloudflare", "103.21.244.0/22"),
    ("Cloudflare", "103.22.200.0/22"),
    ("Cloudflare", "103.31.4.0/22"),
    ("Cloudflare", "104.16.0.0/13"),
    ("Cloudflare", "104.24.0.0/14"),
    ("Cloudflare", "108.162.192.0/18"),
    ("Cloudflare", "131.0.72.0/22"),
    ("Cloudflare", "141.101.64.0/18"),
    ("Cloudflare", "162.158.0.0/15"),
    ("Cloudflare", "172.64.0.0/13"),
    ("Cloudflare", "173.245.48.0/20"),
    ("Cloudflare", "188.114.96.0/20"),
    ("Cloudflare", "190.93.240.0/20"),
    ("Cloudflare", "197.234.240.0/22"),
    ("Cloudflare", "198.41.128.0/17"),
    ("CloudFront", "13.32.0.0/15"),
    ("CloudFront", "13.224.0.0/14"),
    ("CloudFront", "52.84.0.0/15"),
    ("CloudFront", "54.230.0.0/16"),
    ("CloudFront", "99.84.0.0/16"),
    ("CloudFront", "143.204.0.0/16"),
    ("CloudFront", "205.251.192.0/19"),
    ("Fastly", "23.235.32.0/20"),
    ("Fastly", "151.101.0.0/16"),
    ("Fastly", "199.232.0.0/16"),
    ("Akamai", "23.32.0.0/11"),
    ("Akamai", "23.64.0.0/14"),
    ("Akamai", "104.64.0.0/10"),
    ("Akamai", "184.24.0.0/13"),
]


def _networks():
    out = []
    for vendor, cidr in STATIC_RANGES:
        try:
            out.append((vendor, ipaddress.ip_network(cidr, strict=False)))
        except ValueError:
            continue
    return out


NETWORKS = _networks()


def get_vendor(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for vendor, net in NETWORKS:
        if addr in net:
            return vendor
    return None


def is_cdn(ip: str) -> bool:
    return get_vendor(ip) is not None


def filter_candidates(ips: Iterable[str]) -> List[str]:
    kept = []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        if not is_cdn(ip):
            kept.append(ip)
    return kept


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="CDN range classify / filter")
    p.add_argument("ips", nargs="*", help="IPs to classify")
    p.add_argument("--filter", nargs="+", metavar="IP", help="Keep non-CDN IPs only")
    p.add_argument("--dump", action="store_true", help="Dump static ranges JSON")
    args = p.parse_args(argv)

    if args.dump:
        print(json.dumps([{"vendor": v, "cidr": c} for v, c in STATIC_RANGES], indent=2))
        return 0

    if args.filter is not None:
        for ip in filter_candidates(args.filter):
            print(ip)
        return 0

    if not args.ips:
        print(f"vendors≈{len({v for v, _ in STATIC_RANGES})} static_cidrs={len(STATIC_RANGES)}")
        return 0

    for ip in args.ips:
        v = get_vendor(ip)
        if v:
            print(f"{ip}\tCDN:{v}")
        else:
            print(f"{ip}\tnon-CDN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
