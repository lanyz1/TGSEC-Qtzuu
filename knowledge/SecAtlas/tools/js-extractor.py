#!/usr/bin/env python3
"""
JS Extractor — Extract secrets, endpoints, and API keys from JavaScript files.

Recursively scans JS files for:
  - API keys (AWS, GitHub, Google, Stripe, etc.)
  - Internal endpoints (/api/, /graphql, /v1/, etc.)
  - JWT tokens and session secrets
  - Hardcoded credentials
  - Internal hostnames and IPs
  - WebSocket endpoints
  - Firebase/Supabase configs

Usage:
  python3 js-extractor.py <url_or_file>               # Single URL or file
  python3 js-extractor.py -f urls.txt                  # Batch from file
  python3 js-extractor.py -d ./js_files/               # Directory of JS files
  python3 js-extractor.py https://target.com -r         # Recursive (follow imports)
"""

import re
import sys
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

PATTERNS = {
    # API Keys & Tokens
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?i)aws.{0,20}(?:secret|key).{0,20}[0-9a-zA-Z/+]{40}',
    "GitHub Token": r'(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}',
    "GitHub PAT": r'github_pat_[0-9a-zA-Z_]{36,}',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Stripe Key": r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
    "Slack Token": r'xox[bprs]-[0-9a-zA-Z\-]{10,}',
    "JWT Token": r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',
    "Generic API Key": r'(?i)(?:api[_-]?key|apikey|api_secret|access[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']',
    "Bearer Token": r'(?i)bearer\s+[A-Za-z0-9\-_.~+/]+=*',
    "Basic Auth": r'(?i)basic\s+[A-Za-z0-9+/=]{20,}',

    # Endpoints
    "Internal API": r'["\'`](/api(?:/[a-zA-Z0-9_\-./]+)*)["\'`]',
    "GraphQL Endpoint": r'["\'`](/graphql)["\'`]',
    "REST API v1/v2": r'["\'`](/v[12]/[a-zA-Z0-9_\-./]+)["\'`]',
    "WebSocket": r'(?:wss?://[a-zA-Z0-9.\-]+(?::\d+)?/\S+)',
    "Internal Host": r'(?:https?://(?:[a-zA-Z0-9\-]+\.)*internal[a-zA-Z0-9\-\.]+)',
    "Staging Host": r'(?:https?://(?:[a-zA-Z0-9\-]+\.)*(?:staging|dev|test|uat)[a-zA-Z0-9\-\.]+)',

    # Configs
    "Firebase Config": r'(?s)firebase\.initializeApp\(\{[^}]+\}\)',
    "Supabase Config": r'supabase[a-zA-Z0-9._]*\s*[:=]\s*["\'][^"\']{8,}["\']',
    "Database URL": r'(?:postgres|mysql|mongodb|redis)://[^"\'\s]+',
    "S3 Bucket": r's3\.amazonaws\.com/[a-zA-Z0-9\-_.]+',
    "Cloud Metadata URL": r'http://169\.254\.169\.254/\S+',

    # Credentials
    "Password in JS": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']',
    "Hardcoded Secret": r'(?i)(?:secret|token|key)\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}["\']',

    # Source Maps
    "Source Map Ref": r'//#\s*sourceMappingURL=(\S+)',
}

def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Linux x86_64) js-extractor/1.0'
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode('utf-8', errors='replace')

def scan_content(content: str, source: str) -> list:
    findings = []
    for name, pattern in PATTERNS.items():
        matches = list(set(re.findall(pattern, content, re.IGNORECASE if '(?i)' not in pattern else 0)))
        for match in matches[:5]:
            if isinstance(match, tuple):
                match = match[0] if match[0] else match[1] if len(match) > 1 else str(match)
            findings.append({
                'type': name,
                'value': match.strip()[:120],
                'source': source
            })
    return findings

def scan_file(filepath: str) -> list:
    try:
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()
        return scan_content(content, filepath)
    except Exception as e:
        return [{'type': 'ERROR', 'value': str(e), 'source': filepath}]

def scan_url(url: str, recursive: bool = False) -> list:
    findings = []
    try:
        content = fetch_url(url)
        findings.extend(scan_content(content, url))

        if recursive:
            source_maps = re.findall(r'//#\s*sourceMappingURL=(\S+)', content)
            for sm_url in source_maps:
                if not sm_url.startswith('http'):
                    base = url.rsplit('/', 1)[0]
                    sm_url = f"{base}/{sm_url}"
                try:
                    sm_content = fetch_url(sm_url)
                    sm_data = json.loads(sm_content)
                    for src in sm_data.get('sources', []):
                        findings.append({
                            'type': 'SourceMap Source',
                            'value': src,
                            'source': sm_url
                        })
                except:
                    pass
    except Exception as e:
        findings.append({'type': 'ERROR', 'value': str(e), 'source': url})
    return findings

def main():
    parser = argparse.ArgumentParser(description='JS Extractor — secrets & endpoints from JavaScript')
    parser.add_argument('target', nargs='?', help='URL or file to scan')
    parser.add_argument('-f', '--file', help='File with URLs (one per line)')
    parser.add_argument('-d', '--dir', help='Directory of JS files')
    parser.add_argument('-r', '--recursive', action='store_true', help='Follow source maps')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')

    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    if args.file:
        with open(args.file) as f:
            targets.extend(line.strip() for line in f if line.strip())
    if args.dir:
        targets.extend(str(p) for p in Path(args.dir).rglob('*.js'))

    if not targets:
        parser.print_help()
        return

    all_findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for t in targets:
            if t.startswith('http'):
                futures[executor.submit(scan_url, t, args.recursive)] = t
            else:
                futures[executor.submit(scan_file, t)] = t

        for future in as_completed(futures):
            target = futures[future]
            try:
                findings = future.result()
                if findings:
                    if not args.quiet:
                        print(f"\n--- {target} ({len(findings)} findings) ---")
                    for f in findings:
                        if not args.quiet:
                            print(f"  [{f['type']}] {f['value'][:100]}")
                        all_findings.append(f)
            except Exception as e:
                if not args.quiet:
                    print(f"[!] {target}: {e}")

    # Summary
    type_counts = {}
    for f in all_findings:
        t = f['type']
        type_counts[t] = type_counts.get(t, 0) + 1

    print(f"\n{'='*50}")
    print(f"SUMMARY: {len(all_findings)} findings from {len(targets)} targets")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {t}: {c}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_findings, f, indent=2, ensure_ascii=False)
        print(f"\n[✓] Saved to {args.output}")

if __name__ == '__main__':
    main()
