"""GoFile HTTP client. Documented REST API + the website-token header the
official web app sends on listing calls.

Documented rules we honour:

* POST /accounts  — mint one guest and reuse it
* GET  /accounts/getid
* GET  /accounts/{accountId}  — usage / tier / stats
* GET  /contents/{contentId}  — Premium-badged; password = SHA-256 hex
* 429 / error-rateLimit → back off (never tight-loop)
* GET /servers at most once per 10s (we simply do not call it)

The web client also sends ``X-Website-Token`` / ``X-BL`` on listing
requests so a guest can read a public share the same way the official web client does.
Without that header the listing endpoint answers error-notPremium.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .ratelimit import RateLimiter
from .wt import DEFAULT_SALT, WT_SCRIPT_URL, extract_salts_from_obf, generate_wt

API_BASE = "https://api.gofile.io"
ORIGIN = "https://gofile.io"
REFERER = "https://gofile.io/"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
LANGUAGE = "en-US"
HTTP_TIMEOUT = httpx.Timeout(20.0, connect=8.0, pool=8.0)
DOWNLOAD_CHUNK = 64 * 1024
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f]")

ProgressFn = Callable[[int, int], None]


@dataclass
class ApiResponse:
    endpoint: str
    http_status: int
    api_status: str
    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    retry_after: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.api_status == "ok"

    @property
    def rate_limited(self) -> bool:
        return self.api_status == "error-rateLimit" or self.http_status == 429

    @property
    def not_premium(self) -> bool:
        return self.api_status == "error-notPremium"


@dataclass
class ListingResult(ApiResponse):
    can_access: bool | None = None
    password_protected: bool = False
    password_status: str | None = None

    @property
    def password_ok(self) -> bool:
        if not self.ok:
            return False
        if self.can_access is False:
            return False
        if self.password_status in ("passwordWrong", "passwordRequired"):
            return False
        if self.password_status == "passwordOk":
            return True
        if self.can_access is True:
            return True
        # Unprotected (or owner) listing: no gate fields, children present.
        return not self.password_protected

    @property
    def password_wrong(self) -> bool:
        return self.ok and self.password_status == "passwordWrong"

    @property
    def needs_password(self) -> bool:
        return self.ok and self.can_access is False and self.password_protected

    @property
    def children(self) -> list[dict[str, Any]]:
        kids = self.data.get("children") or {}
        if isinstance(kids, dict):
            return list(kids.values())
        if isinstance(kids, list):
            return kids
        return []


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


class GofileClient:
    def __init__(self, token: str = "", limiter: RateLimiter | None = None) -> None:
        self.token = token
        self.salt = DEFAULT_SALT
        self.limiter = limiter or RateLimiter()
        self._http = httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Origin": ORIGIN,
                "Referer": REFERER,
                "X-BL": LANGUAGE,
            },
            follow_redirects=True,
            http2=False,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    def _auth_headers(self, *, listing: bool = False, window_offset: int = 0) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if listing and self.token:
            headers["X-Website-Token"] = generate_wt(
                self.token, USER_AGENT, LANGUAGE, self.salt, window_offset=window_offset
            )
            headers["X-BL"] = LANGUAGE
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        endpoint: str,
        listing: bool = False,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        window_offset: int = 0,
    ) -> ApiResponse:
        await self.limiter.acquire(endpoint, self._sleep)
        url = path if path.startswith("http") else f"{API_BASE}{path}"
        try:
            response = await self._http.request(
                method,
                url,
                params=params,
                json=json,
                headers=self._auth_headers(listing=listing, window_offset=window_offset),
            )
        except httpx.HTTPError as exc:
            self.limiter.observe(endpoint, api_status="error-network", http_status=None)
            return ApiResponse(
                endpoint=endpoint,
                http_status=0,
                api_status="error-network",
                data={"message": str(exc)},
            )

        try:
            body = response.json()
        except ValueError:
            body = {"status": "error-noResponse", "data": {"body": response.text[:500]}}

        api_status = body.get("status") if isinstance(body, dict) else "error-noResponse"
        if not isinstance(api_status, str):
            api_status = "error-noResponse"
        data = body.get("data") if isinstance(body, dict) else {}
        if not isinstance(data, dict):
            data = {"value": data}
        metadata = body.get("metadata") if isinstance(body, dict) else {}
        if not isinstance(metadata, dict):
            metadata = {}

        result = ApiResponse(
            endpoint=endpoint,
            http_status=response.status_code,
            api_status=api_status,
            data=data,
            metadata=metadata,
            retry_after=_retry_after(response),
            raw=body if isinstance(body, dict) else {},
        )
        self.limiter.observe(
            endpoint,
            api_status=api_status,
            http_status=response.status_code,
            retry_after=result.retry_after,
        )
        return result

    async def _sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    async def refresh_salt(self) -> str:
        """Best-effort pull of the current wt.obf.js salt. Safe to skip."""
        try:
            await self.limiter.acquire("wt_script", self._sleep)
            response = await self._http.get(WT_SCRIPT_URL, headers={"Accept": "*/*"})
            self.limiter.observe(
                "wt_script",
                api_status="ok" if response.status_code == 200 else "error",
                http_status=response.status_code,
            )
            if response.status_code == 200:
                salts = extract_salts_from_obf(response.text)
                if salts:
                    self.salt = salts[0]
        except httpx.HTTPError:
            self.limiter.observe("wt_script", api_status="error-network")
        return self.salt

    async def create_guest(self) -> ApiResponse:
        result = await self._request("POST", "/accounts", endpoint="accounts_create", json={})
        if result.ok:
            self.token = str(result.data.get("token") or self.token)
        return result

    async def get_id(self) -> ApiResponse:
        return await self._request("GET", "/accounts/getid", endpoint="accounts_getid")

    async def get_account(self, account_id: str) -> ApiResponse:
        return await self._request(
            "GET",
            f"/accounts/{account_id}",
            endpoint="accounts",
        )

    async def get_contents(
        self,
        content_id: str,
        password_hash: str | None = None,
        *,
        page: int = 1,
        page_size: int = 100,
        window_offset: int = 0,
    ) -> ListingResult:
        params: dict[str, str | int] = {
            "page": page,
            "pageSize": page_size,
            "sortField": "name",
            "sortDirection": 1,
        }
        if password_hash:
            params["password"] = password_hash
        base = await self._request(
            "GET",
            f"/contents/{content_id}",
            endpoint="contents",
            listing=True,
            params=params,
            window_offset=window_offset,
        )
        data = base.data
        return ListingResult(
            endpoint=base.endpoint,
            http_status=base.http_status,
            api_status=base.api_status,
            data=data,
            metadata=base.metadata,
            retry_after=base.retry_after,
            raw=base.raw,
            can_access=data.get("canAccess"),
            password_protected=bool(data.get("password")),
            password_status=data.get("passwordStatus"),
        )

    async def download_file(
        self,
        url: str,
        dest: Path,
        on_progress: ProgressFn | None = None,
    ) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        headers = {
            "User-Agent": USER_AGENT,
            "Authorization": f"Bearer {self.token}",
            "Cookie": f"accountToken={self.token}",
            "Referer": REFERER,
            "Origin": ORIGIN,
        }
        await self.limiter.acquire("download", self._sleep)
        async with self._http.stream("GET", url, headers=headers) as response:
            self.limiter.observe(
                "download",
                api_status="ok" if response.status_code == 200 else "error",
                http_status=response.status_code,
            )
            response.raise_for_status()
            total = int(response.headers.get("Content-Length") or 0)
            written = 0
            tmp = dest.with_suffix(dest.suffix + ".part")
            with tmp.open("wb") as handle:
                async for chunk in response.aiter_bytes(DOWNLOAD_CHUNK):
                    handle.write(chunk)
                    written += len(chunk)
                    if on_progress:
                        on_progress(written, total)
            tmp.replace(dest)
        return dest


def sanitize_filename(name: str) -> str:
    name = name.replace("/", "_").replace("\\", "_")
    name = CONTROL_CHAR_RE.sub("", name).strip()
    return name or "download"
