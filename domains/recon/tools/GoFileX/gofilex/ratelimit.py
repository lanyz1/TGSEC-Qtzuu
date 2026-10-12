"""Per-endpoint + global rate limiter.

GoFile documents that:

* limits are per endpoint, per IP and per account
* exact numbers are not disclosed
* 429 / error-rateLimit means back off and retry
* repeatedly exceeding limits may trigger an automatic IP ban

Cruise at a few seconds per listing call (no bursts). On 429, honour
Retry-After when present, otherwise exponential cooldown (15s, 30s, 60s, …)
and briefly raise the cruise interval. Pause only after several consecutive
429s so a single spike cannot walk into an IP ban.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

# Documented: GET /servers must not be called more than once every 10s.
# The earlier IP block came from a short burst, not from ~3s spacing.
GLOBAL_MIN_INTERVAL = 1.0
DEFAULT_INTERVALS: dict[str, float] = {
    "contents": 3.0,
    "accounts": 12.0,
    "accounts_getid": 8.0,
    "accounts_create": 30.0,
    "servers": 10.0,
    "wt_script": 86400.0,
    "download": 1.0,
}
FLOOR_INTERVALS: dict[str, float] = {
    "contents": 1.5,
    "accounts": 6.0,
    "accounts_getid": 5.0,
    "accounts_create": 15.0,
    "servers": 10.0,
    "wt_script": 3600.0,
    "download": 0.5,
}
# 15s, 30s, 60s, 120s, 240s, cap 8 min
FIRST_429_BACKOFF = 15.0
MAX_429_BACKOFF = 480.0
PAUSE_AFTER_CONSECUTIVE_429 = 3
NETWORK_BACKOFF = 30.0
PAUSE_ON_NETWORK_ERROR = True
MAX_CONTENTS_INTERVAL = 20.0
OK_STREAK_TO_RELAX = 8
DEFAULT_UNKNOWN_INTERVAL = 5.0

SleepFn = Callable[[float], Awaitable[None]]


@dataclass
class EndpointStats:
    name: str
    min_interval: float
    last_request: float = 0.0
    last_ok: float = 0.0
    requests: int = 0
    ok: int = 0
    errors: int = 0
    rate_limits: int = 0
    consecutive_429: int = 0
    consecutive_ok: int = 0
    cooldown_until: float = 0.0
    last_status: str = ""
    last_http: int | None = None
    retry_after: float | None = None


@dataclass
class RateLimiter:
    global_min_interval: float = GLOBAL_MIN_INTERVAL
    contents_interval: float = DEFAULT_INTERVALS["contents"]
    last_any: float = 0.0
    endpoints: dict[str, EndpointStats] = field(default_factory=dict)
    paused: bool = False
    pause_reason: str = ""
    session_started: float = field(default_factory=time.time)

    def endpoint(self, name: str) -> EndpointStats:
        stats = self.endpoints.get(name)
        if stats is None:
            interval = DEFAULT_INTERVALS.get(name, DEFAULT_UNKNOWN_INTERVAL)
            if name == "contents":
                interval = self.contents_interval
            stats = EndpointStats(name=name, min_interval=interval)
            self.endpoints[name] = stats
        return stats

    def set_contents_interval(self, seconds: float) -> float:
        floor = FLOOR_INTERVALS["contents"]
        self.contents_interval = max(floor, float(seconds))
        self.endpoint("contents").min_interval = self.contents_interval
        return self.contents_interval

    def next_allowed_at(self, name: str, now: float | None = None) -> float:
        now = now if now is not None else time.time()
        stats = self.endpoint(name)
        candidates = [
            self.last_any + self.global_min_interval,
            stats.last_request + stats.min_interval,
            stats.cooldown_until,
        ]
        return max(candidates)

    def wait_seconds(self, name: str, now: float | None = None) -> float:
        now = now if now is not None else time.time()
        return max(0.0, self.next_allowed_at(name, now) - now)

    async def acquire(self, name: str, sleep: SleepFn) -> None:
        """Block via the provided async sleep until this endpoint may fire."""
        while True:
            wait = self.wait_seconds(name)
            if wait <= 0:
                self.mark_request(name)
                return
            await sleep(min(wait, 1.0))

    def mark_request(self, name: str, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        stats = self.endpoint(name)
        stats.last_request = now
        stats.requests += 1
        self.last_any = now

    def observe(
        self,
        name: str,
        *,
        api_status: str,
        http_status: int | None = None,
        retry_after: float | None = None,
        now: float | None = None,
    ) -> None:
        now = now if now is not None else time.time()
        stats = self.endpoint(name)
        stats.last_status = api_status
        stats.last_http = http_status
        stats.retry_after = retry_after

        if api_status == "error-rateLimit" or http_status == 429:
            stats.rate_limits += 1
            stats.consecutive_429 += 1
            stats.consecutive_ok = 0
            backoff = min(
                MAX_429_BACKOFF,
                FIRST_429_BACKOFF * (2 ** (stats.consecutive_429 - 1)),
            )
            if retry_after is not None:
                backoff = max(backoff, retry_after)
            stats.cooldown_until = now + backoff
            if name == "contents":
                self.set_contents_interval(
                    min(MAX_CONTENTS_INTERVAL, self.contents_interval * 2.0)
                )
            else:
                floor = FLOOR_INTERVALS.get(name, DEFAULT_UNKNOWN_INTERVAL)
                stats.min_interval = min(
                    MAX_CONTENTS_INTERVAL,
                    max(stats.min_interval * 2.0, floor),
                )
            if stats.consecutive_429 >= PAUSE_AFTER_CONSECUTIVE_429:
                self.paused = True
                self.pause_reason = (
                    f"{stats.consecutive_429} consecutive 429s on {name}; "
                    f"paused after exponential backoff ({backoff:.0f}s). "
                    "When the listing slot is 0s, /heartbeat once."
                )
            return

        if api_status == "ok" or (http_status is not None and 200 <= http_status < 300):
            stats.ok += 1
            stats.last_ok = now
            stats.consecutive_429 = 0
            stats.consecutive_ok += 1
            if (
                name == "contents"
                and stats.consecutive_ok >= OK_STREAK_TO_RELAX
                and self.contents_interval > DEFAULT_INTERVALS["contents"]
            ):
                self.set_contents_interval(
                    max(DEFAULT_INTERVALS["contents"], self.contents_interval * 0.75)
                )
                stats.consecutive_ok = 0
            return

        stats.errors += 1
        if api_status == "error-network":
            stats.cooldown_until = max(stats.cooldown_until, now + NETWORK_BACKOFF)
            if PAUSE_ON_NETWORK_ERROR:
                self.paused = True
                self.pause_reason = (
                    f"network timeout on {name}; treating this as an IP cooldown. "
                    "When the listing slot is 0s, /heartbeat once — do not loop."
                )
        stats.consecutive_429 = 0
        stats.consecutive_ok = 0

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        return {
            "global_min_interval": self.global_min_interval,
            "contents_interval": self.contents_interval,
            "paused": self.paused,
            "pause_reason": self.pause_reason,
            "uptime_s": now - self.session_started,
            "endpoints": {
                name: {
                    "min_interval": ep.min_interval,
                    "requests": ep.requests,
                    "ok": ep.ok,
                    "errors": ep.errors,
                    "rate_limits": ep.rate_limits,
                    "consecutive_429": ep.consecutive_429,
                    "consecutive_ok": ep.consecutive_ok,
                    "cooldown_s": max(0.0, ep.cooldown_until - now),
                    "next_s": self.wait_seconds(name, now),
                    "last_status": ep.last_status,
                    "last_http": ep.last_http,
                }
                for name, ep in self.endpoints.items()
            },
        }
