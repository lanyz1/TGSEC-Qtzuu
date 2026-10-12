from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from gofilex.api import ListingResult
from gofilex.ratelimit import FLOOR_INTERVALS, RateLimiter
from gofilex.session import Session, WordlistRecord, parse_content_id
from gofilex.wordlist import WordlistQueue, bundled_wordlists, sha256_hex, usable_password
from gofilex.wt import DEFAULT_SALT, generate_wt, time_window


def test_bundled_wordlists_scans_local_dir() -> None:
    # Wordlists are not shipped in the public tree. If the operator
    # dropped files locally, every returned path must exist.
    paths = bundled_wordlists()
    assert all(p.is_file() for p in paths)


def test_parse_target() -> None:
    assert parse_content_id("https://gofile.io/d/Example01") == "Example01"
    assert parse_content_id("Example01") == "Example01"


def test_session_multi_target_resume(tmp_path: Path, monkeypatch: Any) -> None:
    from gofilex import session as session_mod

    monkeypatch.setattr(session_mod, "SESSION_DIR", tmp_path)
    monkeypatch.setattr(session_mod, "APP_DIR", tmp_path)
    monkeypatch.setattr(session_mod, "ACTIVE_PATH", tmp_path / "active.json")

    s = Session(name="hunt")
    s.set_target("ShareAAAA")
    s.add_wordlist(tmp_path / "a.txt")
    (tmp_path / "a.txt").write_text("alpha\nbeta\n", encoding="utf-8")
    s.wordlists[0].line = 12
    s.wordlists[0].tried = 10
    s.save()

    s.set_target("https://gofile.io/d/ShareBBBB")
    assert s.content_id == "ShareBBBB"
    assert s.wordlists[0].line == 0
    assert s.wordlists[0].path.endswith("a.txt")
    s.wordlists[0].line = 3
    s.save()

    s.set_target("ShareAAAA")
    assert s.wordlists[0].line == 12
    s.set_target("ShareBBBB")
    assert s.wordlists[0].line == 3

    reloaded = Session.load("hunt")
    assert reloaded.content_id == "ShareBBBB"
    assert reloaded.wordlists[0].line == 3
    assert "ShareAAAA" in reloaded.targets
    assert reloaded.targets["ShareAAAA"].wordlists[0].line == 12


def test_password_hash_and_filter() -> None:
    assert sha256_hex("test") == hashlib.sha256(b"test").hexdigest()
    assert usable_password("abcd")
    assert not usable_password("ab")
    assert not usable_password("x" * 101)


def test_wt_formula() -> None:
    ua = "Mozilla/5.0"
    token = "abc"
    now = 124146 * 14400
    got = generate_wt(token, ua, "en-US", DEFAULT_SALT, now=now)
    raw = f"{ua}::en-US::{token}::{time_window(now)}::{DEFAULT_SALT}"
    assert got == hashlib.sha256(raw.encode()).hexdigest()


def test_rate_limiter_floor_and_429() -> None:
    limiter = RateLimiter()
    applied = limiter.set_contents_interval(0.1)
    assert applied >= FLOOR_INTERVALS["contents"]
    limiter.mark_request("contents")
    limiter.observe("contents", api_status="error-rateLimit", http_status=429)
    stats = limiter.endpoint("contents")
    assert stats.rate_limits == 1
    assert stats.consecutive_429 == 1
    assert stats.cooldown_until > time.time() + 10
    assert limiter.wait_seconds("contents") > 0
    assert limiter.paused is False
    limiter.observe("contents", api_status="error-rateLimit", http_status=429)
    limiter.observe("contents", api_status="error-rateLimit", http_status=429)
    assert limiter.paused is True
    assert stats.consecutive_429 == 3


def test_network_error_pauses() -> None:
    limiter = RateLimiter()
    limiter.mark_request("contents")
    limiter.observe("contents", api_status="error-network")
    assert limiter.paused is True
    assert limiter.wait_seconds("contents") > 0


def test_listing_gates() -> None:
    wrong = ListingResult(
        endpoint="contents",
        http_status=200,
        api_status="ok",
        data={"canAccess": False, "password": True, "passwordStatus": "passwordWrong"},
        can_access=False,
        password_protected=True,
        password_status="passwordWrong",
    )
    assert wrong.password_wrong
    assert not wrong.password_ok
    hit = ListingResult(
        endpoint="contents",
        http_status=200,
        api_status="ok",
        data={"canAccess": True, "passwordStatus": "passwordOk", "children": {}},
        can_access=True,
        password_protected=True,
        password_status="passwordOk",
    )
    assert hit.password_ok


def test_wordlist_resume(tmp_path: Path) -> None:
    path = tmp_path / "wl.txt"
    path.write_text("a\nabcd\nsecret\n", encoding="utf-8")

    rec = WordlistRecord(path=str(path), line=0)
    queue = WordlistQueue([rec])
    first = queue.next_candidate()
    assert first and first.skipped
    second = queue.next_candidate()
    assert second and second.password == "abcd" and not second.skipped
    third = queue.next_candidate()
    assert third and third.password == "secret"
    assert queue.next_candidate() is None
