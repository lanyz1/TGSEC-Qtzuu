#!/usr/bin/env python3
"""
vdp_finder.py — Finds newly-listed VDP (non-paying) bug bounty programs
across HackerOne, Bugcrowd, and Intigriti.

Data source: https://github.com/arkadiyt/bounty-targets-data
(community-maintained, refreshed every 30 min)

v3 changes (corrected after live field verification on 2026-09-11):
- HackerOne: added response_efficiency_percentage (confirmed real,
  populated field — contrary to earlier assumption it wasn't available).
  Use --min-efficiency to filter (default 0, no filter).
- Intigriti: now actually fetched and included in the new-program diff,
  same as HackerOne/Bugcrowd. Still NOT auto-classified as VDP/Paid
  (no reliable field exists) — flagged UNVERIFIED, same treatment as
  Bugcrowd, with a link to the live filtered page.
- Removed a submission_state == "open" filter that a prior draft added —
  verified live that every entry in the dataset has submission_state
  "open" already, so that filter was a no-op, not real protection.

Usage:
    python vdp_finder.py --keyword api --save results.txt
    python vdp_finder.py --save results.txt
    python vdp_finder.py --force
    python vdp_finder.py --reset-cache --save results.txt
    python vdp_finder.py --min-efficiency 80 --save results.txt
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_FILE = SCRIPT_DIR / "seen_cache.json"

DATASET_BASE = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
HACKERONE_URL = f"{DATASET_BASE}/hackerone_data.json"
BUGCROWD_URL = f"{DATASET_BASE}/bugcrowd_data.json"
INTIGRITI_URL = f"{DATASET_BASE}/intigriti_data.json"

BUGCROWD_LIVE_PAGE = "https://bugcrowd.com/engagements?category=vulnerability_disclosure_program"
INTIGRITI_LIVE_PAGE = "https://app.intigriti.com/researcher/programs"


def fetch_json(url: str):
    """Fetch and parse JSON from a URL. Returns None on failure (does not crash)."""
    try:
        req = Request(url, headers={"User-Agent": "vdp_finder/1.0"})
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError, TimeoutError) as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        return None


def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {"hackerone": [], "bugcrowd": [], "intigriti": []}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # backfill in case of an old-format cache missing a key
            data.setdefault("hackerone", [])
            data.setdefault("bugcrowd", [])
            data.setdefault("intigriti", [])
            return data
    except (json.JSONDecodeError, OSError):
        return {"hackerone": [], "bugcrowd": [], "intigriti": []}


def save_cache(cache: dict):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def get_hackerone_vdps(keyword: str | None, min_efficiency: int) -> list[dict]:
    """
    HackerOne: offers_bounties is the confirmed-reliable VDP classification
    field. response_efficiency_percentage is also confirmed real/populated
    (verified live 2026-09-11) and used here for the hunter's >80% target.
    """
    data = fetch_json(HACKERONE_URL)
    if data is None:
        return []

    results = []
    for program in data:
        if program.get("offers_bounties") is True:
            continue  # paid program, skip — VDP only

        efficiency = program.get("response_efficiency_percentage")
        if min_efficiency > 0:
            if efficiency is None or efficiency < min_efficiency:
                continue

        name = program.get("name", "Unknown")
        handle = program.get("handle", "")
        url = program.get("url", f"https://hackerone.com/{handle}")

        if keyword and keyword.lower() not in name.lower() and keyword.lower() not in handle.lower():
            continue

        results.append({
            "platform": "HackerOne",
            "name": name,
            "handle": handle,
            "url": url,
            "response_efficiency": efficiency,
        })

    return results


def get_bugcrowd_listing(keyword: str | None) -> list[dict]:
    """
    Bugcrowd: no reliable field to auto-classify VDP vs Paid from this
    dataset (max_payout is NOT reliable — confirmed by cross-checking a
    program paused since 2015 that it misclassified). Every entry is
    flagged UNVERIFIED — cross-check manually against Bugcrowd's own
    live-filtered VDP page before spending hunting time on it.
    """
    data = fetch_json(BUGCROWD_URL)
    if data is None:
        return []

    results = []
    for program in data:
        name = program.get("name", "Unknown")
        code = program.get("code", "")
        url = program.get("url", f"https://bugcrowd.com/{code}")

        if keyword and keyword.lower() not in name.lower() and keyword.lower() not in code.lower():
            continue

        results.append({
            "platform": "Bugcrowd",
            "name": name,
            "handle": code,
            "url": url,
        })

    return results


def get_intigriti_listing(keyword: str | None) -> list[dict]:
    """
    Intigriti: no field for Paid/VDP status was ever confirmed from this
    dataset (status/min_bounty/max_bounty are not reliable classifiers).
    Fetched and diffed for the "new program" tracking mechanism, but
    every entry is flagged UNVERIFIED — cross-check the live page.
    """
    data = fetch_json(INTIGRITI_URL)
    if data is None:
        return []

    results = []
    for program in data:
        name = program.get("name", "Unknown")
        handle = program.get("handle", "") or str(program.get("id", ""))
        url = program.get("url", INTIGRITI_LIVE_PAGE)

        if keyword and keyword.lower() not in name.lower() and keyword.lower() not in handle.lower():
            continue

        results.append({
            "platform": "Intigriti",
            "name": name,
            "handle": handle,
            "url": url,
        })

    return results


def diff_against_cache(programs: list[dict], cache_key: str, cache: dict) -> list[dict]:
    seen = set(cache.get(cache_key, []))
    new_programs = [p for p in programs if p["handle"] not in seen]
    cache[cache_key] = list(seen | {p["handle"] for p in programs})
    return new_programs


def format_output(h1_new, bc_new, ig_new, reset_cache: bool, min_efficiency: int) -> str:
    lines = []
    lines.append(f"VDP Program Monitor — run at {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("=" * 60)

    tag = "ALL (cache reset)" if reset_cache else "NEW SINCE LAST RUN"

    eff_note = f" (response_efficiency >= {min_efficiency}%)" if min_efficiency > 0 else ""
    lines.append(f"\n--- HackerOne VDPs [{tag}]{eff_note} — fully classified via offers_bounties ---")
    if h1_new:
        for p in h1_new:
            eff = p.get("response_efficiency")
            eff_str = f" [response efficiency: {eff}%]" if eff is not None else " [response efficiency: unknown]"
            lines.append(f"  {p['name']}{eff_str}")
            lines.append(f"    {p['url']}")
    else:
        lines.append("  (none new)")

    lines.append(f"\n--- Bugcrowd listings [{tag}] — UNVERIFIED VDP status, check manually ---")
    lines.append(f"  Cross-check against live filtered page: {BUGCROWD_LIVE_PAGE}")
    if bc_new:
        for p in bc_new:
            lines.append(f"  {p['name']}")
            lines.append(f"    {p['url']}")
    else:
        lines.append("  (none new)")

    lines.append(f"\n--- Intigriti listings [{tag}] — UNVERIFIED VDP status, check manually ---")
    lines.append(f"  Cross-check against live filtered page: {INTIGRITI_LIVE_PAGE}")
    if ig_new:
        for p in ig_new:
            lines.append(f"  {p['name']}")
            lines.append(f"    {p['url']}")
    else:
        lines.append("  (none new)")

    lines.append(f"\n--- Known limitations (not fabricated, deliberately omitted) ---")
    lines.append("  Resolved-report count, scope breadth, and general competition level")
    lines.append("  are NOT available from this dataset for any platform. Response")
    lines.append("  efficiency IS available for HackerOne only (response_efficiency_percentage,")
    lines.append("  confirmed live). Bugcrowd/Intigriti VDP-vs-Paid status cannot be")
    lines.append("  auto-classified — always check each program's own page before testing.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Find newly-listed VDP programs.")
    parser.add_argument("--keyword", help="Filter results by keyword in program name/handle")
    parser.add_argument("--save", metavar="FILE", help="Save output to a text file")
    parser.add_argument("--force", action="store_true", help="Run even on a weekend")
    parser.add_argument("--reset-cache", action="store_true", help="Ignore history, show everything again")
    parser.add_argument("--min-efficiency", type=int, default=0,
                         help="Minimum HackerOne response_efficiency_percentage (e.g. 80). HackerOne only.")
    args = parser.parse_args()

    if datetime.now().weekday() >= 5 and not args.force:
        print("Today is a weekend — smart-contract-security study day, skipping VDP scan.")
        print("Use --force to run anyway.")
        sys.exit(0)

    cache = {"hackerone": [], "bugcrowd": [], "intigriti": []} if args.reset_cache else load_cache()

    print("Fetching HackerOne data...")
    h1_all = get_hackerone_vdps(args.keyword, args.min_efficiency)
    print("Fetching Bugcrowd data...")
    bc_all = get_bugcrowd_listing(args.keyword)
    print("Fetching Intigriti data...")
    ig_all = get_intigriti_listing(args.keyword)

    h1_new = diff_against_cache(h1_all, "hackerone", cache)
    bc_new = diff_against_cache(bc_all, "bugcrowd", cache)
    ig_new = diff_against_cache(ig_all, "intigriti", cache)

    save_cache(cache)

    output = format_output(h1_new, bc_new, ig_new, args.reset_cache, args.min_efficiency)
    print("\n" + output)

    if args.save:
        save_path = Path(args.save)
        save_path.write_text(output, encoding="utf-8")
        print(f"\n[Saved to {save_path}]")


if __name__ == "__main__":
    main()
