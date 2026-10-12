"""python -m gofilex  (GoFileX)"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .session import last_session_name
from .tui import GoFileXApp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gofilex",
        description="GoFileX — rate-limit-aware GoFile wordlist TUI (documented API only).",
    )
    parser.add_argument(
        "--session",
        default=None,
        help="reusable session name (default: last used, else 'default')",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="GoFile share URL or id (default: last session target, else unset)",
    )
    parser.add_argument(
        "--wordlist",
        "-w",
        action="append",
        default=[],
        help="wordlist file to queue (repeatable). Same as /wl add",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="existing GoFile API token (Premium for GET /contents)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="seconds between GET /contents (floor 1.5, default 3)",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="headless GET /contents once, then exit (no TUI)",
    )
    parser.add_argument("--version", action="version", version=f"GoFileX {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    session_name = args.session or last_session_name()
    app = GoFileXApp(session_name=session_name)
    if args.target:
        try:
            app.session.set_target(args.target)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
    if args.token:
        app.session.account.token = args.token
        app.client.token = args.token
    if args.interval is not None:
        applied = app.limiter.set_contents_interval(args.interval)
        app.session.contents_interval = applied
    for spec in args.wordlist:
        path = Path(spec).expanduser()
        if not path.is_file():
            print(f"not a file: {path}", file=sys.stderr)
            return 2
        app.session.add_wordlist(path)
    app.session.save()
    if args.probe:
        return _probe(app)
    app.run()
    return 0


def _probe(app: GoFileXApp) -> int:
    logs: list[str] = []

    def log(kind: str, message: str) -> None:
        logs.append(f"{kind:4} {message}")
        print(f"{kind:4} {message}")

    app.engine.log = log

    async def run() -> int:
        try:
            listing = await app.engine.probe()
            if listing is None:
                return 1
            if listing.rate_limited:
                return 3
            if listing.not_premium:
                return 4
            return 0 if listing.ok else 1
        finally:
            await app.client.aclose()

    return asyncio.run(run())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
