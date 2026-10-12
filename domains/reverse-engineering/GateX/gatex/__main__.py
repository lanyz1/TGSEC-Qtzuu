"""python -m gatex"""

from __future__ import annotations

import argparse
import asyncio

from . import __version__
from .session import last_session_name
from .tui import GateXApp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gatex",
        description="Re-key the 7350FH Nuitka password gate (static unpack + Docker cage).",
    )
    parser.add_argument(
        "--session",
        default=None,
        help="reusable session name (default: last used, else 'default')",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="zip or ELF path (default: session target or files/7350FH.zip)",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="headless static unpack + print the assembled hash, then exit",
    )
    parser.add_argument(
        "--bypass",
        nargs="?",
        const="gatex",
        default=None,
        help="re-key the inner ELF to PASS (default gatex) and exec list in the cage",
    )
    parser.add_argument("--version", action="version", version=f"GateX {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    session_name = args.session or last_session_name()
    app = GateXApp(session_name=session_name)
    if args.target:
        app.session.set_target(args.target)
        app.session.save()
    if args.probe or args.bypass:
        return _headless(app, probe=args.probe, bypass=args.bypass)
    app.run()
    return 0


def _headless(app: GateXApp, *, probe: bool, bypass: str | None) -> int:
    def log(kind: str, message: str) -> None:
        print(f"{kind:4} {message}")

    app.engine.log = log

    async def run() -> int:
        if probe:
            if not await app.engine.probe():
                return 1
            if not bypass:
                print(app.session.hash_phc or "")
                return 0
        if bypass:
            ok = await app.engine.bypass(bypass)
            return 0 if ok else 1
        return 0

    return asyncio.run(run())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
