#!/usr/bin/env python3

# +--------------------------------------------------------------------------+
# |                                                                          |
# |                       Veneficus Mini Worm Toolkit                        |
# |                                                                          |
# +--------------------------------------------------------------------------+

"""Diagrams for the public README (obfuscated labels only)."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent
BG, PANEL, BORDER = (12, 16, 24), (22, 30, 44), (42, 70, 52)
TEXT, MUTED = (232, 255, 232), (140, 180, 140)
GREEN, AMBER, RED, CYAN = (72, 220, 110), (245, 180, 70), (232, 93, 72), (80, 190, 180)
FONT = "/System/Library/Fonts/Supplemental/Arial.ttf"
FONTB = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"

def f(sz, b=False):
    return ImageFont.truetype(FONTB if b else FONT, sz)

def rounded(d, box, fill, outline=None, r=10):
    d.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=2)

def canvas(w, h, title, sub):
    im = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, w, 64], fill=(10, 18, 12))
    d.rectangle([0, 64, w, 68], fill=GREEN)
    d.text((24, 12), title, font=f(20, True), fill=TEXT)
    d.text((24, 40), sub, font=f(12), fill=MUTED)
    d.rectangle([0, h - 28, w, h], fill=(10, 18, 12))
    d.text((24, h - 22), "VENEFICUS MINI  ·  PUBLIC PSEUDO-CODE  ·  NOT EXECUTABLE", font=f(11), fill=MUTED)
    return im, d

def flow():
    im, d = canvas(1100, 520, "INTENDED FLOW", "dropper → score → conceal → harvest → hold")
    steps = [
        ("1 DROPPER", ["quiet script engine", "GET /payload", "temp image, hidden start"], GREEN),
        ("2 SCORE", ["debugger / HV / hardware", "idle, timing, outbound", "HIGH wipe  ·  MED quiet", "LOW = full run"], CYAN),
        ("3 CONCEAL", ["native-call (stub)", "kernel hide (stub)", "in-process patches"], AMBER),
        ("4 HARVEST", ["host card, browser logins", "secret-store dump", "clipboard swap"], RED),
        ("5 HOLD", ["WMI / task / Run key", "loopback relay", "edge poll + jitter"], GREEN),
    ]
    x = 24
    for title, lines, col in steps:
        rounded(d, [x, 90, x + 200, 470], PANEL, col)
        d.rectangle([x, 90, x + 200, 128], fill=col)
        d.text((x + 10, 100), title, font=f(13, True), fill=BG)
        yy = 148
        for line in lines:
            d.ellipse([x + 14, yy + 6, x + 22, yy + 14], fill=col)
            d.text((x + 30, yy), line, font=f(13), fill=TEXT)
            yy += 36
        if x < 24 + 4 * 216:
            d.polygon([(x + 208, 270), (x + 220, 264), (x + 220, 276)], fill=GREEN)
        x += 216
    im.save(OUT / "flow.png")

def status():
    im, d = canvas(1100, 620, "MODULE STATUS", "as designed in this outline — not a running implant")
    rows = [
        ("in-process patches", "INTENT REAL", GREEN),
        ("host scoring", "INTENT REAL", GREEN),
        ("persistence (3-way)", "INTENT REAL", GREEN),
        ("SOCKS-like relay", "LOOPBACK / GATED", AMBER),
        ("channel crypto", "AEAD OK · KEYING WEAK", AMBER),
        ("browser harvest", "MISSES MODERN WRAPPING", AMBER),
        ("secret-store dump", "PPL BLOCKS NATIVE PATH", AMBER),
        ("clipboard swap", "PATTERNS TOO BROAD", AMBER),
        ("edge relay", "WOULD NOT LOAD", RED),
        ("URL embedding", "DECODER DEFECT", RED),
        ("native-call / kernel hide / view / coerce", "STUB OR DEAD CODE", RED),
        ("driver pool", "IMAGES ABSENT · SOME SLOTS WRONG", RED),
    ]
    y = 86
    for name, st, col in rows:
        rounded(d, [24, y, 1076, y + 40], PANEL, (32, 48, 36), r=6)
        d.text((40, y + 10), name, font=f(14), fill=TEXT)
        rounded(d, [720, y + 8, 1056, y + 32], col, r=4)
        d.text((736, y + 11), st, font=f(12, True), fill=BG)
        y += 44
    im.save(OUT / "status.png")

def control():
    im, d = canvas(1100, 480, "EDGE RELAY ROUTES", "aliases — not the private path strings")
    cols = [
        (24, "AGENT", [
            "POST /inbox   sealed blob",
            "POST /queue   pull jobs",
            "POST /profile  operator JSON",
            "GET  /payload  dropper fetch",
        ], RED),
        (380, "EDGE WORKER", [
            "enroll check on agent_id",
            "one-shot job queue",
            "per-id or global profile",
            "never holds the AEAD key",
        ], CYAN),
        (736, "OPERATOR", [
            "POST /ops      queue a job",
            "POST /enroll   add agent_id",
            "POST /revoke   drop agent_id",
            "GET  /roster   list agents",
            "POST /profile/set",
        ], GREEN),
    ]
    for x, title, lines, col in cols:
        rounded(d, [x, 90, x + 340, 430], PANEL, col)
        d.rectangle([x, 90, x + 340, 128], fill=col)
        d.text((x + 16, 100), title, font=f(16, True), fill=BG)
        yy = 150
        for line in lines:
            d.text((x + 18, yy), line, font=f(14), fill=TEXT)
            yy += 42
    im.save(OUT / "control.png")

if __name__ == "__main__":
    flow()
    status()
    control()
    print("wrote", list(OUT.glob("*.png")))
