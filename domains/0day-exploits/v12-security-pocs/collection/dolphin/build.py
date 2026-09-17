#!/usr/bin/env python3
"""Build the animated GameCube DOL and package its resident DSP data."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ROM = ROOT / "rom"
OUT = ROOT / "out"
sys.path.insert(0, str(ROOT / "tools"))

import elf2dol  # noqa: E402

CFLAGS = [
    "--target=powerpc-none-eabi",
    "-mbig-endian",
    "-mcpu=750",
    "-ffreestanding",
    "-nostdlib",
    "-fno-builtin",
    "-fno-pic",
    "-msoft-float",
    "-O2",
    "-Wall",
]


def run(argv: list[str]) -> None:
    print("+", " ".join(argv))
    subprocess.run(argv, check=True)


def macro_int(header: str, name: str) -> int:
    match = re.search(rf"^#define\s+{re.escape(name)}\s+(0x[0-9a-fA-F]+|\d+)", header, re.M)
    if not match:
        raise ValueError(f"missing integer macro {name} in exploit.h")
    return int(match.group(1), 0)


def byte_array(header: str, name: str) -> bytes:
    match = re.search(
        rf"static const unsigned char\s+{re.escape(name)}\[\d+\]\s*=\s*\{{(.*?)\}};",
        header,
        re.S,
    )
    if not match:
        raise ValueError(f"missing byte array {name} in exploit.h")
    return bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})", match.group(1)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang", help="PowerPC-capable clang executable")
    parser.add_argument("--lld", default="ld.lld", help="LLVM linker executable")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "v12.dol",
        help="output DOL path",
    )
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    start_o = OUT / "start.o"
    driver_o = OUT / "driver_fancy.o"
    elf = OUT / "fancy.elf"
    include = ["-I", str(ROM)]

    run([args.clang, *CFLAGS, *include, "-c", str(ROM / "start.S"), "-o", str(start_o)])
    run([args.clang, *CFLAGS, *include, "-c", str(ROM / "driver_fancy.c"), "-o", str(driver_o)])
    run(
        [
            args.lld,
            "-T",
            str(ROM / "link.ld"),
            "-o",
            str(elf),
            str(start_o),
            str(driver_o),
            "--no-dynamic-linker",
            "-static",
            "--build-id=none",
        ]
    )

    header = (ROM / "exploit.h").read_text()
    pb_base = macro_int(header, "PB_BASE")
    pb_stride = macro_int(header, "PB_STRIDE")
    pb_count = macro_int(header, "PB_COUNT")
    leak_vpb_addr = macro_int(header, "LEAK_OUT_ADDR")

    entry, segments = elf2dol.read_elf_segments(str(elf))
    resident = [
        (0x80120000, byte_array(header, "kZeldaUcode")),
        (0x80120100, byte_array(header, "kAxUcode")),
        (0x80000000 | leak_vpb_addr, byte_array(header, "kLeakVpb")),
        (0x8012A000, byte_array(header, "kAxCmdList")),
        (0x80000000 | pb_base, bytes(pb_stride * pb_count)),
    ]
    for address, data in resident:
        segments.append({"vaddr": address, "data": data, "memsz": len(data)})

    dol = elf2dol.build_dol(entry, segments)
    output.write_bytes(dol)
    digest = hashlib.sha256(dol).hexdigest()
    print(f"\nBuilt {output}")
    print(f"Entry: {entry:#010x}; sections: {len(segments)}; bytes: {len(dol)}")
    print(f"SHA256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
