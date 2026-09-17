#!/usr/bin/env python3
"""elf2dol.py — minimal ELF -> Nintendo GameCube/Wii DOL converter.

DOL is the executable format Dolphin boots directly with `-e file.dol`
(Core/Boot/DolReader.cpp). Header (big-endian, 0x100 bytes):
  0x00: 7 text section file offsets
  0x1C: 11 data section file offsets
  0x48: 7 text section load addresses
  0x64: 11 data section load addresses
  0x90: 7 text section sizes
  0xAC: 11 data section sizes
  0xD8: BSS load address
  0xDC: BSS size
  0xE0: entry point
We pack every PT_LOAD segment as data sections (Dolphin treats text/data
identically for loading); one text slot carries the entry segment.
"""
import struct
import sys


def read_elf_segments(path):
    with open(path, "rb") as f:
        elf = f.read()
    assert elf[:4] == b"\x7fELF", "not an ELF"
    is64 = elf[4] == 2
    be = elf[5] == 2
    endc = ">" if be else "<"
    if is64:
        e_entry = struct.unpack_from(endc + "Q", elf, 24)[0]
        e_phoff = struct.unpack_from(endc + "Q", elf, 32)[0]
        e_phentsize = struct.unpack_from(endc + "H", elf, 54)[0]
        e_phnum = struct.unpack_from(endc + "H", elf, 56)[0]
    else:
        e_entry = struct.unpack_from(endc + "I", elf, 24)[0]
        e_phoff = struct.unpack_from(endc + "I", elf, 28)[0]
        e_phentsize = struct.unpack_from(endc + "H", elf, 42)[0]
        e_phnum = struct.unpack_from(endc + "H", elf, 44)[0]

    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from(endc + "I", elf, off)[0]
        if p_type != 1:  # PT_LOAD
            continue
        if is64:
            p_offset = struct.unpack_from(endc + "Q", elf, off + 8)[0]
            p_vaddr = struct.unpack_from(endc + "Q", elf, off + 16)[0]
            p_filesz = struct.unpack_from(endc + "Q", elf, off + 32)[0]
            p_memsz = struct.unpack_from(endc + "Q", elf, off + 40)[0]
        else:
            p_offset = struct.unpack_from(endc + "I", elf, off + 4)[0]
            p_vaddr = struct.unpack_from(endc + "I", elf, off + 8)[0]
            p_filesz = struct.unpack_from(endc + "I", elf, off + 16)[0]
            p_memsz = struct.unpack_from(endc + "I", elf, off + 20)[0]
        if p_memsz == 0:
            continue
        # Skip the segment that exists only to map the ELF ehdr+phdrs (lld emits
        # it at file offset 0 and the image base). It is not program content and
        # would clobber low MRAM if loaded.
        if p_offset == 0:
            continue
        data = elf[p_offset:p_offset + p_filesz]
        segs.append({"vaddr": p_vaddr, "data": data, "memsz": p_memsz})
    return e_entry, segs


def build_dol(entry, segs):
    HDR = 0x100
    text_off = [0] * 7
    text_addr = [0] * 7
    text_size = [0] * 7
    data_off = [0] * 11
    data_addr = [0] * 11
    data_size = [0] * 11

    payload = bytearray()
    cursor = HDR

    # Segment 0 -> text[0] (entry segment). Rest -> data[].
    di = 0
    for si, seg in enumerate(segs):
        raw = bytes(seg["data"])
        # DOL sections are 32-byte aligned in file (matches loaders' expectation).
        if cursor % 32:
            pad = 32 - (cursor % 32)
            payload += b"\x00" * pad
            cursor += pad
        seg_file_off = cursor
        payload += raw
        cursor += len(raw)
        if si == 0:
            text_off[0] = seg_file_off
            text_addr[0] = seg["vaddr"]
            text_size[0] = len(raw)
        else:
            assert di < 11, "too many data segments"
            data_off[di] = seg_file_off
            data_addr[di] = seg["vaddr"]
            data_size[di] = len(raw)
            di += 1

    hdr = bytearray(HDR)
    o = 0
    for v in text_off:
        struct.pack_into(">I", hdr, o, v); o += 4
    for v in data_off:
        struct.pack_into(">I", hdr, o, v); o += 4
    for v in text_addr:
        struct.pack_into(">I", hdr, o, v); o += 4
    for v in data_addr:
        struct.pack_into(">I", hdr, o, v); o += 4
    for v in text_size:
        struct.pack_into(">I", hdr, o, v); o += 4
    for v in data_size:
        struct.pack_into(">I", hdr, o, v); o += 4
    struct.pack_into(">I", hdr, 0xD8, 0)       # bss addr
    struct.pack_into(">I", hdr, 0xDC, 0)       # bss size
    struct.pack_into(">I", hdr, 0xE0, entry)   # entry point
    return bytes(hdr) + bytes(payload)


def main():
    if len(sys.argv) != 3:
        print("usage: elf2dol.py in.elf out.dol", file=sys.stderr)
        return 2
    entry, segs = read_elf_segments(sys.argv[1])
    dol = build_dol(entry, segs)
    with open(sys.argv[2], "wb") as f:
        f.write(dol)
    print(f"wrote {sys.argv[2]} ({len(dol)} bytes), entry={entry:#010x}, "
          f"{len(segs)} PT_LOAD segs", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
