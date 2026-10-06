#!/usr/bin/env python3
"""zipalign 的纯 Python 替代（沙箱里 x86 zipalign 跑不了）。
只保证 STORED 条目按 4 字节对齐 —— 对 libxposed/LSPosed 识别足够。"""
import zipfile, sys, os

work = sys.argv[1]
src = os.path.join(work, 'withlib.apk')
dst = os.path.join(work, 'aligned.apk')
ALIGN = int(sys.argv[2]) if len(sys.argv) > 2 else 4

zin = zipfile.ZipFile(src)
zout = zipfile.ZipFile(dst, 'w')
for info in zin.infolist():
    data = zin.read(info.filename)
    zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    zi.compress_type = info.compress_type
    zi.external_attr = info.external_attr
    zi.create_system = 0
    if info.compress_type == zipfile.ZIP_STORED:
        hdr = 30 + len(info.filename.encode())
        cur = zout.fp.tell()
        extra = (ALIGN - (cur + hdr) % ALIGN) % ALIGN
        if extra:
            zi.extra = b'\x00' * extra
    zout.writestr(zi, data)
zout.close()
zin.close()
os.replace(dst, src)
print('  aligned ->', src)
