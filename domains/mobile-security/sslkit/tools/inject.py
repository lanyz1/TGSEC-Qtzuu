#!/usr/bin/env python3
"""把 dex / so / xposed 声明注入到 aapt2 产出的 APK 里。"""
import zipfile, os, sys

work = sys.argv[1]
dst = os.path.join(work, 'withlib.apk')
src = os.path.join(work, 'unsigned.apk')

with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zout:
    with zipfile.ZipFile(src) as zin:
        for i in zin.infolist():
            zout.writestr(i, zin.read(i.filename))

    # classes.dex
    dex = os.path.join(work, 'dex', 'classes.dex')
    zout.write(dex, 'classes.dex', zipfile.ZIP_STORED)

    # native so（所有 abi）
    jroot = os.path.join(work, 'jniLibs')
    if os.path.isdir(jroot):
        for abi in sorted(os.listdir(jroot)):
            p = os.path.join(jroot, abi, 'libsslkit.so')
            if os.path.exists(p):
                zout.write(p, 'lib/%s/libsslkit.so' % abi, zipfile.ZIP_DEFLATED)

    # libxposed 102 声明（LSPosed 靠这个识别为模块）
    zout.writestr('META-INF/xposed/java_init.list', 'com.sslkit.MainHook')
    zout.writestr('META-INF/xposed/module.prop',
                  'minApiVersion=101\n'
                  'targetApiVersion=102\n'
                  'autoHotReload=true\n'
                  'name=SSLKit\n'
                  'description=Universal SSL Pinning Bypass\n')
    zout.writestr('assets/xposed_init', 'com.sslkit.MainHook')

print('  inject ok ->', dst)
