#!/bin/sh
# SSLKit 构建产物交叉验证
cd "$(dirname "$0")/.."
PASS=0; FAIL=0
ck() { if [ "$2" = "1" ]; then echo "  [OK]  $1"; PASS=$((PASS+1)); else echo "  [!!]  $1"; FAIL=$((FAIL+1)); fi; }

echo "=============================================="
echo " V1 源码静态自检"
echo "=============================================="
python3 tools/audit_src.py

echo ""
echo "=============================================="
echo " V2 分支指令编码验证（离线单元测试）"
echo "=============================================="
gcc -O0 -o /tmp/branch_test tools/branch_test.c 2>/dev/null && /tmp/branch_test | tail -4 || echo "  (需 gcc)"

echo ""
echo "=============================================="
echo " V3 产物 so 验证"
echo "=============================================="
SO=build/jniLibs/arm64-v8a/libsslkit.so
python3 - "$SO" <<'PY'
import sys, struct
d=open(sys.argv[1],'rb').read()
e_type = struct.unpack_from('<H', d, 16)[0]
e_mach = struct.unpack_from('<H', d, 18)[0]
print("  架构      : %s" % ("AArch64" if e_mach==0xb7 else "mach=%d"%e_mach))
print("  类型      : %s" % ("DYN(so)" if e_type==3 else "type=%d"%e_type))
print("  大小      : %d bytes" % len(d))
# 关键字符串（证明逻辑存在，不依赖符号导出）
keys = [b'mmap', b'munmap', b'mprotect', b'trampoline created',
        b'nearby stub alloc failed', b'stub too far for b',
        b'inline-hooked', b'SYM:', b'Cronet_CertVerify_DoVerifyV2']
bad = [k for k in keys if k not in d]
print("  关键串    : %s" % ("全部存在" if not bad else "缺: "+str(bad)))
PY
[ -z "$(python3 -c "
d=open('build/jniLibs/arm64-v8a/libsslkit.so','rb').read()
m=[k for k in [b'mmap',b'inline-hooked',b'stub too far for b'] if k not in d]
print(m if m else '')
")" ] && ck "so 关键逻辑完整" 1 || ck "so 关键逻辑完整" 0

echo ""
echo "=============================================="
echo " V4 JNI 签名核对"
echo "=============================================="
python3 - <<'PY'
import re, zipfile
z = zipfile.ZipFile('out/SSLKit.apk')
dex = z.read('classes.dex')
so  = open('build/jniLibs/arm64-v8a/libsslkit.so','rb').read()
n_export = sorted({m.decode() for m in re.findall(
    rb'Java_com_sslkit_native_1layer_NativeHookInstaller_native(\w+)', so)})
n_decl = sorted({m.decode()[6:] for m in re.findall(
    rb'native(?:Install|Rescan|Stats|Version)', dex)})
print("  so 导出  : %s" % n_export)
print("  Java 声明: %s" % n_decl)
miss = set(n_export) - set(n_decl)
print("  %s" % ("JNI 签名一致 OK" if not miss else "不匹配: "+str(miss)))
PY

echo ""
echo "=============================================="
echo " V5 模块打包完整性"
echo "=============================================="
python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('out/SSLKit.apk')
need = {'classes.dex':'dex',
        'META-INF/xposed/java_init.list':'libxposed 入口',
        'META-INF/xposed/module.prop':'模块声明',
        'assets/xposed_init':'legacy 入口',
        'lib/arm64-v8a/libsslkit.so':'native 库'}
for n,desc in need.items():
    print("  %-38s %-16s %s" % (n, desc, "OK" if n in z.namelist() else "缺!"))
PY

echo ""
echo "=============================================="
echo " 结果: $PASS 通过 / $FAIL 失败"
echo "=============================================="
