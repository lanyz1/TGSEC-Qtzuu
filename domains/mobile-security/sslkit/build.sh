#!/bin/sh
# SSLKit 本地构建脚本（aarch64 沙箱版）
# 用法: sh build.sh
# 产物: out/SSLKit.apk
#
# ⚠️ 避坑要点（已踩）：
#   1. NDK 的 clang 是 x86_64 二进制，PRoot 里子进程 fork 执行会失败
#      → 改用【系统自带的 clang-18（aarch64 原生）】直接交叉编译
#   2. 需要 --target=aarch64-linux-android26 + --sysroot=NDK/sysroot
#   3. 链接器要加 -L$FW_LIB（NDK 的 libunwind.a 目录）
#   4. clang-18 默认注入 -lssp_nonshared（NDK sysroot 里没有）
#      → 用 /root/fakelib 里的空库顶替
#   5. aapt2/zipalign 是 x86_64 → 用 qemu-x86_64 -L /var/minis/shared/x86sys/sysroot 跑
set -e

# ---------- 路径 ----------
# 注意：re-toolkit 的 env.sh 会改 LD_LIBRARY_PATH（glibc-root），
# 那会污染 clang-18 的原生编译。所以只对 java/aapt2 阶段临时启用。
RT=/var/minis/shared/re-toolkit
RT_JDK=$RT/jdk-17.0.20+8
if [ -x "$RT_JDK/bin/java" ]; then
  export JAVA_HOME=$RT_JDK
else
  export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
fi
export PATH=$JAVA_HOME/bin:$PATH

SDK=/opt/android-sdk
BT=$SDK/build-tools/34.0.0
ANDROID_JAR=$SDK/platforms/android-37/android.jar
NDK=$SDK/ndk/android-ndk-r25c
NDK_SYSROOT=$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot
NDK_LLVM_LIB=$NDK/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/14.0.7/lib/linux/aarch64
QEMU_SYSROOT=/var/minis/shared/x86sys/sysroot
FAKELIB=/root/fakelib

LXAPI=/root/lxapi102/api-102.jar
[ -f "$LXAPI" ] || LXAPI=/var/minis/shared/libxposed_module_template/libs/api-102.jar

SRC=app/src/main/java
WORK=build
OUT=out

echo "=== [0] 清理 ==="
rm -rf "$WORK" "$OUT"
mkdir -p "$WORK/classes" "$WORK/dex" "$WORK/jniLibs/arm64-v8a" "$OUT"

# ---------- [1] 编译 native ----------
echo "=== [1] 编译 libsslkit.so (arm64-v8a) ==="
# ★ 必须清空 LD_LIBRARY_PATH，否则 glibc-root 会污染原生 clang-18
unset LD_LIBRARY_PATH
mkdir -p "$FAKELIB"
if [ ! -f "$FAKELIB/libssp_nonshared.a" ]; then
  clang-18 --target=aarch64-linux-android26 --sysroot="$NDK_SYSROOT" \
    -c -x c /dev/null -o "$FAKELIB/empty.o"
  (llvm-ar rcs "$FAKELIB/libssp_nonshared.a" "$FAKELIB/empty.o" 2>/dev/null) \
    || ar rcs "$FAKELIB/libssp_nonshared.a" "$FAKELIB/empty.o"
fi
clang-18 --target=aarch64-linux-android26 \
  --sysroot="$NDK_SYSROOT" -fuse-ld=lld \
  -shared -fPIC -O2 -fno-stack-protector \
  -L"$FAKELIB" -L"$NDK_LLVM_LIB" \
  -o "$WORK/jniLibs/arm64-v8a/libsslkit.so" \
  app/src/main/cpp/sslkit.c \
  -llog -ldl -lm
echo "   -> $(stat -c%s $WORK/jniLibs/arm64-v8a/libsslkit.so) bytes"
unset LD_LIBRARY_PATH

# ---------- [2] javac ----------
echo "=== [2] javac ==="
# javac 需要 glibc-root（Temurin JDK 依赖 glibc）
if [ -d "$RT/glibc-root/usr/lib/aarch64-linux-gnu" ]; then
  export LD_LIBRARY_PATH=$RT/glibc-root/usr/lib/aarch64-linux-gnu
fi
find "$SRC" -name '*.java' > "$WORK/srcs.txt"
echo "   源码文件: $(wc -l < $WORK/srcs.txt)"
javac -source 8 -target 8 -nowarn -encoding UTF-8 \
  -cp "$ANDROID_JAR:$LXAPI" \
  -d "$WORK/classes" \
  @"$WORK/srcs.txt" 2>&1 | grep -v "bootstrap class path" || true

[ -d "$WORK/classes/com/sslkit" ] || { echo "!! javac 失败"; exit 1; }

# ---------- [3] d8 ----------
echo "=== [3] d8 -> dex ==="
find "$WORK/classes" -name '*.class' > "$WORK/dex_inputs.txt"
java -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 --release \
  --lib "$ANDROID_JAR" --lib "$LXAPI" \
  --min-api 26 \
  --output "$WORK/dex" \
  @"$WORK/dex_inputs.txt" 2>&1 | tail -3

# ---------- [4] aapt2 link ----------
echo "=== [4] aapt2 link ==="
"$BT/aapt2" link \
  -o "$WORK/unsigned.apk" \
  --manifest app/src/main/AndroidManifest.xml \
  -I "$ANDROID_JAR" \
  --min-sdk-version 26 --target-sdk-version 37 2>&1 | tail -3

# ---------- [5] 注入 ----------
echo "=== [5] 打包注入 ==="
python3 - "$WORK" "$OUT" <<'PYEOF'
import zipfile, os, sys
work, out = sys.argv[1], sys.argv[2]
dst = os.path.join(work, 'withlib.apk')
with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zout:
    with zipfile.ZipFile(os.path.join(work, 'unsigned.apk')) as zin:
        for i in zin.infolist():
            zout.writestr(i, zin.read(i.filename))
    zout.write(os.path.join(work, 'dex/classes.dex'), 'classes.dex', zipfile.ZIP_STORED)
    p = os.path.join(work, 'jniLibs', 'arm64-v8a', 'libsslkit.so')
    if os.path.exists(p):
        zout.write(p, 'lib/arm64-v8a/libsslkit.so', zipfile.ZIP_DEFLATED)
    # libxposed 102 新式声明
    zout.writestr('META-INF/xposed/java_init.list', 'com.sslkit.MainHook')
    zout.writestr('META-INF/xposed/module.prop',
        'minApiVersion=101\n'
        'targetApiVersion=102\n'
        'autoHotReload=true\n'
        'name=SSLKit\n'
        'description=Universal SSL Pinning Bypass\n')
    zout.writestr('assets/xposed_init', 'com.sslkit.MainHook')
print('  inject ok ->', dst)
PYEOF

# ---------- [6] align + sign ----------
echo "=== [6] align + sign ==="
# zipalign 在沙箱里跑不了 → 用 tools/zipalign.py
python3 tools/zipalign.py "$WORK" 4

KS=/opt/android-sdk/debug.keystore
KSPASS=android

java -jar "$BT/lib/apksigner.jar" sign \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --ks "$KS" --ks-pass pass:$KSPASS --key-pass pass:$KSPASS \
  --out "$OUT/SSLKit.apk" "$WORK/withlib.apk" 2>&1 | tail -3

echo "=== [7] verify ==="
java -jar "$BT/lib/apksigner.jar" verify -v "$OUT/SSLKit.apk" 2>&1 | grep -E "Verified using|DOES NOT" || true

echo ""
echo "===== 产物 ====="
ls -la "$OUT/SSLKit.apk"
echo "dex:  $(stat -c%s $WORK/dex/classes.dex) bytes"
echo "so:   $(stat -c%s $WORK/jniLibs/arm64-v8a/libsslkit.so) bytes"
