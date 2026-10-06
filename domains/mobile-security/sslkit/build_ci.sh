#!/usr/bin/env bash
# SSLKit CI 构建脚本（Ubuntu + Android SDK + NDK r25c）
#
# 与本地 build.sh 的区别：
#   - CI 上 aapt2/zipalign 是原生可执行的，不需要 qemu
#   - CI 上用 NDK 官方 clang（能正常 fork）
#
# 用法:
#   ./build_ci.sh all      # 全流程
#   ./build_ci.sh native   # 只编 native
#   ./build_ci.sh apk      # 只编 APK（假定 so 已就绪）
set -e

SDK_ROOT=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/usr/local/lib/android/sdk}}
BT_VER=${BUILD_TOOLS_VERSION:-34.0.0}

# build-tools 版本兜底（runner 上可能只有别的版本）
if [ ! -d "$SDK_ROOT/build-tools/$BT_VER" ]; then
  ALT=$(ls -d "$SDK_ROOT"/build-tools/* 2>/dev/null | sort -V | tail -1)
  [ -n "$ALT" ] && BT_VER=$(basename "$ALT")
fi
BT=$SDK_ROOT/build-tools/$BT_VER

# platforms 兜底
PLATFORM=${COMPILE_SDK:-android-34}
if [ ! -f "$SDK_ROOT/platforms/$PLATFORM/android.jar" ]; then
  ALT=$(ls -d "$SDK_ROOT"/platforms/* 2>/dev/null | sort -V | tail -1)
  [ -n "$ALT" ] && PLATFORM=$(basename "$ALT")
fi
ANDROID_JAR=$SDK_ROOT/platforms/$PLATFORM/android.jar

# NDK 兜底
NDK=${NDK_PATH:-${ANDROID_NDK_HOME:-}}
if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
  NDK=$(ls -d "$SDK_ROOT"/ndk/* 2>/dev/null | head -1)
fi

echo "SDK_ROOT=$SDK_ROOT"
echo "BUILD_TOOLS=$BT_VER"
echo "PLATFORM=$PLATFORM"
echo "NDK=$NDK"

LXAPI=${LXAPI_JAR:-libs/api-102.jar}
SRC=app/src/main/java
WORK=build
OUT=out
KS=${KEYSTORE:-ci.keystore}
KSPASS=${KEYSTORE_PASS:-android}

mkdir -p "$WORK/classes" "$WORK/dex" "$WORK/jniLibs/arm64-v8a" "$OUT"

build_native() {
  echo "=== [native] 编译 libsslkit.so ==="
  CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang
  [ -x "$CC" ] || CC=$(find "$NDK/toolchains/llvm/prebuilt" -name 'aarch64-linux-android26-clang' | head -1)
  echo "  使用编译器: $CC"
  "$CC" -shared -fPIC -O2 -Wall \
    -o "$WORK/jniLibs/arm64-v8a/libsslkit.so" \
    app/src/main/cpp/sslkit.c \
    -llog -ldl -lm
  echo "  -> $(stat -c%s "$WORK/jniLibs/arm64-v8a/libsslkit.so") bytes"
}

build_apk() {
  echo "=== [javac] ==="
  find "$SRC" -name '*.java' > "$WORK/srcs.txt"
  echo "  源码: $(wc -l < "$WORK/srcs.txt") 个"
  javac -source 8 -target 8 -nowarn -encoding UTF-8 \
    -cp "$ANDROID_JAR:$LXAPI" \
    -d "$WORK/classes" @"$WORK/srcs.txt"

  echo "=== [d8] ==="
  find "$WORK/classes" -name '*.class' > "$WORK/dex_inputs.txt"
  java -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 --release \
    --lib "$ANDROID_JAR" --lib "$LXAPI" \
    --min-api 26 --output "$WORK/dex" @"$WORK/dex_inputs.txt"

  echo "=== [aapt2] ==="
  "$BT/aapt2" link -o "$WORK/unsigned.apk" \
    --manifest app/src/main/AndroidManifest.xml \
    -I "$ANDROID_JAR" \
    --min-sdk-version 26 --target-sdk-version 34

  echo "=== [inject] ==="
  python3 tools/inject.py "$WORK"

  echo "=== [zipalign] ==="
  "$BT/zipalign" -f 4 "$WORK/withlib.apk" "$WORK/aligned.apk"

  echo "=== [sign] ==="
  if [ ! -f "$KS" ]; then
    keytool -genkeypair -v -keystore "$KS" -alias sslkit \
      -keyalg RSA -keysize 2048 -validity 10950 \
      -storepass "$KSPASS" -keypass "$KSPASS" \
      -dname "CN=SSLKit, OU=Dev, O=SSLKit, L=City, S=State, C=CN"
  fi
  java -jar "$BT/lib/apksigner.jar" sign \
    --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
    --ks "$KS" --ks-pass "pass:$KSPASS" --key-pass "pass:$KSPASS" \
    --out "$OUT/SSLKit.apk" "$WORK/aligned.apk"

  echo "=== [verify] ==="
  java -jar "$BT/lib/apksigner.jar" verify -v "$OUT/SSLKit.apk" | grep -E "Verified using" || true

  echo ""
  echo "===== 产物 ====="
  ls -la "$OUT/SSLKit.apk"
}

case "${1:-all}" in
  native) build_native ;;
  apk)    build_apk ;;
  all)    build_native; build_apk ;;
  *) echo "usage: $0 [all|native|apk]"; exit 1 ;;
esac
