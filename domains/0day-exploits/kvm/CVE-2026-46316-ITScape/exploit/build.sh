#!/bin/bash
# Build poc.c (a Linux KVM selftest) against an UNMODIFIED kernel selftest tree.
# Usage: ./build.sh <linux>/tools/testing/selftests/kvm   [env CROSS_COMPILE=aarch64-linux-gnu-]
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
K="$(cd "$1" && pwd)"
CROSS="${CROSS_COMPILE:-aarch64-linux-gnu-}"
[ -d "$K/arm64" ] || { echo "usage: $0 <linux>/tools/testing/selftests/kvm"; exit 1; }
ST="$K/.."; TOOLS="$K/../../.."; LX="$K/../../../.."

# Build the in-tree support objects only (uapi headers + libkvm); no source / Makefile edits.
make -C "$LX" ARCH=arm64 headers >/dev/null 2>&1 || true
( cd "$K" && make ARCH=arm64 CROSS_COMPILE="$CROSS" -j"$(nproc)" ) || true

# Compile + link poc.c (kept here, never copied into the tree) against the prebuilt libkvm objects.
"${CROSS}gcc" -D_GNU_SOURCE= -std=gnu99 -O2 -g -pthread -no-pie -DCONFIG_64BIT \
	-U_FORTIFY_SOURCE -fno-stack-protector -fno-PIE -fno-strict-aliasing \
	-fno-builtin-memcmp -fno-builtin-memcpy -fno-builtin-memset -fno-builtin-strnlen \
	-I"$K/include" -I"$K/include/arm64" -I"$ST" -I"$ST/rseq" -I"$ST/cgroup/lib/include" \
	-I"$TOOLS/include" -I"$TOOLS/arch/arm64/include" -I"$TOOLS/arch/arm64/include/generated" \
	-isystem "$LX/usr/include" -I"$LX/usr/include" \
	"$HERE/poc.c" "$K"/lib/*.o "$K"/lib/arm64/*.o -ldl -o "$HERE/poc"
echo "built: poc"
