#!/bin/bash
# Boot a kernel + initramfs under QEMU (arm64 virt, GICv3 + ITS).
# Usage: ./qemu.sh <kernel-Image> <initramfs.cpio.gz>   [env QEMU=qemu-system-aarch64]
set -e
KERNEL="$1"; INITRD="$2"
QEMU="${QEMU:-qemu-system-aarch64}"
[ -f "$KERNEL" ] && [ -f "$INITRD" ] || { echo "usage: $0 <kernel-Image> <initramfs.cpio.gz>"; exit 1; }

exec "$QEMU" \
	-machine virt,gic-version=3,its=on,virtualization=on \
	-accel tcg,thread=multi -cpu max -smp 4 -m 6G \
	-kernel "$KERNEL" -initrd "$INITRD" \
	-append "console=ttyAMA0 rdinit=/init" \
	-nographic -no-reboot
