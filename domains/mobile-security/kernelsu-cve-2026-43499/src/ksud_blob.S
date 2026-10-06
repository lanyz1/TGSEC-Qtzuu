.section .rodata
.global embedded_ksud_start
.global embedded_ksud_end
.balign 16
embedded_ksud_start:
.incbin "build/embed/ksud"
embedded_ksud_end:
.balign 16
