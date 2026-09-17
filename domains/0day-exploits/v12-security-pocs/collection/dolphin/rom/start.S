# start.S — GameCube homebrew entry stub for the combined DSP-HLE escape.
#
# Dolphin boots a DOL with MSR.IR=MSR.DR=1 and the BS2 BATs already set:
#   DBAT0/IBAT0: 0x80000000 -> phys 0x00000000 (cached MRAM)
#   DBAT1:       0xC0000000 -> phys 0x00000000 (uncached MRAM + MMIO)
# gpr[1] (stack) is NOT initialized for GC executables, so we set it here to a
# valid MRAM location, then jump to the C driver. No libc, no CRT.

    .section .init, "ax"
    .globl _start
_start:
    # Set up a stack well clear of our code and the exploit scratch window.
    lis     1, 0x8130           # r1 = 0x81300000
    ori     1, 1, 0xFFF0        # r1 = 0x8130FFF0
    # Small frame so any EABI prologue in driver_main has room.
    subi    1, 1, 0x40
    # r13 (small-data base) unused by our -msdata=none build, but zero it.
    li      13, 0
    bl      driver_main
hang:
    b       hang
