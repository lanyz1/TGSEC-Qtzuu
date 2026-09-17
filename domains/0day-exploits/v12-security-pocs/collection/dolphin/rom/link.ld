/* link.ld — GameCube homebrew layout for the combined leak-and-write PoC.
 *
 * Loads at 0x80003100, the classic GC homebrew entry above the low BS2 and
 * exception-vector region. Code and referenced rodata occupy one PT_LOAD
 * segment; build.py packages the DSP blobs from exploit.h as resident DOL
 * sections at their final MRAM addresses.
 */
OUTPUT_FORMAT("elf32-powerpc")
OUTPUT_ARCH(powerpc:common)
ENTRY(_start)

MEMORY
{
  mram (rwx) : ORIGIN = 0x80003100, LENGTH = 0x100000
}

SECTIONS
{
  . = 0x80003100;
  .text : {
    *(.init)
    *(.text*)
  } > mram
  .rodata : {
    *(.rodata*)
    *(.data*)
    *(.sdata*)
  } > mram
  /DISCARD/ : { *(.comment) *(.eh_frame) *(.note*) *(.glink) }
}
