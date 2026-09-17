# Dolphin DSP-HLE Guest-to-Host RCE

These vulnerabilities were discovered with [V12](https://v12.sh) by Rick de
Jager of the [V12 security team](https://x.com/v12sec).

## Abstract

This PoC is a single animated GameCube DOL that chains two memory-safety bugs in
Dolphin's default DSP-HLE audio implementation and opens Calculator in the host:

- a Zelda AFC out-of-bounds stack read leaks a host code pointer and defeats
  ASLR;
- an AX parameter-block out-of-bounds stack write installs a rebased ROP chain.

**Impact: full guest-to-host escape.** Malicious code running inside the
emulated GameCube or Wii can execute arbitrary native code in the host Dolphin
process, with the same privileges as Dolphin. The guest code can come from a
purpose-built ROM or DOL, or from a malicious save file that first exploits a
game and gains code execution inside the guest.

The exploit targets **Dolphin 2606 x64 for Windows** with ASLR and DEP enabled.
It is build-specific; other revisions or platforms will normally crash instead
of opening Calculator.

## Build

Requirements are Python 3, Clang with the `powerpc-none-eabi` backend, and LLVM
`ld.lld`.

```bash
python3 build.py
# output: v12.dol
```

The normal build uses checked-in visual data. To regenerate it, install Pillow,
run `python3 tools/gen_fancy.py`, then rerun `build.py`.

## Run

Use Dolphin's default HLE DSP backend:

```powershell
Dolphin.exe -b -a HLE -e v12.dol
```

The DOL displays the V12 animation, leaks Dolphin's randomized image base,
builds the target-specific Win64 chain, and invokes
`ShellExecuteW(..., L"calc.exe", ...)`.

> This is a guest-to-host code-execution PoC. Run it only in a disposable
> environment that you control.

## How It Works

1. The guest boots a crafted Zelda-family HLE ucode and submits an AFC voice
   parameter block with a malicious `afc_remaining_decoded_samples` value.
2. `DownloadAFCSamplesFromARAM` subtracts that unchecked count from a 16-element
   stack array and reads before the object.
3. The resampler copies a saved host return address into guest-visible VPB
   output. The guest uses it to recover Dolphin's randomized image base.
4. The guest resets the DSP, boots AX HLE, and submits crafted parameter-block
   updates.
5. `ApplyUpdatesForMs` uses each unchecked guest `pb_offset` as an index into a
   stack array. Repeated 16-bit writes place a rebased ROP chain around the saved
   return path and open Calculator.

In the source, stage 1 reconstructs the pointer from four 16-bit words starting
at `LEAK_OUT_ADDR + 2 * LEAK_OUT_WORD`, then subtracts `RVA_LEAK`. Stage 2
rebases the tagged `kRopVal` slots; stage 3 emits four offset/value updates per
slot at the `kSlotWord` positions across `PB_COUNT` parameter blocks.

## Fixed upstream

[PR #14747](https://github.com/dolphin-emu/dolphin/pull/14747), and
[PR #14805](https://github.com/dolphin-emu/dolphin/pull/14805) were introduced to
fix this chain. This PoC targets the pre-fix 2606 build.
