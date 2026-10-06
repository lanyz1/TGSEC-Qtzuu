# tools/build.ps1 - compiles the payloads to DLLs for LOCAL testing only
# (e.g. together with tools/Loader.aspx). Production delivery uses ysoserial.net directly
# on the .cs sources - see README "Delivery".
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin  = Join-Path (Split-Path -Parent $root) 'bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null

$fw  = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$csc = Join-Path $fw 'csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }

$items = @(
    @{ src = Join-Path $root '..\payloads\HttpModuleShell.cs';  out = 'Payload_HttpModule.dll';  refs = @('System.dll','System.Web.dll') },
    @{ src = Join-Path $root '..\payloads\WsTakeoverShell.cs';  out = 'Payload_WsTakeover.dll';  refs = @('System.dll','System.Web.dll') },
    @{ src = Join-Path $root '..\payloads\RemotingUriShell.cs'; out = 'Payload_RemotingUri.dll'; refs = @('System.dll','System.Runtime.Remoting.dll') }
)

foreach ($it in $items) {
    $refArgs = @()
    foreach ($r in $it.refs) { $refArgs += "/r:$(Join-Path $fw $r)" }
    & $csc /nologo /target:library ("/out:$(Join-Path $bin $it.out)") $it.src $refArgs
    if ($LASTEXITCODE -ne 0) { throw "build failed: $($it.src)" }
    Write-Host "built $(Join-Path $bin $it.out)"
}
