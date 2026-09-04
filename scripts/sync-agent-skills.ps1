# TGSEC — Windows 一键把技能装进 Claude / Cursor 等
# 用法（在 security-suite 根目录）:
#   powershell -ExecutionPolicy Bypass -File .\scripts\sync-agent-skills.ps1
# @TGSEC社区 · @TGSEC-Qtzuu 整理

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) { $ScriptDir = Get-Location }
$Root = Split-Path -Parent $ScriptDir
$BashScript = Join-Path $Root "scripts\sync-agent-skills.sh"

$bash = $null
foreach ($c in @(
  "bash",
  "$env:ProgramFiles\Git\bin\bash.exe",
  "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
  "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
)) {
  if ($c -eq "bash") {
    $cmd = Get-Command bash -ErrorAction SilentlyContinue
    if ($cmd) { $bash = $cmd.Source; break }
  } elseif (Test-Path $c) { $bash = $c; break }
}

if (-not $bash) {
  Write-Host "[!] 需要 Git Bash。或手动把 hermes-skills\* 复制到 .claude\skills\"
  exit 1
}

$unix = $Root
if ($Root -match '^([A-Za-z]):\\(.*)$') {
  $unix = "/" + $Matches[1].ToLower() + "/" + ($Matches[2] -replace '\\', '/')
}

$argLine = ($args -join ' ')
& $bash -lc "cd '$unix' && bash scripts/sync-agent-skills.sh $argLine"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "OK — 新开 Claude/Cursor 会话后生效"
