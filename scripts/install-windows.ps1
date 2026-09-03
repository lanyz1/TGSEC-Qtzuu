# TGSEC 小白一键 Windows
# irm https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-windows.ps1 | iex
$ErrorActionPreference = "Stop"
$Repo = if ($env:TGSEC_REPO_URL) { $env:TGSEC_REPO_URL } else { "https://github.com/lanyz1/TGSEC-Qtzuu.git" }
$Dir  = if ($env:TGSEC_DIR) { $env:TGSEC_DIR } else { Join-Path $HOME "security-suite" }
Write-Host "[TGSEC] 安装到 $Dir"
if (-not (Test-Path (Join-Path $Dir ".git"))) {
  if ((Test-Path $Dir) -and -not (Test-Path (Join-Path $Dir ".git"))) {
    Rename-Item $Dir "$Dir.bak.$(Get-Date -Format yyyyMMddHHmmss)"
  }
  git clone --depth 1 $Repo $Dir
  if ($LASTEXITCODE -ne 0) { Write-Host "git clone 失败，请先安装 Git for Windows"; exit 1 }
} else {
  Push-Location $Dir
  git pull --ff-only 2>$null; if ($LASTEXITCODE -ne 0) { git pull 2>$null }
  Pop-Location
}
$bash = $null
foreach ($c in @("bash", "$env:ProgramFiles\Git\bin\bash.exe", "${env:ProgramFiles(x86)}\Git\bin\bash.exe")) {
  if ($c -eq "bash") {
    $cmd = Get-Command bash -ErrorAction SilentlyContinue
    if ($cmd) { $bash = $cmd.Source; break }
  } elseif (Test-Path $c) { $bash = $c; break }
}
if ($bash -and (Test-Path (Join-Path $Dir "scripts\bootstrap.sh"))) {
  $unix = $Dir
  if ($Dir -match '^([A-Za-z]):\\(.*)$') {
    $unix = "/" + $Matches[1].ToLower() + "/" + ($Matches[2] -replace '\\','/')
  }
  & $bash -lc "cd '$unix' && bash scripts/bootstrap.sh --force" 2>$null
}
Write-Host ""
Write-Host "完成！下一步："
Write-Host "  1. 用 AI 打开文件夹: $Dir"
Write-Host "  2. 对 AI 说: 请先读 START.md"
Write-Host "  详情见 $Dir\START.md"
