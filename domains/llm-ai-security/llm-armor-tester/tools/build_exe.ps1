# Build single-file exe (Windows)
# Usage: powershell -ExecutionPolicy Bypass -File tools\build_exe.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

python -m PyInstaller --onefile --name armor-tester `
    --paths . `
    --distpath dist --workpath build --specpath build `
    armor_tester_entry.py

if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }
Write-Host "[+] exe built: dist\armor-tester.exe"
Write-Host "[*] example: dist\armor-tester.exe payloads stats  (run inside workspace with payloads\ dir, or pass --payloads)"
