# LLM Armor Tester - one-shot full scan against an AUTHORIZED endpoint
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\full_scan.ps1 `
#     -BaseUrl http://TARGET:PORT/v1 -ApiKey sk-TOKEN -Model MODEL_NAME `
#     [-SystemFile known_system_prompt.txt] [-Repeat 3] [-Qps 4] [-Tag run1]
param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    [Parameter(Mandatory = $true)][string]$ApiKey,
    [Parameter(Mandatory = $true)][string]$Model,
    [string]$SystemFile = "",
    [int]$Repeat = 3,
    [double]$Qps = 4,
    [int]$Concurrency = 6,
    [string]$Tag = (Get-Date -Format "yyyyMMdd-HHmmss")
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# Authorization gate: refuse to run against unconfirmed targets
$confirm = Read-Host "Confirm $BaseUrl is an AUTHORIZED test target (yes/no)"
if ($confirm -ne "yes") { Write-Host "aborted"; exit 1 }

$sysArgs = @()
if ($SystemFile -ne "") { $sysArgs = @("--system-file", $SystemFile) }

Write-Host "[STAGE] 1/5 single-payload scan (repeat x$Repeat)"
python -m armor_tester run --base-url $BaseUrl --api-key $ApiKey --model $Model `
    @sysArgs --repeat $Repeat --carrier none --qps $Qps --concurrency $Concurrency `
    --out "results/$Tag.run.csv" --resume
python -m armor_tester run --base-url $BaseUrl --api-key $ApiKey --model $Model `
    @sysArgs --repeat $Repeat --carrier email --qps $Qps --concurrency $Concurrency `
    --out "results/$Tag.carrier.csv" --resume

Write-Host "[STAGE] 2/5 multi-turn attack chains"
python -m armor_tester chains --base-url $BaseUrl --api-key $ApiKey --model $Model `
    @sysArgs --chains chains/attack_chains.jsonl --concurrency 3 `
    --out "results/$Tag.chains.csv" --resume

Write-Host "[STAGE] 3/5 model judge review (SUSPECT/UNKNOWN)"
python -m armor_tester judge --results "results/$Tag.run.csv" --mode both `
    --base-url $BaseUrl --api-key $ApiKey --judge-model $Model @sysArgs `
    --out "results/$Tag.judged.csv"

Write-Host "[STAGE] 4/5 reports (MD/HTML/PDF)"
python -m armor_tester report --results "results/$Tag.judged.csv" `
    --target $BaseUrl --model $Model --out "reports/$Tag.report.md" --pdf
python -m armor_tester report --results "results/$Tag.chains.csv" `
    --target $BaseUrl --model $Model --out "reports/$Tag.chains.md"

Write-Host "[STAGE] 5/5 deep analysis (attack-chain breakdown)"
python -m armor_tester analyze --results "results/$Tag.judged.csv" "results/$Tag.chains.csv" `
    --target $BaseUrl --model $Model --analyst-model $Model @sysArgs `
    --top 8 --pdf --out "reports/$Tag.analysis.md"

Write-Host "[STAGE] done"
Write-Host "results: results\$Tag.*.csv | reports: reports\$Tag.report.md/.pdf, reports\$Tag.analysis.md/.pdf"
Write-Host "regression diff: python -m armor_tester diff --old results/<baseline>.judged.csv --new results/$Tag.judged.csv --out reports/$Tag.regression.md"
