param(
    [int]$PowerShellIterations = 6,
    [int]$ServiceIterations = 4,
    [int]$FileCount = 30
)

$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonExe)) {
    throw "Python environment not found at $pythonExe. Run environment setup first."
}

Set-Location $projectRoot

Write-Host "[STEP 1/5] Simulating attack activity..." -ForegroundColor Cyan
& $pythonExe scripts\attack_simulation.py --powershell-iterations $PowerShellIterations --service-iterations $ServiceIterations --file-count $FileCount --command-sleep 0.05 --file-burst-delay 0.01

Write-Host "[STEP 2/5] Generating tampered logs..." -ForegroundColor Cyan
& $pythonExe scripts\log_tampering.py --input data\sysmon_logs.csv --output data\tampered_logs.csv

Write-Host "[STEP 3/5] Building ML features..." -ForegroundColor Cyan
& $pythonExe scripts\feature_engineering.py --input data\sysmon_logs.csv --output data\features.csv

Write-Host "[STEP 4/5] Training anomaly model..." -ForegroundColor Cyan
& $pythonExe scripts\anomaly_detection.py --input data\features.csv --model-output models\anomaly_model.pkl --results-output data\anomaly_results.csv

Write-Host "[STEP 5/5] Running one-pass real-time detection..." -ForegroundColor Cyan
& $pythonExe scripts\realtime_detector.py --log-file data\sysmon_logs.csv --model models\anomaly_model.pkl --once

Write-Host "[DONE] Pipeline run completed successfully." -ForegroundColor Green
Write-Host "Check files: data\tampered_logs.csv, data\features.csv, data\anomaly_results.csv, models\anomaly_model.pkl" -ForegroundColor Green
