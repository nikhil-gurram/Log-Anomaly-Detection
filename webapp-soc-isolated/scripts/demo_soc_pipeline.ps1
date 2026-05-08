param(
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonExe)) {
    throw "Python not found at $pythonExe"
}

Set-Location $projectRoot

Write-Host "[STEP 1/4] Generating web traffic" -ForegroundColor Cyan
& $pythonExe scripts\generate_web_traffic.py --base-url $BaseUrl

Write-Host "[STEP 2/4] Building features" -ForegroundColor Cyan
& $pythonExe scripts\web_log_feature_engineering.py --input logs\webapp_access.log --output data\web_features.csv

Write-Host "[STEP 3/4] Training anomaly model" -ForegroundColor Cyan
& $pythonExe scripts\web_anomaly_detection.py --input data\web_features.csv --model-output models\web_anomaly_model.pkl --results-output data\web_anomaly_results.csv

Write-Host "[STEP 4/4] Running one-pass real-time detector" -ForegroundColor Cyan
& $pythonExe scripts\web_realtime_detector.py --log-file logs\webapp_access.log --model models\web_anomaly_model.pkl --once

Write-Host "[DONE] Web SOC pipeline completed" -ForegroundColor Green
