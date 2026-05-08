param(
    [switch]$SkipAttack,
    [int]$MaxEvents = 5000,
    [switch]$RunRealtime,
    [switch]$KeepRealtimeRunning,
    [double]$PollSeconds = 5,
    [switch]$PublishToElasticsearch,
    [string]$ElasticUser = "elastic",
    [string]$ElasticPassword = "",
    [switch]$UseCurrentTime
)

$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$windowsRoot = Join-Path $projectRoot "windows-soc-isolated"
$dataDir = Join-Path $windowsRoot "data"
$modelsDir = Join-Path $windowsRoot "models"

if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir | Out-Null
}
if (-not (Test-Path $modelsDir)) {
    New-Item -ItemType Directory -Path $modelsDir | Out-Null
}

$pythonCandidates = @(
    (Join-Path $projectRoot ".venv\Scripts\python.exe"),
    (Join-Path $projectRoot "..\.venv\Scripts\python.exe")
)

$pythonExe = $null
foreach ($candidate in $pythonCandidates) {
    if (Test-Path $candidate) {
        $pythonExe = (Resolve-Path $candidate).Path
        break
    }
}

if (-not $pythonExe) {
    throw "Python virtual environment not found. Expected .venv at project root or parent root."
}

function Invoke-Step {
    param(
        [string]$Title,
        [string[]]$StepArgs
    )

    Write-Host "[STEP] $Title" -ForegroundColor Cyan
    Write-Host "       $pythonExe $($StepArgs -join ' ')" -ForegroundColor DarkGray
    & $pythonExe @StepArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Step failed: $Title"
    }
}

Set-Location $projectRoot

$sysmonCsv = Join-Path $dataDir "sysmon_logs.csv"
$featuresCsv = Join-Path $dataDir "features.csv"
$anomalyCsv = Join-Path $dataDir "anomaly_results.csv"
$modelPath = Join-Path $modelsDir "anomaly_model.pkl"

if (-not $SkipAttack) {
    Invoke-Step -Title "Attack simulation" -StepArgs @((Join-Path $windowsRoot "scripts\attack_simulation.py"), "--attack-dir", (Join-Path $windowsRoot "attack_files"))
}

function Test-CsvHasRows {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        return $false
    }
    $lineCount = (Get-Content -Path $Path -TotalCount 3 | Measure-Object -Line).Lines
    return $lineCount -ge 2
}

$exportArgs = @(
    (Join-Path $windowsRoot "scripts\export_sysmon_logs.py"),
    "--max-events", "$MaxEvents",
    "--output", "$sysmonCsv"
)

Write-Host "[STEP] Export Sysmon logs" -ForegroundColor Cyan
Write-Host "       $pythonExe $($exportArgs -join ' ')" -ForegroundColor DarkGray
$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$exportOutput = & $pythonExe @exportArgs 2>&1
$exportExitCode = $LASTEXITCODE
$ErrorActionPreference = $previousErrorActionPreference
if ($exportExitCode -eq 0) {
    $exportOutput | ForEach-Object { Write-Host $_ }
}
if ($exportExitCode -ne 0) {
    if (Test-CsvHasRows -Path $sysmonCsv) {
        Write-Host "[WARN] Live Sysmon export failed, probably because this terminal is not Administrator." -ForegroundColor Yellow
        Write-Host "[WARN] Continuing with existing CSV: $sysmonCsv" -ForegroundColor Yellow
    } else {
        throw "Sysmon export failed and no existing CSV was available. Run PowerShell as Administrator, then rerun."
    }
}

if (-not (Test-Path $sysmonCsv)) {
    throw "Expected output file not found: $sysmonCsv"
}

$lineCount = (Get-Content -Path $sysmonCsv | Measure-Object -Line).Lines
if ($lineCount -lt 2) {
    throw "Sysmon export looks empty ($sysmonCsv). Run PowerShell as Administrator and verify Sysmon events exist."
}

Invoke-Step -Title "Feature engineering" -StepArgs @(
    (Join-Path $windowsRoot "scripts\feature_engineering.py"),
    "--input", "$sysmonCsv",
    "--output", "$featuresCsv"
)

Invoke-Step -Title "Anomaly detection" -StepArgs @(
    (Join-Path $windowsRoot "scripts\anomaly_detection.py"),
    "--input", "$featuresCsv",
    "--model-output", "$modelPath",
    "--results-output", "$anomalyCsv"
)

if ($RunRealtime) {
    $realtimeArgs = @(
        (Join-Path $windowsRoot "scripts\realtime_detector.py"),
        "--log-file", "$sysmonCsv",
        "--model", "$modelPath",
        "--poll-seconds", "$PollSeconds"
    )

    if (-not $KeepRealtimeRunning) {
        $realtimeArgs += "--once"
    }

    Invoke-Step -Title "Real-time detector" -StepArgs $realtimeArgs
}

if ($PublishToElasticsearch) {
    if ([string]::IsNullOrWhiteSpace($ElasticPassword)) {
        $ElasticPassword = Read-Host "Enter Elasticsearch password"
    }

    $publishArgs = @(
        (Join-Path $windowsRoot "scripts\publish_anomalies_to_elasticsearch.py"),
        "--input", "$anomalyCsv",
        "--es-url", "http://localhost:9200",
        "--username", "$ElasticUser",
        "--password", "$ElasticPassword"
    )

    if ($UseCurrentTime) {
        $publishArgs += "--use-current-time"
    }

    Invoke-Step -Title "Publish anomalies to Elasticsearch" -StepArgs $publishArgs
}

Write-Host "" 
Write-Host "[DONE] Windows SOC pipeline completed." -ForegroundColor Green
Write-Host "sysmon logs : $sysmonCsv"
Write-Host "features   : $featuresCsv"
Write-Host "anomalies  : $anomalyCsv"
Write-Host "model      : $modelPath"
