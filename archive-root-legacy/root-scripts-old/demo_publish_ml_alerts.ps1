param(
    [string]$ElasticUser = "elastic",
    [string]$ElasticPassword = "",
    [int]$RepeatCount = 5
)

$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonExe)) {
    throw "Python environment not found at $pythonExe. Run environment setup first."
}

if ([string]::IsNullOrWhiteSpace($ElasticPassword)) {
    $ElasticPassword = Read-Host "Enter Elasticsearch password"
}

Set-Location $projectRoot

Write-Host "Publishing ML anomaly alerts $RepeatCount time(s)..." -ForegroundColor Cyan
for ($i = 1; $i -le $RepeatCount; $i++) {
    Write-Host "  -> Publish batch $i" -ForegroundColor DarkCyan
    & $pythonExe scripts\publish_anomalies_to_elasticsearch.py --input data\anomaly_results.csv --es-url http://localhost:9200 --username $ElasticUser --password $ElasticPassword --use-current-time
}

$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$ElasticUser`:$ElasticPassword"))
$headers = @{"Authorization" = "Basic $auth"; "Content-Type" = "application/json"}
$query = '{"query":{"bool":{"filter":[{"range":{"timestamp":{"gte":"now-24h","lte":"now"}}},{"term":{"prediction":"anomaly"}}]}}}'
$result = Invoke-RestMethod -Uri "http://localhost:9200/ml-anomalies-*/_count" -Method POST -Headers $headers -Body $query

Write-Host "[DONE] Current ML anomalies in last 24h: $($result.count)" -ForegroundColor Green
Write-Host "Refresh Grafana dashboard to see spikes." -ForegroundColor Green
