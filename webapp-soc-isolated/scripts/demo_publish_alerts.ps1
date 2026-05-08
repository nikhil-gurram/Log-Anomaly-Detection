param(
    [string]$ElasticUser = "elastic",
    [string]$ElasticPassword = "",
    [int]$RepeatCount = 6
)

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonExe)) {
    throw "Python not found at $pythonExe"
}

if ([string]::IsNullOrWhiteSpace($ElasticPassword)) {
    $ElasticPassword = Read-Host "Enter Elasticsearch password"
}

Set-Location $projectRoot

for ($i = 1; $i -le $RepeatCount; $i++) {
    & $pythonExe scripts\publish_web_anomalies_to_elasticsearch.py --input data\web_anomaly_results.csv --es-url http://localhost:9200 --username $ElasticUser --password $ElasticPassword --use-current-time
}

$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$ElasticUser`:$ElasticPassword"))
$headers = @{"Authorization" = "Basic $auth"; "Content-Type" = "application/json"}
$q = '{"query":{"bool":{"filter":[{"range":{"timestamp":{"gte":"now-24h","lte":"now"}}},{"term":{"prediction":"anomaly"}}]}}}'
$result = Invoke-RestMethod -Uri "http://localhost:9200/web-ml-anomalies-*/_count" -Method POST -Headers $headers -Body $q

Write-Host "[DONE] Web ML anomalies in last 24h: $($result.count)" -ForegroundColor Green
