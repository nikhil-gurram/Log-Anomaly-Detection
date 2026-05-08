@echo off
setlocal

for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
cd /d "%PROJECT_ROOT%"
set "PY=%PROJECT_ROOT%\.venv\Scripts\python.exe"
if not exist "%PY%" (
  if exist "%PROJECT_ROOT%\..\.venv\Scripts\python.exe" (
    set "PY=%PROJECT_ROOT%\..\.venv\Scripts\python.exe"
  ) else (
    set "PY=python"
  )
)

if "%~1"=="" (
  echo Usage: scripts\cmd_phase2_refresh.cmd ^<ELASTIC_PASSWORD^>
  exit /b 1
)

set ES_USER=elastic
set ES_PASS=%~1

echo [PHASE2 1/4] Publish raw web logs
"%PY%" scripts\publish_web_logs_to_elasticsearch.py --input logs\webapp_access.log --es-url http://localhost:9200 --username %ES_USER% --password %ES_PASS%

echo [PHASE2 2/4] Rebuild features
"%PY%" scripts\web_log_feature_engineering.py --input logs\webapp_access.log --output data\web_features.csv

echo [PHASE2 3/4] Retrain ML with risk scoring
"%PY%" scripts\web_anomaly_detection.py --input data\web_features.csv --model-output models\web_anomaly_model.pkl --results-output data\web_anomaly_results.csv

echo [PHASE2 4/4] Publish Phase 2 anomalies
"%PY%" scripts\publish_web_anomalies_to_elasticsearch.py --input data\web_anomaly_results.csv --es-url http://localhost:9200 --username %ES_USER% --password %ES_PASS% --use-current-time

echo [DONE] Import/refresh dashboard: dashboards\grafana_web_soc_phase2_dashboard.json
endlocal
