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

if not exist "%PY%" (
  echo [ERROR] Python not found: %PY%
  exit /b 1
)

echo [STEP 1/5] Generate traffic
"%PY%" scripts\generate_web_traffic.py --base-url http://127.0.0.1:8000

echo [STEP 2/5] Publish raw web logs to Elasticsearch
"%PY%" scripts\publish_web_logs_to_elasticsearch.py --input logs\webapp_access.log --es-url http://localhost:9200 --username elastic --password %1

echo [STEP 3/5] Feature engineering
"%PY%" scripts\web_log_feature_engineering.py --input logs\webapp_access.log --output data\web_features.csv

echo [STEP 4/5] Train and score ML
"%PY%" scripts\web_anomaly_detection.py --input data\web_features.csv --model-output models\web_anomaly_model.pkl --results-output data\web_anomaly_results.csv

echo [STEP 5/5] Publish ML anomalies
"%PY%" scripts\publish_web_anomalies_to_elasticsearch.py --input data\web_anomaly_results.csv --es-url http://localhost:9200 --username elastic --password %1 --use-current-time

echo [DONE] Refresh Grafana dashboard.
endlocal
