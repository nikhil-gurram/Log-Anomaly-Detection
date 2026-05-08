# Web SOC Isolated Setup Guide

## 1. Why This Project Is Isolated

This project is in a separate folder:
- [webapp-soc-isolated](webapp-soc-isolated)

It has its own scripts, logs, model, and dashboard.
You can submit this project independently from the Windows Sysmon SOC project.

## 2. Install Dependencies

From project root [webapp-soc-isolated](webapp-soc-isolated):

```powershell
pip install -r requirements.txt
```

## 3. Start Web App

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

This app writes structured logs to:
- [webapp-soc-isolated/logs/webapp_access.log](webapp-soc-isolated/logs/webapp_access.log)

## 4. Generate Demo Traffic

```powershell
python scripts/generate_web_traffic.py --base-url http://127.0.0.1:8000
```

This creates normal and attack-like traffic:
- failed login bursts
- endpoint scan requests
- unauthorized admin access attempts

## 5. Build Features and Train ML

```powershell
python scripts/web_log_feature_engineering.py --input logs/webapp_access.log --output data/web_features.csv
python scripts/web_anomaly_detection.py --input data/web_features.csv --model-output models/web_anomaly_model.pkl --results-output data/web_anomaly_results.csv
```

## 6. Publish ML Alerts to Elasticsearch

```powershell
python scripts/publish_web_anomalies_to_elasticsearch.py --input data/web_anomaly_results.csv --es-url http://localhost:9200 --username elastic --password <password> --use-current-time
```

## 7. Publish Raw Web Logs to Elasticsearch (Recommended for Demo)

Run this after generating traffic:

```powershell
python scripts/publish_web_logs_to_elasticsearch.py --input logs/webapp_access.log --es-url http://localhost:9200 --username elastic --password <password>
```

This directly indexes app logs into:
- webapp-logs-*

You can still use Filebeat if needed, but direct publish is simpler for live demos.

## 8. Grafana Datasources

Provisioning option:

1. Copy `config/grafana-datasource.yaml` to:
	C:\Program Files\GrafanaLabs\grafana\conf\provisioning\datasources\
2. Restart Grafana service.

Create 2 datasources:

1. Elasticsearch-WebApp
- index pattern: webapp-logs-*
- time field: timestamp

2. Elasticsearch-WebML
- index pattern: web-ml-anomalies-*
- time field: timestamp

If panels show "No data", set dashboard time range to Last 90 days, or re-publish with `--use-current-time`.

## 9. Import Dashboard

Import:
- [webapp-soc-isolated/dashboards/grafana_web_soc_dashboard.json](webapp-soc-isolated/dashboards/grafana_web_soc_dashboard.json)

It contains:
- Request Volume Timeline
- HTTP Error Burst
- Login Failure Timeline
- Endpoint Recon Activity
- Latency p95
- ML Web Anomaly Alerts (Primary)

## 10. One-Command Demo

### Run whole local pipeline

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts/demo_soc_pipeline.ps1
```

### Publish multiple alert spikes

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts/demo_publish_alerts.ps1 -ElasticUser elastic -RepeatCount 6
```

### Full CMD-friendly live demo (single command)

```cmd
scripts\cmd_live_demo_web_soc.cmd <ELASTIC_PASSWORD>
```

## 11. Phase 2 Dashboard and Refresh Workflow

Import Phase 2 dashboard:
- [webapp-soc-isolated/dashboards/grafana_web_soc_phase2_dashboard.json](webapp-soc-isolated/dashboards/grafana_web_soc_phase2_dashboard.json)

Run Phase 2 refresh from CMD:

```cmd
scripts\cmd_phase2_refresh.cmd <ELASTIC_PASSWORD>
```

This command does all required phase-2 steps:
- publish raw logs to webapp-logs-*
- rebuild feature dataset
- retrain model with risk and severity enrichment
- publish enriched anomalies to web-ml-anomalies-*
