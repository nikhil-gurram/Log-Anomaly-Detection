# Unified SOC Log Anomaly Detection Platform

Final-year B.Tech cybersecurity project for attack simulation, evidence upload, ML anomaly detection, Elasticsearch indexing, and Grafana visualization across three SOC domains:

- Web SOC: web attack simulations, audit/CSV analysis, web anomaly detection.
- Windows SOC: PowerShell/service/file simulations, Sysmon/EVTX analytics, Windows anomaly detection.


## Quick Start

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
scripts\cmd_start_unified_soc_app.cmd
```

Open:

```text
http://127.0.0.1:8088
```

## Final Documents

- `FINAL_PROJECT_GUIDE.md`: complete runbook for local and fresh-system setup.
- `ARCHITECTURE.md`: architecture and file ownership.
- `BTECH_SOC_REPORT.tex`: editable LaTeX report.
- `ROOT_CLEANUP_GUIDE.md`: explains what was archived and what must remain.

## Grafana

Import:

```text
dashboards/unified_soc_professor_dashboard.json
```

Use datasource provisioning:

```text
config/grafana-datasources-unified.yaml
```

Expected Elasticsearch index patterns:

- `winlogbeat-fallback-*`
- `ml-anomalies-*`
- `webapp-logs-*`
- `web-ml-anomalies-*`
- `network-logs-*`
- `network-ml-anomalies-*`

## Windows Pipeline

For live Sysmon export, run as Administrator:

```powershell
cd windows-soc-isolated
.\scripts\run_windows_soc_pipeline.cmd -MaxEvents 3000
```

If not Administrator, the pipeline falls back to the last exported Sysmon CSV when available so demos can continue.
