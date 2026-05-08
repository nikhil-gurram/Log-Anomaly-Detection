# WebApp SOC (Isolated Project)

This is a completely isolated second project focused on web application logs.
It is separate from the Windows Sysmon SOC project so you can choose either one for final submission.

## Project Goal

Detect suspicious web traffic patterns and visualize them in Grafana with machine-learning anomaly alerts.

## Pipeline

Web App (structured JSON logs)
-> Filebeat
-> Elasticsearch
-> Python ML Engine
-> ML alerts index
-> Grafana dashboard

## Folder Structure

- app
  - main.py
- scripts
  - generate_web_traffic.py
  - web_log_feature_engineering.py
  - web_anomaly_detection.py
  - web_realtime_detector.py
  - publish_web_anomalies_to_elasticsearch.py
  - demo_soc_pipeline.ps1
  - demo_publish_alerts.ps1
- config
  - filebeat_webapp.yml
- dashboards
  - grafana_web_soc_dashboard.json
- documentation
  - setup_guide_web_soc.md
  - easy_explanation_for_professor_web_soc.md
  - project_selection_guide.md
- data
- logs
- models

## Quick Start

1. Install dependencies

   pip install -r requirements.txt

2. Start app

   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

   Open live UI at: http://127.0.0.1:8000/control-center
   Use the on-screen buttons to trigger anomalies manually.

3. Generate traffic

   python scripts/generate_web_traffic.py --base-url http://127.0.0.1:8000

4. Build features

   python scripts/web_log_feature_engineering.py --input logs/webapp_access.log --output data/web_features.csv

5. Train and score model

   python scripts/web_anomaly_detection.py --input data/web_features.csv --model-output models/web_anomaly_model.pkl --results-output data/web_anomaly_results.csv

6. Publish ML anomalies to Elasticsearch

   python scripts/publish_web_anomalies_to_elasticsearch.py --input data/web_anomaly_results.csv --username elastic --password <password> --use-current-time

7. Publish raw web logs to Elasticsearch (for non-ML panels)

   python scripts/publish_web_logs_to_elasticsearch.py --input logs/webapp_access.log --username elastic --password <password>

8. Import dashboard

   Import dashboards/grafana_web_soc_dashboard.json in Grafana.

9. Phase 2 dashboard (advanced)

   Import dashboards/grafana_web_soc_phase2_dashboard.json in Grafana.

10. Phase 2 refresh pipeline

   scripts\cmd_phase2_refresh.cmd <ELASTIC_PASSWORD>

## Easy Demo Commands

- PowerShell -ExecutionPolicy Bypass -File scripts/demo_soc_pipeline.ps1
- PowerShell -ExecutionPolicy Bypass -File scripts/demo_publish_alerts.ps1 -ElasticUser elastic -RepeatCount 6

CMD one-shot demo:
- scripts\cmd_start_web_app.cmd
- scripts\cmd_live_demo_web_soc.cmd <ELASTIC_PASSWORD>
