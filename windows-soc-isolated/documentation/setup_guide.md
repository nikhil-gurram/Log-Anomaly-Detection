# Full Setup Guide: Winlogbeat + Elasticsearch + Grafana + ML

## 1. Prerequisites

- Windows 11 machine with administrator access
- Python 3.10+
- Sysmon installed
- Elasticsearch 8.x
- Grafana 10.x
- Winlogbeat 8.x

## 2. Install Sysmon and Enable Logging

1. Download Sysmon from Microsoft Sysinternals.
2. Open PowerShell as Administrator.
3. Install with a baseline config:

   Sysmon64.exe -accepteula -i sysmonconfig.xml

4. Confirm log channel exists:

   Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational

## 3. Python Project Setup

1. Open project root in terminal.
2. Install dependencies:

   pip install -r requirements.txt

3. Run red-team simulation:

   python scripts/attack_simulation.py

4. Export logs:

   python scripts/export_sysmon_logs.py --max-events 5000 --output data/sysmon_logs.csv

5. Create tampered logs:

   python scripts/log_tampering.py --input data/sysmon_logs.csv --output data/tampered_logs.csv

6. Build features:

   python scripts/feature_engineering.py --input data/sysmon_logs.csv --output data/features.csv

7. Train anomaly model:

   python scripts/anomaly_detection.py --input data/features.csv --model-output models/anomaly_model.pkl --results-output data/anomaly_results.csv

8. Start real-time detection:

   python scripts/realtime_detector.py --log-file data/sysmon_logs.csv --model models/anomaly_model.pkl --poll-seconds 5

9. Publish anomaly alerts to Elasticsearch:

   python scripts/publish_anomalies_to_elasticsearch.py --input data/anomaly_results.csv --es-url http://localhost:9200 --username elastic --password <your_password> --use-current-time

## 4. Elasticsearch Setup

1. Start Elasticsearch service and verify:

   curl http://localhost:9200

2. Create anomaly index template:

   curl -X PUT "http://localhost:9200/_index_template/ml-anomalies-template" -H "Content-Type: application/json" -d @config/elasticsearch-index-template.json

3. Verify template:

   curl http://localhost:9200/_index_template/ml-anomalies-template

## 5. Winlogbeat Setup

1. Install Winlogbeat on Windows host.
2. Replace default config with config/winlogbeat.yml.
3. Load template and dashboards:

   winlogbeat.exe setup -e

4. Start Winlogbeat:

   Start-Service winlogbeat

5. Validate incoming documents:

   curl "http://localhost:9200/winlogbeat-*/_search?size=1&pretty"

## 6. Grafana Datasource Setup

### Option A: Provisioning file

1. Copy config/grafana-datasource.yaml to Grafana provisioning path:

   C:\Program Files\GrafanaLabs\grafana\conf\provisioning\datasources\

2. Restart Grafana service.
3. Confirm both datasources exist in Grafana:
   - Elasticsearch-SOC (index `winlogbeat-*`, time field `@timestamp`)
   - Elasticsearch-ML (index `ml-anomalies-*`, time field `timestamp`)

### Option B: UI setup

1. Open Grafana at http://localhost:3000.
2. Add datasource type Elasticsearch.
3. URL: http://localhost:9200
4. Index pattern: winlogbeat-*
5. Time field: @timestamp

For ML alerts, add a second Elasticsearch datasource:

1. URL: http://localhost:9200
2. Index pattern: ml-anomalies-*
3. Time field: timestamp

## 7. Dashboard Setup

1. In Grafana, import dashboards/grafana_dashboard.json.
2. Select datasource Elasticsearch-SOC.
3. Set auto-refresh to 5 seconds.

Panels included:

- Process Creation Activity
- File Creation Spikes
- PowerShell Execution Frequency
- Machine Learning Anomaly Alerts

## 8. Stream ML Alerts to Elasticsearch

To visualize model alerts in Grafana, index anomaly rows to Elasticsearch using bulk API with index name ml-anomalies-YYYY.MM.DD.

Suggested fields:

- timestamp
- event_id
- event_type
- anomaly_score
- prediction
- message

Example publish command with auth:

python scripts/publish_anomalies_to_elasticsearch.py --input data/anomaly_results.csv --es-url http://localhost:9200 --username elastic --password <your_password>

## 9. Demonstration Flow

1. Keep normal system running for baseline.
2. Execute attack simulation script.
3. Export fresh Sysmon logs.
4. Re-run feature engineering and model inference.
5. Start real-time detector.
6. Observe spikes and anomaly alerts in Grafana.

## 10. Grafana "No Data" Quick Checks

1. In Grafana, set dashboard time range to Last 90 days (or Last 24 hours if you publish with --use-current-time).
2. Confirm datasource health in Grafana Connections for both Elasticsearch-SOC and Elasticsearch-ML.
3. Verify Winlogbeat docs exist:

   curl "http://localhost:9200/winlogbeat-*/_count?pretty"

4. Verify ML alert docs exist:

   curl "http://localhost:9200/ml-anomalies-*/_count?pretty"

5. If counts are zero:
   - Re-run log export, feature engineering, anomaly detection.
   - Re-run ML publish script with correct Elasticsearch username/password.
   - Ensure Winlogbeat service is running (`Get-Service winlogbeat`).
