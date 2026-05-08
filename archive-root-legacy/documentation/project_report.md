# Detection of Windows Log Tampering and Anomalous Activity Using Machine Learning

## Abstract

This project presents a Security Operations Center style monitoring pipeline for detecting suspicious Windows activity and potential log tampering using machine learning. Sysmon captures host telemetry such as process execution, network connections, file creation, and registry changes. Winlogbeat forwards logs to Elasticsearch, while Grafana visualizes real-time events and anomaly trends. An Isolation Forest model is trained on engineered log features to identify abnormal process bursts, unusual activity timing, and tampered log artifacts such as missing sequences and timestamp disordering. The system demonstrates coordinated red-team simulation and blue-team detection, providing an academic and practical foundation for modern cyber defense monitoring.

## Introduction

Windows endpoints are primary targets for adversaries due to widespread enterprise usage and rich attack surface. Attackers often attempt to blend into normal administrative activity and may tamper with logs to conceal traces. Traditional rule-based monitoring can miss novel behavior patterns. Therefore, combining system telemetry, centralized logging, and machine learning offers a stronger approach for identifying subtle deviations and forensic inconsistencies.

## Problem Statement

Organizations need a lightweight and cost-effective method to:

- detect suspicious endpoint behavior in near real time
- identify potential log manipulation artifacts
- centralize and visualize security data for SOC analysts

The challenge is to build a reproducible pipeline that includes both attack simulation and defensive analytics in a single research prototype.

## Literature Survey

Recent SOC research emphasizes endpoint telemetry collection, SIEM correlation, and anomaly detection for unknown threats. Sysmon is widely used for enriched Windows telemetry. Beats agents are commonly used for log transport into Elasticsearch-based stacks. Unsupervised models such as Isolation Forest and One-Class methods are suitable where labeled attack data is scarce. Studies also show that log integrity indicators, including event sequence gaps and timestamp inconsistencies, can reveal anti-forensic behavior.

## System Architecture

Attack Simulation Scripts
-> Windows Event Logs + Sysmon
-> Winlogbeat
-> Elasticsearch
-> Python ML Engine
-> Anomaly Alerts
-> Grafana SOC Dashboard

### Major Components

- Data Collection: Sysmon event channels
- Shipping Layer: Winlogbeat
- Storage Layer: Elasticsearch indices
- Analytics Layer: Python feature engineering and Isolation Forest
- Visualization Layer: Grafana real-time dashboard

## Methodology

1. Simulate suspicious host behavior with controlled scripts.
2. Collect and export Sysmon logs into CSV format.
3. Generate tampered datasets by deleting and reordering selected events.
4. Engineer temporal and frequency-based features.
5. Train Isolation Forest model on baseline behavior.
6. Perform batch and real-time inference.
7. Visualize telemetry and anomaly counts in Grafana.

## Attack Simulation Design

The red-team module generates telemetry-rich suspicious activity without destructive payloads:

- repeated PowerShell command execution
- repeated service enumeration
- rapid file creation bursts

These behaviors intentionally increase Event IDs associated with process and file operations, creating measurable deviations from baseline host activity.

## Log Collection Pipeline

- Sysmon captures endpoint activity in Microsoft-Windows-Sysmon/Operational.
- Winlogbeat collects Security and Sysmon channels.
- Logs are forwarded to Elasticsearch for indexing and querying.
- Python scripts export or process records for ML workflow.

## Machine Learning Model

### Feature Set

- EventID
- hour_of_day
- event_frequency per time window
- inter_event_gap_seconds
- message_length

### Model Choice

Isolation Forest is used due to:

- effectiveness on high-dimensional unlabeled telemetry
- ability to isolate outliers by random partitioning
- low operational complexity for real-time scoring

### Detection Targets

- abnormal event spikes
- suspicious off-hour activity
- process burst patterns
- log sequence gaps
- timestamp disordering from tampering

## Experimental Results

### Scenario

1. Baseline data collected during normal operations.
2. Attack simulation executed.
3. Logs exported and tampered variants generated.
4. Features built and model trained.
5. Batch and streaming anomaly detection performed.

### Observations

- process and file event frequencies increased sharply during attack mode
- tampered logs showed larger sequence gaps and reordered timestamps
- Isolation Forest assigned lower anomaly scores to suspicious rows
- real-time detector generated alert messages for high-risk events

## Grafana Dashboard Visualization

The dashboard includes panels for:

- Process Creation Activity
- File Creation Spikes
- PowerShell Execution Frequency
- Machine Learning Anomaly Alerts

With 5-second refresh, SOC analysts can observe suspicious bursts immediately and correlate anomalies with event context.

## Conclusion

The project successfully demonstrates an end-to-end SOC prototype that integrates attack simulation, log collection, machine learning anomaly detection, and real-time visualization. The dual red-team and blue-team workflow highlights practical detection engineering steps and supports academic evaluation of telemetry-driven cyber defense.

## Future Work

- integrate additional algorithms such as One-Class SVM and Local Outlier Factor
- add model drift monitoring and periodic retraining
- deploy secure alert transport to SIEM or SOAR tooling
- include labeled benchmark datasets for quantitative comparison
- add host identity and user behavior features for improved precision
