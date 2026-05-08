"""Real-time anomaly scoring for appended web app JSON logs."""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict, deque
from pathlib import Path

import joblib
import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Realtime detector for web app logs")
    parser.add_argument("--log-file", default="logs/webapp_access.log")
    parser.add_argument("--model", default="models/web_anomaly_model.pkl")
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def to_feature_row(entry: dict, per_ip_times: dict[str, deque], lookback_seconds: int = 60) -> dict:
    ts = pd.to_datetime(entry.get("timestamp"), utc=True, errors="coerce")
    if pd.isna(ts):
        ts = pd.Timestamp.utcnow(tz="UTC")

    ip = str(entry.get("client_ip", "unknown"))
    q = per_ip_times[ip]
    while q and (ts - q[0]).total_seconds() > lookback_seconds:
        q.popleft()
    q.append(ts)

    path = str(entry.get("path", ""))
    status_code = int(entry.get("status_code", 0))
    event_type = str(entry.get("event_type", "web_request"))

    return {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "status_code": status_code,
        "latency_ms": float(entry.get("latency_ms", 0.0)),
        "hour_of_day": int(ts.hour),
        "is_error": int(status_code >= 400),
        "is_auth_failed": int(event_type == "auth_failed"),
        "is_scan": int(event_type == "endpoint_scan"),
        "is_admin_path": int(path.startswith("/admin")),
        "req_per_min_ip": len(q),
        "unique_paths_per_min_ip": 1,
        "path": path,
        "client_ip": ip,
        "event_type": event_type,
    }


def main() -> None:
    args = parse_args()
    log_path = Path(args.log_file)
    bundle = joblib.load(args.model)
    model = bundle["model"]
    scaler = bundle["scaler"]
    feature_columns = bundle["feature_columns"]

    last_size = 0
    per_ip_times: dict[str, deque] = defaultdict(deque)

    print(f"[INFO] Monitoring {log_path} for anomalies")

    while True:
        if not log_path.exists():
            print("[WARN] Waiting for log file...")
            time.sleep(args.poll_seconds)
            if args.once:
                return
            continue

        current_size = log_path.stat().st_size
        if current_size <= last_size:
            if args.once:
                return
            time.sleep(args.poll_seconds)
            continue

        with log_path.open("r", encoding="utf-8") as handle:
            handle.seek(last_size)
            new_lines = handle.readlines()
        last_size = current_size

        rows = []
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append(to_feature_row(entry, per_ip_times))

        if not rows:
            if args.once:
                return
            time.sleep(args.poll_seconds)
            continue

        df = pd.DataFrame(rows)
        x = scaler.transform(df[feature_columns])
        scores = model.decision_function(x)
        preds = model.predict(x)

        for i, pred in enumerate(preds):
            if pred == -1:
                row = df.iloc[i]
                print("[ALERT] Web anomaly detected")
                print(f"Timestamp: {row['timestamp']}")
                print(f"Path: {row['path']} | IP: {row['client_ip']}")
                print(f"Score: {scores[i]:.6f}")
                print("-" * 60)

        print(f"[INFO] Batch rows: {len(df)} | Anomalies: {(preds == -1).sum()}")

        if args.once:
            return

        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
