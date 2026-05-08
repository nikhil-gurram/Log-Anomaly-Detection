"""Near-real-time anomaly detection on appended log CSV rows."""

from __future__ import annotations

import argparse
import time
from collections import defaultdict, deque
from pathlib import Path

import joblib
import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Real-time log anomaly detector")
    parser.add_argument("--log-file", default="data/sysmon_logs.csv", help="CSV log source that grows over time")
    parser.add_argument("--model", default="models/anomaly_model.pkl", help="Trained model bundle path")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--lookback-seconds", type=int, default=60)
    parser.add_argument("--once", action="store_true", help="Process current rows once and exit")
    return parser.parse_args()


def load_model_bundle(model_path: Path) -> dict:
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    return joblib.load(model_path)


def build_realtime_features(new_rows: pd.DataFrame, history_times_by_event: dict[int, deque], lookback_seconds: int) -> pd.DataFrame:
    rows = new_rows.copy()
    rows["TimeCreated"] = pd.to_datetime(rows["TimeCreated"], errors="coerce")
    rows["EventID"] = pd.to_numeric(rows["EventID"], errors="coerce")
    rows = rows.dropna(subset=["TimeCreated", "EventID"]).sort_values("TimeCreated").reset_index(drop=True)
    rows["EventID"] = rows["EventID"].astype(int)

    event_frequency = []
    inter_event_gap_seconds = []

    prev_time = None
    for _, row in rows.iterrows():
        ts = row["TimeCreated"]
        event_id = int(row["EventID"])

        queue = history_times_by_event[event_id]
        while queue and (ts - queue[0]).total_seconds() > lookback_seconds:
            queue.popleft()

        queue.append(ts)
        event_frequency.append(len(queue))

        if prev_time is None:
            inter_event_gap_seconds.append(0.0)
        else:
            inter_event_gap_seconds.append(max(0.0, (ts - prev_time).total_seconds()))
        prev_time = ts

    rows["hour_of_day"] = rows["TimeCreated"].dt.hour
    rows["event_frequency"] = event_frequency
    rows["inter_event_gap_seconds"] = inter_event_gap_seconds
    rows["message_length"] = rows["Message"].fillna("").str.len()

    return rows


def print_alert(row: pd.Series, score: float) -> None:
    print("[ALERT] Anomalous log event detected")
    print(f"Timestamp: {row['TimeCreated']}")
    print(f"Event ID: {int(row['EventID'])}")
    print(f"Anomaly Score: {score:.6f}")
    print(f"Message Preview: {str(row['Message'])[:140]}")
    print("-" * 70)


def run_detector(args: argparse.Namespace) -> None:
    log_file = Path(args.log_file)
    bundle = load_model_bundle(Path(args.model))

    model = bundle["model"]
    scaler = bundle["scaler"]
    feature_columns = bundle["feature_columns"]

    last_processed = 0
    history_times_by_event: dict[int, deque] = defaultdict(deque)

    print("[INFO] Real-time detector started")
    print(f"[INFO] Monitoring: {log_file}")

    while True:
        if not log_file.exists():
            print(f"[WARN] Waiting for file: {log_file}")
            time.sleep(args.poll_seconds)
            if args.once:
                return
            continue

        df = pd.read_csv(log_file)
        if len(df) <= last_processed:
            if args.once:
                print("[INFO] No new rows to process.")
                return
            time.sleep(args.poll_seconds)
            continue

        new_rows = df.iloc[last_processed:].copy()
        last_processed = len(df)

        processed = build_realtime_features(new_rows, history_times_by_event, args.lookback_seconds)
        if processed.empty:
            if args.once:
                return
            time.sleep(args.poll_seconds)
            continue

        x = scaler.transform(processed[feature_columns])
        scores = model.decision_function(x)
        predictions = model.predict(x)

        for idx, pred in enumerate(predictions):
            if pred == -1:
                print_alert(processed.iloc[idx], float(scores[idx]))

        normal_count = int((predictions == 1).sum())
        anomaly_count = int((predictions == -1).sum())
        print(f"[INFO] Batch processed: {len(processed)} | Normal: {normal_count} | Anomaly: {anomaly_count}")

        if args.once:
            return

        time.sleep(args.poll_seconds)


def main() -> None:
    args = parse_args()
    run_detector(args)


if __name__ == "__main__":
    main()
