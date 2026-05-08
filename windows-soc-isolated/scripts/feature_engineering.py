"""Convert raw Windows log rows into numerical features for anomaly detection."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def build_features(df: pd.DataFrame, window: str = "1min") -> pd.DataFrame:
    data = df.copy()
    data["TimeCreated"] = pd.to_datetime(data["TimeCreated"], errors="coerce")
    data = data.dropna(subset=["TimeCreated", "EventID"]).sort_values("TimeCreated").reset_index(drop=True)

    data["EventID"] = pd.to_numeric(data["EventID"], errors="coerce")
    data = data.dropna(subset=["EventID"]).reset_index(drop=True)
    data["EventID"] = data["EventID"].astype(int)

    data["hour_of_day"] = data["TimeCreated"].dt.hour
    data["window_bucket"] = data["TimeCreated"].dt.floor(window)

    # Frequency of each event type within the selected rolling time bucket.
    freq = data.groupby(["window_bucket", "EventID"], as_index=False).size().rename(columns={"size": "event_frequency"})
    data = data.merge(freq, on=["window_bucket", "EventID"], how="left")

    data["inter_event_gap_seconds"] = (
        data["TimeCreated"].diff().dt.total_seconds().fillna(0.0).clip(lower=0.0)
    )

    data["message_length"] = data["Message"].fillna("").str.len()

    feature_cols = [
        "TimeCreated",
        "EventID",
        "hour_of_day",
        "event_frequency",
        "inter_event_gap_seconds",
        "message_length",
    ]

    return data[feature_cols]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Feature engineering for Sysmon logs")
    parser.add_argument("--input", default="data/sysmon_logs.csv")
    parser.add_argument("--output", default="data/features.csv")
    parser.add_argument("--window", default="1min", help="Aggregation window, e.g., 30s, 1min, 5min")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    raw = pd.read_csv(input_path)
    required_columns = {"TimeCreated", "EventID", "Message"}
    missing = required_columns.difference(raw.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    features = build_features(raw, window=args.window)
    features.to_csv(output_path, index=False)

    print(f"[INFO] Wrote feature dataset: {output_path}")
    print(f"[INFO] Rows: {len(features)}, Columns: {len(features.columns)}")


if __name__ == "__main__":
    main()
