"""Convert web JSON logs into ML features."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from pathlib import Path

import pandas as pd


def load_json_lines(path: Path) -> pd.DataFrame:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return pd.DataFrame(rows)


def engineer_features(df: pd.DataFrame, lookback_seconds: int = 60) -> pd.DataFrame:
    frame = df.copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["timestamp", "status_code", "latency_ms"]).sort_values("timestamp").reset_index(drop=True)

    frame["status_code"] = pd.to_numeric(frame["status_code"], errors="coerce").fillna(0).astype(int)
    frame["latency_ms"] = pd.to_numeric(frame["latency_ms"], errors="coerce").fillna(0.0)
    frame["event_type"] = frame.get("event_type", "web_request").astype(str)
    frame["method"] = frame.get("method", "GET").astype(str)
    frame["query"] = frame.get("query", "").fillna("").astype(str)
    frame["hour_of_day"] = frame["timestamp"].dt.hour
    frame["is_error"] = (frame["status_code"] >= 400).astype(int)
    frame["is_auth_failed"] = (frame["event_type"] == "auth_failed").astype(int)
    frame["is_scan"] = (frame["event_type"] == "endpoint_scan").astype(int)
    frame["is_admin_path"] = frame["path"].str.startswith("/admin").fillna(False).astype(int)
    frame["is_sqli"] = frame["event_type"].isin({"sqli_probe", "sqli_attempt"}).astype(int)
    frame["is_xss"] = frame["event_type"].isin({"xss_probe", "xss_attempt"}).astype(int)
    frame["is_token_abuse"] = (frame["event_type"] == "token_abuse").astype(int)
    frame["is_bot"] = frame["event_type"].isin({"bot_scrape", "api_abuse"}).astype(int)

    per_ip_times: dict[str, deque] = defaultdict(deque)
    req_rate = []
    unique_paths_window = []

    for _, row in frame.iterrows():
        ip = str(row.get("client_ip", "unknown"))
        ts = row["timestamp"]

        q = per_ip_times[ip]
        while q and (ts - q[0]).total_seconds() > lookback_seconds:
            q.popleft()
        q.append(ts)
        req_rate.append(len(q))

        window_start = ts - pd.Timedelta(seconds=lookback_seconds)
        window_paths = frame[(frame["client_ip"] == ip) & (frame["timestamp"] >= window_start) & (frame["timestamp"] <= ts)]["path"]
        unique_paths_window.append(window_paths.nunique())

    frame["req_per_min_ip"] = req_rate
    frame["unique_paths_per_min_ip"] = unique_paths_window

    feature_cols = [
        "timestamp",
        "client_ip",
        "method",
        "path",
        "query",
        "event_type",
        "status_code",
        "latency_ms",
        "hour_of_day",
        "is_error",
        "is_auth_failed",
        "is_scan",
        "is_admin_path",
        "is_sqli",
        "is_xss",
        "is_token_abuse",
        "is_bot",
        "req_per_min_ip",
        "unique_paths_per_min_ip",
    ]
    return frame[feature_cols]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Feature engineering for web app logs")
    parser.add_argument("--input", default="logs/webapp_access.log")
    parser.add_argument("--output", default="data/web_features.csv")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    raw = load_json_lines(input_path)
    features = engineer_features(raw)
    features.to_csv(output_path, index=False)

    print(f"[INFO] Features saved: {output_path}")
    print(f"[INFO] Rows: {len(features)}, Columns: {len(features.columns)}")


if __name__ == "__main__":
    main()
