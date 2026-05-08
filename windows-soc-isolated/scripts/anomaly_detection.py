"""Train and run Isolation Forest on engineered Windows log features."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS = [
    "EventID",
    "hour_of_day",
    "event_frequency",
    "inter_event_gap_seconds",
    "message_length",
]


def prepare_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    frame = df.copy()

    if "EventID" not in frame.columns and "event_id" in frame.columns:
        frame = frame.rename(columns={"event_id": "EventID"})

    missing = [c for c in FEATURE_COLUMNS if c not in frame.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    for col in FEATURE_COLUMNS:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")

    frame = frame.dropna(subset=FEATURE_COLUMNS).reset_index(drop=True)
    return frame


def train_isolation_forest(feature_df: pd.DataFrame, contamination: float, random_state: int) -> dict:
    scaler = StandardScaler()
    x_all = scaler.fit_transform(feature_df[FEATURE_COLUMNS])

    # Fit on earliest 70% as baseline normal behavior.
    train_cut = max(10, int(len(x_all) * 0.7))
    x_train = x_all[:train_cut]

    model = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        random_state=random_state,
        n_jobs=1,
    )
    model.fit(x_train)

    score = model.decision_function(x_all)
    pred = model.predict(x_all)  # 1 = normal, -1 = anomaly

    return {
        "model": model,
        "scaler": scaler,
        "feature_columns": FEATURE_COLUMNS,
        "scores": score,
        "predictions": pred,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train Isolation Forest for log anomaly detection")
    parser.add_argument("--input", default="data/features.csv")
    parser.add_argument("--model-output", default="models/anomaly_model.pkl")
    parser.add_argument("--results-output", default="data/anomaly_results.csv")
    parser.add_argument("--contamination", type=float, default=0.08)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    model_path = Path(args.model_output)
    results_path = Path(args.results_output)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.parent.mkdir(parents=True, exist_ok=True)

    raw_features = pd.read_csv(input_path)
    feature_df = prepare_feature_frame(raw_features)

    bundle = train_isolation_forest(feature_df, args.contamination, args.random_state)

    scored = feature_df.copy()
    scored["anomaly_score"] = bundle["scores"]
    scored["prediction"] = np.where(bundle["predictions"] == -1, "anomaly", "normal")
    scored.to_csv(results_path, index=False)

    joblib.dump(
        {
            "model": bundle["model"],
            "scaler": bundle["scaler"],
            "feature_columns": bundle["feature_columns"],
        },
        model_path,
    )

    anomaly_count = int((scored["prediction"] == "anomaly").sum())
    print(f"[INFO] Model saved: {model_path}")
    print(f"[INFO] Scored results saved: {results_path}")
    print(f"[INFO] Total rows: {len(scored)} | Anomalies: {anomaly_count}")


if __name__ == "__main__":
    main()
