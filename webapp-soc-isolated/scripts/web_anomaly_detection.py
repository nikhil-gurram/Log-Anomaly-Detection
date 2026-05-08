"""Train Isolation Forest on web log features and label anomalies."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS = [
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


def build_risk_and_severity(row: pd.Series) -> tuple[float, str, str]:
    score = 0.0
    reasons: list[str] = []

    status_code = int(row.get("status_code", 0))
    latency = float(row.get("latency_ms", 0.0))
    req_rate = float(row.get("req_per_min_ip", 0.0))
    unique_paths = float(row.get("unique_paths_per_min_ip", 0.0))
    anomaly_score = float(row.get("anomaly_score", 0.0))

    if int(row.get("is_auth_failed", 0)) == 1:
        score += 22
        reasons.append("auth_failed")
    if int(row.get("is_scan", 0)) == 1:
        score += 25
        reasons.append("endpoint_scan")
    if int(row.get("is_admin_path", 0)) == 1 and int(row.get("is_error", 0)) == 1:
        score += 20
        reasons.append("admin_probe")
    if int(row.get("is_sqli", 0)) == 1:
        score += 26
        reasons.append("sqli_probe")
    if int(row.get("is_xss", 0)) == 1:
        score += 18
        reasons.append("xss_probe")
    if int(row.get("is_token_abuse", 0)) == 1:
        score += 24
        reasons.append("token_abuse")
    if int(row.get("is_bot", 0)) == 1:
        score += 14
        reasons.append("bot_activity")

    if status_code >= 500:
        score += 18
        reasons.append("server_error")
    elif status_code >= 400:
        score += 10
        reasons.append("client_error")

    if latency >= 1200:
        score += 18
        reasons.append("extreme_latency")
    elif latency >= 700:
        score += 10
        reasons.append("high_latency")

    if req_rate >= 45:
        score += 20
        reasons.append("req_rate_very_high")
    elif req_rate >= 20:
        score += 10
        reasons.append("req_rate_high")

    if unique_paths >= 15:
        score += 15
        reasons.append("path_enumeration")
    elif unique_paths >= 8:
        score += 8
        reasons.append("path_variance_high")

    # IsolationForest anomalies have negative decision function values.
    if anomaly_score < 0:
        score += min(25.0, abs(anomaly_score) * 120)
        reasons.append("ml_outlier")

    score = round(max(0.0, min(100.0, score)), 2)

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    else:
        severity = "low"

    reason_text = "|".join(sorted(set(reasons))) if reasons else "baseline"
    return score, severity, reason_text


def prepare_data(df: pd.DataFrame) -> pd.DataFrame:
    frame = df.copy()
    missing = [c for c in FEATURE_COLUMNS if c not in frame.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    for col in FEATURE_COLUMNS:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
    frame = frame.dropna(subset=FEATURE_COLUMNS).reset_index(drop=True)
    return frame


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Web log anomaly detection")
    parser.add_argument("--input", default="data/web_features.csv")
    parser.add_argument("--model-output", default="models/web_anomaly_model.pkl")
    parser.add_argument("--results-output", default="data/web_anomaly_results.csv")
    parser.add_argument("--contamination", type=float, default=0.08)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    model_path = Path(args.model_output)
    results_path = Path(args.results_output)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.parent.mkdir(parents=True, exist_ok=True)

    raw = pd.read_csv(input_path)
    frame = prepare_data(raw)

    scaler = StandardScaler()
    x_all = scaler.fit_transform(frame[FEATURE_COLUMNS])

    split = max(20, int(len(x_all) * 0.7))
    x_train = x_all[:split]

    model = IsolationForest(n_estimators=300, contamination=args.contamination, random_state=42, n_jobs=1)
    model.fit(x_train)

    scores = model.decision_function(x_all)
    preds = model.predict(x_all)

    output = raw.loc[frame.index].copy()
    output["anomaly_score"] = scores
    output["prediction"] = np.where(preds == -1, "anomaly", "normal")

    phase2 = output.apply(build_risk_and_severity, axis=1, result_type="expand")
    phase2.columns = ["risk_score", "severity", "reason_tags"]
    output = pd.concat([output, phase2], axis=1)

    output.to_csv(results_path, index=False)

    joblib.dump({"model": model, "scaler": scaler, "feature_columns": FEATURE_COLUMNS}, model_path)

    print(f"[INFO] Model saved: {model_path}")
    print(f"[INFO] Results saved: {results_path}")
    print(f"[INFO] Total rows: {len(output)} | Anomalies: {(output['prediction'] == 'anomaly').sum()}")


if __name__ == "__main__":
    main()
