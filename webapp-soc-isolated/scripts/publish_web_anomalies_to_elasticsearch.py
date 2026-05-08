"""Publish web anomaly results to Elasticsearch for Grafana visualization."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish web anomaly results to Elasticsearch")
    parser.add_argument("--input", default="data/web_anomaly_results.csv")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--index-prefix", default="web-ml-anomalies")
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--use-current-time", action="store_true")
    return parser.parse_args()


def build_payload(df: pd.DataFrame, index_name: str, use_current_time: bool) -> str:
    lines = []
    for _, row in df.iterrows():
        now_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if use_current_time:
            ts = now_ts
        else:
            parsed = pd.to_datetime(row.get("timestamp", now_ts), utc=True, errors="coerce")
            ts = now_ts if pd.isna(parsed) else parsed.isoformat().replace("+00:00", "Z")

        header = {"index": {"_index": index_name}}
        doc = {
            "timestamp": ts,
            "prediction": str(row.get("prediction", "normal")),
            "anomaly_score": float(row.get("anomaly_score", 0.0)),
            "risk_score": float(row.get("risk_score", 0.0)),
            "severity": str(row.get("severity", "low")),
            "reason_tags": str(row.get("reason_tags", "baseline")),
            "path": str(row.get("path", "")),
            "client_ip": str(row.get("client_ip", "")),
            "status_code": int(float(row.get("status_code", 0))),
            "event_type": str(row.get("event_type", "web_request")),
            "source": "web-ml",
            "ingest_timestamp": now_ts,
        }
        lines.append(json.dumps(header, ensure_ascii=True))
        lines.append(json.dumps(doc, ensure_ascii=True))

    return "\n".join(lines) + "\n"


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    df = pd.read_csv(input_path)
    if "prediction" not in df.columns:
        raise ValueError("Input must contain prediction column")

    anomalies = df[df["prediction"] == "anomaly"].copy()
    if anomalies.empty:
        print("[INFO] No anomalies to publish")
        return

    index_name = f"{args.index_prefix}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
    payload = build_payload(anomalies, index_name, use_current_time=args.use_current_time)

    endpoint = f"{args.es_url}/_bulk?refresh=wait_for"
    auth = base64.b64encode(f"{args.username}:{args.password}".encode("utf-8")).decode("ascii")

    req = request.Request(
        endpoint,
        data=payload.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/x-ndjson", "Authorization": f"Basic {auth}"},
    )

    try:
        with request.urlopen(req, timeout=30) as response:
            body = response.read().decode("utf-8", errors="replace")
            if response.status >= 300:
                raise RuntimeError(f"Bulk ingest failed: {response.status} {body}")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Bulk ingest failed: {exc.code} {body}") from exc
    except URLError as exc:
        raise RuntimeError(f"Could not connect to Elasticsearch at {endpoint}: {exc}") from exc

    parsed = json.loads(body)
    if parsed.get("errors"):
        raise RuntimeError("Bulk indexing returned item errors")

    print(f"[INFO] Published {len(anomalies)} web anomaly rows to {index_name}")


if __name__ == "__main__":
    main()
