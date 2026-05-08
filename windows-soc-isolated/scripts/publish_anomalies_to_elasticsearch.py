"""Publish anomaly results CSV to Elasticsearch index for Grafana visualization."""

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
    parser = argparse.ArgumentParser(description="Publish anomaly results to Elasticsearch")
    parser.add_argument("--input", default="data/anomaly_results.csv")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--index-prefix", default="ml-anomalies")
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--password", default="changeme")
    parser.add_argument(
        "--use-current-time",
        action="store_true",
        help="Use current UTC time for indexed timestamp instead of source TimeCreated",
    )
    return parser.parse_args()


def build_bulk_payload(df: pd.DataFrame, index_name: str, use_current_time: bool = False) -> str:
    lines = []
    for _, row in df.iterrows():
        header = {"index": {"_index": index_name}}
        default_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if use_current_time:
            final_ts = default_ts
        else:
            raw_ts = row.get("TimeCreated", default_ts)
            parsed_ts = pd.to_datetime(raw_ts, utc=True, errors="coerce")
            if pd.isna(parsed_ts):
                final_ts = default_ts
            else:
                final_ts = parsed_ts.isoformat().replace("+00:00", "Z")
        document = {
            "timestamp": final_ts,
            "@timestamp": final_ts,
            "event_id": int(row.get("EventID", 0)),
            "event_type": f"sysmon_{int(row.get('EventID', 0))}",
            "anomaly_score": float(row.get("anomaly_score", 0.0)),
            "prediction": str(row.get("prediction", "normal")),
            "source": "python-ml",
            "message": str(row.get("Message", "")),
        }
        lines.append(json.dumps(header, ensure_ascii=True))
        lines.append(json.dumps(document, ensure_ascii=True))
    return "\n".join(lines) + "\n"


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    df = pd.read_csv(input_path)
    if "prediction" not in df.columns:
        raise ValueError("Input CSV must include prediction column")

    anomalies = df[df["prediction"] == "anomaly"].copy()
    if anomalies.empty:
        print("[INFO] No anomaly rows to publish.")
        return

    date_part = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"{args.index_prefix}-{date_part}"
    payload = build_bulk_payload(anomalies, index_name, use_current_time=args.use_current_time)

    endpoint = f"{args.es_url}/_bulk?refresh=wait_for"
    auth_token = base64.b64encode(f"{args.username}:{args.password}".encode("utf-8")).decode("ascii")
    req = request.Request(
        endpoint,
        data=payload.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/x-ndjson",
            "Authorization": f"Basic {auth_token}",
        },
    )

    try:
        with request.urlopen(req, timeout=30) as response:
            if response.status >= 300:
                body = response.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Bulk ingest failed: {response.status} {body}")
            body = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Bulk ingest failed: {exc.code} {body}") from exc
    except URLError as exc:
        raise RuntimeError(f"Could not connect to Elasticsearch at {endpoint}: {exc}") from exc

    parsed = json.loads(body)
    if parsed.get("errors"):
        failed = []
        for item in parsed.get("items", []):
            op = item.get("index", {})
            status = op.get("status", 0)
            if status >= 300:
                failed.append(op.get("error", {}))
        raise RuntimeError(f"Bulk ingest completed with item errors: {failed}")

    print(f"[INFO] Published {len(anomalies)} anomaly rows to index {index_name}")


if __name__ == "__main__":
    main()
