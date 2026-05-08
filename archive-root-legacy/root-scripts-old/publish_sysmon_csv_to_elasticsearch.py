"""Publish exported Sysmon CSV rows to Elasticsearch for Grafana Windows panels."""

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
    parser = argparse.ArgumentParser(description="Publish Sysmon CSV rows to Elasticsearch")
    parser.add_argument("--input", default="data/sysmon_logs.csv")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--index-prefix", default="winlogbeat-fallback")
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--max-rows", type=int, default=5000)
    parser.add_argument(
        "--use-current-time",
        action="store_true",
        help="Use current UTC time instead of TimeCreated from CSV",
    )
    return parser.parse_args()


def build_bulk_payload(df: pd.DataFrame, index_name: str, use_current_time: bool) -> str:
    lines: list[str] = []

    now_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for _, row in df.iterrows():
        raw_message = str(row.get("Message", ""))
        event_id = int(pd.to_numeric(row.get("EventID", 0), errors="coerce") or 0)

        if use_current_time:
            ts = now_ts
        else:
            parsed_ts = pd.to_datetime(row.get("TimeCreated", now_ts), utc=True, errors="coerce")
            ts = now_ts if pd.isna(parsed_ts) else parsed_ts.isoformat().replace("+00:00", "Z")

        doc = {
            "@timestamp": ts,
            "TimeCreated": str(row.get("TimeCreated", "")),
            "EventID": event_id,
            "event": {"code": str(event_id)},
            "winlog": {"event_id": event_id},
            "message": raw_message,
            "source": "sysmon-csv",
        }

        lowered = raw_message.lower()
        if "powershell" in lowered:
            doc["process"] = {"name": "powershell.exe"}

        header = {"index": {"_index": index_name}}
        lines.append(json.dumps(header, ensure_ascii=True))
        lines.append(json.dumps(doc, ensure_ascii=True))

    return "\n".join(lines) + "\n"


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    frame = pd.read_csv(input_path)
    required = {"TimeCreated", "EventID", "Message"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Missing required columns in CSV: {sorted(missing)}")

    if frame.empty:
        raise ValueError("Input CSV has no rows to publish")

    frame = frame.tail(args.max_rows).copy()

    date_part = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"{args.index_prefix}-{date_part}"
    payload = build_bulk_payload(frame, index_name, args.use_current_time)

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
        with request.urlopen(req, timeout=40) as response:
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
        failed = []
        for item in parsed.get("items", []):
            op = item.get("index", {})
            if int(op.get("status", 0)) >= 300:
                failed.append(op.get("error", {}))
        raise RuntimeError(f"Bulk ingest completed with item errors: {failed}")

    print(f"[INFO] Published {len(frame)} Sysmon rows to {index_name}")


if __name__ == "__main__":
    main()
