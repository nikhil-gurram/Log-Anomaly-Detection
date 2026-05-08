"""Publish raw webapp JSON logs directly to Elasticsearch for dashboard panels."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish raw web app logs to Elasticsearch")
    parser.add_argument("--input", default="logs/webapp_access.log")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--index-prefix", default="webapp-logs")
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--max-lines", type=int, default=5000)
    return parser.parse_args()


def build_bulk_payload(lines: list[str], index_name: str) -> str:
    out: list[str] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            continue

        ts = doc.get("timestamp")
        if not ts:
            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            doc["timestamp"] = ts

        doc.setdefault("source", "webapp")
        header = {"index": {"_index": index_name}}
        out.append(json.dumps(header, ensure_ascii=True))
        out.append(json.dumps(doc, ensure_ascii=True))

    return "\n".join(out) + "\n"


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input log file not found: {input_path}")

    all_lines = input_path.read_text(encoding="utf-8").splitlines()
    if not all_lines:
        print("[INFO] No web logs to publish")
        return

    lines = all_lines[-args.max_lines :]
    date_part = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"{args.index_prefix}-{date_part}"
    payload = build_bulk_payload(lines, index_name)

    endpoint = f"{args.es_url}/_bulk?refresh=wait_for"
    auth = base64.b64encode(f"{args.username}:{args.password}".encode("utf-8")).decode("ascii")

    req = request.Request(
        endpoint,
        data=payload.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/x-ndjson",
            "Authorization": f"Basic {auth}",
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
        raise RuntimeError("Bulk indexing returned item errors")

    print(f"[INFO] Published approximately {len(lines)} web log lines to {index_name}")


if __name__ == "__main__":
    main()
