"""Unified SOC dashboard for web, Windows, network, and PCAP analytics."""

from __future__ import annotations

import json
import base64
import random
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError

import pandas as pd
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel


ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "webapp-soc-isolated"
WINDOWS_ROOT = ROOT / "windows-soc-isolated"
NETWORK_ROOT = ROOT / "network-soc-isolated"

WEB_LOGS = WEB_ROOT / "logs" / "webapp_access.log"
WEB_FEATURES = WEB_ROOT / "data" / "web_features.csv"
WEB_ANOMALIES = WEB_ROOT / "data" / "web_anomaly_results.csv"
WEB_MODEL = WEB_ROOT / "models" / "web_anomaly_model.pkl"

WINDOWS_ATTACK_DIR = WINDOWS_ROOT / "attack_files"
WINDOWS_LOGS = WINDOWS_ROOT / "data" / "sysmon_logs.csv"
WINDOWS_FEATURES = WINDOWS_ROOT / "data" / "features.csv"
WINDOWS_ANOMALIES = WINDOWS_ROOT / "data" / "anomaly_results.csv"
WINDOWS_MODEL = WINDOWS_ROOT / "models" / "anomaly_model.pkl"

NETWORK_LOGS = NETWORK_ROOT / "data" / "network_flows.csv"
NETWORK_FEATURES = NETWORK_ROOT / "data" / "network_features.csv"
NETWORK_ANOMALIES = NETWORK_ROOT / "data" / "network_anomaly_results.csv"
NETWORK_MODEL = NETWORK_ROOT / "models" / "network_anomaly_model.pkl"
NETWORK_UPLOADS = NETWORK_ROOT / "uploads"
EVIDENCE_UPLOADS = ROOT / "evidence-uploads"

ARCHITECTURE_DOC = ROOT / "ARCHITECTURE.md"

WEB_LOGS.parent.mkdir(parents=True, exist_ok=True)
WINDOWS_ATTACK_DIR.mkdir(parents=True, exist_ok=True)
NETWORK_UPLOADS.mkdir(parents=True, exist_ok=True)
EVIDENCE_UPLOADS.mkdir(parents=True, exist_ok=True)


WEB_SCENARIOS = [
    {
        "id": "failed-logins",
        "label": "Failed Logins",
        "summary": "Brute-force authentication failure burst.",
        "process": ["POST /login repeated", "401 responses generated", "web auth failure features rise"],
        "signals": ["auth_failed", "high req_per_min_ip", "401 spikes"],
    },
    {
        "id": "endpoint-scan",
        "label": "Endpoint Scan",
        "summary": "Recon against admin and exposed paths.",
        "process": ["Enumerate /.git and admin paths", "404-heavy probing", "scan flags appear in features"],
        "signals": ["endpoint_scan", "path variance", "4xx concentration"],
    },
    {
        "id": "sql-injection",
        "label": "SQL Injection",
        "summary": "Injected search and API payloads.",
        "process": ["Malicious query strings emitted", "mixed 400/403/500 responses", "SQLi markers feed risk scoring"],
        "signals": ["sqli_probe", "error bursts", "ml outlier"],
    },
    {
        "id": "xss-probe",
        "label": "XSS Probe",
        "summary": "Reflected script injection attempts.",
        "process": ["Script-like inputs sent", "validation errors logged", "XSS flags score anomalies"],
        "signals": ["xss_probe", "path variance", "client error spikes"],
    },
    {
        "id": "token-abuse",
        "label": "Token Abuse",
        "summary": "Suspicious API token reuse on privileged endpoints.",
        "process": ["Protected APIs called with bad token scope", "401/403 responses captured", "token abuse features rise"],
        "signals": ["token_abuse", "API focus", "privileged endpoint attempts"],
    },
    {
        "id": "bot-scraping",
        "label": "Bot Scraping",
        "summary": "Fast crawling of product and search pages.",
        "process": ["Crawler user-agent emitted", "high request rate built", "bot features raise anomaly pressure"],
        "signals": ["bot_scrape", "high req_per_min_ip", "catalog scraping"],
    },
    {
        "id": "api-abuse",
        "label": "API Abuse",
        "summary": "Aggressive service/API consumption with rate pressure.",
        "process": ["Noisy API requests sent", "200 and 429 mix logged", "bot and rate features increase"],
        "signals": ["api_abuse", "429 responses", "automation pattern"],
    },
    {
        "id": "latency-spike",
        "label": "Latency Spike",
        "summary": "Stress traffic with slow response behavior.",
        "process": ["Slow endpoints emitted", "latency rises sharply", "performance anomaly signals appear"],
        "signals": ["high latency", "service stress", "ml outlier"],
    },
    {
        "id": "mixed-attack",
        "label": "Full Web Attack",
        "summary": "Multi-stage web campaign across auth, recon, exploit, and abuse.",
        "process": ["Blend multiple attack generators", "retrain features once", "publish logs plus anomaly rows"],
        "signals": ["mixed reason_tags", "high anomaly density", "Grafana web panels refresh"],
    },
]

WINDOWS_SCENARIOS = [
    {
        "id": "powershell-spike",
        "label": "PowerShell Spike",
        "summary": "Repeated PowerShell launches for execution telemetry.",
        "process": ["Spawn PowerShell repeatedly", "export Sysmon", "score Windows features"],
        "signals": ["EventID changes", "process telemetry", "execution spike"],
    },
    {
        "id": "service-enumeration",
        "label": "Service Enumeration",
        "summary": "Repeated service discovery against the host.",
        "process": ["Run Get-Service repeatedly", "collect Sysmon rows", "detect discovery anomalies"],
        "signals": ["service query pattern", "event frequency", "discovery-like behavior"],
    },
    {
        "id": "file-burst",
        "label": "Rapid File Burst",
        "summary": "Fast file creation to trigger file telemetry.",
        "process": ["Create many files quickly", "export Sysmon file events", "score anomaly model"],
        "signals": ["file creation bursts", "high event frequency", "artifact spike"],
    },
    {
        "id": "recon-blend",
        "label": "Recon Blend",
        "summary": "PowerShell and service reconnaissance together.",
        "process": ["Blend discovery behaviors", "export and featurize", "publish Windows detections"],
        "signals": ["mixed discovery pattern", "process + service activity", "Grafana Windows signal"],
    },
    {
        "id": "all",
        "label": "Full Windows Attack",
        "summary": "Runs the full Windows simulation chain.",
        "process": ["Execution + discovery + file burst", "feature engineering", "anomaly publish"],
        "signals": ["dense Sysmon changes", "multi-stage activity", "Windows anomaly rows"],
    },
]

NETWORK_SCENARIOS = [
    {
        "id": "port-scan",
        "label": "Port Scan",
        "summary": "Wide destination-port sweep from one source.",
        "process": ["Generate scan-like flows", "feature engineering", "rule + ML scoring"],
        "signals": ["rule_port_scan", "unique dst ports", "recon pattern"],
    },
    {
        "id": "ddos",
        "label": "DDoS-like",
        "summary": "Distributed volume spike to a victim host.",
        "process": ["Generate flood-like flows", "detect rate spikes", "publish network rows"],
        "signals": ["rule_ddos_like", "request burst", "volume anomaly"],
    },
    {
        "id": "blacklist",
        "label": "Blacklist IP",
        "summary": "Known-bad IP communicating with the network.",
        "process": ["Emit blacklisted source traffic", "mark intel hit", "raise high-severity detections"],
        "signals": ["blacklist_ip", "rule severity high", "intel correlation"],
    },
    {
        "id": "dns-tunnel",
        "label": "DNS Tunnel",
        "summary": "High-frequency DNS-like traffic to an external resolver.",
        "process": ["Emit UDP/53 bursts", "aggregate bytes per source", "mark covert pattern"],
        "signals": ["dns_tunnel", "UDP 53 traffic", "bytes_per_src_min"],
    },
    {
        "id": "exfiltration",
        "label": "Exfiltration",
        "summary": "Large outbound transfers to a small target set.",
        "process": ["Generate large 443 transfers", "detect egress concentration", "publish critical anomaly hints"],
        "signals": ["exfiltration", "high bytes_per_src_min", "critical severity"],
    },
    {
        "id": "lateral-movement",
        "label": "Lateral Movement",
        "summary": "East-west activity on admin ports.",
        "process": ["Emit internal 445/3389-style traffic", "aggregate internal dst hosts", "mark lateral movement rule"],
        "signals": ["lateral_movement", "internal host spread", "admin ports"],
    },
    {
        "id": "mixed",
        "label": "Full Network Attack",
        "summary": "Combined recon, covert, and exfiltration flow burst.",
        "process": ["Blend multiple network attack generators", "detect + publish once", "refresh Grafana network panels"],
        "signals": ["multiple rule hits", "high anomaly density", "flow surge"],
    },
]

CATALOG = {
    "web": {"title": "Web", "accent": "web", "default_count": 120, "count_min": 10, "count_max": 500, "scenarios": WEB_SCENARIOS},
    "windows": {"title": "Windows", "accent": "windows", "default_count": 30, "count_min": 5, "count_max": 400, "scenarios": WINDOWS_SCENARIOS},
    "network": {"title": "Network", "accent": "network", "default_count": 1200, "count_min": 100, "count_max": 5000, "scenarios": NETWORK_SCENARIOS},
}

RUNTIME = {
    "last_action": "Idle",
    "last_publish_status": "No publish yet",
    "last_publish_ok": False,
    "last_grafana_hint": "Provide Elasticsearch credentials to publish and then refresh Grafana.",
    "last_pcap_eda": None,
    "last_audit_eda": None,
    "last_evtx_eda": None,
    "last_evidence": None,
    "last_result": None,
}


app = FastAPI(title="Unified SOC Dashboard", version="2.0.0")


class BaseSimulationRequest(BaseModel):
    count: int = 120
    es_user: str = "elastic"
    es_password: str = ""


class WebSimulationRequest(BaseSimulationRequest):
    scenario: str = "mixed-attack"
    source_ip: str = "203.0.113.77"


class WindowsSimulationRequest(BaseSimulationRequest):
    scenario: str = "all"
    max_events: int = 5000


class NetworkSimulationRequest(BaseSimulationRequest):
    scenario: str = "mixed"


def run_cmd(args: list[str], cwd: Path) -> dict:
    result = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, check=False)
    return {
        "ok": result.returncode == 0,
        "code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "command": " ".join(args),
    }


def safe_read_csv(path: Path) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


def safe_read_json_lines(path: Path) -> list[dict]:
    if not path.exists():
        return []

    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clip_text(text: str, limit: int = 170) -> str:
    clean = " ".join(str(text).split())
    return clean if len(clean) <= limit else clean[: limit - 3] + "..."


def update_runtime(result: dict) -> None:
    publish_steps = [step for step in result.get("steps", []) if "publish_" in step.get("command", "")]
    publish_ok = bool(publish_steps) and all(step.get("ok") for step in publish_steps)
    if publish_steps:
        publish_status = "Published to Elasticsearch for Grafana" if publish_ok else "Publish attempted but failed"
        grafana_hint = "Elasticsearch publish completed. Refresh Grafana dashboards and panels." if publish_ok else "Publish step failed. Grafana may not reflect this run."
    else:
        publish_status = "Local run only"
        grafana_hint = "No publish step ran. Grafana stays unchanged until Elasticsearch credentials are supplied."

    RUNTIME["last_action"] = f"{result.get('source', '').upper()} / {result.get('scenario', '')}"
    RUNTIME["last_publish_status"] = publish_status
    RUNTIME["last_publish_ok"] = publish_ok
    RUNTIME["last_grafana_hint"] = grafana_hint
    RUNTIME["last_result"] = result


def service_status(url: str) -> dict:
    try:
        req = request.Request(url, method="GET")
        with request.urlopen(req, timeout=2.5) as response:
            return {"ok": response.status < 400, "status": response.status, "reachable": True, "auth_required": False}
    except HTTPError as exc:
        if exc.code in {401, 403}:
            return {"ok": True, "status": exc.code, "reachable": True, "auth_required": True}
        return {"ok": False, "status": exc.code, "reachable": False, "auth_required": False}
    except URLError as exc:
        return {"ok": False, "status": str(exc.reason), "reachable": False, "auth_required": False}
    except Exception as exc:
        return {"ok": False, "status": str(exc), "reachable": False, "auth_required": False}


def elastic_request(path: str, es_user: str = "", es_password: str = "") -> dict:
    endpoint = f"http://localhost:9200{path}"
    headers = {}
    if es_user and es_password:
        token = base64.b64encode(f"{es_user}:{es_password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    req = request.Request(endpoint, method="GET", headers=headers)
    try:
        with request.urlopen(req, timeout=4) as response:
            body = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(body) if body else {}
            return {"ok": response.status < 400, "status": response.status, "body": parsed, "reachable": True, "auth_required": False}
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        parsed = json.loads(body) if body else {}
        if exc.code in {401, 403}:
            return {"ok": False, "status": exc.code, "body": parsed, "reachable": True, "auth_required": True}
        return {"ok": False, "status": exc.code, "body": parsed, "reachable": False, "auth_required": False}
    except URLError as exc:
        return {"ok": False, "status": str(exc.reason), "body": {}, "reachable": False, "auth_required": False}
    except Exception as exc:
        return {"ok": False, "status": str(exc), "body": {}, "reachable": False, "auth_required": False}


def elastic_index_status(es_user: str = "", es_password: str = "") -> dict:
    patterns = {
        "windows_raw": "winlogbeat-fallback-*",
        "windows_ml": "ml-anomalies-*",
        "web_raw": "webapp-logs-*",
        "web_ml": "web-ml-anomalies-*",
        "network_raw": "network-logs-*",
        "network_ml": "network-ml-anomalies-*",
    }
    check = elastic_request("/", es_user, es_password)
    if not check["reachable"]:
        return {"reachable": False, "auth_required": False, "indices": {}, "status": check["status"]}
    if check["auth_required"]:
        return {"reachable": True, "auth_required": True, "indices": {}, "status": check["status"]}

    indices: dict[str, dict] = {}
    for name, pattern in patterns.items():
        response = elastic_request(f"/{pattern}/_count", es_user, es_password)
        count = int(response.get("body", {}).get("count", 0)) if response["ok"] else 0
        indices[name] = {"pattern": pattern, "count": count, "ok": response["ok"], "status": response["status"]}
    return {"reachable": True, "auth_required": False, "indices": indices, "status": check["status"]}


def platform_health() -> dict:
    elastic = service_status("http://localhost:9200")
    grafana = service_status("http://localhost:3000/api/health")
    return {"elasticsearch": elastic, "grafana": grafana}


def write_web_log(entry: dict) -> None:
    with WEB_LOGS.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True) + "\n")


def emit_web_event(
    *,
    path: str,
    status_code: int,
    event_type: str,
    client_ip: str,
    latency_ms: float,
    method: str = "GET",
    user: str = "demo-user",
    role: str = "user",
    query: str = "",
    user_agent: str = "soc-unified-dashboard",
) -> None:
    write_web_log(
        {
            "timestamp": utc_now(),
            "request_id": str(uuid.uuid4()),
            "method": method,
            "path": path,
            "query": query,
            "status_code": int(status_code),
            "latency_ms": float(latency_ms),
            "client_ip": client_ip,
            "user_agent": user_agent,
            "user": user,
            "role": role,
            "event_type": event_type,
            "source": "webapp",
        }
    )


def generate_web_events(scenario: str, count: int, source_ip: str) -> int:
    if scenario == "failed-logins":
        for _ in range(count):
            emit_web_event(path="/login", method="POST", status_code=401, event_type="auth_failed", user="attacker", role="guest", client_ip=source_ip, latency_ms=random.uniform(4, 35))
    elif scenario == "endpoint-scan":
        targets = ["/.git/config", "/wp-admin", "/phpmyadmin", "/etc/passwd", "/admin.php", "/server-status"]
        for _ in range(count):
            emit_web_event(path=random.choice(targets), status_code=404, event_type="endpoint_scan", user="attacker", role="guest", client_ip=source_ip, latency_ms=random.uniform(8, 95))
    elif scenario == "sql-injection":
        payloads = ["q=' OR 1=1 --", "email=admin' UNION SELECT *", "id=1;DROP TABLE users--"]
        for _ in range(count):
            emit_web_event(path=random.choice(["/search", "/login", "/api/orders"]), method=random.choice(["GET", "POST"]), query=random.choice(payloads), status_code=random.choice([400, 403, 500]), event_type="sqli_probe", user="attacker", role="guest", client_ip=source_ip, latency_ms=random.uniform(25, 280))
    elif scenario == "xss-probe":
        payloads = ["q=<script>alert(1)</script>", "name=<svg/onload=alert(1)>", "comment=%3Cimg%20src=x%20onerror=alert(1)%3E"]
        for _ in range(count):
            emit_web_event(path=random.choice(["/search", "/feedback", "/profile"]), method="GET", query=random.choice(payloads), status_code=random.choice([400, 422]), event_type="xss_probe", user="attacker", role="guest", client_ip=source_ip, latency_ms=random.uniform(18, 160))
    elif scenario == "token-abuse":
        for _ in range(count):
            emit_web_event(path=random.choice(["/api/admin/export", "/api/finance/report", "/api/users/reset"]), method="POST", query="token_scope=read-only", status_code=random.choice([401, 403]), event_type="token_abuse", user="stolen-token", role="service", client_ip=source_ip, latency_ms=random.uniform(14, 90), user_agent="curl/abuse-client")
    elif scenario == "bot-scraping":
        for _ in range(count):
            emit_web_event(path=random.choice(["/catalog", "/search", "/products/7", "/products/18"]), method="GET", status_code=200, event_type="bot_scrape", user="crawler", role="guest", client_ip=source_ip, latency_ms=random.uniform(5, 45), user_agent="masscan-like-scraper/1.0")
    elif scenario == "api-abuse":
        for _ in range(count):
            emit_web_event(path=random.choice(["/api/orders", "/api/search", "/api/inventory"]), method=random.choice(["GET", "POST"]), status_code=random.choice([200, 429]), event_type="api_abuse", user="noisy-client", role="service", client_ip=source_ip, latency_ms=random.uniform(20, 220), user_agent="python-requests/abuse")
    elif scenario == "latency-spike":
        for _ in range(count):
            emit_web_event(path=random.choice(["/products", "/search", "/checkout", "/api/report"]), status_code=200, event_type="web_request", user="normal-user", role="user", client_ip=source_ip, latency_ms=random.uniform(700, 1800))
    else:
        total = 0
        for scenario_id, scenario_count in [("failed-logins", max(8, count // 6)), ("endpoint-scan", max(8, count // 6)), ("sql-injection", max(8, count // 6)), ("xss-probe", max(8, count // 6)), ("token-abuse", max(8, count // 6)), ("bot-scraping", max(10, count // 6))]:
            total += generate_web_events(scenario_id, scenario_count, source_ip)
        return total
    return count


def run_web_pipeline(es_user: str, es_password: str) -> list[dict]:
    steps = [
        run_cmd([sys.executable, str(WEB_ROOT / "scripts" / "web_log_feature_engineering.py"), "--input", str(WEB_LOGS), "--output", str(WEB_FEATURES)], WEB_ROOT),
        run_cmd([sys.executable, str(WEB_ROOT / "scripts" / "web_anomaly_detection.py"), "--input", str(WEB_FEATURES), "--model-output", str(WEB_MODEL), "--results-output", str(WEB_ANOMALIES)], WEB_ROOT),
    ]
    if es_password.strip():
        steps.extend(
            [
                run_cmd([sys.executable, str(WEB_ROOT / "scripts" / "publish_web_logs_to_elasticsearch.py"), "--input", str(WEB_LOGS), "--es-url", "http://localhost:9200", "--username", es_user, "--password", es_password], WEB_ROOT),
                run_cmd([sys.executable, str(WEB_ROOT / "scripts" / "publish_web_anomalies_to_elasticsearch.py"), "--input", str(WEB_ANOMALIES), "--es-url", "http://localhost:9200", "--username", es_user, "--password", es_password, "--use-current-time"], WEB_ROOT),
            ]
        )
    return steps


def simulate_web(payload: WebSimulationRequest) -> dict:
    count = max(1, min(payload.count, 500))
    generated = generate_web_events(payload.scenario, count, payload.source_ip)
    result = {
        "ok": True,
        "source": "web",
        "scenario": payload.scenario,
        "events_generated": generated,
        "steps": run_web_pipeline(payload.es_user, payload.es_password),
        "timestamp": utc_now(),
    }
    result["ok"] = all(step["ok"] for step in result["steps"])
    update_runtime(result)
    return result


def simulate_windows(payload: WindowsSimulationRequest) -> dict:
    count = max(5, min(payload.count, 400))
    steps = [
        run_cmd(
            [
                sys.executable,
                str(WINDOWS_ROOT / "scripts" / "attack_simulation.py"),
                "--scenario",
                payload.scenario,
                "--powershell-iterations",
                str(count),
                "--service-iterations",
                str(max(5, count // 2)),
                "--file-count",
                str(count),
                "--attack-dir",
                str(WINDOWS_ATTACK_DIR),
            ],
            WINDOWS_ROOT,
        ),
        run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "export_sysmon_logs.py"), "--max-events", str(max(500, payload.max_events)), "--output", str(WINDOWS_LOGS)], WINDOWS_ROOT),
    ]
    if all(step["ok"] for step in steps):
        steps.extend(
            [
                run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "feature_engineering.py"), "--input", str(WINDOWS_LOGS), "--output", str(WINDOWS_FEATURES)], WINDOWS_ROOT),
                run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "anomaly_detection.py"), "--input", str(WINDOWS_FEATURES), "--model-output", str(WINDOWS_MODEL), "--results-output", str(WINDOWS_ANOMALIES)], WINDOWS_ROOT),
            ]
        )
    if payload.es_password.strip() and all(step["ok"] for step in steps):
        steps.extend(
            [
                run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "publish_anomalies_to_elasticsearch.py"), "--input", str(WINDOWS_ANOMALIES), "--es-url", "http://localhost:9200", "--username", payload.es_user, "--password", payload.es_password, "--use-current-time"], WINDOWS_ROOT),
                run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "publish_sysmon_csv_to_elasticsearch.py"), "--input", str(WINDOWS_LOGS), "--es-url", "http://localhost:9200", "--username", payload.es_user, "--password", payload.es_password, "--use-current-time", "--max-rows", str(max(500, payload.max_events))], WINDOWS_ROOT),
            ]
        )
    result = {"ok": all(step["ok"] for step in steps), "source": "windows", "scenario": payload.scenario, "events_generated": count, "steps": steps, "timestamp": utc_now()}
    update_runtime(result)
    return result


def run_network_detect_publish(es_user: str, es_password: str) -> list[dict]:
    steps = [
        run_cmd([sys.executable, str(NETWORK_ROOT / "scripts" / "network_feature_engineering.py"), "--input", str(NETWORK_LOGS), "--output", str(NETWORK_FEATURES)], NETWORK_ROOT),
        run_cmd([sys.executable, str(NETWORK_ROOT / "scripts" / "network_anomaly_detection.py"), "--input", str(NETWORK_FEATURES), "--model-output", str(NETWORK_MODEL), "--results-output", str(NETWORK_ANOMALIES)], NETWORK_ROOT),
    ]
    if es_password.strip():
        steps.extend(
            [
                run_cmd([sys.executable, str(NETWORK_ROOT / "scripts" / "publish_network_logs_to_elasticsearch.py"), "--input", str(NETWORK_FEATURES), "--es-url", "http://localhost:9200", "--username", es_user, "--password", es_password, "--use-current-time"], NETWORK_ROOT),
                run_cmd([sys.executable, str(NETWORK_ROOT / "scripts" / "publish_network_anomalies_to_elasticsearch.py"), "--input", str(NETWORK_ANOMALIES), "--es-url", "http://localhost:9200", "--username", es_user, "--password", es_password, "--use-current-time"], NETWORK_ROOT),
            ]
        )
    return steps


def simulate_network(payload: NetworkSimulationRequest) -> dict:
    count = max(100, min(payload.count, 5000))
    steps = [
        run_cmd([sys.executable, str(NETWORK_ROOT / "scripts" / "attack_simulation_network.py"), "--output", str(NETWORK_LOGS), "--attack-type", payload.scenario, "--count", str(count), "--append"], NETWORK_ROOT)
    ]
    if all(step["ok"] for step in steps):
        steps.extend(run_network_detect_publish(payload.es_user, payload.es_password))
    result = {"ok": all(step["ok"] for step in steps), "source": "network", "scenario": payload.scenario, "events_generated": count, "steps": steps, "timestamp": utc_now()}
    update_runtime(result)
    return result


def value_counts_records(frame: pd.DataFrame, column: str, label: str, limit: int = 8) -> list[dict]:
    if frame.empty or column not in frame.columns:
        return []
    series = frame[column].astype(str).replace({"": pd.NA, "nan": pd.NA, "None": pd.NA}).dropna()
    return series.value_counts().head(limit).rename_axis(label).reset_index(name="count").to_dict(orient="records")


def numeric_profile(frame: pd.DataFrame, column: str) -> dict:
    if frame.empty or column not in frame.columns:
        return {"min": 0, "median": 0, "p95": 0, "max": 0}
    series = pd.to_numeric(frame[column], errors="coerce").dropna()
    if series.empty:
        return {"min": 0, "median": 0, "p95": 0, "max": 0}
    return {
        "min": round(float(series.min()), 2),
        "median": round(float(series.median()), 2),
        "p95": round(float(series.quantile(0.95)), 2),
        "max": round(float(series.max()), 2),
    }


def time_bucket_records(frame: pd.DataFrame, column: str, label: str = "bucket", limit: int = 8) -> list[dict]:
    if frame.empty or column not in frame.columns:
        return []
    times = pd.to_datetime(frame[column], errors="coerce", format="mixed").dropna()
    if times.empty:
        return []
    buckets = times.dt.floor("h").astype(str).value_counts().sort_index().tail(limit)
    return buckets.rename_axis(label).reset_index(name="count").to_dict(orient="records")


def build_pcap_eda() -> dict:
    flows = safe_read_csv(NETWORK_LOGS)
    anomalies = safe_read_csv(NETWORK_ANOMALIES)
    if flows.empty:
        return {
            "summary": {"flow_rows": 0, "total_packets": 0, "total_bytes": 0, "anomaly_count": 0},
            "byte_profile": {"min": 0, "median": 0, "p95": 0, "max": 0},
            "protocol_distribution": [],
            "top_source_ips": [],
            "top_destination_ips": [],
            "top_destination_ports": [],
            "top_conversations": [],
            "potential_threats": [],
        }

    total_packets = int(pd.to_numeric(flows.get("packets", 0), errors="coerce").fillna(0).sum())
    total_bytes = float(pd.to_numeric(flows.get("bytes", 0), errors="coerce").fillna(0).sum())
    eda = {
        "summary": {
            "flow_rows": int(len(flows)),
            "total_packets": total_packets,
            "total_bytes": round(total_bytes, 2),
            "anomaly_count": int((anomalies.get("prediction", pd.Series(dtype=str)).astype(str) == "anomaly").sum()) if not anomalies.empty else 0,
        },
        "byte_profile": numeric_profile(flows, "bytes"),
        "protocol_distribution": [],
        "top_source_ips": [],
        "top_destination_ips": [],
        "top_destination_ports": [],
        "top_conversations": [],
        "potential_threats": [],
    }
    if "protocol" in flows.columns:
        eda["protocol_distribution"] = value_counts_records(flows, "protocol", "protocol", 8)
    if "src_ip" in flows.columns:
        eda["top_source_ips"] = value_counts_records(flows, "src_ip", "src_ip", 8)
    if "dst_ip" in flows.columns:
        eda["top_destination_ips"] = value_counts_records(flows, "dst_ip", "dst_ip", 8)
    if "dst_port" in flows.columns:
        eda["top_destination_ports"] = value_counts_records(flows, "dst_port", "dst_port", 8)
    if {"src_ip", "dst_ip"}.issubset(flows.columns):
        pairs = flows.assign(conversation=flows["src_ip"].astype(str) + " -> " + flows["dst_ip"].astype(str))
        eda["top_conversations"] = value_counts_records(pairs, "conversation", "conversation", 8)
    if not anomalies.empty and "rule_name" in anomalies.columns:
        anomaly_rows = anomalies[anomalies.get("prediction", "").astype(str) == "anomaly"] if "prediction" in anomalies.columns else anomalies
        eda["potential_threats"] = value_counts_records(anomaly_rows, "rule_name", "threat", 8)
    return eda


def parse_jsonish(value: str) -> dict:
    try:
        return json.loads(value) if str(value).strip() else {}
    except Exception:
        return {}


def build_audit_insights(frame: pd.DataFrame) -> dict:
    if frame.empty:
        return {
            "summary": {"rows": 0, "unique_users": 0, "unique_ips": 0, "suspicious_hits": 0},
            "top_operations": [],
            "top_users": [],
            "top_ips": [],
            "result_status": [],
            "request_types": [],
            "timeline": [],
            "findings": [],
        }

    data = frame.copy()
    if "CreationDate" in data.columns:
        data["CreationDate"] = pd.to_datetime(data["CreationDate"], errors="coerce", format="mixed")
    data["AuditDataJson"] = data.get("AuditData", "").fillna("").astype(str).map(parse_jsonish)
    data["ClientIPExtract"] = data["AuditDataJson"].map(lambda row: row.get("ClientIP") or row.get("ActorIpAddress") or "")
    data["ResultStatus"] = data["AuditDataJson"].map(lambda row: row.get("ResultStatus") or "")
    data["RequestType"] = data["AuditDataJson"].map(lambda row: "|".join(str(item.get("Value", "")) for item in row.get("ExtendedProperties", []) if item.get("Name") == "RequestType"))
    data["ManagedState"] = data["AuditDataJson"].map(
        lambda row: "|".join(str(item.get("Value", "")) for item in row.get("DeviceProperties", []) if item.get("Name") == "IsCompliantAndManaged")
    )

    findings: list[str] = []
    if (data.get("UserId", pd.Series(dtype=str)).astype(str).str.contains("SYNC_|Sync_|AD-CONNECTOR", case=False, na=False)).sum() >= 10:
        findings.append("High-frequency service or sync-account logins detected.")
    if (data.get("RequestType", pd.Series(dtype=str)).astype(str).str.contains("OAuth2:Token", case=False, na=False)).sum() >= 5:
        findings.append("Repeated OAuth2 token-based sign-ins present in the audit trail.")
    if (data.get("ManagedState", pd.Series(dtype=str)).astype(str).str.contains("False", case=False, na=False)).sum() >= 1:
        findings.append("Access from unmanaged or non-compliant devices appears in the audit log.")
    if (data.get("Operation", pd.Series(dtype=str)).astype(str).str.contains("Policy|Mailbox|Retention|Role|Consent|Application", case=False, na=False)).sum() >= 1:
        findings.append("Administrative or policy-changing operations appear and should be reviewed.")

    return {
        "summary": {
            "rows": int(len(data)),
            "unique_users": int(data.get("UserId", pd.Series(dtype=str)).astype(str).nunique()),
            "unique_ips": int(data.get("ClientIPExtract", pd.Series(dtype=str)).astype(str).replace("", pd.NA).dropna().nunique()),
            "suspicious_hits": len(findings),
        },
        "top_operations": value_counts_records(data, "Operation", "operation", 10),
        "top_users": value_counts_records(data, "UserId", "user", 10),
        "top_ips": value_counts_records(data, "ClientIPExtract", "ip", 10),
        "result_status": value_counts_records(data, "ResultStatus", "status", 8),
        "request_types": value_counts_records(data, "RequestType", "request_type", 8),
        "timeline": time_bucket_records(data, "CreationDate", "bucket", 10),
        "findings": findings,
    }


def export_evtx_to_csv(evtx_path: Path, output_csv: Path, max_events: int = 3000) -> dict:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    ps_script = f"""
$ErrorActionPreference = 'Stop'
$events = Get-WinEvent -Path '{evtx_path.as_posix()}' -MaxEvents {max_events} |
    Select-Object @{{Name='TimeCreated';Expression={{ $_.TimeCreated.ToString('o') }}}},
                  @{{Name='EventID';Expression={{ $_.Id }}}},
                  @{{Name='ProviderName';Expression={{ $_.ProviderName }}}},
                  @{{Name='Message';Expression={{ $_.Message }}}}
$events | Export-Csv -Path '{output_csv.as_posix()}' -NoTypeInformation -Encoding UTF8
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "ok": result.returncode == 0 and output_csv.exists(),
        "code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "command": f"Get-WinEvent -Path {evtx_path.name}",
    }


def build_evtx_insights(frame: pd.DataFrame) -> dict:
    if frame.empty:
        return {
            "summary": {"rows": 0, "unique_event_ids": 0, "suspicious_hits": 0},
            "top_event_ids": [],
            "providers": [],
            "timeline": [],
            "severity_mix": [],
            "findings": [],
        }

    data = frame.copy()
    data["EventID"] = pd.to_numeric(data.get("EventID", 0), errors="coerce").fillna(0).astype(int)
    data["Message"] = data.get("Message", "").fillna("").astype(str)
    findings: list[str] = []
    counts = data["EventID"].value_counts().to_dict()

    if counts.get(4625, 0) >= 5:
        findings.append("Multiple failed logon events (4625) indicate possible credential attacks.")
    if counts.get(4672, 0) >= 1:
        findings.append("Privileged logon events (4672) are present and should be correlated with user activity.")
    if counts.get(1102, 0) >= 1:
        findings.append("Audit log clear event (1102) is highly suspicious.")
    if counts.get(8, 0) >= 1 or counts.get(10, 0) >= 1:
        findings.append("Sysmon remote-thread or process-access events suggest possible injection or tampering behavior.")
    if counts.get(3, 0) >= 10:
        findings.append("High Sysmon network-connect activity detected.")
    if counts.get(11, 0) >= 10:
        findings.append("Frequent Sysmon file creation events detected.")
    if counts.get(22, 0) >= 10:
        findings.append("Heavy DNS query telemetry in Sysmon may indicate beaconing or tunneling.")

    high_value = {4625, 4672, 1102, 8, 10, 22}
    data["AnalystSeverity"] = data["EventID"].map(lambda event_id: "watch" if event_id in high_value else "baseline")

    return {
        "summary": {"rows": int(len(data)), "unique_event_ids": int(data["EventID"].nunique()), "suspicious_hits": len(findings)},
        "top_event_ids": data["EventID"].value_counts().head(12).rename_axis("event_id").reset_index(name="count").to_dict(orient="records"),
        "providers": value_counts_records(data, "ProviderName", "provider", 8),
        "timeline": time_bucket_records(data, "TimeCreated", "bucket", 10),
        "severity_mix": value_counts_records(data, "AnalystSeverity", "severity", 4),
        "findings": findings,
    }


async def upload_pcap_and_analyze(pcap_file: UploadFile, es_user: str, es_password: str) -> dict:
    filename = pcap_file.filename or "capture.pcap"
    suffix = Path(filename).suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        return {"ok": False, "source": "pcap", "scenario": "upload", "error": "Upload must be .pcap or .pcapng", "steps": [], "timestamp": utc_now()}

    stored = NETWORK_UPLOADS / f"upload_{int(datetime.now(timezone.utc).timestamp())}{suffix}"
    with stored.open("wb") as handle:
        shutil.copyfileobj(pcap_file.file, handle)

    steps = [
        run_cmd([sys.executable, str(NETWORK_ROOT / "scripts" / "pcap_to_flows.py"), "--input", str(stored), "--output", str(NETWORK_LOGS), "--limit", "60000"], NETWORK_ROOT)
    ]
    if all(step["ok"] for step in steps):
        steps.extend(run_network_detect_publish(es_user, es_password))

    eda = build_pcap_eda()
    result = {
        "ok": all(step["ok"] for step in steps),
        "source": "pcap",
        "scenario": "upload",
        "steps": steps,
        "eda": eda,
        "timestamp": utc_now(),
    }
    RUNTIME["last_pcap_eda"] = eda
    RUNTIME["last_evidence"] = result
    update_runtime(result)
    return result


async def upload_audit_csv_and_analyze(audit_file: UploadFile) -> dict:
    filename = audit_file.filename or "audit.csv"
    suffix = Path(filename).suffix.lower()
    if suffix not in {".csv", ".log"}:
        return {"ok": False, "source": "audit", "scenario": "upload", "error": "Upload must be a CSV-like audit export.", "steps": [], "timestamp": utc_now()}

    stored = EVIDENCE_UPLOADS / f"audit_{int(datetime.now(timezone.utc).timestamp())}_{Path(filename).name}"
    with stored.open("wb") as handle:
        shutil.copyfileobj(audit_file.file, handle)

    frame = pd.read_csv(stored)
    insights = build_audit_insights(frame)
    result = {
        "ok": True,
        "source": "audit",
        "scenario": "upload",
        "steps": [{"ok": True, "command": f"read {stored.name}", "stdout": f"Loaded {len(frame)} audit rows", "stderr": ""}],
        "insights": insights,
        "timestamp": utc_now(),
    }
    RUNTIME["last_audit_eda"] = insights
    RUNTIME["last_evidence"] = result
    update_runtime(result)
    return result


async def upload_evtx_and_analyze(evtx_file: UploadFile, es_user: str, es_password: str) -> dict:
    filename = evtx_file.filename or "uploaded.evtx"
    if Path(filename).suffix.lower() != ".evtx":
        return {"ok": False, "source": "evtx", "scenario": "upload", "error": "Upload must be an .evtx file.", "steps": [], "timestamp": utc_now()}

    stored = EVIDENCE_UPLOADS / f"evtx_{int(datetime.now(timezone.utc).timestamp())}_{Path(filename).name}"
    with stored.open("wb") as handle:
        shutil.copyfileobj(evtx_file.file, handle)

    export_step = export_evtx_to_csv(stored, WINDOWS_LOGS, max_events=3000)
    steps = [export_step]
    if export_step["ok"]:
        steps.extend(
            [
                run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "feature_engineering.py"), "--input", str(WINDOWS_LOGS), "--output", str(WINDOWS_FEATURES)], WINDOWS_ROOT),
                run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "anomaly_detection.py"), "--input", str(WINDOWS_FEATURES), "--model-output", str(WINDOWS_MODEL), "--results-output", str(WINDOWS_ANOMALIES)], WINDOWS_ROOT),
            ]
        )
        if es_password.strip() and all(step["ok"] for step in steps):
            steps.extend(
                [
                    run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "publish_anomalies_to_elasticsearch.py"), "--input", str(WINDOWS_ANOMALIES), "--es-url", "http://localhost:9200", "--username", es_user, "--password", es_password, "--use-current-time"], WINDOWS_ROOT),
                    run_cmd([sys.executable, str(WINDOWS_ROOT / "scripts" / "publish_sysmon_csv_to_elasticsearch.py"), "--input", str(WINDOWS_LOGS), "--es-url", "http://localhost:9200", "--username", es_user, "--password", es_password, "--use-current-time", "--max-rows", "3000"], WINDOWS_ROOT),
                ]
            )

    frame = safe_read_csv(WINDOWS_LOGS)
    insights = build_evtx_insights(frame)
    result = {
        "ok": all(step["ok"] for step in steps),
        "source": "evtx",
        "scenario": "upload",
        "steps": steps,
        "insights": insights,
        "timestamp": utc_now(),
    }
    RUNTIME["last_evtx_eda"] = insights
    RUNTIME["last_evidence"] = result
    update_runtime(result)
    return result


def windows_incidents(limit: int) -> list[dict]:
    frame = safe_read_csv(WINDOWS_ANOMALIES)
    if frame.empty or "prediction" not in frame.columns:
        return []
    anomalies = frame[frame["prediction"].astype(str) == "anomaly"].tail(limit)
    out = []
    for _, row in anomalies[::-1].iterrows():
        out.append({"timestamp": str(row.get("TimeCreated", "")), "source": "windows", "title": f"Sysmon {row.get('EventID', '')}", "severity": "high" if float(row.get("anomaly_score", 0.0)) < -0.05 else "medium", "summary": f"score={round(float(row.get('anomaly_score', 0.0)), 3)}"})
    return out[:limit]


def web_incidents(limit: int) -> list[dict]:
    frame = safe_read_csv(WEB_ANOMALIES)
    if frame.empty or "prediction" not in frame.columns:
        return []
    anomalies = frame[frame["prediction"].astype(str) == "anomaly"].tail(limit)
    out = []
    for _, row in anomalies[::-1].iterrows():
        out.append({"timestamp": str(row.get("timestamp", "")), "source": "web", "title": f"{row.get('event_type', 'web')} {row.get('path', '/')}", "severity": str(row.get("severity", "low")), "summary": str(row.get("reason_tags", "ml_outlier")).replace("|", ", ")})
    return out[:limit]


def network_incidents(limit: int) -> list[dict]:
    frame = safe_read_csv(NETWORK_ANOMALIES)
    if frame.empty or "prediction" not in frame.columns:
        return []
    anomalies = frame[frame["prediction"].astype(str) == "anomaly"].tail(limit)
    out = []
    for _, row in anomalies[::-1].iterrows():
        out.append({"timestamp": str(row.get("timestamp", "")), "source": "network", "title": f"{row.get('rule_name', 'none')} {row.get('src_ip', '')}", "severity": str(row.get("severity", row.get("rule_severity", "low"))), "summary": f"risk={row.get('risk_score', 0)} -> {row.get('dst_ip', '')}"})
    return out[:limit]


def collect_logs(limit: int) -> list[dict]:
    items: list[dict] = []
    for row in safe_read_json_lines(WEB_LOGS)[-limit:]:
        items.append({"timestamp": str(row.get("timestamp", "")), "source": "web", "summary": f"{row.get('event_type', 'web_request')} {row.get('path', '')} {row.get('status_code', '')}", "details": clip_text(f"ip={row.get('client_ip', '')} query={row.get('query', '')}")})
    win = safe_read_csv(WINDOWS_LOGS)
    if not win.empty:
        for _, row in win.tail(limit).iterrows():
            first_line = str(row.get("Message", "")).splitlines()[0] if str(row.get("Message", "")).splitlines() else ""
            items.append({"timestamp": str(row.get("TimeCreated", "")), "source": "windows", "summary": f"Event {row.get('EventID', '')}", "details": clip_text(first_line)})
    net = safe_read_csv(NETWORK_LOGS)
    if not net.empty:
        for _, row in net.tail(limit).iterrows():
            items.append({"timestamp": str(row.get("timestamp", "")), "source": "network", "summary": f"{row.get('protocol', '')} {row.get('src_ip', '')}:{row.get('src_port', '')}", "details": clip_text(f"dst={row.get('dst_ip', '')}:{row.get('dst_port', '')} bytes={row.get('bytes', '')}")})
    items.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
    return items[:limit]


def source_summary() -> dict:
    def anomaly_count(frame: pd.DataFrame) -> int:
        if frame.empty or "prediction" not in frame.columns:
            return 0
        return int((frame["prediction"].astype(str) == "anomaly").sum())

    web_frame = safe_read_csv(WEB_ANOMALIES)
    win_frame = safe_read_csv(WINDOWS_ANOMALIES)
    net_frame = safe_read_csv(NETWORK_ANOMALIES)
    return {
        "web": {"rows": len(safe_read_json_lines(WEB_LOGS)), "anomalies": anomaly_count(web_frame)},
        "windows": {"rows": len(safe_read_csv(WINDOWS_LOGS)), "anomalies": anomaly_count(win_frame)},
        "network": {"rows": len(safe_read_csv(NETWORK_LOGS)), "anomalies": anomaly_count(net_frame)},
    }


def build_architecture() -> dict:
    return {
        "doc_path": str(ARCHITECTURE_DOC),
        "flows": [
            {"source": "web", "summary": "dashboard -> /api/run/web -> generated web logs -> web feature engineering -> web anomaly detection -> optional Elasticsearch publish -> Grafana", "files": ["app/main.py", "webapp-soc-isolated/scripts/web_log_feature_engineering.py", "webapp-soc-isolated/scripts/web_anomaly_detection.py", "webapp-soc-isolated/scripts/publish_web_logs_to_elasticsearch.py", "webapp-soc-isolated/scripts/publish_web_anomalies_to_elasticsearch.py"]},
            {"source": "windows", "summary": "dashboard -> /api/run/windows -> windows-soc-isolated/scripts/attack_simulation.py -> export Sysmon -> Windows feature engineering -> anomaly detection -> optional Elasticsearch publish -> Grafana", "files": ["app/main.py", "windows-soc-isolated/scripts/attack_simulation.py", "windows-soc-isolated/scripts/export_sysmon_logs.py", "windows-soc-isolated/scripts/feature_engineering.py", "windows-soc-isolated/scripts/anomaly_detection.py", "windows-soc-isolated/scripts/publish_anomalies_to_elasticsearch.py", "windows-soc-isolated/scripts/publish_sysmon_csv_to_elasticsearch.py"]},
            {"source": "network", "summary": "dashboard -> /api/run/network -> attack_simulation_network.py or pcap_to_flows.py -> network feature engineering -> anomaly detection -> optional Elasticsearch publish -> Grafana", "files": ["app/main.py", "network-soc-isolated/scripts/attack_simulation_network.py", "network-soc-isolated/scripts/pcap_to_flows.py", "network-soc-isolated/scripts/network_feature_engineering.py", "network-soc-isolated/scripts/network_anomaly_detection.py", "network-soc-isolated/scripts/publish_network_logs_to_elasticsearch.py", "network-soc-isolated/scripts/publish_network_anomalies_to_elasticsearch.py"]},
        ],
    }


def build_state(limit: int = 24, es_user: str = "", es_password: str = "") -> dict:
    sources = source_summary()
    incidents = sorted(windows_incidents(limit) + web_incidents(limit) + network_incidents(limit), key=lambda item: item.get("timestamp", ""), reverse=True)[:limit]
    health = platform_health()
    elastic_indices = elastic_index_status(es_user, es_password)
    total_logs = sum(group["rows"] for group in sources.values())
    total_anomalies = sum(group["anomalies"] for group in sources.values())
    return {
        "generated_at": utc_now(),
        "summary": {"total_logs": total_logs, "total_anomalies": total_anomalies, "critical_watch": sum(1 for item in incidents if item.get("severity") in {"critical", "high"})},
        "sources": sources,
        "incidents": incidents,
        "logs": collect_logs(limit),
        "health": health,
        "elastic_indices": elastic_indices,
        "runtime": RUNTIME,
        "pcap_eda": RUNTIME.get("last_pcap_eda"),
        "audit_eda": RUNTIME.get("last_audit_eda"),
        "evtx_eda": RUNTIME.get("last_evtx_eda"),
        "evidence": RUNTIME.get("last_evidence"),
    }


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return UI_HTML


@app.get("/eda", response_class=HTMLResponse)
def eda_home() -> str:
    return EDA_HTML


@app.get("/api/catalog")
def api_catalog() -> dict:
    return CATALOG


@app.get("/api/state")
def api_state(limit: int = 24, es_user: str = "", es_password: str = "") -> dict:
    return build_state(max(6, min(limit, 80)), es_user, es_password)


@app.get("/api/architecture")
def api_architecture() -> dict:
    return build_architecture()


@app.post("/api/run/web")
def api_run_web(payload: WebSimulationRequest) -> JSONResponse:
    result = simulate_web(payload)
    return JSONResponse(result, status_code=200 if result["ok"] else 500)


@app.post("/api/run/windows")
def api_run_windows(payload: WindowsSimulationRequest) -> JSONResponse:
    result = simulate_windows(payload)
    return JSONResponse(result, status_code=200 if result["ok"] else 500)


@app.post("/api/run/network")
def api_run_network(payload: NetworkSimulationRequest) -> JSONResponse:
    result = simulate_network(payload)
    return JSONResponse(result, status_code=200 if result["ok"] else 500)


@app.post("/api/upload/pcap")
async def api_upload_pcap(
    pcap_file: UploadFile = File(...),
    es_user: str = Form("elastic"),
    es_password: str = Form(""),
) -> JSONResponse:
    result = await upload_pcap_and_analyze(pcap_file, es_user, es_password)
    return JSONResponse(result, status_code=200 if result["ok"] else 500)


@app.post("/api/upload/audit")
async def api_upload_audit(audit_file: UploadFile = File(...)) -> JSONResponse:
    result = await upload_audit_csv_and_analyze(audit_file)
    return JSONResponse(result, status_code=200 if result["ok"] else 500)


@app.post("/api/upload/evtx")
async def api_upload_evtx(
    evtx_file: UploadFile = File(...),
    es_user: str = Form("elastic"),
    es_password: str = Form(""),
) -> JSONResponse:
    result = await upload_evtx_and_analyze(evtx_file, es_user, es_password)
    return JSONResponse(result, status_code=200 if result["ok"] else 500)


UI_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Unified SOC Dashboard</title>
  <style>
    :root {
      --bg: #0f0f10;
      --panel: #171819;
      --panel-2: #222324;
      --line: #343638;
      --text: #f7f7f8;
      --muted: #b9bec7;
      --accent: #60a5fa;
      --web: #4ade80;
      --windows: #facc15;
      --network: #60a5fa;
      --magenta: #c05ad9;
      --good: #4ade80;
      --bad: #ef3d43;
      --warn: #facc15;
      --shadow: 0 20px 70px rgba(0,0,0,0.52);
    }
    body[data-theme="light"] {
      --bg: #edf2f7;
      --panel: #ffffff;
      --panel-2: #f7fafc;
      --line: #d7e0ea;
      --text: #111827;
      --muted: #526070;
      --shadow: 0 18px 48px rgba(15,23,42,0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: "Segoe UI", "Trebuchet MS", sans-serif;
      background: var(--bg);
      padding: 13px;
    }
    .shell { max-width: 1560px; margin: 0 auto; display: grid; gap: 12px; }
    body::before { content: none; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      box-shadow: var(--shadow);
      backdrop-filter: none;
    }
    .topbar {
      padding: 14px 16px 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
    }
    .eyebrow { margin: 0 0 6px; color: var(--accent); font-size: 11px; text-transform: uppercase; letter-spacing: .22em; font-weight: 800; }
    .brand h1 { margin: 0; font-size: clamp(24px, 3vw, 38px); letter-spacing: -0.055em; line-height: .98; }
    .brand p { margin: 6px 0 0; color: var(--muted); }
    .toolbar { display: flex; gap: 10px; flex-wrap: wrap; }
    .tabbar {
      display: flex;
      gap: 8px;
      padding: 0 16px 12px;
      flex-wrap: wrap;
    }
    .tabbar button {
      width: auto;
      min-width: 132px;
      border-radius: 9px;
      border: 1px solid var(--line);
      padding: 9px 13px;
      background: var(--panel-2);
      color: var(--muted);
      cursor: pointer;
      font-weight: 700;
    }
    .tabbar button.active { color: #050505; background: #f7f7f8; border-color: transparent; }
    button, input, select {
      width: 100%;
      border-radius: 7px;
      border: 1px solid var(--line);
      background: var(--panel-2);
      color: var(--text);
      padding: 9px 11px;
      font-size: 14px;
    }
    button { cursor: pointer; font-weight: 700; transition: transform .14s ease, filter .14s ease; }
    button:hover { transform: translateY(-1px); filter: brightness(1.06); }
    .primary { background: var(--web); color: #050505; border: none; }
    .ghost { background: var(--panel-2); }
    .control-row {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr auto auto auto;
      gap: 8px;
      padding: 0 16px 12px;
      align-items: end;
    }
    .control-row label { display: block; color: var(--muted); font-size: 10px; letter-spacing: .12em; text-transform: uppercase; margin-bottom: 5px; }
    .control-row button { white-space: nowrap; }
    .health-grid, .ops-layout, .analytics-layout, .upload-stack, .source-strip {
      display: grid;
      gap: 10px;
    }
    .health-grid { grid-template-columns: repeat(4, minmax(0,1fr)); padding: 0 16px 12px; }
    .source-strip { grid-template-columns: repeat(3, minmax(0,1fr)); padding: 0 16px 14px; }
    .source-pill {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 9px 11px;
      background: var(--panel-2);
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
    }
    .source-pill strong { font-size: 15px; }
    .source-pill span { color: var(--muted); font-size: 12px; }
    .source-pill.web { border-color: rgba(0,212,166,.55); box-shadow: inset 0 0 26px rgba(0,212,166,.08); }
    .source-pill.windows { border-color: rgba(255,176,32,.55); box-shadow: inset 0 0 26px rgba(255,176,32,.08); }
    .source-pill.network { border-color: rgba(55,168,255,.55); box-shadow: inset 0 0 26px rgba(55,168,255,.08); }
    .health-card, .metric-card, .detail-card, .scenario-card, .pcap-card {
      border: 1px solid var(--line);
      border-radius: 9px;
      background: var(--panel-2);
    }
    .health-card { padding: 9px 11px; }
    .health-card .k { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }
    .health-card .v { margin-top: 4px; font-size: 17px; font-weight: 800; letter-spacing: -.03em; color: var(--accent); }
    .good { color: var(--good); }
    .bad { color: var(--bad); }
    .warn { color: var(--warn); }
    .tab { display: none; }
    .tab.active { display: block; }
    .ops-layout { grid-template-columns: .92fr 1.08fr; align-items: start; }
    .analytics-layout { grid-template-columns: .62fr 1.38fr; }
    .block { padding: 12px; }
    .block header { display: flex; justify-content: space-between; gap: 12px; align-items: start; margin-bottom: 14px; }
    .block h2, .block h3, .block h4, .block p { margin: 0; }
    .sub { color: var(--muted); font-size: 13px; line-height: 1.6; }
    .source-rail { display: grid; gap: 14px; }
    .source-card { padding: 13px 15px; display: grid; gap: 11px; position: relative; overflow: hidden; border-radius: 10px; }
    .source-card::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 4px; background: var(--web); }
    .source-head { display: flex; justify-content: space-between; gap: 12px; align-items: start; }
    .source-head h2 { letter-spacing: -.04em; font-size: 21px; }
    .source-card.web { border-color: rgba(0,212,166,.5); }
    .source-card.windows { border-color: rgba(255,176,32,.5); }
    .source-card.windows::before { background: var(--windows); }
    .source-card.network { border-color: rgba(55,168,255,.5); }
    .source-card.network::before { background: var(--network); }
    .chip { display: inline-flex; padding: 7px 11px; border-radius: 999px; font-size: 11px; text-transform: uppercase; letter-spacing: .12em; border: 1px solid var(--line); color: var(--muted); }
    .field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; max-width: 520px; }
    .scenario-grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; }
    .scenario-card { padding: 15px; display: grid; gap: 8px; position: relative; overflow: hidden; min-height: 150px; align-content: space-between; border-radius: 8px; }
    .scenario-card::after { content: ""; position: absolute; inset: auto -30px -40px auto; width: 86px; height: 86px; border-radius: 999px; opacity: .16; background: currentColor; }
    .scenario-card.web { color: var(--web); }
    .scenario-card.windows { color: var(--windows); }
    .scenario-card.network { color: var(--network); }
    .scenario-card h4, .scenario-card .sub, .scenario-card button { color: var(--text); position: relative; z-index: 1; }
    .scenario-card h4 { font-size: 14px; margin: 0; }
    .scenario-card .sub { font-size: 12px; line-height: 1.35; }
    .scenario-card .mini { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }
    .scenario-card.web button { background: var(--web); color:#050505; border: none; }
    .scenario-card.windows button { background: var(--windows); color:#050505; border: none; }
    .scenario-card.network button { background: var(--network); color:#050505; border: none; }
    .scenario-card:nth-child(2n) button { background: var(--bad); color:#fff; }
    .scenario-card:nth-child(3n) button { background: var(--windows); color:#050505; }
    .scenario-actions { display: grid; grid-template-columns: 1fr auto; gap: 7px; }
    .scenario-card button { padding: 9px 10px; border-radius: 7px; font-size: 12px; text-transform: uppercase; }
    .scenario-card .ghost { width: auto; padding-inline: 12px; }
    .detail-card { padding: 11px; border-radius: 10px; }
    .detail-meta { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 10px; margin-top: 14px; }
    .metric-card { padding: 10px 12px; }
    .metric-card span { display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }
    .metric-card strong { display: block; margin-top: 6px; font-size: 20px; letter-spacing: -.03em; }
    .list { display: grid; gap: 8px; max-height: 280px; overflow: auto; }
    .list-item {
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 10px 12px;
      background: var(--panel-2);
    }
    .list-item strong { display: block; margin-bottom: 5px; }
    .list-item span { display: block; color: var(--muted); font-size: 13px; line-height: 1.5; }
    .sev-critical, .sev-high { border-left: 4px solid var(--bad); }
    .sev-medium { border-left: 4px solid var(--warn); }
    .sev-low { border-left: 4px solid var(--web); }
    .code {
      margin: 0;
      max-height: 260px;
      overflow: auto;
      background: #0d1117;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      color: #d8e7ff;
      font-size: 12px;
      line-height: 1.55;
      white-space: pre-wrap;
    }
    .pcap-form { display: grid; gap: 12px; }
    .upload-stack { grid-template-columns: 1fr; }
    .upload-card {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 13px;
      background: var(--panel-2);
      display: grid;
      gap: 9px;
    }
    .upload-card h4 { margin: 0; }
    .upload-card p { margin: 0; }
    .insight-group { display: grid; gap: 12px; }
    .pcap-grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 8px; margin-top: 12px; }
    .eda-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }
    body[data-theme="light"] .code { background: #f8fafc; color: #182230; }
    .eda-section { border: 1px solid var(--line); border-radius: 9px; padding: 12px; background: var(--panel); margin-top: 12px; }
    .eda-section.web { border-color: rgba(0,212,166,.45); }
    .eda-section.windows { border-color: rgba(255,176,32,.45); }
    .eda-section.network { border-color: rgba(55,168,255,.45); }
    .eda-list { border: 1px solid var(--line); border-radius: 8px; padding: 11px; background: var(--panel-2); }
    .eda-list ul { margin: 10px 0 0; padding-left: 18px; color: var(--muted); }
    .eda-list li {
      list-style: none;
      margin: 8px 0 0 -18px;
      padding: 8px 9px;
      border-radius: 11px;
      background: var(--panel);
      border: 1px solid rgba(255,255,255,.045);
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
    }
    .eda-list li b { color: var(--text); font-weight: 800; }
    .bar {
      height: 5px;
      border-radius: 99px;
      background: linear-gradient(90deg, var(--web), var(--network), var(--magenta));
      margin-top: 6px;
      min-width: 18px;
    }
    .compact-list { margin: 0; padding-left: 18px; color: var(--muted); }
    .compact-list li { margin-top: 8px; }
    .drawer {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,.68);
      padding: 24px;
      z-index: 50;
    }
    .drawer.open { display: block; }
    .drawer-card {
      max-width: 980px;
      max-height: calc(100vh - 48px);
      overflow: auto;
      margin: 0 auto;
      border-radius: 24px;
      border: 1px solid var(--line);
      background: #0b1320;
      padding: 20px;
      box-shadow: var(--shadow);
    }
    .flow {
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 14px;
      background: #0d1625;
      margin-top: 12px;
    }
    .flow ul { margin: 10px 0 0; padding-left: 18px; color: var(--muted); }
    @media (max-width: 1280px) {
      .health-grid, .ops-layout, .analytics-layout, .source-strip, .control-row { grid-template-columns: 1fr; }
      .scenario-grid, .detail-meta, .pcap-grid, .eda-grid, .field-row { grid-template-columns: 1fr; }
    }
    @media (max-width: 760px) {
      body { padding: 12px; }
      .topbar { flex-direction: column; align-items: stretch; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="panel">
      <div class="topbar">
        <div class="brand">
          <p class="eyebrow">Unified Threat Intelligence Lab</p>
          <h1>Unified SOC Dashboard</h1>
          <p id="statusLine">Ready.</p>
        </div>
        <div class="toolbar">
          <button class="ghost" onclick="toggleTheme()">Theme</button>
        </div>
      </div>
      <div class="control-row">
        <div>
          <label>Elastic User</label>
          <input id="elasticUser" value="elastic" />
        </div>
        <div>
          <label>Elastic Password</label>
          <input id="elasticPassword" type="password" placeholder="one global password for publish + checks" />
        </div>
        <div>
          <label>Web Source IP</label>
          <input id="webIp" value="203.0.113.77" />
        </div>
        <button class="ghost" onclick="window.location.href='/eda'">Open EDA</button>
        <button class="ghost" onclick="toggleArchitecture(true)">Architecture</button>
        <button class="ghost" onclick="toggleTheme()">Dark / Light</button>
        <button class="primary" onclick="refreshState()">Refresh</button>
      </div>
      <div class="tabbar">
        <button id="tabBtn-web" class="active" onclick="switchTab('web')">Web Traffic</button>
        <button id="tabBtn-windows" onclick="switchTab('windows')">Windows Events</button>
        <button id="tabBtn-network" onclick="switchTab('network')">Network Traffic</button>
        <button id="tabBtn-analytics" onclick="window.location.href='/eda'">EDA Dashboard</button>
      </div>
      <div class="health-grid">
        <div class="health-card"><div class="k">Last Action</div><div class="v" id="healthAction">Idle</div></div>
        <div class="health-card"><div class="k">Publish Status</div><div class="v" id="healthPublish">Local</div></div>
        <div class="health-card"><div class="k">Elasticsearch</div><div class="v" id="healthElastic">Unknown</div></div>
        <div class="health-card"><div class="k">Grafana</div><div class="v" id="healthGrafana">Unknown</div></div>
      </div>
      <div class="source-strip">
        <div class="source-pill web"><div><strong>Web SOC</strong><br><span id="webRows">0 logs</span></div><strong id="webAnoms">0</strong></div>
        <div class="source-pill windows"><div><strong>Windows SOC</strong><br><span id="windowsRows">0 logs</span></div><strong id="windowsAnoms">0</strong></div>
        <div class="source-pill network"><div><strong>Network SOC</strong><br><span id="networkRows">0 logs</span></div><strong id="networkAnoms">0</strong></div>
      </div>
    </section>

    <section id="tab-web" class="tab active">
      <div class="source-rail" id="sourceRailWeb"></div>
    </section>

    <section id="tab-windows" class="tab">
      <div class="source-rail" id="sourceRailWindows"></div>
    </section>

    <section id="tab-network" class="tab">
      <div class="source-rail" id="sourceRailNetwork"></div>
    </section>

    <section class="ops-layout" style="margin-top:18px;">
        <div class="source-rail">
          <section class="detail-card">
            <header>
              <div>
                <h2 id="detailTitle">Attack Details</h2>
                <p class="sub" id="detailSummary">Choose an attack card to see process and captured signal hints.</p>
              </div>
              <span class="chip" id="detailSource">idle</span>
            </header>
            <div class="detail-meta">
              <div class="metric-card"><span>Process</span><strong id="detailProcessCount">0</strong></div>
              <div class="metric-card"><span>Signals</span><strong id="detailSignalCount">0</strong></div>
              <div class="metric-card"><span>Total Logs</span><strong id="detailTotalLogs">0</strong></div>
            </div>
            <div style="margin-top:14px;">
              <h4>Attack Process</h4>
              <div id="detailProcess" class="list" style="margin-top:10px;"></div>
            </div>
            <div style="margin-top:14px;">
              <h4>Captured Signals</h4>
              <div id="detailSignals" class="list" style="margin-top:10px;"></div>
            </div>
          </section>
          <section class="detail-card">
            <header>
              <div>
                <h2>Incident Board</h2>
                <p class="sub">Latest anomalies across web, Windows, and network.</p>
              </div>
            </header>
            <div id="incidentList" class="list"></div>
          </section>
          <section class="detail-card">
            <header>
              <div>
                <h2>Recent Logs</h2>
                <p class="sub">Latest captured logs across all sources.</p>
              </div>
              <select id="sourceFilter" onchange="renderLogs()">
                <option value="all">All</option>
                <option value="web">Web</option>
                <option value="windows">Windows</option>
                <option value="network">Network</option>
              </select>
            </header>
            <div id="logList" class="list"></div>
          </section>
          <section class="detail-card">
            <header>
              <div>
                <h2>Elastic Data Check</h2>
                <p class="sub">Shows whether Elasticsearch is reachable, requires auth, and whether expected source indices currently contain data.</p>
              </div>
            </header>
            <div id="elasticIndexList" class="list"></div>
          </section>
        </div>
        <section class="panel block">
          <header>
            <div>
              <h2>Execution Output</h2>
              <p class="sub">Latest run trace, publish steps, and any errors returned by the pipeline.</p>
            </div>
          </header>
          <pre id="outputBox" class="code">Ready.</pre>
        </section>
    </section>
      <section class="panel block" style="margin-top:18px;">
        <header><div><h2>Analyst Note</h2><p class="sub">Use the Web, Windows, and Network tabs independently. Every run updates this shared console, incidents, logs, Elasticsearch index check, and Grafana publish state.</p></div></header>
      </section>

    <section id="tab-analytics" class="tab" style="display:none;">
      <div class="analytics-layout">
        <section class="panel block">
          <header>
            <div>
              <h2>Evidence Uploads</h2>
              <p class="sub">Upload audit CSV, Security/Sysmon EVTX, or PCAP evidence and get clear summaries, suspicious findings, and visible execution output.</p>
            </div>
          </header>
          <div class="upload-stack">
            <div class="upload-card">
              <h4>Web/Audit CSV</h4>
              <p class="sub">Upload web CSV exports, Microsoft audit CSV, or files like <code>audit.log - audit.log.csv</code>.</p>
              <input id="auditFile" type="file" accept=".csv,.log" style="margin-top:10px;" />
              <button class="primary" style="margin-top:10px;" onclick="uploadAudit()">Analyze CSV</button>
            </div>
            <div class="upload-card">
              <h4>EVTX Evidence</h4>
              <p class="sub">Upload Security or Sysmon exported EVTX files.</p>
              <input id="evtxFile" type="file" accept=".evtx" style="margin-top:10px;" />
              <button class="primary" style="margin-top:10px;" onclick="uploadEvtx()">Upload EVTX</button>
            </div>
            <div class="upload-card">
              <h4>PCAP Evidence</h4>
              <p class="sub">Upload packet captures for flow conversion and analytics.</p>
              <input id="pcapFile" type="file" accept=".pcap,.pcapng" style="margin-top:10px;" />
              <button class="primary" style="margin-top:10px;" onclick="uploadPcap()">Upload PCAP</button>
            </div>
          </div>
        </section>
        <section class="panel block">
          <header>
            <div>
              <h2>Evidence Insights</h2>
              <p class="sub">Most recent evidence findings and execution trace are kept visible here while you work.</p>
            </div>
          </header>
          <div class="insight-group">
            <div class="eda-section web">
              <h3>Web / CSV EDA</h3>
              <p class="sub">Rows, users, IPs, operations, result statuses, request types, and timeline from the latest CSV upload.</p>
              <div class="pcap-grid">
                <div class="metric-card"><span>Rows</span><strong id="auditRows">0</strong></div>
                <div class="metric-card"><span>Users</span><strong id="auditUsers">0</strong></div>
                <div class="metric-card"><span>IPs</span><strong id="auditIps">0</strong></div>
                <div class="metric-card"><span>Findings</span><strong id="auditSuspicious">0</strong></div>
              </div>
              <div class="eda-grid">
                <div class="eda-list"><h4>Top Operations</h4><ul id="auditOps"></ul></div>
                <div class="eda-list"><h4>Top Users</h4><ul id="auditUsersList"></ul></div>
                <div class="eda-list"><h4>Top IPs</h4><ul id="auditIpList"></ul></div>
                <div class="eda-list"><h4>Result Status</h4><ul id="auditStatus"></ul></div>
                <div class="eda-list"><h4>Request Types</h4><ul id="auditRequestTypes"></ul></div>
                <div class="eda-list"><h4>Hourly Timeline</h4><ul id="auditTimeline"></ul></div>
              </div>
            </div>
            <div class="eda-section windows">
              <h3>Windows / EVTX EDA</h3>
              <p class="sub">Event ID distribution, providers, severity watch mix, and hourly timeline from Security/Sysmon EVTX.</p>
              <div class="pcap-grid">
                <div class="metric-card"><span>Events</span><strong id="evtxRows">0</strong></div>
                <div class="metric-card"><span>Event IDs</span><strong id="evtxIds">0</strong></div>
                <div class="metric-card"><span>Findings</span><strong id="evtxSuspicious">0</strong></div>
                <div class="metric-card"><span>ML Rows</span><strong id="evtxMlRows">0</strong></div>
              </div>
              <div class="eda-grid">
                <div class="eda-list"><h4>Top Event IDs</h4><ul id="evtxTopIds"></ul></div>
                <div class="eda-list"><h4>Providers</h4><ul id="evtxProviders"></ul></div>
                <div class="eda-list"><h4>Severity Mix</h4><ul id="evtxSeverity"></ul></div>
                <div class="eda-list"><h4>Hourly Timeline</h4><ul id="evtxTimeline"></ul></div>
              </div>
            </div>
            <div class="eda-section network">
              <h3>Network / PCAP EDA</h3>
              <p class="sub">Flow conversion, traffic volume, protocol mix, conversations, destination ports, and rule/ML threat indications.</p>
              <div class="pcap-grid">
                <div class="metric-card"><span>Flow Rows</span><strong id="pcapFlows">0</strong></div>
                <div class="metric-card"><span>Packets</span><strong id="pcapPackets">0</strong></div>
                <div class="metric-card"><span>Bytes</span><strong id="pcapBytes">0</strong></div>
                <div class="metric-card"><span>Anomalies</span><strong id="pcapAnomalies">0</strong></div>
              </div>
              <div class="eda-grid">
                <div class="eda-list"><h4>Top Source IPs</h4><ul id="pcapTopSrc"></ul></div>
                <div class="eda-list"><h4>Top Destination IPs</h4><ul id="pcapTopDstIp"></ul></div>
                <div class="eda-list"><h4>Top Destination Ports</h4><ul id="pcapTopDst"></ul></div>
                <div class="eda-list"><h4>Protocol Distribution</h4><ul id="pcapProto"></ul></div>
                <div class="eda-list"><h4>Top Conversations</h4><ul id="pcapConversations"></ul></div>
                <div class="eda-list"><h4>Byte Profile</h4><ul id="pcapByteProfile"></ul></div>
                <div class="eda-list"><h4>Potential Threats</h4><ul id="pcapThreats"></ul></div>
              </div>
            </div>
            <div class="eda-section">
              <h3>Evidence Findings</h3>
              <ul id="evidenceFindings" class="compact-list"></ul>
            </div>
            <pre id="evidenceOutput" class="code">No evidence processed yet.</pre>
          </div>
        </section>
      </div>
    </section>
  </div>

  <div id="architectureDrawer" class="drawer" onclick="toggleArchitecture(false)">
    <div class="drawer-card" onclick="event.stopPropagation()">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
        <div>
          <h2>System Architecture</h2>
          <p class="sub">Root-level architecture file and source-by-source execution paths.</p>
        </div>
        <button class="ghost" style="width:auto;" onclick="toggleArchitecture(false)">Close</button>
      </div>
      <div id="architectureBody"></div>
    </div>
  </div>

  <script>
    let catalog = null;
    let architecture = null;
    let cachedState = null;

    function toggleTheme() {
      const current = document.body.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      document.body.setAttribute('data-theme', next);
      localStorage.setItem('socTheme', next);
    }

    function switchTab(name) {
      document.getElementById('tab-web').classList.toggle('active', name === 'web');
      document.getElementById('tab-windows').classList.toggle('active', name === 'windows');
      document.getElementById('tab-network').classList.toggle('active', name === 'network');
      const analyticsTab = document.getElementById('tab-analytics');
      if (analyticsTab) analyticsTab.classList.toggle('active', name === 'analytics');
      document.getElementById('tabBtn-web').classList.toggle('active', name === 'web');
      document.getElementById('tabBtn-windows').classList.toggle('active', name === 'windows');
      document.getElementById('tabBtn-network').classList.toggle('active', name === 'network');
      const analyticsBtn = document.getElementById('tabBtn-analytics');
      if (analyticsBtn) analyticsBtn.classList.toggle('active', name === 'analytics');
    }

    function creds() {
      return {
        es_user: document.getElementById('elasticUser').value || 'elastic',
        es_password: document.getElementById('elasticPassword').value || ''
      };
    }

    function setStatus(text) {
      document.getElementById('statusLine').textContent = text;
    }

    function showOutput(id, payload) {
      document.getElementById(id).textContent = JSON.stringify(payload, null, 2);
    }

    function renderList(id, rows, keyA, keyB) {
      const host = document.getElementById(id);
      if (!host) return;
      host.innerHTML = '';
      if (!rows || !rows.length) {
        host.innerHTML = '<li>No data yet</li>';
        return;
      }
      const maxValue = Math.max(...rows.map((row) => Number(row[keyB]) || 0), 1);
      rows.forEach((row) => {
        const li = document.createElement('li');
        const value = Number(row[keyB]) || 0;
        const width = Math.max(8, Math.round((value / maxValue) * 100));
        li.innerHTML = '<span><b>' + (row[keyA] || 'unknown') + '</b><div class="bar" style="width:' + width + '%"></div></span><b>' + (row[keyB] ?? 0) + '</b>';
        host.appendChild(li);
      });
    }

    function setMetric(id, value) {
      const node = document.getElementById(id);
      if (node) node.textContent = value || 0;
    }

    function renderProfile(id, profile) {
      const rows = Object.entries(profile || {}).map(([metric, value]) => ({ metric, value }));
      renderList(id, rows, 'metric', 'value');
    }

    function renderPcap(eda) {
      const summary = (eda && eda.summary) || {};
      setMetric('pcapFlows', summary.flow_rows || 0);
      setMetric('pcapPackets', summary.total_packets || 0);
      setMetric('pcapBytes', summary.total_bytes || 0);
      setMetric('pcapAnomalies', summary.anomaly_count || 0);
      renderList('pcapTopSrc', eda ? eda.top_source_ips || [] : [], 'src_ip', 'count');
      renderList('pcapTopDstIp', eda ? eda.top_destination_ips || [] : [], 'dst_ip', 'count');
      renderList('pcapTopDst', eda ? eda.top_destination_ports || [] : [], 'dst_port', 'count');
      renderList('pcapProto', eda ? eda.protocol_distribution || [] : [], 'protocol', 'count');
      renderList('pcapConversations', eda ? eda.top_conversations || [] : [], 'conversation', 'count');
      renderProfile('pcapByteProfile', eda ? eda.byte_profile || {} : {});
      renderList('pcapThreats', eda ? eda.potential_threats || [] : [], 'threat', 'count');
    }

    function renderAudit(eda) {
      const summary = (eda && eda.summary) || {};
      setMetric('auditRows', summary.rows || 0);
      setMetric('auditUsers', summary.unique_users || 0);
      setMetric('auditIps', summary.unique_ips || 0);
      setMetric('auditSuspicious', summary.suspicious_hits || 0);
      renderList('auditOps', eda ? eda.top_operations || [] : [], 'operation', 'count');
      renderList('auditUsersList', eda ? eda.top_users || [] : [], 'user', 'count');
      renderList('auditIpList', eda ? eda.top_ips || [] : [], 'ip', 'count');
      renderList('auditStatus', eda ? eda.result_status || [] : [], 'status', 'count');
      renderList('auditRequestTypes', eda ? eda.request_types || [] : [], 'request_type', 'count');
      renderList('auditTimeline', eda ? eda.timeline || [] : [], 'bucket', 'count');
    }

    function renderEvtx(eda) {
      const summary = (eda && eda.summary) || {};
      setMetric('evtxRows', summary.rows || 0);
      setMetric('evtxIds', summary.unique_event_ids || 0);
      setMetric('evtxSuspicious', summary.suspicious_hits || 0);
      setMetric('evtxMlRows', cachedState && cachedState.sources ? cachedState.sources.windows.rows : 0);
      renderList('evtxTopIds', eda ? eda.top_event_ids || [] : [], 'event_id', 'count');
      renderList('evtxProviders', eda ? eda.providers || [] : [], 'provider', 'count');
      renderList('evtxSeverity', eda ? eda.severity_mix || [] : [], 'severity', 'count');
      renderList('evtxTimeline', eda ? eda.timeline || [] : [], 'bucket', 'count');
    }

    function renderEvidence(evidence) {
      const host = document.getElementById('evidenceFindings');
      if (!host) return;
      host.innerHTML = '';
      const findings = evidence && evidence.insights ? evidence.insights.findings || [] : [];
      if (!findings.length) {
        host.innerHTML = '<li>No evidence findings yet.</li>';
      } else {
        findings.forEach((finding) => {
          const li = document.createElement('li');
          li.textContent = finding;
          host.appendChild(li);
        });
      }
    }

    function renderElasticIndices(state) {
      const host = document.getElementById('elasticIndexList');
      host.innerHTML = '';
      const status = state.elastic_indices || {};
      if (!status.reachable) {
        host.innerHTML = '<div class="list-item"><strong>Elasticsearch unreachable</strong><span>Dashboard could not contact localhost:9200.</span></div>';
        return;
      }
      if (status.auth_required) {
        host.innerHTML = '<div class="list-item"><strong>Elasticsearch reachable, authentication required</strong><span>Provide the Elastic username and password in the dashboard to inspect source indices and stop the false "not reachable" impression.</span></div>';
        return;
      }
      const indices = status.indices || {};
      Object.entries(indices).forEach(([name, info]) => {
        const row = document.createElement('div');
        row.className = 'list-item';
        row.innerHTML = '<strong>' + name + '</strong><span>pattern=' + info.pattern + '</span><span>documents=' + info.count + ' | status=' + info.status + '</span>';
        host.appendChild(row);
      });
    }

    function renderHealth(state) {
      const runtime = state.runtime || {};
      const health = state.health || {};
      document.getElementById('healthAction').textContent = runtime.last_action || 'Idle';
      document.getElementById('healthPublish').textContent = runtime.last_publish_status || 'Local';
      const elasticInfo = health.elasticsearch || {};
      const grafanaInfo = health.grafana || {};
      const elasticOk = !!elasticInfo.reachable;
      const grafanaOk = health.grafana && health.grafana.ok;
      const elasticEl = document.getElementById('healthElastic');
      const grafanaEl = document.getElementById('healthGrafana');
      elasticEl.textContent = elasticInfo.auth_required ? 'Reachable / Auth' : (elasticOk ? 'Reachable' : 'Not Reachable');
      elasticEl.className = 'v ' + (elasticOk ? 'good' : 'bad');
      grafanaEl.textContent = grafanaOk ? 'Reachable' : 'Not Reachable';
      grafanaEl.className = 'v ' + (grafanaOk ? 'good' : 'warn');
      setStatus((runtime.last_grafana_hint || 'Ready.') + ' Elasticsearch=' + (elasticOk ? 'reachable' : 'down') + ', Grafana=' + (grafanaInfo.ok ? 'up' : 'down'));
    }

    function renderSourceOverview(state) {
      const sources = state.sources || {};
      ['web', 'windows', 'network'].forEach((source) => {
        const info = sources[source] || {};
        const rowNode = document.getElementById(source + 'Rows');
        const anomNode = document.getElementById(source + 'Anoms');
        if (rowNode) rowNode.textContent = (info.rows || 0) + ' logs';
        if (anomNode) anomNode.textContent = (info.anomalies || 0) + ' anomalies';
      });
    }

    function selectScenario(source, scenarioId) {
      const sourceMeta = catalog[source];
      const scenario = sourceMeta.scenarios.find((item) => item.id === scenarioId);
      if (!scenario) return;
      document.getElementById('detailTitle').textContent = scenario.label;
      document.getElementById('detailSummary').textContent = scenario.summary;
      document.getElementById('detailSource').textContent = source.toUpperCase();
      document.getElementById('detailProcessCount').textContent = scenario.process.length;
      document.getElementById('detailSignalCount').textContent = scenario.signals.length;
      document.getElementById('detailTotalLogs').textContent = cachedState ? cachedState.summary.total_logs : 0;

      const processHost = document.getElementById('detailProcess');
      processHost.innerHTML = '';
      scenario.process.forEach((step) => {
        const row = document.createElement('div');
        row.className = 'list-item';
        row.innerHTML = '<strong>Process Step</strong><span>' + step + '</span>';
        processHost.appendChild(row);
      });

      const signalsHost = document.getElementById('detailSignals');
      signalsHost.innerHTML = '';
      scenario.signals.forEach((signal) => {
        const row = document.createElement('div');
        row.className = 'list-item';
        row.innerHTML = '<strong>Captured Signal</strong><span>' + signal + '</span>';
        signalsHost.appendChild(row);
      });

      showOutput('outputBox', {
        mode: 'explain',
        source,
        attack: scenario.label,
        description: scenario.summary,
        what_happens: scenario.process,
        logs_captured: scenario.signals,
        grafana_effect: 'If a global Elasticsearch password is provided, running this attack publishes raw and anomaly records to the matching Grafana index patterns.',
        next_step: 'Press Run on this card to execute the simulation and watch this output panel for each pipeline step.'
      });
    }

    function renderSourceCard(source, hostId) {
      const host = document.getElementById(hostId);
      host.innerHTML = '';
      const meta = catalog[source];
        const section = document.createElement('section');
        section.className = 'panel source-card ' + source;
        const countInput = source + 'Count';
        const extraField = source === 'windows'
          ? '<div><label>Max Sysmon Events</label><input id="windowsMaxEvents" type="number" value="5000" min="500" step="500" /></div>'
          : '<div><label>Grafana Publish</label><input value="Uses global Elastic password" disabled /></div>';
        section.innerHTML =
          '<div class="source-head">' +
            '<div><h2>' + meta.title + '</h2><p class="sub">Open the attack cards below, inspect the process, then run the selected scenario.</p></div>' +
            '<span class="chip">' + meta.scenarios.length + ' attacks</span>' +
          '</div>' +
          '<div class="field-row">' +
            '<div><label>Count</label><input id="' + countInput + '" type="number" value="' + meta.default_count + '" min="' + meta.count_min + '" max="' + meta.count_max + '" /></div>' +
            extraField +
          '</div>' +
          '<div class="scenario-grid">' +
            meta.scenarios.map((item) =>
              '<article class="scenario-card ' + source + '">' +
                '<div class="mini">' + source + '</div>' +
                '<h4>' + item.label + '</h4>' +
                '<p class="sub">' + item.summary + '</p>' +
                '<div class="scenario-actions">' +
                  '<button onclick="runScenario(\\'' + source + '\\', \\''
                    + item.id + '\\')">Run</button>' +
                  '<button class="ghost" onclick="selectScenario(\\'' + source + '\\', \\''
                    + item.id + '\\')">Explain</button>' +
                '</div>' +
              '</article>'
            ).join('') +
          '</div>';
        host.appendChild(section);
    }

    function renderSourceCards() {
      renderSourceCard('web', 'sourceRailWeb');
      renderSourceCard('windows', 'sourceRailWindows');
      renderSourceCard('network', 'sourceRailNetwork');
      selectScenario('web', catalog.web.scenarios[0].id);
    }

    function severityClass(sev) {
      const value = String(sev || 'low').toLowerCase();
      if (value === 'critical') return 'sev-critical';
      if (value === 'high') return 'sev-high';
      if (value === 'medium') return 'sev-medium';
      return 'sev-low';
    }

    function renderIncidents(items) {
      const host = document.getElementById('incidentList');
      host.innerHTML = '';
      if (!items.length) {
        host.innerHTML = '<div class="list-item sev-low"><strong>No incidents yet</strong><span>Run an attack card to populate detections.</span></div>';
        return;
      }
      items.forEach((item) => {
        const row = document.createElement('div');
        row.className = 'list-item ' + severityClass(item.severity);
        row.innerHTML = '<strong>' + item.source.toUpperCase() + ' | ' + item.title + '</strong><span>' + item.summary + '</span><span>' + item.timestamp + ' | severity=' + item.severity + '</span>';
        host.appendChild(row);
      });
    }

    function renderLogs() {
      const host = document.getElementById('logList');
      host.innerHTML = '';
      if (!cachedState) return;
      const filter = document.getElementById('sourceFilter').value;
      const rows = (cachedState.logs || []).filter((row) => filter === 'all' || row.source === filter);
      if (!rows.length) {
        host.innerHTML = '<div class="list-item"><strong>No logs</strong><span>Nothing matches the selected source.</span></div>';
        return;
      }
      rows.forEach((row) => {
        const item = document.createElement('div');
        item.className = 'list-item';
        item.innerHTML = '<strong>' + row.source.toUpperCase() + ' | ' + row.summary + '</strong><span>' + row.details + '</span><span>' + row.timestamp + '</span>';
        host.appendChild(item);
      });
    }

    function renderArchitecture() {
      const host = document.getElementById('architectureBody');
      host.innerHTML = '';
      if (!architecture) return;
      const intro = document.createElement('div');
      intro.className = 'flow';
      intro.innerHTML = '<strong>Root Architecture File</strong><p class="sub">See <code>' + architecture.doc_path + '</code> in the repository root for the full system diagram and file ownership.</p>';
      host.appendChild(intro);
      architecture.flows.forEach((flow) => {
        const block = document.createElement('div');
        block.className = 'flow';
        block.innerHTML = '<strong>' + flow.source.toUpperCase() + '</strong><p class="sub" style="margin-top:6px;">' + flow.summary + '</p><ul>' + flow.files.map((file) => '<li>' + file + '</li>').join('') + '</ul>';
        host.appendChild(block);
      });
    }

    function toggleArchitecture(open) {
      const drawer = document.getElementById('architectureDrawer');
      drawer.classList.toggle('open', open);
      if (open) renderArchitecture();
    }

    async function refreshState() {
      const auth = creds();
      const query = new URLSearchParams({ limit: '24' });
      if (auth.es_user) query.set('es_user', auth.es_user);
      if (auth.es_password) query.set('es_password', auth.es_password);
      const resp = await fetch('/api/state?' + query.toString());
      cachedState = await resp.json();
      renderHealth(cachedState);
      renderSourceOverview(cachedState);
      renderIncidents(cachedState.incidents || []);
      renderLogs();
      renderPcap(cachedState.pcap_eda || null);
      renderAudit(cachedState.audit_eda || null);
      renderEvtx(cachedState.evtx_eda || null);
      renderEvidence(cachedState.evidence || null);
      renderElasticIndices(cachedState);
    }

    async function runScenario(source, scenario) {
      selectScenario(source, scenario);
      const auth = creds();
      const payload = {
        scenario,
        count: Number(document.getElementById(source + 'Count').value || catalog[source].default_count),
        es_user: auth.es_user,
        es_password: auth.es_password
      };
      if (source === 'web') payload.source_ip = document.getElementById('webIp').value || '203.0.113.77';
      if (source === 'windows') payload.max_events = Number(document.getElementById('windowsMaxEvents').value || 5000);

      setStatus('Running ' + source + ' / ' + scenario + '...');
      try {
        const resp = await fetch('/api/run/' + source, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await resp.json();
        showOutput('outputBox', data);
        await refreshState();
      } catch (err) {
        showOutput('outputBox', { ok: false, source, scenario, error: String(err) });
        setStatus('Run failed for ' + source + ' / ' + scenario);
      }
    }

    async function uploadPcap() {
      const file = document.getElementById('pcapFile').files[0];
      if (!file) {
        showOutput('evidenceOutput', { ok: false, error: 'Select a PCAP first.' });
        return;
      }
      setStatus('Uploading PCAP and running analytics...');
      const form = new FormData();
      const auth = creds();
      form.append('pcap_file', file);
      form.append('es_user', auth.es_user);
      form.append('es_password', auth.es_password);
      try {
        const resp = await fetch('/api/upload/pcap', { method: 'POST', body: form });
        const data = await resp.json();
        showOutput('evidenceOutput', data);
        renderPcap(data.eda || null);
        renderAudit(cachedState ? cachedState.audit_eda : null);
        renderEvtx(cachedState ? cachedState.evtx_eda : null);
        renderEvidence(data);
        await refreshState();
        switchTab('analytics');
      } catch (err) {
        showOutput('evidenceOutput', { ok: false, error: String(err) });
        setStatus('PCAP upload failed');
      }
    }

    async function uploadAudit() {
      const file = document.getElementById('auditFile').files[0];
      if (!file) {
        showOutput('evidenceOutput', { ok: false, error: 'Select an audit CSV first.' });
        return;
      }
      setStatus('Uploading audit CSV and generating insights...');
      const form = new FormData();
      form.append('audit_file', file);
      try {
        const resp = await fetch('/api/upload/audit', { method: 'POST', body: form });
        const data = await resp.json();
        showOutput('evidenceOutput', data);
        renderAudit(data.insights || null);
        renderEvidence(data);
        await refreshState();
        switchTab('analytics');
      } catch (err) {
        showOutput('evidenceOutput', { ok: false, error: String(err) });
        setStatus('Audit CSV upload failed');
      }
    }

    async function uploadEvtx() {
      const file = document.getElementById('evtxFile').files[0];
      if (!file) {
        showOutput('evidenceOutput', { ok: false, error: 'Select an EVTX file first.' });
        return;
      }
      setStatus('Uploading EVTX and converting it into analyzable Windows events...');
      const form = new FormData();
      const auth = creds();
      form.append('evtx_file', file);
      form.append('es_user', auth.es_user);
      form.append('es_password', auth.es_password);
      try {
        const resp = await fetch('/api/upload/evtx', { method: 'POST', body: form });
        const data = await resp.json();
        showOutput('evidenceOutput', data);
        showOutput('outputBox', data);
        renderEvtx(data.insights || null);
        renderEvidence(data);
        await refreshState();
        switchTab('analytics');
      } catch (err) {
        showOutput('evidenceOutput', { ok: false, error: String(err) });
        setStatus('EVTX upload failed');
      }
    }

    async function boot() {
      document.body.setAttribute('data-theme', localStorage.getItem('socTheme') || 'dark');
      const [catalogResp, architectureResp] = await Promise.all([
        fetch('/api/catalog'),
        fetch('/api/architecture')
      ]);
      catalog = await catalogResp.json();
      architecture = await architectureResp.json();
      renderSourceCards();
      await refreshState();
    }

    boot();
    setInterval(refreshState, 15000);
  </script>
</body>
</html>
"""


EDA_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SOC EDA Workbench</title>
  <style>
    :root {
      --bg:#0f0f10; --panel:#171819; --card:#222324; --line:#343638;
      --text:#f7f7f8; --muted:#b9bec7; --blue:#60a5fa; --green:#4ade80;
      --yellow:#facc15; --red:#ef3d43; --purple:#c05ad9;
      --shadow:0 20px 70px rgba(0,0,0,.52);
    }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family:"Segoe UI", "Trebuchet MS", sans-serif; padding:14px; }
    .shell { max-width:1560px; margin:0 auto; display:grid; gap:14px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:10px; box-shadow:var(--shadow); }
    .hero { padding:18px 20px; display:flex; justify-content:space-between; gap:16px; align-items:flex-start; }
    h1,h2,h3,h4,p { margin:0; }
    h1 { font-size:38px; letter-spacing:-.055em; }
    .sub { color:var(--muted); line-height:1.55; font-size:13px; }
    .accent { color:var(--blue); font-weight:800; letter-spacing:.16em; text-transform:uppercase; font-size:11px; margin-bottom:6px; }
    button,input { border:1px solid var(--line); border-radius:7px; background:var(--card); color:var(--text); padding:10px 12px; font-size:14px; width:100%; }
    button { cursor:pointer; font-weight:800; text-transform:uppercase; }
    .green { background:var(--green); color:#050505; border:none; }
    .yellow { background:var(--yellow); color:#050505; border:none; }
    .blue { background:var(--blue); color:#050505; border:none; }
    .red { background:var(--red); color:#fff; border:none; }
    .ghost { background:var(--card); }
    .grid { display:grid; gap:14px; }
    .layout { grid-template-columns:.72fr 1.28fr; align-items:start; }
    .uploads { display:grid; gap:12px; padding:14px; }
    .upload-card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:14px; display:grid; gap:10px; }
    .mini-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; }
    .metric { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px; }
    .metric span { color:var(--muted); font-size:11px; letter-spacing:.13em; text-transform:uppercase; }
    .metric strong { display:block; color:var(--blue); font-size:24px; margin-top:5px; }
    .section { padding:14px; }
    .section + .section { border-top:1px solid var(--line); }
    .plot-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; margin-top:12px; }
    .plot { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px; min-height:245px; }
    canvas { width:100%; height:180px; display:block; margin-top:10px; }
    ul { margin:10px 0 0; padding:0; display:grid; gap:8px; }
    li { list-style:none; background:var(--card); border:1px solid var(--line); border-radius:8px; padding:9px 10px; color:var(--muted); display:flex; justify-content:space-between; gap:10px; }
    li b { color:var(--text); }
    .code { max-height:220px; overflow:auto; background:#0d1117; border:1px solid var(--line); border-radius:8px; padding:12px; color:#7CFF9B; white-space:pre-wrap; font-size:12px; }
    .top-actions { display:flex; gap:10px; flex-wrap:wrap; }
    .top-actions button { width:auto; }
    @media (max-width:1100px){ .layout,.plot-grid,.mini-grid{ grid-template-columns:1fr; } .hero{ flex-direction:column; } }
  </style>
</head>
<body>
  <main class="shell">
    <section class="panel hero">
      <div>
        <p class="accent">Streamlit-style forensic EDA</p>
        <h1>SOC Evidence Workbench</h1>
        <p class="sub">Upload CSV, EVTX, and PCAP evidence. The page builds clear summaries, plots, timelines, top entities, and possible threat findings.</p>
      </div>
      <div class="top-actions">
        <button class="ghost" onclick="window.location.href='/'">Back to SOC</button>
        <button class="blue" onclick="refreshState()">Refresh</button>
      </div>
    </section>

    <section class="grid layout">
      <aside class="panel uploads">
        <h2>Evidence Uploads</h2>
        <p class="sub">Use one source at a time or upload all three for cross-source analysis.</p>
        <div>
          <label class="sub">Elastic User</label>
          <input id="elasticUser" value="elastic" />
        </div>
        <div>
          <label class="sub">Elastic Password</label>
          <input id="elasticPassword" type="password" placeholder="optional, needed to publish to Grafana" />
        </div>
        <article class="upload-card">
          <h3>Web / Audit CSV</h3>
          <p class="sub">Operations, users, IPs, request types, result status, and suspicious cloud/web activity.</p>
          <input id="auditFile" type="file" accept=".csv,.log" />
          <button class="green" onclick="uploadAudit()">Analyze CSV</button>
        </article>
        <article class="upload-card">
          <h3>Windows EVTX</h3>
          <p class="sub">Security/Sysmon Event IDs, providers, severity mix, ML scoring, and suspicious host indicators.</p>
          <input id="evtxFile" type="file" accept=".evtx" />
          <button class="yellow" onclick="uploadEvtx()">Analyze EVTX</button>
        </article>
        <article class="upload-card">
          <h3>Network PCAP</h3>
          <p class="sub">Flow conversion, bytes, packets, ports, protocols, conversations, and threat rules.</p>
          <input id="pcapFile" type="file" accept=".pcap,.pcapng" />
          <button class="red" onclick="uploadPcap()">Analyze PCAP</button>
        </article>
        <pre id="rawOutput" class="code">Waiting for evidence...</pre>
      </aside>

      <section class="panel">
        <div class="section">
          <h2>Executive Summary</h2>
          <p class="sub">High-level counts from the latest uploads and generated analytics.</p>
          <div class="mini-grid">
            <div class="metric"><span>CSV Rows</span><strong id="auditRows">0</strong></div>
            <div class="metric"><span>EVTX Events</span><strong id="evtxRows">0</strong></div>
            <div class="metric"><span>PCAP Flows</span><strong id="pcapFlows">0</strong></div>
            <div class="metric"><span>Threat Hints</span><strong id="findingCount">0</strong></div>
          </div>
        </div>

        <div class="section">
          <h2>Web / CSV Log Analysis</h2>
          <p class="sub">Good for audit logs, web exports, SaaS/cloud activity, authentication activity, and administrative operations.</p>
          <div class="plot-grid">
            <div class="plot"><h3>Top Operations</h3><canvas id="auditOpsChart"></canvas></div>
            <div class="plot"><h3>Top Users</h3><canvas id="auditUsersChart"></canvas></div>
            <div class="plot"><h3>Client IP Hotspots</h3><canvas id="auditIpsChart"></canvas></div>
            <div class="plot"><h3>Hourly Activity</h3><canvas id="auditTimelineChart"></canvas></div>
          </div>
        </div>

        <div class="section">
          <h2>Windows EVTX Analysis</h2>
          <p class="sub">Focuses on Event IDs, providers, privileged actions, failed logons, Sysmon activity, and possible host compromise indicators.</p>
          <div class="plot-grid">
            <div class="plot"><h3>Top Event IDs</h3><canvas id="evtxIdsChart"></canvas></div>
            <div class="plot"><h3>Provider Distribution</h3><canvas id="evtxProvidersChart"></canvas></div>
            <div class="plot"><h3>Severity Mix</h3><canvas id="evtxSeverityChart"></canvas></div>
            <div class="plot"><h3>Hourly Event Timeline</h3><canvas id="evtxTimelineChart"></canvas></div>
          </div>
        </div>

        <div class="section">
          <h2>Network PCAP Analysis</h2>
          <p class="sub">Extracts conversations, source and destination hotspots, port usage, protocols, byte profile, and rule/ML threat hints.</p>
          <div class="mini-grid">
            <div class="metric"><span>Packets</span><strong id="pcapPackets">0</strong></div>
            <div class="metric"><span>Bytes</span><strong id="pcapBytes">0</strong></div>
            <div class="metric"><span>Anomalies</span><strong id="pcapAnomalies">0</strong></div>
            <div class="metric"><span>Protocols</span><strong id="pcapProtoCount">0</strong></div>
          </div>
          <div class="plot-grid">
            <div class="plot"><h3>Top Source IPs</h3><canvas id="pcapSrcChart"></canvas></div>
            <div class="plot"><h3>Top Destination Ports</h3><canvas id="pcapPortsChart"></canvas></div>
            <div class="plot"><h3>Protocol Distribution</h3><canvas id="pcapProtoChart"></canvas></div>
            <div class="plot"><h3>Possible Threats</h3><canvas id="pcapThreatChart"></canvas></div>
          </div>
        </div>

        <div class="section">
          <h2>Possible Threats and Analyst Notes</h2>
          <ul id="findings"><li><b>No evidence yet</b><span>Upload a file to generate findings.</span></li></ul>
        </div>
      </section>
    </section>
  </main>

  <script>
    let latest = { audit:null, evtx:null, pcap:null, findings:[] };

    function creds() {
      return {
        es_user: document.getElementById('elasticUser').value || 'elastic',
        es_password: document.getElementById('elasticPassword').value || ''
      };
    }

    function out(payload) {
      document.getElementById('rawOutput').textContent = JSON.stringify(payload, null, 2);
    }

    function setText(id, value) {
      const node = document.getElementById(id);
      if (node) node.textContent = value || 0;
    }

    function rowsToLabels(rows, labelKey, valueKey) {
      return (rows || []).slice(0, 8).map((row) => ({
        label: String(row[labelKey] || 'unknown').slice(0, 24),
        value: Number(row[valueKey]) || 0
      }));
    }

    function drawBar(canvasId, rows, color) {
      const canvas = document.getElementById(canvasId);
      if (!canvas) return;
      const ratio = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * ratio;
      canvas.height = rect.height * ratio;
      const ctx = canvas.getContext('2d');
      ctx.scale(ratio, ratio);
      ctx.clearRect(0, 0, rect.width, rect.height);
      ctx.fillStyle = '#b9bec7';
      ctx.font = '11px Segoe UI';
      if (!rows.length) {
        ctx.fillText('No data yet', 12, 24);
        return;
      }
      const max = Math.max(...rows.map(r => r.value), 1);
      const barH = Math.max(14, Math.floor((rect.height - 20) / rows.length) - 8);
      rows.forEach((row, idx) => {
        const y = 10 + idx * (barH + 8);
        const w = Math.max(5, (rect.width - 150) * row.value / max);
        ctx.fillStyle = '#2d2f33';
        ctx.fillRect(128, y, rect.width - 150, barH);
        ctx.fillStyle = color;
        ctx.fillRect(128, y, w, barH);
        ctx.fillStyle = '#f7f7f8';
        ctx.fillText(row.label, 8, y + barH - 3);
        ctx.fillStyle = '#b9bec7';
        ctx.fillText(String(row.value), 134 + w, y + barH - 3);
      });
    }

    function renderFindings() {
      const host = document.getElementById('findings');
      host.innerHTML = '';
      const findings = latest.findings.length ? latest.findings : ['No suspicious evidence findings yet.'];
      setText('findingCount', latest.findings.length);
      findings.forEach((finding, idx) => {
        const li = document.createElement('li');
        li.innerHTML = '<b>Finding ' + (idx + 1) + '</b><span>' + finding + '</span>';
        host.appendChild(li);
      });
    }

    function renderAudit(insights) {
      latest.audit = insights || {};
      const summary = latest.audit.summary || {};
      setText('auditRows', summary.rows || 0);
      drawBar('auditOpsChart', rowsToLabels(latest.audit.top_operations, 'operation', 'count'), '#4ade80');
      drawBar('auditUsersChart', rowsToLabels(latest.audit.top_users, 'user', 'count'), '#60a5fa');
      drawBar('auditIpsChart', rowsToLabels(latest.audit.top_ips, 'ip', 'count'), '#facc15');
      drawBar('auditTimelineChart', rowsToLabels(latest.audit.timeline, 'bucket', 'count'), '#c05ad9');
    }

    function renderEvtx(insights) {
      latest.evtx = insights || {};
      const summary = latest.evtx.summary || {};
      setText('evtxRows', summary.rows || 0);
      drawBar('evtxIdsChart', rowsToLabels(latest.evtx.top_event_ids, 'event_id', 'count'), '#facc15');
      drawBar('evtxProvidersChart', rowsToLabels(latest.evtx.providers, 'provider', 'count'), '#60a5fa');
      drawBar('evtxSeverityChart', rowsToLabels(latest.evtx.severity_mix, 'severity', 'count'), '#ef3d43');
      drawBar('evtxTimelineChart', rowsToLabels(latest.evtx.timeline, 'bucket', 'count'), '#4ade80');
    }

    function renderPcap(eda) {
      latest.pcap = eda || {};
      const summary = latest.pcap.summary || {};
      setText('pcapFlows', summary.flow_rows || 0);
      setText('pcapPackets', summary.total_packets || 0);
      setText('pcapBytes', summary.total_bytes || 0);
      setText('pcapAnomalies', summary.anomaly_count || 0);
      setText('pcapProtoCount', (latest.pcap.protocol_distribution || []).length);
      drawBar('pcapSrcChart', rowsToLabels(latest.pcap.top_source_ips, 'src_ip', 'count'), '#60a5fa');
      drawBar('pcapPortsChart', rowsToLabels(latest.pcap.top_destination_ports, 'dst_port', 'count'), '#facc15');
      drawBar('pcapProtoChart', rowsToLabels(latest.pcap.protocol_distribution, 'protocol', 'count'), '#4ade80');
      drawBar('pcapThreatChart', rowsToLabels(latest.pcap.potential_threats, 'threat', 'count'), '#ef3d43');
    }

    async function uploadAudit() {
      const file = document.getElementById('auditFile').files[0];
      if (!file) return out({ ok:false, error:'Select a CSV or audit log first.' });
      const form = new FormData();
      form.append('audit_file', file);
      const data = await (await fetch('/api/upload/audit', { method:'POST', body:form })).json();
      out(data);
      renderAudit(data.insights || {});
      latest.findings = (data.insights && data.insights.findings) || [];
      renderFindings();
    }

    async function uploadEvtx() {
      const file = document.getElementById('evtxFile').files[0];
      if (!file) return out({ ok:false, error:'Select an EVTX file first.' });
      const form = new FormData();
      const auth = creds();
      form.append('evtx_file', file);
      form.append('es_user', auth.es_user);
      form.append('es_password', auth.es_password);
      const data = await (await fetch('/api/upload/evtx', { method:'POST', body:form })).json();
      out(data);
      renderEvtx(data.insights || {});
      latest.findings = (data.insights && data.insights.findings) || [];
      renderFindings();
    }

    async function uploadPcap() {
      const file = document.getElementById('pcapFile').files[0];
      if (!file) return out({ ok:false, error:'Select a PCAP or PCAPNG first.' });
      const form = new FormData();
      const auth = creds();
      form.append('pcap_file', file);
      form.append('es_user', auth.es_user);
      form.append('es_password', auth.es_password);
      const data = await (await fetch('/api/upload/pcap', { method:'POST', body:form })).json();
      out(data);
      renderPcap(data.eda || {});
      latest.findings = data.eda && data.eda.potential_threats ? data.eda.potential_threats.map(t => t.threat + ' observed in ' + t.count + ' anomalous flows.') : [];
      renderFindings();
    }

    async function refreshState() {
      const auth = creds();
      const qs = new URLSearchParams({ es_user: auth.es_user, es_password: auth.es_password });
      const state = await (await fetch('/api/state?' + qs.toString())).json();
      renderAudit(state.audit_eda || {});
      renderEvtx(state.evtx_eda || {});
      renderPcap(state.pcap_eda || {});
      latest.findings = state.evidence && state.evidence.insights ? state.evidence.insights.findings || [] : latest.findings;
      renderFindings();
      out({ ok:true, refreshed:true, generated_at:state.generated_at, summary:state.summary });
    }

    refreshState();
  </script>
</body>
</html>
"""
