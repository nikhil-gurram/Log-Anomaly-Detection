"""Isolated web app that emits structured security logs for SOC analytics."""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel


ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
LOG_FILE = LOG_DIR / "webapp_access.log"
LOG_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Web SOC Demo Application", version="1.1.0")


class LoginRequest(BaseModel):
    username: str
    password: str


class SimulateRequest(BaseModel):
    count: int = 10
    source_ip: str = "203.0.113.77"
    publish_live: bool = True
    es_url: str = "http://localhost:9200"
    es_user: str = "elastic"
    es_password: str = ""


def write_log(entry: dict) -> None:
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True) + "\n")


def run_web_log_publisher(es_url: str, es_user: str, es_password: str) -> dict:
    if not es_password:
        return {"published": False, "reason": "missing Elasticsearch password"}

    script = ROOT / "scripts" / "publish_web_logs_to_elasticsearch.py"
    cmd = [
        sys.executable,
        str(script),
        "--input",
        str(LOG_FILE),
        "--es-url",
        es_url,
        "--username",
        es_user,
        "--password",
        es_password,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return {"published": False, "reason": result.stderr.strip() or result.stdout.strip()}
    return {"published": True, "output": result.stdout.strip()}


def emit_event(
    *,
    path: str,
    status_code: int,
    event_type: str,
    method: str = "GET",
    user: str = "demo-user",
    role: str = "user",
    client_ip: str = "203.0.113.77",
    latency_ms: float = 50.0,
) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "request_id": str(uuid.uuid4()),
        "method": method,
        "path": path,
        "query": "",
        "status_code": int(status_code),
        "latency_ms": float(latency_ms),
        "client_ip": client_ip,
        "user_agent": "soc-live-demo-browser",
        "user": user,
        "role": role,
        "event_type": event_type,
        "source": "webapp",
    }
    write_log(entry)


UI_HTML = """<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Web SOC Live Control Center</title>
    <style>
        :root {
            --bg-deep: #0d0d0d;
            --bg-card: #1a1a1a;
            --bg-input: #242424;
            --border: #333333;
            --text-primary: #f5f5f5;
            --text-muted: #a8a8a8;
            --success: #4ade80;
            --warning: #facc15;
            --danger: #ef4444;
            --info: #60a5fa;
        }
        
        * { box-sizing: border-box; }
        
        body {
            margin: 0;
            min-height: 100vh;
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
            background: var(--bg-deep);
            padding: 24px;
            line-height: 1.6;
        }
        
        .wrap {
            max-width: 1280px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 340px 1fr;
            gap: 16px;
        }
        
        .left, .right {
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--bg-card);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            transition: all 0.2s ease;
        }
        
        .left:hover, .right:hover {
            border-color: var(--info);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        }
        
        .left { padding: 16px; }
        .right { padding: 16px; }
        
        .title {
            font-size: 28px;
            font-weight: 700;
            line-height: 1.2;
            margin: 0 0 4px;
            letter-spacing: -0.5px;
            color: var(--text-primary);
        }
        
        .sub {
            margin: 0 0 16px;
            color: var(--text-muted);
            font-size: 13px;
        }
        
        .kpi {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-bottom: 14px;
        }
        
        .chip {
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-input);
            padding: 12px;
            min-height: 70px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: all 0.2s ease;
        }
        
        .chip:hover {
            border-color: var(--info);
            background: #2a2a2a;
        }
        
        .chip .label { 
            color: var(--text-muted); 
            font-size: 11px; 
            text-transform: uppercase; 
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        
        .chip .value { 
            margin-top: 4px; 
            font-size: 18px; 
            font-weight: 700;
            color: var(--info);
        }

        .section { 
            margin-top: 16px; 
            padding-top: 16px;
            border-top: 1px solid var(--border);
        }
        
        .section:first-of-type {
            border-top: none;
            margin-top: 0;
            padding-top: 0;
        }
        
        .section h4 {
            margin: 0 0 10px;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-primary);
            font-weight: 600;
        }
        
        .input, .range {
            width: 100%;
            border: 1px solid var(--border);
            background: var(--bg-input);
            color: var(--text-primary);
            border-radius: 6px;
            padding: 10px;
            outline: none;
            margin-bottom: 8px;
            font-family: inherit;
            font-size: 13px;
            transition: all 0.2s ease;
        }
        
        .input:focus, .range:focus {
            border-color: var(--info);
            background: #2a2a2a;
        }

        .scenario-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        
        .card {
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-input);
            padding: 14px;
            min-height: 160px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: all 0.2s ease;
        }
        
        .card-content {
            flex-grow: 1;
        }
        
        .card h3 {
            margin: 0 0 4px;
            font-size: 13px;
            line-height: 1.3;
            font-weight: 600;
            letter-spacing: -0.3px;
        }
        
        .card p {
            margin: 0 0 12px;
            color: var(--text-muted);
            font-size: 12px;
            min-height: 32px;
            line-height: 1.4;
        }
        
        .card:hover {
            border-color: var(--info);
            background: #2a2a2a;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        .btn {
            border: 1px solid;
            border-radius: 6px;
            padding: 10px 14px;
            cursor: pointer;
            font-weight: 600;
            letter-spacing: -0.3px;
            transition: all 0.15s ease;
            font-family: inherit;
            font-size: 12px;
            text-transform: uppercase;
            width: 100%;
        }
        
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .good { 
            background: var(--success);
            color: #000;
            border-color: var(--success);
        }
        
        .good:hover {
            background: #5edf8b;
        }
        
        .warn { 
            background: var(--warning);
            color: #000;
            border-color: var(--warning);
        }
        
        .warn:hover {
            background: #fcd34d;
        }
        
        .bad { 
            background: var(--danger);
            color: #fff;
            border-color: var(--danger);
        }
        
        .bad:hover {
            background: #f87171;
        }

        .status-wrap {
            margin-top: 16px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-input);
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            transition: all 0.2s ease;
        }
        
        .status-wrap:hover {
            border-color: var(--info);
        }
        
        .status-head {
            padding: 10px 12px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-primary);
            background: #242424;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
        }
        
        .status-body {
            min-height: 100px;
            max-height: 240px;
            overflow: auto;
            white-space: pre-wrap;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 12px;
            color: var(--success);
            padding: 12px;
            line-height: 1.6;
        }
        
        .feed {
            margin-top: 12px;
            border-top: 1px solid var(--border);
            padding-top: 12px;
        }
        
        .feed-label {
            margin-bottom: 8px;
            font-size: 11px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            color: var(--text-primary);
            font-weight: 600;
        }
        
        .feed-item {
            padding: 8px 10px;
            border: 1px solid var(--border);
            border-left: 3px solid var(--info);
            border-radius: 4px;
            background: #242424;
            margin-bottom: 6px;
            font-size: 12px;
            color: var(--text-primary);
            transition: all 0.2s ease;
        }
        
        .feed-item:hover {
            background: #2a2a2a;
            border-left-color: var(--success);
        }
        
        .pill {
            display: inline-block;
            border-radius: 12px;
            padding: 3px 8px;
            font-size: 10px;
            margin-left: 8px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        @media (max-width: 1024px) {
            .wrap { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class=\"wrap\">
        <section class=\"left\">
            <h1 class=\"title\">SOC Control</h1>
            <p class=\"sub\">Web security incident simulator</p>

            <div class=\"kpi\">
                <div class=\"chip\"><div class=\"label\">Last Action</div><div id=\"kpiAction\" class=\"value\">None</div></div>
                <div class=\"chip\"><div class=\"label\">Events Sent</div><div id=\"kpiCount\" class=\"value\">0</div></div>
                <div class=\"chip\"><div class=\"label\">Publish State</div><div id=\"kpiPublish\" class=\"value\">Idle</div></div>
                <div class=\"chip\"><div class=\"label\">Last Update</div><div id=\"kpiTime\" class=\"value\">--:--:--</div></div>
            </div>

            <div class=\"section\">
                <h4>Elasticsearch Credentials</h4>
                <input id=\"esUser\" class=\"input\" value=\"elastic\" placeholder=\"Username\" />
                <input id=\"esPassword\" class=\"input\" type=\"password\" placeholder=\"Password\" />
            </div>

            <div class=\"section\">
                <h4>Incident Parameters</h4>
                <input id=\"sourceIp\" class=\"input\" value=\"203.0.113.77\" placeholder=\"Source IP\" />
                <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;\">
                    <label style=\"font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:var(--text-muted);\">Event Volume</label>
                    <span style=\"font-size:12px;font-weight:900;color:var(--info);\"  id=\"eventCountLabel\">120</span>
                </div>
                <input id=\"eventCount\" class=\"range\" type=\"range\" min=\"30\" max=\"300\" value=\"120\" step=\"10\" />
            </div>
        </section>

        <section class=\"right\">
            <div class=\"scenario-grid\">
                <div class=\"card\">
                    <div class=\"card-content\"><h3>Normal Traffic</h3><p>Baseline user browsing activity.</p></div>
                    <button class=\"btn good\" onclick=\"runAction('/simulate/normal','Normal Traffic')\">Execute</button>
                </div>
                <div class=\"card\">
                    <div class=\"card-content\"><h3>Login Attack</h3><p>Brute-force login failures.</p></div>
                    <button class=\"btn bad\" onclick=\"runAction('/simulate/failed-logins','Login Attack')\">Execute</button>
                </div>
                <div class=\"card\">
                    <div class=\"card-content\"><h3>Port Scan</h3><p>Endpoint enumeration probe.</p></div>
                    <button class=\"btn warn\" onclick=\"runAction('/simulate/endpoint-scan','Port Scan')\">Execute</button>
                </div>
                <div class=\"card\">
                    <div class=\"card-content\"><h3>Privilege Escalation</h3><p>Admin access attempt.</p></div>
                    <button class=\"btn bad\" onclick=\"runAction('/simulate/admin-probe','Privilege Escalation')\">Execute</button>
                </div>
                <div class=\"card\">
                    <div class=\"card-content\"><h3>Performance Attack</h3><p>Latency spike and stress.</p></div>
                    <button class=\"btn warn\" onclick=\"runAction('/simulate/latency-spike','Performance Attack')\">Execute</button>
                </div>
                <div class=\"card\">
                    <div class=\"card-content\"><h3>Full Attack</h3><p>Combined multi-stage attack.</p></div>
                    <button class=\"btn bad\" onclick=\"runAction('/simulate/mixed-attack','Full Attack')\">Execute</button>
                </div>
            </div>

            <div class=\"status-wrap\">
                <div class=\"status-head\">Output <span class=\"pill\">Live</span></div>
                <div id=\"status\" class=\"status-body\">Ready. Enter credentials and execute a scenario.</div>
            </div>

            <div class=\"feed\">
                <div class=\"feed-label\">Activity Log</div>
                <div id=\"feed\"></div>
            </div>
        </section>
    </div>

    <script>
        // Update event count display
        document.getElementById('eventCount').addEventListener('input', function() {
            document.getElementById('eventCountLabel').textContent = this.value;
        });

        function appendFeed(text) {
            const container = document.getElementById('feed');
            const item = document.createElement('div');
            item.className = 'feed-item';
            item.textContent = '[' + new Date().toLocaleTimeString() + '] ' + text;
            container.prepend(item);
            while (container.children.length > 10) {
                container.removeChild(container.lastChild);
            }
        }

        async function runAction(path, label) {
            const status = document.getElementById('status');
            const esUser = document.getElementById('esUser').value || 'elastic';
            const esPassword = document.getElementById('esPassword').value || '';
            const sourceIp = document.getElementById('sourceIp').value || '203.0.113.77';
            const count = parseInt(document.getElementById('eventCount').value, 10) || 120;

            document.getElementById('kpiAction').textContent = label;
            document.getElementById('kpiCount').textContent = String(count);
            document.getElementById('kpiPublish').textContent = 'Running';
            status.textContent = 'Running ' + label + '...\\nEvents: ' + count + '\\nSource: ' + sourceIp;

            try {
                const res = await fetch(path, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        count: count,
                        source_ip: sourceIp,
                        publish_live: true,
                        es_url: 'http://localhost:9200',
                        es_user: esUser,
                        es_password: esPassword
                    })
                });

                const body = await res.json();
                const publishOk = body.publish && body.publish.published === true;
                document.getElementById('kpiPublish').textContent = publishOk ? 'Published' : 'Failed';
                document.getElementById('kpiTime').textContent = new Date().toLocaleTimeString();
                
                const statusMsg = publishOk ? 'SUCCESS' : 'FAILED';
                
                appendFeed(label + ' | Events=' + (body.events_generated || 0) + ' | ' + statusMsg);

                status.textContent = 'Scenario: ' + label + '\\nStatus: ' + statusMsg + '\\nEvents: ' + (body.events_generated || 0) + '\\n\\nResponse:\\n' + JSON.stringify(body, null, 2);
            } catch (err) {
                document.getElementById('kpiPublish').textContent = 'Error';
                status.textContent = 'Error: ' + String(err);
                appendFeed(label + ' | ERROR');
            }
        }
    </script>
</body>
</html>
"""


@app.middleware("http")
async def log_requests(request: Request, call_next):
    started = time.perf_counter()
    request_id = str(uuid.uuid4())
    event_type = "web_request"
    user = request.headers.get("x-user", "anonymous")
    role = request.headers.get("x-role", "guest")

    try:
        response = await call_next(request)
        status_code = response.status_code
    except HTTPException as exc:
        status_code = exc.status_code
        raise
    finally:
        latency_ms = (time.perf_counter() - started) * 1000
        if request.url.path.startswith("/admin") and role != "admin":
            event_type = "privilege_violation"
        elif request.url.path in {"/login"} and request.method.upper() == "POST":
            event_type = "auth_attempt"
        elif any(request.url.path.startswith(p) for p in ["/.git", "/wp-admin", "/phpmyadmin", "/etc/passwd"]):
            event_type = "endpoint_scan"

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query),
            "status_code": int(status_code),
            "latency_ms": round(latency_ms, 3),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown"),
            "user": user,
            "role": role,
            "event_type": event_type,
            "source": "webapp",
        }
        write_log(log_entry)

    return response


@app.get("/")
def root() -> dict:
    return {"message": "Web SOC demo app running", "ui": "/control-center"}


@app.get("/control-center", response_class=HTMLResponse)
def control_center() -> str:
    return UI_HTML


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}


@app.get("/products")
def products(limit: int = 10) -> dict:
    items = [{"id": i, "name": f"product-{i}"} for i in range(1, min(limit, 25) + 1)]
    return {"count": len(items), "items": items}


@app.get("/slow")
def slow() -> dict:
    time.sleep(0.9)
    return {"status": "slow endpoint complete"}


@app.post("/login")
def login(payload: LoginRequest, request: Request) -> dict:
    if payload.username == "admin" and payload.password == "admin123":
        return {"status": "success", "user": payload.username}

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "request_id": str(uuid.uuid4()),
        "method": "POST",
        "path": "/login",
        "query": "",
        "status_code": 401,
        "latency_ms": 3.0,
        "client_ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
        "user": payload.username,
        "role": "guest",
        "event_type": "auth_failed",
        "source": "webapp",
    }
    write_log(log_entry)
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/admin")
def admin(request: Request) -> dict:
    role = request.headers.get("x-role", "guest")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"status": "admin access granted"}


@app.post("/simulate/normal")
def simulate_normal(payload: SimulateRequest) -> dict:
    for _ in range(max(1, min(payload.count, 300))):
        emit_event(
            path=random.choice(["/", "/health", "/products", "/products"]),
            status_code=200,
            event_type="web_request",
            user="normal-user",
            role="user",
            client_ip=payload.source_ip,
            latency_ms=random.uniform(20, 120),
        )
    publish = run_web_log_publisher(payload.es_url, payload.es_user, payload.es_password) if payload.publish_live else {"published": False, "reason": "publish_live disabled"}
    return {"status": "ok", "scenario": "normal", "events_generated": payload.count, "publish": publish}


@app.post("/simulate/failed-logins")
def simulate_failed_logins(payload: SimulateRequest) -> dict:
    for _ in range(max(1, min(payload.count, 500))):
        emit_event(
            method="POST",
            path="/login",
            status_code=401,
            event_type="auth_failed",
            user="attacker",
            role="guest",
            client_ip=payload.source_ip,
            latency_ms=random.uniform(4, 35),
        )
    publish = run_web_log_publisher(payload.es_url, payload.es_user, payload.es_password) if payload.publish_live else {"published": False, "reason": "publish_live disabled"}
    return {"status": "ok", "scenario": "failed-logins", "events_generated": payload.count, "publish": publish}


@app.post("/simulate/endpoint-scan")
def simulate_endpoint_scan(payload: SimulateRequest) -> dict:
    paths = ["/.git/config", "/wp-admin", "/phpmyadmin", "/etc/passwd", "/admin.php"]
    for _ in range(max(1, min(payload.count, 500))):
        emit_event(
            path=random.choice(paths),
            status_code=404,
            event_type="endpoint_scan",
            user="attacker",
            role="guest",
            client_ip=payload.source_ip,
            latency_ms=random.uniform(8, 80),
        )
    publish = run_web_log_publisher(payload.es_url, payload.es_user, payload.es_password) if payload.publish_live else {"published": False, "reason": "publish_live disabled"}
    return {"status": "ok", "scenario": "endpoint-scan", "events_generated": payload.count, "publish": publish}


@app.post("/simulate/admin-probe")
def simulate_admin_probe(payload: SimulateRequest) -> dict:
    for _ in range(max(1, min(payload.count, 500))):
        emit_event(
            path="/admin",
            status_code=403,
            event_type="privilege_violation",
            user="attacker",
            role="guest",
            client_ip=payload.source_ip,
            latency_ms=random.uniform(12, 110),
        )
    publish = run_web_log_publisher(payload.es_url, payload.es_user, payload.es_password) if payload.publish_live else {"published": False, "reason": "publish_live disabled"}
    return {"status": "ok", "scenario": "admin-probe", "events_generated": payload.count, "publish": publish}


@app.post("/simulate/latency-spike")
def simulate_latency_spike(payload: SimulateRequest) -> dict:
    for _ in range(max(1, min(payload.count, 500))):
        emit_event(
            path=random.choice(["/products", "/search", "/checkout"]),
            status_code=200,
            event_type="web_request",
            user="normal-user",
            role="user",
            client_ip=payload.source_ip,
            latency_ms=random.uniform(650, 1800),
        )
    publish = run_web_log_publisher(payload.es_url, payload.es_user, payload.es_password) if payload.publish_live else {"published": False, "reason": "publish_live disabled"}
    return {"status": "ok", "scenario": "latency-spike", "events_generated": payload.count, "publish": publish}


@app.post("/simulate/mixed-attack")
def simulate_mixed_attack(payload: SimulateRequest) -> dict:
    each = max(5, min(payload.count, 500))
    for _ in range(each):
        emit_event(method="POST", path="/login", status_code=401, event_type="auth_failed", user="attacker", role="guest", client_ip=payload.source_ip, latency_ms=random.uniform(4, 35))
        emit_event(path=random.choice(["/.git/config", "/wp-admin", "/phpmyadmin", "/etc/passwd", "/admin.php"]), status_code=404, event_type="endpoint_scan", user="attacker", role="guest", client_ip=payload.source_ip, latency_ms=random.uniform(8, 80))
        emit_event(path="/admin", status_code=403, event_type="privilege_violation", user="attacker", role="guest", client_ip=payload.source_ip, latency_ms=random.uniform(12, 110))
        emit_event(path=random.choice(["/products", "/search", "/checkout"]), status_code=200, event_type="web_request", user="normal-user", role="user", client_ip=payload.source_ip, latency_ms=random.uniform(650, 1800))

    publish = run_web_log_publisher(payload.es_url, payload.es_user, payload.es_password) if payload.publish_live else {"published": False, "reason": "publish_live disabled"}
    return {
        "status": "ok",
        "scenario": "mixed-attack",
        "events_generated": each * 4,
        "publish": publish,
        "note": "Refresh Grafana to view spikes.",
    }
