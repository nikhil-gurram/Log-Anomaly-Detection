"""Unified SOC dashboard with Streamlit-like EDA for uploaded evidence files."""

from datetime import datetime
import csv
import io
import json
import random
import re
import struct
from collections import Counter

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse

app = FastAPI(title="Unified SOC Dashboard")

attack_history = []
soc_status = {
    "windows": {"last_attack": None, "anomalies": 0, "flows": 0},
    "web": {"last_attack": None, "anomalies": 0, "requests": 0},
    "network": {"last_attack": None, "anomalies": 0, "packets": 0},
}

HTML_CONTENT = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unified SOC - Live EDA</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg: #07151f;
            --bg-elev: #0f2431;
            --bg-card: #102836;
            --line: #244b60;
            --text: #e9f4fb;
            --muted: #9ec2d7;
            --critical: #ff4d6d;
            --high: #ff8f00;
            --medium: #ffd166;
            --low: #6dd3b7;
            --accent: #52d1ff;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            background:
                radial-gradient(circle at 10% 10%, rgba(82, 209, 255, 0.14), transparent 38%),
                radial-gradient(circle at 90% 30%, rgba(255, 77, 109, 0.12), transparent 34%),
                linear-gradient(160deg, #040d14 0%, var(--bg) 48%, #041019 100%);
            color: var(--text);
            font-family: "Space Grotesk", sans-serif;
            min-height: 100vh;
            padding: 18px;
        }

        .container {
            max-width: 1460px;
            margin: 0 auto;
            display: grid;
            gap: 16px;
        }

        .hero {
            border: 1px solid var(--line);
            background: linear-gradient(120deg, rgba(16, 40, 54, 0.95), rgba(8, 22, 32, 0.95));
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 14px 30px rgba(0, 0, 0, 0.28);
        }

        .hero h1 {
            margin: 0;
            font-size: 32px;
            letter-spacing: 0.02em;
        }

        .hero p {
            margin: 8px 0 0;
            color: var(--muted);
            font-size: 14px;
        }

        .card {
            border: 1px solid var(--line);
            border-radius: 14px;
            background: rgba(15, 36, 49, 0.86);
            padding: 16px;
        }

        .title {
            margin: 0 0 12px;
            font-size: 12px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.14em;
            font-weight: 700;
        }

        .upload-grid {
            display: grid;
            grid-template-columns: 1.1fr 2fr;
            gap: 16px;
        }

        .dropzone {
            border: 2px dashed var(--accent);
            border-radius: 12px;
            background: rgba(82, 209, 255, 0.07);
            color: var(--text);
            padding: 24px;
            text-align: center;
            cursor: pointer;
        }

        .dropzone strong { display: block; font-size: 17px; }
        .dropzone span { color: var(--muted); font-size: 13px; }

        .meta {
            margin-top: 14px;
            font-size: 12px;
            color: var(--muted);
        }

        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(110px, 1fr));
            gap: 10px;
        }

        .kpi {
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 12px;
            background: rgba(7, 21, 31, 0.65);
        }

        .kpi .label {
            font-size: 11px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .kpi .value {
            margin-top: 4px;
            font-size: 22px;
            font-weight: 700;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(320px, 1fr));
            gap: 14px;
        }

        .chart-card {
            border: 1px solid var(--line);
            border-radius: 12px;
            background: rgba(16, 40, 54, 0.76);
            padding: 12px;
            min-height: 300px;
            display: flex;
            flex-direction: column;
        }

        .chart-title {
            margin: 0 0 8px;
            font-size: 14px;
            font-weight: 700;
        }

        .chart-wrap {
            flex: 1;
            min-height: 240px;
            position: relative;
        }

        .threat-list {
            display: grid;
            gap: 8px;
            max-height: 300px;
            overflow-y: auto;
        }

        .threat-item {
            border: 1px solid var(--line);
            border-left-width: 5px;
            border-radius: 10px;
            padding: 10px;
            background: rgba(7, 21, 31, 0.75);
        }

        .severity-critical { border-left-color: var(--critical); }
        .severity-high { border-left-color: var(--high); }
        .severity-medium { border-left-color: var(--medium); }
        .severity-low { border-left-color: var(--low); }

        .threat-head {
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            font-weight: 700;
        }

        .pill {
            border-radius: 999px;
            padding: 2px 8px;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .pill.critical { background: rgba(255, 77, 109, 0.2); color: #ff94a7; }
        .pill.high { background: rgba(255, 143, 0, 0.2); color: #ffbb66; }
        .pill.medium { background: rgba(255, 209, 102, 0.25); color: #ffe2a0; }
        .pill.low { background: rgba(109, 211, 183, 0.2); color: #a8f5df; }

        .threat-reason {
            font-size: 12px;
            color: var(--muted);
            margin-top: 6px;
        }

        .insight-list {
            margin: 0;
            padding-left: 18px;
            color: var(--muted);
            display: grid;
            gap: 6px;
            font-size: 13px;
        }

        .files {
            display: grid;
            gap: 8px;
            max-height: 250px;
            overflow-y: auto;
        }

        .file-item {
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 8px;
            font-size: 12px;
            font-family: "JetBrains Mono", monospace;
            background: rgba(7, 21, 31, 0.72);
        }

        @media (max-width: 1100px) {
            .upload-grid { grid-template-columns: 1fr; }
            .grid { grid-template-columns: 1fr; }
            .kpi-grid { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
        }
    </style>
</head>
<body>
    <div class="container">
        <section class="hero">
            <h1>Unified SOC EDA Studio</h1>
            <p>Upload CSV, PCAP, or EVTX evidence and get real operational insights, trend plots, and threat scoring.</p>
        </section>

        <section class="card upload-grid">
            <div>
                <p class="title">Evidence Upload</p>
                <div class="dropzone" onclick="document.getElementById('fileInput').click()">
                    <strong>Select Evidence Files</strong>
                    <span>Supported: .csv .pcap .pcapng .evtx</span>
                </div>
                <input id="fileInput" type="file" multiple style="display:none" onchange="handleFileUpload(event)" />
                <div class="meta" id="uploadStatus">No files analyzed yet.</div>
                <div class="files" id="filesList"></div>
            </div>
            <div>
                <p class="title">Global KPIs</p>
                <div class="kpi-grid">
                    <div class="kpi"><div class="label">Files</div><div class="value" id="kpiFiles">0</div></div>
                    <div class="kpi"><div class="label">Records</div><div class="value" id="kpiRecords">0</div></div>
                    <div class="kpi"><div class="label">Packets</div><div class="value" id="kpiPackets">0</div></div>
                    <div class="kpi"><div class="label">Events</div><div class="value" id="kpiEvents">0</div></div>
                    <div class="kpi"><div class="label">Threats</div><div class="value" id="kpiThreats">0</div></div>
                </div>
                <div style="margin-top: 12px;">
                    <p class="title">Key Insights</p>
                    <ul class="insight-list" id="insightList">
                        <li>Upload files to populate insights and visual analytics.</li>
                    </ul>
                </div>
            </div>
        </section>

        <section class="grid">
            <article class="chart-card">
                <h3 class="chart-title">Threat Severity Mix</h3>
                <div class="chart-wrap"><canvas id="severityChart"></canvas></div>
            </article>
            <article class="chart-card">
                <h3 class="chart-title">Top Operations / Event IDs</h3>
                <div class="chart-wrap"><canvas id="operationChart"></canvas></div>
            </article>
            <article class="chart-card">
                <h3 class="chart-title">Hourly Activity Trend</h3>
                <div class="chart-wrap"><canvas id="timelineChart"></canvas></div>
            </article>
            <article class="chart-card">
                <h3 class="chart-title">Network Protocol Share</h3>
                <div class="chart-wrap"><canvas id="protocolChart"></canvas></div>
            </article>
            <article class="chart-card">
                <h3 class="chart-title">Top Source/Destination IPs</h3>
                <div class="chart-wrap"><canvas id="ipChart"></canvas></div>
            </article>
            <article class="chart-card">
                <h3 class="chart-title">Detected Threats</h3>
                <div class="threat-list" id="threatList"></div>
            </article>
        </section>
    </div>

    <script>
        const palette = {
            critical: '#ff4d6d',
            high: '#ff8f00',
            medium: '#ffd166',
            low: '#6dd3b7',
            accent: '#52d1ff',
            line: '#244b60',
            text: '#e9f4fb'
        };

        const state = {
            analyses: []
        };

        const charts = {};

        function baseChartConfig(type, labels = [], data = [], color = palette.accent) {
            return {
                type,
                data: {
                    labels,
                    datasets: [{
                        data,
                        backgroundColor: Array.isArray(color) ? color : color,
                        borderColor: palette.line,
                        borderWidth: 1.2,
                        tension: 0.34,
                        fill: type === 'line'
                    }]
                },
                options: {
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { labels: { color: palette.text } }
                    },
                    scales: {
                        x: { ticks: { color: '#9ec2d7' }, grid: { color: 'rgba(36,75,96,0.25)' } },
                        y: { ticks: { color: '#9ec2d7' }, grid: { color: 'rgba(36,75,96,0.25)' } }
                    }
                }
            };
        }

        function initCharts() {
            charts.severity = new Chart(document.getElementById('severityChart'), {
                ...baseChartConfig('doughnut', ['Critical', 'High', 'Medium', 'Low'], [0, 0, 0, 0], [palette.critical, palette.high, palette.medium, palette.low]),
                options: { maintainAspectRatio: false, plugins: { legend: { labels: { color: palette.text } } } }
            });

            charts.operations = new Chart(document.getElementById('operationChart'), baseChartConfig('bar'));
            charts.timeline = new Chart(document.getElementById('timelineChart'), {
                ...baseChartConfig('line', [], [], 'rgba(82,209,255,0.24)'),
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Events/Packets',
                        data: [],
                        borderColor: palette.accent,
                        backgroundColor: 'rgba(82,209,255,0.17)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true
                    }]
                }
            });

            charts.protocols = new Chart(document.getElementById('protocolChart'), {
                ...baseChartConfig('polarArea', ['TCP', 'UDP', 'ICMP', 'OTHER'], [0, 0, 0, 0], [palette.accent, palette.low, palette.medium, palette.high]),
                options: { maintainAspectRatio: false, plugins: { legend: { labels: { color: palette.text } } } }
            });

            charts.ips = new Chart(document.getElementById('ipChart'), {
                ...baseChartConfig('bar'),
                options: {
                    indexAxis: 'y',
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#9ec2d7' }, grid: { color: 'rgba(36,75,96,0.25)' } },
                        y: { ticks: { color: '#9ec2d7' }, grid: { display: false } }
                    }
                }
            });
        }

        function updateKpis(aggregate) {
            document.getElementById('kpiFiles').textContent = aggregate.fileCount;
            document.getElementById('kpiRecords').textContent = aggregate.records;
            document.getElementById('kpiPackets').textContent = aggregate.packets;
            document.getElementById('kpiEvents').textContent = aggregate.events;
            document.getElementById('kpiThreats').textContent = aggregate.threats.length;
        }

        function updateInsights(insights) {
            const el = document.getElementById('insightList');
            if (!insights.length) {
                el.innerHTML = '<li>No major anomalies detected from current uploads.</li>';
                return;
            }
            el.innerHTML = insights.slice(0, 8).map((i) => '<li>' + i + '</li>').join('');
        }

        function updateThreatList(threats) {
            const el = document.getElementById('threatList');
            if (!threats.length) {
                el.innerHTML = '<div class="threat-item severity-low"><div class="threat-head"><span>No actionable threats</span><span class="pill low">low</span></div><div class="threat-reason">No high-confidence indicators triggered.</div></div>';
                return;
            }
            el.innerHTML = threats.map((t) => (
                '<div class="threat-item severity-' + t.severity + '">' +
                    '<div class="threat-head"><span>' + t.name + '</span><span class="pill ' + t.severity + '">' + t.severity + '</span></div>' +
                    '<div class="threat-reason">' + t.reason + '</div>' +
                '</div>'
            )).join('');
        }

        function updateFiles(analyses) {
            const el = document.getElementById('filesList');
            if (!analyses.length) {
                el.innerHTML = '';
                return;
            }
            el.innerHTML = analyses.map((a) => (
                '<div class="file-item">' +
                    'file=' + a.filename + ' | type=' + a.file_type + ' | size=' + (a.file_size_bytes / 1024).toFixed(1) + 'KB' +
                '</div>'
            )).join('');
        }

        function toSortedArray(counterObj) {
            return Object.entries(counterObj || {}).sort((a, b) => b[1] - a[1]);
        }

        function aggregateAnalyses(analyses) {
            const aggregate = {
                fileCount: analyses.length,
                records: 0,
                packets: 0,
                events: 0,
                threats: [],
                insights: [],
                operations: {},
                protocols: {},
                timeline: new Array(24).fill(0),
                ips: {}
            };

            analyses.forEach((a) => {
                const summary = a.summary || {};
                aggregate.records += summary.total_rows || 0;
                aggregate.packets += summary.packet_count || 0;
                aggregate.events += summary.estimated_events || 0;
                (a.threats || []).forEach((t) => aggregate.threats.push(t));
                (a.insights || []).forEach((i) => aggregate.insights.push(i));

                Object.entries((a.charts || {}).operations || {}).forEach(([k, v]) => {
                    aggregate.operations[k] = (aggregate.operations[k] || 0) + v;
                });
                Object.entries((a.charts || {}).protocols || {}).forEach(([k, v]) => {
                    aggregate.protocols[k] = (aggregate.protocols[k] || 0) + v;
                });
                Object.entries((a.charts || {}).ips || {}).forEach(([k, v]) => {
                    aggregate.ips[k] = (aggregate.ips[k] || 0) + v;
                });
                ((a.charts || {}).timeline || []).forEach((v, idx) => {
                    aggregate.timeline[idx] += v;
                });
            });

            return aggregate;
        }

        function updateCharts(aggregate) {
            const severityCount = { critical: 0, high: 0, medium: 0, low: 0 };
            aggregate.threats.forEach((t) => {
                severityCount[t.severity] = (severityCount[t.severity] || 0) + 1;
            });

            charts.severity.data.datasets[0].data = [
                severityCount.critical,
                severityCount.high,
                severityCount.medium,
                severityCount.low
            ];
            charts.severity.update();

            const ops = toSortedArray(aggregate.operations).slice(0, 8);
            charts.operations.data.labels = ops.map((x) => x[0]);
            charts.operations.data.datasets[0].data = ops.map((x) => x[1]);
            charts.operations.data.datasets[0].backgroundColor = 'rgba(82,209,255,0.62)';
            charts.operations.update();

            charts.timeline.data.labels = [...Array(24).keys()].map((h) => String(h).padStart(2, '0') + ':00');
            charts.timeline.data.datasets[0].data = aggregate.timeline;
            charts.timeline.update();

            const protoEntries = toSortedArray(aggregate.protocols);
            charts.protocols.data.labels = protoEntries.length ? protoEntries.map((x) => x[0]) : ['No Data'];
            charts.protocols.data.datasets[0].data = protoEntries.length ? protoEntries.map((x) => x[1]) : [1];
            charts.protocols.update();

            const ipEntries = toSortedArray(aggregate.ips).slice(0, 8);
            charts.ips.data.labels = ipEntries.map((x) => x[0]);
            charts.ips.data.datasets[0].data = ipEntries.map((x) => x[1]);
            charts.ips.data.datasets[0].backgroundColor = 'rgba(109,211,183,0.72)';
            charts.ips.update();
        }

        async function handleFileUpload(event) {
            const files = Array.from(event.target.files || []);
            const status = document.getElementById('uploadStatus');
            if (!files.length) {
                return;
            }

            status.textContent = 'Analyzing ' + files.length + ' file(s)...';

            const requests = files.map(async (file) => {
                const form = new FormData();
                form.append('file', file);
                const res = await fetch('/upload-evidence', { method: 'POST', body: form });
                const payload = await res.json();
                if (!payload.ok || payload.analysis.error) {
                    throw new Error(file.name + ': ' + (payload.analysis?.error || payload.error || 'Unknown upload error'));
                }
                return payload.analysis;
            });

            try {
                const results = await Promise.all(requests);
                state.analyses = results;
                const aggregate = aggregateAnalyses(results);
                updateKpis(aggregate);
                updateInsights(aggregate.insights);
                updateThreatList(aggregate.threats);
                updateFiles(results);
                updateCharts(aggregate);
                status.textContent = 'Analysis complete for ' + results.length + ' file(s).';
            } catch (err) {
                status.textContent = String(err.message || err);
            }
        }

        window.addEventListener('load', () => {
            initCharts();
        });
    </script>
</body>
</html>
"""


def _normalize_key_lookup(row):
    return {k.strip().lower(): k for k in row.keys()}


def _extract_ip(text):
    if not text:
        return None
    match = re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", text)
    return match.group(0) if match else None


def _safe_parse_datetime(value):
    if not value:
        return None
    candidates = [
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def _threat(name, severity, reason):
    return {"name": name, "severity": severity, "reason": reason}


def analyze_csv_file(content):
    reader = list(csv.DictReader(io.StringIO(content)))
    if not reader:
        return {"error": "CSV has headers but no records."}

    operation_counts = Counter()
    ip_counts = Counter()
    user_counts = Counter()
    hourly = [0] * 24
    failed_logins = 0
    privileged_events = 0

    for row in reader:
        key_lookup = _normalize_key_lookup(row)
        operation_key = key_lookup.get("operation")
        user_key = key_lookup.get("userid")
        date_key = key_lookup.get("creationdate")
        audit_key = key_lookup.get("auditdata")
        client_ip_key = key_lookup.get("clientip")

        operation = (row.get(operation_key) or "unknown").strip() if operation_key else "unknown"
        user = (row.get(user_key) or "unknown").strip() if user_key else "unknown"
        operation_counts[operation] += 1
        user_counts[user] += 1

        raw_audit = row.get(audit_key) if audit_key else ""
        event_ip = row.get(client_ip_key) if client_ip_key else None
        event_ip = event_ip or _extract_ip(raw_audit)
        if event_ip:
            ip_counts[event_ip] += 1

        event_dt = _safe_parse_datetime(row.get(date_key) if date_key else "")
        if event_dt:
            hourly[event_dt.hour] += 1

        op_lower = operation.lower()
        if "failed" in op_lower:
            failed_logins += 1
        if any(term in op_lower for term in ["role", "permission", "admin", "policy", "delete"]):
            privileged_events += 1

    top_ops = dict(operation_counts.most_common(8))
    top_ips = dict(ip_counts.most_common(8))

    insights = [
        f"Top operation is {operation_counts.most_common(1)[0][0]} with {operation_counts.most_common(1)[0][1]} events.",
        f"Observed {len(user_counts)} unique users and {len(ip_counts)} unique IP addresses.",
    ]

    threats = []
    if failed_logins >= 5:
        threats.append(_threat("Possible Brute Force", "high", f"Detected {failed_logins} failed login events in audit logs."))
    if privileged_events >= 10:
        threats.append(_threat("Privileged Action Spike", "medium", f"Detected {privileged_events} admin-sensitive operations."))

    if operation_counts:
        top_name, top_count = operation_counts.most_common(1)[0]
        if top_count / len(reader) > 0.85:
            threats.append(_threat("Automation/Scripted Activity", "medium", f"Operation {top_name} dominates {round(top_count * 100 / len(reader), 1)}% of events."))

    return {
        "file_type": "CSV Log",
        "summary": {
            "total_rows": len(reader),
            "unique_users": len(user_counts),
            "unique_ips": len(ip_counts),
            "estimated_events": 0,
            "packet_count": 0,
        },
        "charts": {
            "operations": top_ops,
            "ips": top_ips,
            "timeline": hourly,
            "protocols": {},
        },
        "threats": threats,
        "insights": insights,
    }


def analyze_pcap_file(content):
    if len(content) < 24:
        return {"error": "PCAP file is too small."}

    magic = struct.unpack("<I", content[0:4])[0]
    supported = {0xA1B2C3D4, 0xD4C3B2A1}
    if magic not in supported:
        # minimal fallback for pcapng magic
        pcapng_magic = struct.unpack("<I", content[0:4])[0]
        if pcapng_magic == 0x0A0D0D0A:
            return {
                "file_type": "PCAPNG Capture",
                "summary": {
                    "total_rows": 0,
                    "unique_users": 0,
                    "unique_ips": 0,
                    "estimated_events": 0,
                    "packet_count": 0,
                },
                "charts": {"operations": {}, "ips": {}, "timeline": [0] * 24, "protocols": {}},
                "threats": [_threat("PCAPNG Limited Parser", "low", "PCAPNG detected. Convert to PCAP for deep packet EDA.")],
                "insights": ["PCAPNG identified. Current parser provides lightweight validation only."],
            }
        return {"error": "Unsupported capture format. Upload PCAP or PCAPNG."}

    fmt = "<" if magic == 0xA1B2C3D4 else ">"
    offset = 24
    packet_count = 0
    protocol_counts = Counter()
    ip_counts = Counter()
    port_counts = Counter()
    hourly = [0] * 24

    while offset + 16 <= len(content):
        pkt_hdr = content[offset:offset + 16]
        if len(pkt_hdr) < 16:
            break
        ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(fmt + "IIII", pkt_hdr)
        offset += 16

        if incl_len <= 0 or offset + incl_len > len(content):
            break
        data = content[offset:offset + incl_len]
        offset += incl_len
        packet_count += 1

        dt = datetime.utcfromtimestamp(ts_sec)
        hourly[dt.hour] += 1

        if len(data) < 34:
            continue
        eth_type = struct.unpack(">H", data[12:14])[0]
        if eth_type != 0x0800:
            if eth_type == 0x86DD:
                protocol_counts["IPv6"] += 1
            elif eth_type == 0x0806:
                protocol_counts["ARP"] += 1
            else:
                protocol_counts["OTHER"] += 1
            continue

        src_ip = ".".join(str(b) for b in data[26:30])
        dst_ip = ".".join(str(b) for b in data[30:34])
        ip_counts[src_ip] += 1
        ip_counts[dst_ip] += 1

        ip_proto = data[23]
        if ip_proto == 6:
            protocol_counts["TCP"] += 1
        elif ip_proto == 17:
            protocol_counts["UDP"] += 1
        elif ip_proto == 1:
            protocol_counts["ICMP"] += 1
        else:
            protocol_counts["OTHER"] += 1

        ihl = (data[14] & 0x0F) * 4
        l4_start = 14 + ihl
        if len(data) >= l4_start + 4 and ip_proto in (6, 17):
            src_port, dst_port = struct.unpack(">HH", data[l4_start:l4_start + 4])
            port_counts[src_port] += 1
            port_counts[dst_port] += 1

    top_ips = dict(ip_counts.most_common(8))
    top_ports = port_counts.most_common(3)

    insights = [
        f"Capture contains {packet_count} packets and {len(ip_counts)} unique IP endpoints.",
        f"Top protocols: {', '.join([f'{k}:{v}' for k, v in protocol_counts.most_common(3)]) or 'none'}.",
    ]
    if top_ports:
        insights.append(f"Most active ports: {', '.join([str(p[0]) for p in top_ports])}.")

    threats = []
    if packet_count >= 10000:
        threats.append(_threat("Potential DDoS Volume", "critical", f"Observed {packet_count} packets in a single capture."))
    elif packet_count >= 2000:
        threats.append(_threat("Traffic Surge", "high", f"Observed elevated packet volume: {packet_count} packets."))

    if len(ip_counts) >= 120:
        threats.append(_threat("Wide Recon Footprint", "high", f"Found {len(ip_counts)} unique IPs, consistent with scanning activity."))

    if top_ports and top_ports[0][1] > 0.45 * max(packet_count, 1):
        threats.append(_threat("Single-Port Concentration", "medium", f"Port {top_ports[0][0]} dominates traffic volume."))

    return {
        "file_type": "PCAP Capture",
        "summary": {
            "total_rows": 0,
            "unique_users": 0,
            "unique_ips": len(ip_counts),
            "estimated_events": 0,
            "packet_count": packet_count,
        },
        "charts": {
            "operations": {f"Port {p}": c for p, c in top_ports},
            "ips": top_ips,
            "timeline": hourly,
            "protocols": dict(protocol_counts),
        },
        "threats": threats,
        "insights": insights,
    }


def analyze_evtx_file(content):
    if len(content) < 4096 or content[0:8] != b"ElfFile\x00":
        return {"error": "Invalid EVTX signature. Expected ElfFile header."}

    chunk_count = struct.unpack("<H", content[42:44])[0] if len(content) > 44 else 0
    estimated_events = max(chunk_count * 64, len(content) // 512)

    # EVTX commonly stores XML fragments in UTF-16LE.
    decoded = content.decode("utf-16le", errors="ignore")
    event_ids = re.findall(r"EventID[^0-9]{0,8}(\d{3,5})", decoded)
    id_counts = Counter(event_ids)

    interesting = {
        "4625": "Failed logon",
        "4624": "Successful logon",
        "4688": "Process creation",
        "4672": "Special privileges assigned",
        "1102": "Audit log cleared",
    }

    operations = {}
    for event_id, name in interesting.items():
        if id_counts[event_id] > 0:
            operations[f"EID {event_id} {name}"] = id_counts[event_id]

    threats = []
    if id_counts["1102"] > 0:
        threats.append(_threat("Event Log Tampering", "critical", f"Event ID 1102 occurred {id_counts['1102']} time(s)."))
    if id_counts["4625"] >= 20:
        threats.append(_threat("Repeated Authentication Failure", "high", f"Event ID 4625 appeared {id_counts['4625']} times."))
    if id_counts["4672"] >= 10:
        threats.append(_threat("Privilege Escalation Exposure", "medium", f"Event ID 4672 appeared {id_counts['4672']} times."))

    insights = [
        f"EVTX header valid with approximately {estimated_events} event records.",
        f"Detected {len(id_counts)} unique event IDs in parsed fragments.",
    ]
    if operations:
        top_label = next(iter(sorted(operations.items(), key=lambda x: x[1], reverse=True)), None)
        if top_label:
            insights.append(f"Most frequent mapped event is {top_label[0]} ({top_label[1]}).")

    return {
        "file_type": "EVTX Security Log",
        "summary": {
            "total_rows": 0,
            "unique_users": 0,
            "unique_ips": 0,
            "estimated_events": estimated_events,
            "packet_count": 0,
        },
        "charts": {
            "operations": operations,
            "ips": {},
            "timeline": [0] * 24,
            "protocols": {},
        },
        "threats": threats,
        "insights": insights,
    }


@app.post("/upload-evidence")
async def upload_evidence(file: UploadFile = File(...), es_user: str = Form("elastic"), es_password: str = Form("")):
    try:
        payload = await file.read()
        name = file.filename or "uploaded_file"
        lowered = name.lower()

        analysis = {
            "filename": name,
            "file_size_bytes": len(payload),
            "file_type": "Unknown",
            "summary": {},
            "charts": {"operations": {}, "ips": {}, "timeline": [0] * 24, "protocols": {}},
            "threats": [],
            "insights": [],
        }

        if lowered.endswith(".csv"):
            decoded = payload.decode("utf-8", errors="replace")
            result = analyze_csv_file(decoded)
        elif lowered.endswith((".pcap", ".pcapng")):
            result = analyze_pcap_file(payload)
        elif lowered.endswith(".evtx") or lowered.endswith(".extv"):
            result = analyze_evtx_file(payload)
        else:
            result = {"error": "Unsupported type. Use CSV, PCAP/PCAPNG, EVTX."}

        if "error" in result:
            analysis["error"] = result["error"]
        else:
            analysis.update(result)

        return {"ok": True, "analysis": analysis}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@app.get("/", response_class=HTMLResponse)
def root():
    return HTML_CONTENT

@app.post("/trigger-attack")
async def trigger_attack(
    soc_type: str = Form(...),
    attack_type: str = Form(...),
    es_user: str = Form("elastic"),
    es_password: str = Form(""),
):
    """Trigger an attack on the specified SOC"""
    global attack_history
    
    timestamp = datetime.now()
    soc_status[soc_type]["last_attack"] = timestamp.isoformat()
    
    # Simulate attack data generation
    soc_status[soc_type]["anomalies"] = random.randint(10, 100)
    
    if soc_type == "windows":
        soc_status[soc_type]["flows"] = random.randint(500, 5000)
    elif soc_type == "web":
        soc_status[soc_type]["requests"] = random.randint(100, 1000)
    else:  # network
        soc_status[soc_type]["packets"] = random.randint(1000, 50000)
    
    attack_history.append({
        "timestamp": timestamp.isoformat(),
        "soc": soc_type,
        "attack_type": attack_type,
        "anomalies": soc_status[soc_type]["anomalies"],
    })
    
    return {
        "ok": True,
        "soc": soc_type,
        "attack_type": attack_type,
        "message": f"Attack triggered on {soc_type} SOC",
        "timestamp": timestamp.isoformat(),
        "anomalies_detected": soc_status[soc_type]["anomalies"],
        "attack_history_length": len(attack_history),
    }

@app.get("/soc-status")
def get_soc_status():
    """Get current status of all SOCs"""
    return {
        "ok": True,
        "status": soc_status,
        "attack_history": attack_history[-10:],  # Last 10 attacks
    }

@app.get("/threat-analysis")
def get_threat_analysis():
    """Get comprehensive threat analysis"""
    total_attacks = len(attack_history)
    total_anomalies = sum(s["anomalies"] for s in soc_status.values())
    
    # Generate threat distribution
    threat_dist = {
        "reconnaissance": random.randint(10, 50),
        "exploitation": random.randint(5, 30),
        "c2_communication": random.randint(5, 25),
        "data_exfiltration": random.randint(2, 15),
        "lateral_movement": random.randint(5, 20),
    }
    
    # Generate anomaly score distribution
    anomaly_scores = {
        "0.0-0.2": random.randint(100, 500),
        "0.2-0.4": random.randint(50, 300),
        "0.4-0.6": random.randint(30, 150),
        "0.6-0.8": random.randint(10, 80),
        "0.8-1.0": random.randint(5, 40),
    }
    
    # Generate attack timeline (24 hours)
    timeline = [random.randint(0, 100) for _ in range(24)]
    
    return {
        "ok": True,
        "total_attacks": total_attacks,
        "total_anomalies": total_anomalies,
        "threat_distribution": threat_dist,
        "anomaly_score_distribution": anomaly_scores,
        "attack_timeline_24h": timeline,
        "active_threats": [
            {"name": "Port Scan", "severity": "high", "count": 23},
            {"name": "DDoS Attack", "severity": "critical", "count": 156},
            {"name": "Exploitation", "severity": "critical", "count": 8},
            {"name": "C2 Beacon", "severity": "high", "count": 12},
        ],
    }

if __name__ == "__main__":
    import uvicorn
    print("🎯 Starting Unified SOC Dashboard on http://localhost:8088")
    uvicorn.run(app, host="0.0.0.0", port=8088)
