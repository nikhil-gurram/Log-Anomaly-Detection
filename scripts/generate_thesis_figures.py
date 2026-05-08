"""Generate thesis-ready report figures from project data.

This script creates report-friendly PNG assets for the Windows and web
application anomaly-detection thesis using the repository's current outputs.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Circle


ROOT = Path(__file__).resolve().parents[1]
THESIS_FIGURES = ROOT / "thesis" / "figures"
WINDOWS_CSV = ROOT / "windows-soc-isolated" / "data" / "anomaly_results.csv"
WEB_CSV = ROOT / "webapp-soc-isolated" / "data" / "web_anomaly_results.csv"


COLORS = {
    "navy": "#102542",
    "blue": "#2563eb",
    "teal": "#0f766e",
    "green": "#16a34a",
    "orange": "#ea580c",
    "amber": "#d97706",
    "red": "#dc2626",
    "rose": "#e11d48",
    "slate": "#475569",
    "light_slate": "#cbd5e1",
    "bg": "#f8fafc",
    "panel": "#ffffff",
    "grid": "#dbe4f0",
    "text": "#0f172a",
    "muted": "#64748b",
}

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#16a34a",
}


def apply_report_style() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": COLORS["bg"],
            "axes.facecolor": COLORS["panel"],
            "axes.edgecolor": COLORS["light_slate"],
            "axes.labelcolor": COLORS["text"],
            "axes.titleweight": "bold",
            "axes.titlesize": 13,
            "axes.labelsize": 10,
            "xtick.color": COLORS["text"],
            "ytick.color": COLORS["text"],
            "grid.color": COLORS["grid"],
            "grid.linestyle": "--",
            "grid.linewidth": 0.7,
            "font.size": 10,
            "savefig.facecolor": COLORS["bg"],
            "savefig.bbox": "tight",
        }
    )


def save_figure(fig: plt.Figure, name: str) -> None:
    THESIS_FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(THESIS_FIGURES / name, dpi=300)
    plt.close(fig)


def load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    windows = pd.read_csv(WINDOWS_CSV)
    web = pd.read_csv(WEB_CSV)

    windows["is_anomaly"] = windows["prediction"].eq("anomaly")
    windows["TimeCreated"] = pd.to_datetime(windows["TimeCreated"], errors="coerce")

    web["is_anomaly"] = web["prediction"].eq("anomaly")
    web["timestamp"] = pd.to_datetime(web["timestamp"], errors="coerce")
    web["severity"] = web["severity"].fillna("unknown").str.lower()
    return windows, web


def metric_card(ax: plt.Axes, title: str, value: str, subtitle: str, color: str) -> None:
    ax.set_axis_off()
    card = FancyBboxPatch(
        (0, 0),
        1,
        1,
        boxstyle="round,pad=0.02,rounding_size=0.08",
        linewidth=1.2,
        edgecolor=color,
        facecolor=COLORS["panel"],
        transform=ax.transAxes,
    )
    ax.add_patch(card)
    ax.text(0.06, 0.74, title, fontsize=10, fontweight="bold", color=COLORS["muted"], transform=ax.transAxes)
    ax.text(0.06, 0.42, value, fontsize=22, fontweight="bold", color=color, transform=ax.transAxes)
    ax.text(0.06, 0.14, subtitle, fontsize=9, color=COLORS["text"], transform=ax.transAxes)


def draw_box(ax: plt.Axes, x: float, y: float, w: float, h: float, title: str, body: str, color: str) -> None:
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.015,rounding_size=0.025",
        linewidth=1.6,
        edgecolor=color,
        facecolor="white",
    )
    ax.add_patch(patch)
    ax.text(x + 0.02, y + h - 0.07, title, fontsize=12, fontweight="bold", color=color, va="top")
    ax.text(x + 0.02, y + h - 0.13, body, fontsize=9.5, color=COLORS["text"], va="top", wrap=True)


def arrow(ax: plt.Axes, start: tuple[float, float], end: tuple[float, float], color: str = COLORS["navy"]) -> None:
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=14,
            linewidth=1.8,
            color=color,
        )
    )


def generate_architecture_figure() -> None:
    fig, ax = plt.subplots(figsize=(15, 8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(
        0.02,
        0.96,
        "Unified Log Anomaly Detection Architecture",
        fontsize=20,
        fontweight="bold",
        color=COLORS["navy"],
        va="top",
    )
    ax.text(
        0.02,
        0.91,
        "Windows host monitoring and web application monitoring share the same high-level pipeline while using domain-specific features.",
        fontsize=10.5,
        color=COLORS["muted"],
        va="top",
    )

    draw_box(
        ax,
        0.04,
        0.58,
        0.22,
        0.22,
        "Windows Telemetry",
        "Security and Sysmon-related events collected through Winlogbeat.\nExamples: process creation, service enumeration, file bursts, administrative events.",
        COLORS["teal"],
    )
    draw_box(
        ax,
        0.04,
        0.24,
        0.22,
        0.22,
        "Web Telemetry",
        "Structured JSON request logs written by the FastAPI demo app and forwarded through Filebeat or publisher scripts.\nExamples: failed logins, scans, admin probes, latency spikes.",
        COLORS["orange"],
    )
    draw_box(
        ax,
        0.34,
        0.58,
        0.24,
        0.22,
        "Feature Engineering",
        "Windows features: EventID, hour_of_day, event_frequency, inter_event_gap_seconds, message_length.\nWeb features: status_code, latency_ms, request rate, path diversity, error and abuse flags.",
        COLORS["blue"],
    )
    draw_box(
        ax,
        0.34,
        0.24,
        0.24,
        0.22,
        "Isolation Forest Scoring",
        "Both modules train on baseline observations and label unusual records as anomalies using unsupervised scoring.\nWeb alerts also receive severity and reason tags.",
        COLORS["navy"],
    )
    draw_box(
        ax,
        0.66,
        0.58,
        0.26,
        0.22,
        "Indexed Outputs",
        "Raw telemetry and anomaly outputs are published to Elasticsearch indices for searchable storage, aggregation, and downstream visual analysis.",
        COLORS["green"],
    )
    draw_box(
        ax,
        0.66,
        0.24,
        0.26,
        0.22,
        "Dashboards and Analyst Review",
        "Grafana panels summarize anomaly counts, severity trends, top event types, top paths, and operational security signals for demonstration and investigation.",
        COLORS["amber"],
    )

    arrow(ax, (0.26, 0.69), (0.34, 0.69), COLORS["teal"])
    arrow(ax, (0.26, 0.35), (0.34, 0.35), COLORS["orange"])
    arrow(ax, (0.58, 0.69), (0.66, 0.69), COLORS["blue"])
    arrow(ax, (0.58, 0.35), (0.66, 0.35), COLORS["navy"])
    arrow(ax, (0.79, 0.58), (0.79, 0.46), COLORS["green"])

    ax.text(0.36, 0.84, "Shared ML pipeline", fontsize=10, fontweight="bold", color=COLORS["blue"])
    ax.text(0.69, 0.84, "Centralized storage + presentation", fontsize=10, fontweight="bold", color=COLORS["green"])

    save_figure(fig, "system_architecture_report.png")


def generate_methodology_figure() -> None:
    fig, ax = plt.subplots(figsize=(15, 5.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.02, 0.95, "Methodology Workflow Used in the Thesis", fontsize=19, fontweight="bold", color=COLORS["navy"], va="top")
    ax.text(
        0.02,
        0.88,
        "The report evaluates two modules with the same engineering pattern: collect telemetry, create compact features, detect anomalies, and visualize the results.",
        fontsize=10.5,
        color=COLORS["muted"],
        va="top",
    )

    steps = [
        ("1", "Simulate Activity", "Generate safe suspicious behaviors in Windows and the web demo app."),
        ("2", "Collect Logs", "Capture Security/Sysmon events and structured web request records."),
        ("3", "Engineer Features", "Convert raw logs into compact numerical and behavioral indicators."),
        ("4", "Detect Anomalies", "Train Isolation Forest and label unusual rows with anomaly scores."),
        ("5", "Publish Results", "Store results in Elasticsearch and review them with Grafana dashboards."),
    ]
    x_positions = np.linspace(0.09, 0.91, len(steps))

    for idx, ((num, title, body), x) in enumerate(zip(steps, x_positions)):
        circ = Circle((x, 0.60), 0.055, facecolor=COLORS["blue"] if idx % 2 == 0 else COLORS["teal"], edgecolor="none")
        ax.add_patch(circ)
        ax.text(x, 0.60, num, color="white", fontsize=18, fontweight="bold", ha="center", va="center")
        box = FancyBboxPatch(
            (x - 0.095, 0.22),
            0.19,
            0.24,
            boxstyle="round,pad=0.02,rounding_size=0.03",
            linewidth=1.2,
            edgecolor=COLORS["light_slate"],
            facecolor="white",
        )
        ax.add_patch(box)
        ax.text(x - 0.075, 0.41, title, fontsize=11, fontweight="bold", color=COLORS["navy"])
        ax.text(x - 0.075, 0.36, body, fontsize=9.2, color=COLORS["text"], va="top", wrap=True)
        if idx < len(steps) - 1:
            arrow(ax, (x + 0.055, 0.60), (x_positions[idx + 1] - 0.055, 0.60), COLORS["slate"])

    save_figure(fig, "methodology_workflow_report.png")


def generate_windows_deep_dive(windows: pd.DataFrame) -> None:
    fig = plt.figure(figsize=(15, 10))
    gs = fig.add_gridspec(2, 2, hspace=0.28, wspace=0.18)

    fig.suptitle("Windows Module Deep-Dive Results", fontsize=18, fontweight="bold", color=COLORS["navy"], y=0.98)

    overall = windows["EventID"].astype(str).value_counts().head(6).sort_values()
    anomalous = windows.loc[windows["is_anomaly"], "EventID"].astype(str).value_counts()
    anomalous = anomalous.reindex(overall.index, fill_value=0)

    ax1 = fig.add_subplot(gs[0, 0])
    ypos = np.arange(len(overall))
    ax1.barh(ypos - 0.18, overall.values, height=0.34, color=COLORS["teal"], label="All rows")
    ax1.barh(ypos + 0.18, anomalous.values, height=0.34, color=COLORS["orange"], label="Anomalies")
    ax1.set_yticks(ypos)
    ax1.set_yticklabels(overall.index)
    ax1.set_title("Top Event IDs: Overall vs Anomalous Rows")
    ax1.set_xlabel("Count")
    ax1.grid(axis="x", alpha=0.5)
    ax1.legend(frameon=False, loc="lower right")

    ax2 = fig.add_subplot(gs[0, 1])
    pred_counts = windows["prediction"].value_counts().reindex(["normal", "anomaly"], fill_value=0)
    wedges, _ = ax2.pie(
        pred_counts.values,
        colors=[COLORS["green"], COLORS["red"]],
        startangle=90,
        wedgeprops={"width": 0.42, "edgecolor": "white"},
    )
    ax2.text(0, 0.08, f"{pred_counts['anomaly']}", ha="center", va="center", fontsize=24, fontweight="bold", color=COLORS["red"])
    ax2.text(0, -0.14, "anomalies", ha="center", va="center", fontsize=11, color=COLORS["muted"])
    ax2.legend(wedges, ["Normal", "Anomaly"], frameon=False, loc="lower center", bbox_to_anchor=(0.5, -0.05), ncol=2)
    ax2.set_title("Prediction Split")

    ax3 = fig.add_subplot(gs[1, 0])
    gap_means = windows.groupby("prediction")["inter_event_gap_seconds"].mean().reindex(["normal", "anomaly"])
    ax3.bar(gap_means.index, gap_means.values, color=[COLORS["green"], COLORS["red"]])
    ax3.set_title("Mean Inter-Event Gap by Prediction")
    ax3.set_ylabel("Seconds")
    ax3.grid(axis="y", alpha=0.5)
    for i, v in enumerate(gap_means.values):
        ax3.text(i, v + max(gap_means.values) * 0.03, f"{v:.2f}", ha="center", fontsize=10, color=COLORS["text"])

    ax4 = fig.add_subplot(gs[1, 1])
    freq_means = windows.groupby("prediction")["event_frequency"].mean().reindex(["normal", "anomaly"])
    ax4.bar(freq_means.index, freq_means.values, color=[COLORS["teal"], COLORS["orange"]])
    ax4.set_title("Mean Event Frequency by Prediction")
    ax4.set_ylabel("Average frequency")
    ax4.grid(axis="y", alpha=0.5)
    for i, v in enumerate(freq_means.values):
        ax4.text(i, v + max(freq_means.values) * 0.03, f"{v:.2f}", ha="center", fontsize=10, color=COLORS["text"])

    save_figure(fig, "windows_anomaly_deep_dive.png")


def generate_web_deep_dive(web: pd.DataFrame) -> None:
    fig = plt.figure(figsize=(15, 10))
    gs = fig.add_gridspec(2, 2, hspace=0.30, wspace=0.22)
    fig.suptitle("Web Application Module Deep-Dive Results", fontsize=18, fontweight="bold", color=COLORS["navy"], y=0.98)

    ax1 = fig.add_subplot(gs[0, 0])
    severity = web["severity"].value_counts().reindex(["critical", "high", "medium", "low"], fill_value=0)
    severity_colors = [SEVERITY_COLORS[k] for k in severity.index]
    ax1.bar(severity.index.str.title(), severity.values, color=severity_colors)
    ax1.set_title("Severity Distribution")
    ax1.set_ylabel("Count")
    ax1.grid(axis="y", alpha=0.5)
    for i, v in enumerate(severity.values):
        ax1.text(i, v + max(severity.values) * 0.02, f"{v:,}", ha="center", fontsize=10, color=COLORS["text"])

    ax2 = fig.add_subplot(gs[0, 1])
    event_types = (
        web.loc[web["is_anomaly"], "event_type"]
        .value_counts()
        .head(6)
        .sort_values()
    )
    ax2.barh(event_types.index, event_types.values, color=COLORS["orange"])
    ax2.set_title("Top Event Types Within Anomalous Requests")
    ax2.set_xlabel("Count")
    ax2.grid(axis="x", alpha=0.5)

    ax3 = fig.add_subplot(gs[1, 0])
    latency = web.groupby("prediction")["latency_ms"].mean().reindex(["normal", "anomaly"])
    ax3.bar(latency.index, latency.values, color=[COLORS["green"], COLORS["red"]])
    ax3.set_title("Average Latency by Prediction")
    ax3.set_ylabel("Milliseconds")
    ax3.grid(axis="y", alpha=0.5)
    for i, v in enumerate(latency.values):
        ax3.text(i, v + max(latency.values) * 0.03, f"{v:.2f}", ha="center", fontsize=10, color=COLORS["text"])

    ax4 = fig.add_subplot(gs[1, 1])
    paths = (
        web.loc[web["is_anomaly"], "path"]
        .value_counts()
        .head(6)
        .sort_values()
    )
    ax4.barh(paths.index, paths.values, color=COLORS["blue"])
    ax4.set_title("Top Paths Within Anomalous Requests")
    ax4.set_xlabel("Count")
    ax4.grid(axis="x", alpha=0.5)

    save_figure(fig, "web_anomaly_deep_dive.png")


def generate_comparison_figure(windows: pd.DataFrame, web: pd.DataFrame) -> None:
    fig = plt.figure(figsize=(15, 8))
    gs = fig.add_gridspec(2, 3, hspace=0.30, wspace=0.20, height_ratios=[0.9, 2.0])
    fig.suptitle("Cross-Module Comparison of Results", fontsize=18, fontweight="bold", color=COLORS["navy"], y=0.98)

    windows_rows = len(windows)
    web_rows = len(web)
    windows_anom = int(windows["is_anomaly"].sum())
    web_anom = int(web["is_anomaly"].sum())
    windows_rate = windows_anom / windows_rows * 100
    web_rate = web_anom / web_rows * 100

    card1 = fig.add_subplot(gs[0, 0])
    metric_card(card1, "Windows Rows", f"{windows_rows:,}", "Scored host-event records", COLORS["teal"])
    card2 = fig.add_subplot(gs[0, 1])
    metric_card(card2, "Web Rows", f"{web_rows:,}", "Scored request records", COLORS["orange"])
    card3 = fig.add_subplot(gs[0, 2])
    metric_card(card3, "Anomaly Rates", f"{windows_rate:.1f}% / {web_rate:.2f}%", "Windows vs web", COLORS["navy"])

    ax1 = fig.add_subplot(gs[1, 0])
    ax1.bar(["Windows", "Web"], [windows_anom, web_anom], color=[COLORS["teal"], COLORS["orange"]])
    ax1.set_title("Detected Anomalies")
    ax1.set_ylabel("Count")
    ax1.grid(axis="y", alpha=0.5)

    ax2 = fig.add_subplot(gs[1, 1])
    ax2.bar(["Windows", "Web"], [windows_rate, web_rate], color=[COLORS["green"], COLORS["red"]])
    ax2.set_title("Anomaly Rate")
    ax2.set_ylabel("Percent")
    ax2.grid(axis="y", alpha=0.5)
    for i, v in enumerate([windows_rate, web_rate]):
        ax2.text(i, v + max(windows_rate, web_rate) * 0.04, f"{v:.2f}%", ha="center", fontsize=10, color=COLORS["text"])

    ax3 = fig.add_subplot(gs[1, 2])
    labels = ["Web anomaly latency", "Web normal latency", "Win anomaly gap", "Win normal gap"]
    values = [
        web.loc[web["is_anomaly"], "latency_ms"].mean(),
        web.loc[~web["is_anomaly"], "latency_ms"].mean(),
        windows.loc[windows["is_anomaly"], "inter_event_gap_seconds"].mean(),
        windows.loc[~windows["is_anomaly"], "inter_event_gap_seconds"].mean(),
    ]
    ax3.barh(labels, values, color=[COLORS["red"], COLORS["green"], COLORS["orange"], COLORS["teal"]])
    ax3.set_title("Key Behavioral Contrasts")
    ax3.grid(axis="x", alpha=0.5)

    save_figure(fig, "cross_module_comparison_report.png")


def generate_dashboard_summary(windows: pd.DataFrame, web: pd.DataFrame) -> None:
    fig = plt.figure(figsize=(16, 9), facecolor="#0b1220")
    gs = fig.add_gridspec(3, 4, hspace=0.26, wspace=0.18, height_ratios=[0.78, 1.3, 1.3])

    fig.text(0.02, 0.965, "SOC Monitoring Dashboard Summary for Thesis Report", fontsize=20, fontweight="bold", color="white")
    fig.text(
        0.02,
        0.93,
        "Dashboard-style composite built from current repository metrics for Windows host monitoring and web application monitoring.",
        fontsize=10.5,
        color="#9fb0c9",
    )

    card_axes = [fig.add_subplot(gs[0, i]) for i in range(4)]
    for ax in card_axes:
        ax.set_facecolor("#101a2d")
    metric_card(card_axes[0], "Windows anomalies", f"{int(windows['is_anomaly'].sum()):,}", "From 3,000 scored rows", "#14b8a6")
    metric_card(card_axes[1], "Web anomalies", f"{int(web['is_anomaly'].sum()):,}", "From 16,492 scored rows", "#f97316")
    metric_card(card_axes[2], "Critical web alerts", f"{int((web['severity'] == 'critical').sum()):,}", "Highest-priority requests", "#ef4444")
    metric_card(card_axes[3], "Top Windows event", "4688", "Most frequent process event", "#60a5fa")

    ax1 = fig.add_subplot(gs[1, 0:2])
    ax2 = fig.add_subplot(gs[1, 2])
    ax3 = fig.add_subplot(gs[1, 3])
    ax4 = fig.add_subplot(gs[2, 0:2])
    ax5 = fig.add_subplot(gs[2, 2:])

    for ax in [ax1, ax2, ax3, ax4, ax5]:
        ax.set_facecolor("#101a2d")
        for spine in ax.spines.values():
            spine.set_color("#273449")
        ax.tick_params(colors="#dbeafe")
        ax.title.set_color("white")
        ax.xaxis.label.set_color("#dbeafe")
        ax.yaxis.label.set_color("#dbeafe")
        ax.grid(color="#243247", linestyle="--", alpha=0.4)

    severity = web["severity"].value_counts().reindex(["critical", "high", "medium", "low"], fill_value=0)
    ax1.bar(severity.index.str.title(), severity.values, color=[SEVERITY_COLORS[k] for k in severity.index])
    ax1.set_title("Web Severity Distribution")
    ax1.set_ylabel("Alert count")

    event_types = windows["EventID"].astype(str).value_counts().head(5).sort_values()
    ax2.barh(event_types.index, event_types.values, color="#22c55e")
    ax2.set_title("Windows Top Event IDs")
    ax2.set_xlabel("Count")

    latency = web.groupby("prediction")["latency_ms"].mean().reindex(["normal", "anomaly"])
    ax3.bar(latency.index, latency.values, color=["#22c55e", "#ef4444"])
    ax3.set_title("Web Latency Contrast")
    ax3.set_ylabel("ms")

    top_paths = web.loc[web["is_anomaly"], "path"].value_counts().head(6).sort_values()
    ax4.barh(top_paths.index, top_paths.values, color="#60a5fa")
    ax4.set_title("Top Suspicious Web Paths")
    ax4.set_xlabel("Anomalous request count")

    comp_labels = ["Windows rate", "Web rate"]
    comp_values = [windows["is_anomaly"].mean() * 100, web["is_anomaly"].mean() * 100]
    ax5.bar(comp_labels, comp_values, color=["#14b8a6", "#f97316"])
    ax5.set_title("Anomaly Rate Comparison")
    ax5.set_ylabel("Percent")
    for i, v in enumerate(comp_values):
        ax5.text(i, v + max(comp_values) * 0.05, f"{v:.2f}%", ha="center", color="white", fontsize=10)

    save_figure(fig, "soc_dashboard_summary_report.png")


def generate_feature_summary_figure() -> None:
    fig, ax = plt.subplots(figsize=(14, 7))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.02, 0.95, "Feature Engineering Summary Used by the Two Modules", fontsize=18, fontweight="bold", color=COLORS["navy"], va="top")
    ax.text(
        0.02,
        0.89,
        "The same anomaly-detection model is reused, but each data source needs features that reflect its own attack surface and normal behavior.",
        fontsize=10.5,
        color=COLORS["muted"],
        va="top",
    )

    draw_box(
        ax,
        0.05,
        0.18,
        0.38,
        0.58,
        "Windows Feature Family",
        "Event category and timing indicators:\n\n• EventID\n• hour_of_day\n• event_frequency\n• inter_event_gap_seconds\n• message_length\n\nThese features emphasize process bursts, administrative irregularity, and non-baseline host behavior.",
        COLORS["teal"],
    )
    draw_box(
        ax,
        0.57,
        0.18,
        0.38,
        0.58,
        "Web Feature Family",
        "Request behavior and abuse indicators:\n\n• status_code and latency_ms\n• request rate per IP\n• path diversity per IP\n• auth_failed, scan, admin_path, SQLi, XSS, token abuse, bot flags\n\nThese features emphasize brute force, probing, endpoint enumeration, and abnormal response behavior.",
        COLORS["orange"],
    )

    arrow(ax, (0.43, 0.47), (0.57, 0.47), COLORS["navy"])
    ax.text(0.47, 0.51, "Shared Isolation Forest scoring", fontsize=10, fontweight="bold", color=COLORS["navy"])

    save_figure(fig, "feature_engineering_summary_report.png")


def write_caption_notes() -> None:
    notes = ROOT / "thesis" / "generated_figure_notes.txt"
    notes.write_text(
        "\n".join(
            [
                "Generated Thesis Figures",
                "",
                "1. system_architecture_report.png",
                "   Suggested caption: Unified architecture showing Windows and web monitoring pipelines, feature engineering, anomaly scoring, indexing, and dashboard review.",
                "",
                "2. methodology_workflow_report.png",
                "   Suggested caption: Methodology workflow used across both monitoring modules.",
                "",
                "3. windows_anomaly_deep_dive.png",
                "   Suggested caption: Windows module deep-dive showing event distribution, anomaly split, inter-event gap comparison, and event-frequency comparison.",
                "",
                "4. web_anomaly_deep_dive.png",
                "   Suggested caption: Web module deep-dive showing severity distribution, anomaly event types, latency contrast, and suspicious path distribution.",
                "",
                "5. cross_module_comparison_report.png",
                "   Suggested caption: Comparative summary of Windows and web module scoring volume, anomaly counts, anomaly rates, and key behavioral contrasts.",
                "",
                "6. soc_dashboard_summary_report.png",
                "   Suggested caption: Dashboard-style composite summarizing the most important Windows and web monitoring metrics for analyst review.",
                "",
                "7. feature_engineering_summary_report.png",
                "   Suggested caption: Feature-engineering summary highlighting the domain-specific indicators used by the shared anomaly-detection model.",
            ]
        ),
        encoding="utf-8",
    )


def main() -> None:
    apply_report_style()
    windows, web = load_data()
    generate_architecture_figure()
    generate_methodology_figure()
    generate_windows_deep_dive(windows)
    generate_web_deep_dive(web)
    generate_comparison_figure(windows, web)
    generate_dashboard_summary(windows, web)
    generate_feature_summary_figure()
    write_caption_notes()


if __name__ == "__main__":
    main()
