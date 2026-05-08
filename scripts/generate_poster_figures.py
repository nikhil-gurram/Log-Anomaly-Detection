"""Generate poster-friendly figures for the IITP thesis poster."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Circle, FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parents[1]
WINDOWS_CSV = ROOT / "windows-soc-isolated" / "data" / "anomaly_results.csv"
WEB_CSV = ROOT / "webapp-soc-isolated" / "data" / "web_anomaly_results.csv"
POSTER_FIGURES = ROOT / "poster" / "figures"

COLORS = {
    "navy": "#14284b",
    "blue": "#2563eb",
    "teal": "#0f766e",
    "green": "#16a34a",
    "orange": "#ea580c",
    "amber": "#d97706",
    "red": "#dc2626",
    "slate": "#64748b",
    "light": "#e2e8f0",
    "panel": "#ffffff",
    "bg": "#f8fafc",
    "text": "#0f172a",
    "muted": "#5b708f",
}

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#16a34a",
}


def apply_style() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": COLORS["bg"],
            "axes.facecolor": COLORS["panel"],
            "axes.edgecolor": COLORS["light"],
            "axes.labelcolor": COLORS["text"],
            "axes.titlecolor": COLORS["navy"],
            "axes.titleweight": "bold",
            "xtick.color": COLORS["text"],
            "ytick.color": COLORS["text"],
            "font.size": 12,
            "savefig.facecolor": COLORS["bg"],
            "savefig.bbox": "tight",
            "axes.grid": True,
            "grid.color": "#dbe6f2",
            "grid.linestyle": "--",
            "grid.linewidth": 0.8,
        }
    )


def save(fig: plt.Figure, filename: str) -> None:
    POSTER_FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(POSTER_FIGURES / filename, dpi=300, pad_inches=0.25)
    plt.close(fig)


def load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    windows = pd.read_csv(WINDOWS_CSV)
    web = pd.read_csv(WEB_CSV)

    windows["prediction"] = windows["prediction"].astype(str).str.lower()
    web["prediction"] = web["prediction"].astype(str).str.lower()
    web["severity"] = web["severity"].fillna("unknown").astype(str).str.lower()

    windows["is_anomaly"] = windows["prediction"].eq("anomaly")
    web["is_anomaly"] = web["prediction"].eq("anomaly")
    return windows, web


def metric_card(ax: plt.Axes, title: str, value: str, subtitle: str, color: str) -> None:
    ax.set_axis_off()
    card = FancyBboxPatch(
        (0, 0),
        1,
        1,
        boxstyle="round,pad=0.02,rounding_size=0.06",
        linewidth=2.0,
        edgecolor=color,
        facecolor=COLORS["panel"],
        transform=ax.transAxes,
    )
    ax.add_patch(card)
    ax.text(0.07, 0.76, title, fontsize=13, fontweight="bold", color=COLORS["muted"], transform=ax.transAxes)
    ax.text(0.07, 0.42, value, fontsize=34, fontweight="bold", color=color, transform=ax.transAxes)
    ax.text(0.07, 0.14, subtitle, fontsize=12, color=COLORS["text"], transform=ax.transAxes)


def info_panel(ax: plt.Axes, title: str, lines: list[str]) -> None:
    ax.set_axis_off()
    card = FancyBboxPatch(
        (0, 0),
        1,
        1,
        boxstyle="round,pad=0.02,rounding_size=0.06",
        linewidth=2.0,
        edgecolor=COLORS["navy"],
        facecolor=COLORS["panel"],
        transform=ax.transAxes,
    )
    ax.add_patch(card)
    ax.text(0.06, 0.86, title, fontsize=15, fontweight="bold", color=COLORS["navy"], transform=ax.transAxes)

    y = 0.67
    for line in lines:
        ax.text(0.08, y, line, fontsize=12.5, color=COLORS["text"], transform=ax.transAxes)
        y -= 0.18


def add_step(ax: plt.Axes, x: float, number: str, title: str, body: str, color: str) -> None:
    circle = Circle((x, 0.68), 0.065, facecolor=color, edgecolor="none", transform=ax.transAxes)
    ax.add_patch(circle)
    ax.text(x, 0.68, number, ha="center", va="center", fontsize=24, fontweight="bold", color="white", transform=ax.transAxes)

    box = FancyBboxPatch(
        (x - 0.11, 0.24),
        0.22,
        0.24,
        boxstyle="round,pad=0.02,rounding_size=0.03",
        linewidth=2.0,
        edgecolor=COLORS["light"],
        facecolor="white",
        transform=ax.transAxes,
    )
    ax.add_patch(box)
    ax.text(x - 0.085, 0.40, title, fontsize=15, fontweight="bold", color=COLORS["navy"], transform=ax.transAxes)
    ax.text(x - 0.085, 0.29, body, fontsize=11.2, color=COLORS["text"], transform=ax.transAxes)


def add_arrow(ax: plt.Axes, x1: float, x2: float) -> None:
    arrow = FancyArrowPatch(
        (x1, 0.68),
        (x2, 0.68),
        arrowstyle="-|>",
        mutation_scale=26,
        linewidth=2.4,
        color=COLORS["slate"],
        transform=ax.transAxes,
    )
    ax.add_patch(arrow)


def generate_methodology_flow() -> None:
    fig, ax = plt.subplots(figsize=(16, 6.5))
    fig.subplots_adjust(left=0.03, right=0.98, top=0.94, bottom=0.08)
    ax.set_axis_off()

    ax.text(
        0.02,
        0.94,
        "Methodology Used in the Poster",
        fontsize=24,
        fontweight="bold",
        color=COLORS["navy"],
        transform=ax.transAxes,
    )
    ax.text(
        0.02,
        0.86,
        "Both modules follow the same engineering pattern: simulate activity, collect logs, engineer features, detect anomalies, and publish results.",
        fontsize=14,
        color=COLORS["muted"],
        transform=ax.transAxes,
    )

    xs = np.linspace(0.1, 0.9, 5)
    steps = [
        ("1", "Simulate", "PowerShell bursts,\nscan traffic, login abuse", COLORS["blue"]),
        ("2", "Collect", "Winlogbeat +\nJSON request logging", COLORS["teal"]),
        ("3", "Engineer", "Temporal, count, and\nbehavioral features", COLORS["blue"]),
        ("4", "Detect", "Isolation Forest scores\nunusual host and web rows", COLORS["teal"]),
        ("5", "Publish", "Elasticsearch indexing\nand Grafana dashboards", COLORS["blue"]),
    ]

    for idx, (number, title, body, color) in enumerate(steps):
        add_step(ax, xs[idx], number, title, body, color)
        if idx < len(steps) - 1:
            add_arrow(ax, xs[idx] + 0.07, xs[idx + 1] - 0.07)

    save(fig, "poster_methodology_flow.png")


def generate_results_overview(windows: pd.DataFrame, web: pd.DataFrame) -> None:
    win_rows = len(windows)
    web_rows = len(web)
    win_anoms = int(windows["is_anomaly"].sum())
    web_anoms = int(web["is_anomaly"].sum())
    win_rate = (win_anoms / win_rows) * 100
    web_rate = (web_anoms / web_rows) * 100

    severity_counts = web["severity"].value_counts().reindex(["critical", "high", "medium", "low"]).fillna(0)
    critical_alerts = int(severity_counts["critical"])

    win_gap_anom = windows.loc[windows["is_anomaly"], "inter_event_gap_seconds"].mean()
    win_gap_normal = windows.loc[~windows["is_anomaly"], "inter_event_gap_seconds"].mean()
    web_latency_anom = web.loc[web["is_anomaly"], "latency_ms"].mean()
    web_latency_normal = web.loc[~web["is_anomaly"], "latency_ms"].mean()

    fig = plt.figure(figsize=(16, 10))
    fig.subplots_adjust(left=0.06, right=0.98, top=0.90, bottom=0.08)
    gs = fig.add_gridspec(3, 4, height_ratios=[1.0, 1.0, 1.3], hspace=0.42, wspace=0.35)

    fig.suptitle("Obtained Results at a Glance", fontsize=24, fontweight="bold", color=COLORS["navy"], y=0.98)

    metric_card(fig.add_subplot(gs[0, 0]), "Windows anomalies", f"{win_anoms:,}", f"From {win_rows:,} scored rows", COLORS["teal"])
    metric_card(fig.add_subplot(gs[0, 1]), "Web anomalies", f"{web_anoms:,}", f"From {web_rows:,} scored rows", COLORS["orange"])
    metric_card(fig.add_subplot(gs[0, 2]), "Critical web alerts", f"{critical_alerts:,}", "Highest-priority web requests", COLORS["red"])
    metric_card(fig.add_subplot(gs[0, 3]), "Anomaly rates", f"{win_rate:.1f}% / {web_rate:.2f}%", "Windows vs web anomaly rate", COLORS["navy"])

    ax_rate = fig.add_subplot(gs[1:, 0])
    rate_labels = ["Windows", "Web"]
    rate_values = [win_rate, web_rate]
    rate_colors = [COLORS["green"], COLORS["red"]]
    bars = ax_rate.bar(rate_labels, rate_values, color=rate_colors)
    ax_rate.set_title("Anomaly Rate Comparison")
    ax_rate.set_ylabel("Percent")
    ax_rate.set_ylim(0, max(rate_values) * 1.25)
    for bar, value in zip(bars, rate_values):
        ax_rate.text(bar.get_x() + bar.get_width() / 2, value + 0.5, f"{value:.2f}%", ha="center", va="bottom", fontsize=12, color=COLORS["text"])

    ax_severity = fig.add_subplot(gs[1:, 1:3])
    sev_labels = [label.title() for label in severity_counts.index]
    sev_values = severity_counts.values
    sev_colors = [SEVERITY_COLORS[label] for label in severity_counts.index]
    bars = ax_severity.bar(sev_labels, sev_values, color=sev_colors)
    ax_severity.set_title("Web Severity Distribution")
    ax_severity.set_ylabel("Alert count")
    for bar, value in zip(bars, sev_values):
        ax_severity.text(bar.get_x() + bar.get_width() / 2, value + max(sev_values) * 0.02, f"{int(value):,}", ha="center", va="bottom", fontsize=11, color=COLORS["text"])

    insight_lines = [
        f"Windows anomaly gap: {win_gap_anom:.2f} s vs {win_gap_normal:.2f} s normal",
        f"Web anomaly latency: {web_latency_anom:.2f} ms vs {web_latency_normal:.2f} ms normal",
        "Web anomalies are driven by high request rate, path diversity, client errors, and auth failures",
        "Windows anomalies highlight non-baseline Event IDs such as 5379, 4702, and 4798",
    ]
    info_panel(fig.add_subplot(gs[1:, 3]), "Key observations", insight_lines)

    save(fig, "poster_results_overview.png")


def generate_alert_patterns(windows: pd.DataFrame, web: pd.DataFrame) -> None:
    win_top = (
        windows.loc[windows["is_anomaly"], "EventID"]
        .astype(str)
        .value_counts()
        .head(5)
        .sort_values()
    )
    web_top_paths = (
        web.loc[web["is_anomaly"], "path"]
        .astype(str)
        .value_counts()
        .head(6)
        .sort_values()
    )

    reason_counter = (
        web.loc[web["is_anomaly"], "reason_tags"]
        .fillna("")
        .str.split("|")
        .explode()
        .str.strip()
    )
    reason_counter = reason_counter[reason_counter.ne("")]
    top_reasons = reason_counter.value_counts().head(6).sort_values()

    fig = plt.figure(figsize=(16, 8.5))
    fig.subplots_adjust(left=0.07, right=0.98, top=0.88, bottom=0.08)
    gs = fig.add_gridspec(2, 2, height_ratios=[1.0, 1.0], hspace=0.42, wspace=0.35)
    fig.suptitle("Dominant Alert Patterns", fontsize=24, fontweight="bold", color=COLORS["navy"], y=0.97)

    ax_win = fig.add_subplot(gs[0, 0])
    ax_win.barh(win_top.index, win_top.values, color=COLORS["teal"])
    ax_win.set_title("Top anomalous Windows Event IDs")
    ax_win.set_xlabel("Anomalous rows")
    for value, label in zip(win_top.values, win_top.index):
        ax_win.text(value + 2, label, f"{value}", va="center", fontsize=11, color=COLORS["text"])

    ax_web = fig.add_subplot(gs[0, 1])
    ax_web.barh(web_top_paths.index, web_top_paths.values, color=COLORS["orange"])
    ax_web.set_title("Top anomalous web paths")
    ax_web.set_xlabel("Anomalous requests")
    for value, label in zip(web_top_paths.values, web_top_paths.index):
        ax_web.text(value + 10, label, f"{value}", va="center", fontsize=11, color=COLORS["text"])

    ax_reason = fig.add_subplot(gs[1, :])
    ax_reason.barh(top_reasons.index, top_reasons.values, color=COLORS["blue"])
    ax_reason.set_title("Most frequent web reason tags inside anomalies")
    ax_reason.set_xlabel("Tagged anomalous requests")
    for value, label in zip(top_reasons.values, top_reasons.index):
        ax_reason.text(value + 15, label, f"{value}", va="center", fontsize=11, color=COLORS["text"])

    save(fig, "poster_alert_patterns.png")


def main() -> None:
    apply_style()
    windows, web = load_data()
    generate_methodology_flow()
    generate_results_overview(windows, web)
    generate_alert_patterns(windows, web)
    print("Poster figures generated in", POSTER_FIGURES)


if __name__ == "__main__":
    main()
