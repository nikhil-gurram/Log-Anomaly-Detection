"""Export Sysmon events to CSV using PowerShell Get-WinEvent.

Use this script after running attack simulation to create datasets for feature
engineering and model training.
"""

from __future__ import annotations

import argparse
import csv
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export Sysmon logs to CSV")
    parser.add_argument("--max-events", type=int, default=5000)
    parser.add_argument("--output", default="data/sysmon_logs.csv")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    ps_script = """
$ErrorActionPreference = 'Stop'
$events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents {max_events} |
    Select-Object TimeCreated, Id, Message

if (-not $events -or $events.Count -eq 0) {{
    throw 'No Sysmon events were returned. Ensure Sysmon is installed, running, and that this terminal has permission to read logs.'
}}

$events |
    Select-Object @{{Name='TimeCreated';Expression={{ $_.TimeCreated.ToString('o') }}}},
                  @{{Name='EventID';Expression={{ $_.Id }}}},
                  @{{Name='Message';Expression={{ $_.Message }}}} |
    Export-Csv -Path '{output_file}' -NoTypeInformation -Encoding UTF8
""".format(max_events=args.max_events, output_file=output_path.as_posix())

    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Failed to export Sysmon logs. Ensure Sysmon is installed and run with administrator privileges.\n"
            + result.stderr
        )

    if not output_path.exists() or output_path.stat().st_size == 0:
        raise RuntimeError(
            "Export completed but output CSV is empty. Run the terminal as Administrator and verify Sysmon events exist."
        )

    with output_path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))

    if len(rows) < 2:
        raise RuntimeError(
            "Exported CSV has no event rows. Run attack simulation, then export again from an elevated terminal."
        )

    print(f"[INFO] Sysmon logs exported to {output_path} ({len(rows) - 1} rows)")


if __name__ == "__main__":
    main()
