"""Simulate suspicious Windows activity to generate security-relevant logs.

This script is intentionally non-destructive. It emulates noisy behavior that is
commonly associated with suspicious activity so Sysmon and Security logs can be
used for blue-team analytics.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_FILE_COUNT = 30
SCENARIOS = ("all", "recon-blend", "powershell-spike", "service-enumeration", "file-burst")


def run_powershell(command: str, timeout: int = 20) -> None:
    """Run a PowerShell command and ignore output unless an error occurs."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        print(f"[WARN] PowerShell command failed: {command}")
        if result.stderr:
            print(result.stderr.strip())


def simulate_powershell_spike(iterations: int, sleep_seconds: float) -> None:
    print(f"[INFO] Simulating repeated PowerShell activity ({iterations} iterations)...")
    for i in range(iterations):
        # Lightweight command that still creates PowerShell process activity.
        run_powershell("Get-Date | Out-Null")
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
        if (i + 1) % 10 == 0:
            print(f"[INFO] Completed {i + 1}/{iterations} PowerShell executions")


def simulate_service_enumeration(iterations: int, sleep_seconds: float) -> None:
    print(f"[INFO] Simulating service enumeration ({iterations} iterations)...")
    for i in range(iterations):
        run_powershell("Get-Service | Select-Object -First 50 | Out-Null")
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
        if (i + 1) % 5 == 0:
            print(f"[INFO] Completed {i + 1}/{iterations} service queries")


def simulate_rapid_file_creation(target_dir: Path, file_count: int, burst_delay: float) -> None:
    print(f"[INFO] Simulating rapid file creation in {target_dir} ({file_count} files)...")
    target_dir.mkdir(parents=True, exist_ok=True)

    for i in range(file_count):
        file_path = target_dir / f"attack_file_{i:03d}.txt"
        with file_path.open("w", encoding="utf-8") as handle:
            handle.write(f"suspicious_simulation_index={i}\n")
            handle.write(f"created_at={datetime.now(timezone.utc).isoformat()}\n")
            handle.write("This file is generated to trigger file creation telemetry.\n")
        if burst_delay > 0:
            time.sleep(burst_delay)

    print(f"[INFO] File creation simulation complete. Created {file_count} files.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate suspicious activity for SOC testing")
    parser.add_argument("--scenario", choices=SCENARIOS, default="all")
    parser.add_argument("--powershell-iterations", type=int, default=25)
    parser.add_argument("--service-iterations", type=int, default=10)
    parser.add_argument("--file-count", type=int, default=DEFAULT_FILE_COUNT)
    parser.add_argument("--command-sleep", type=float, default=0.2)
    parser.add_argument("--file-burst-delay", type=float, default=0.03)
    parser.add_argument("--attack-dir", default="attack_files")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    attack_dir = Path(args.attack_dir)
    if not attack_dir.is_absolute():
        attack_dir = Path.cwd() / attack_dir

    print("[INFO] Starting attack behavior simulation")
    print(f"[INFO] Working directory: {os.getcwd()}")
    print(f"[INFO] Scenario: {args.scenario}")

    if args.scenario in {"all", "recon-blend", "powershell-spike"}:
        simulate_powershell_spike(args.powershell_iterations, args.command_sleep)

    if args.scenario in {"all", "recon-blend", "service-enumeration"}:
        simulate_service_enumeration(args.service_iterations, args.command_sleep)

    if args.scenario in {"all", "file-burst"}:
        simulate_rapid_file_creation(attack_dir, args.file_count, args.file_burst_delay)

    print("[INFO] Attack simulation complete. Export Sysmon logs next for analysis.")


if __name__ == "__main__":
    main()
