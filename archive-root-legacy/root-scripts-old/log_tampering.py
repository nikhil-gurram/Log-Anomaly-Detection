"""Create a tampered version of exported logs for ML robustness testing."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def drop_suspicious_events(df: pd.DataFrame, suspicious_ids: list[int], drop_ratio: float, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    suspicious_mask = df["EventID"].isin(suspicious_ids)
    suspicious_idx = df[suspicious_mask].index.to_numpy()

    if suspicious_idx.size == 0:
        return df

    delete_count = max(1, int(len(suspicious_idx) * drop_ratio))
    to_delete = rng.choice(suspicious_idx, size=min(delete_count, len(suspicious_idx)), replace=False)
    return df.drop(index=to_delete)


def shuffle_timestamps(df: pd.DataFrame, shuffle_ratio: float, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    df = df.copy()

    sample_size = int(len(df) * shuffle_ratio)
    if sample_size < 2:
        return df

    sampled_idx = rng.choice(df.index.to_numpy(), size=sample_size, replace=False)
    shuffled_times = df.loc[sampled_idx, "TimeCreated"].sample(frac=1.0, random_state=seed).to_numpy()
    df.loc[sampled_idx, "TimeCreated"] = shuffled_times
    return df


def create_log_gaps(df: pd.DataFrame, gap_blocks: int, max_block_size: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    if len(df) < 10:
        return df

    df = df.sort_values("TimeCreated").reset_index(drop=True)
    rows_to_drop: set[int] = set()

    for _ in range(gap_blocks):
        start = int(rng.integers(0, len(df) - 1))
        block_size = int(rng.integers(2, max(3, max_block_size)))
        end = min(len(df), start + block_size)
        rows_to_drop.update(range(start, end))

    kept = df.drop(index=list(rows_to_drop)).reset_index(drop=True)
    return kept


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate log tampering on Sysmon CSV exports")
    parser.add_argument("--input", default="data/sysmon_logs.csv", help="Input raw log CSV")
    parser.add_argument("--output", default="data/tampered_logs.csv", help="Output tampered CSV")
    parser.add_argument("--drop-ratio", type=float, default=0.35, help="Fraction of suspicious rows to remove")
    parser.add_argument("--shuffle-ratio", type=float, default=0.25, help="Fraction of rows with shuffled timestamps")
    parser.add_argument("--gap-blocks", type=int, default=4, help="How many gap blocks to create")
    parser.add_argument("--max-gap-size", type=int, default=8, help="Maximum rows removed per gap block")
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_path)
    required_columns = {"TimeCreated", "EventID", "Message"}
    missing = required_columns.difference(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")
    df = df.dropna(subset=["TimeCreated"]).reset_index(drop=True)

    suspicious_ids = [1, 3, 11, 13]
    tampered = drop_suspicious_events(df, suspicious_ids, args.drop_ratio, args.seed)
    tampered = shuffle_timestamps(tampered, args.shuffle_ratio, args.seed + 1)
    tampered = create_log_gaps(tampered, args.gap_blocks, args.max_gap_size, args.seed + 2)

    tampered = tampered.sort_values("TimeCreated").reset_index(drop=True)
    tampered.to_csv(output_path, index=False)

    print(f"[INFO] Saved tampered log file: {output_path}")
    print(f"[INFO] Original rows: {len(df)}")
    print(f"[INFO] Tampered rows: {len(tampered)}")


if __name__ == "__main__":
    main()
