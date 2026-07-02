#!/usr/bin/env python3
"""
Compare model performance across rounds from eval_runs.csv.

Usage:
  python scripts/compare_models.py
  python scripts/compare_models.py --csv data/eval_runs.csv
  python scripts/compare_models.py --round round1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import pandas as pd


def _pct(val: float) -> str:
    try:
        return f"{float(val):.2%}"
    except (ValueError, TypeError):
        return "—"


def print_comparison(csv_path: Path, round_filter: str | None = None) -> str:
    df = pd.read_csv(csv_path, dtype=str)
    required = {"input_round", "model", "label_acc", "camp_f1", "fp_f1", "camp_recall", "camp_precision"}
    if not required.issubset(df.columns):
        missing = required - set(df.columns)
        return f"Missing columns in {csv_path}: {missing}"

    if round_filter:
        df = df[df["input_round"] == round_filter]
    if df.empty:
        return "No eval runs found."

    float_cols = ["label_acc", "camp_f1", "fp_f1", "camp_recall", "camp_precision", "fp_recall", "fp_precision"]
    for c in float_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    last_per_group = df.groupby(["input_round", "model"]).last().reset_index()
    last_per_group = last_per_group.sort_values(["input_round", "model"])

    lines: list[str] = []
    sep = "=" * 95

    for rnd, grp in last_per_group.groupby("input_round"):
        lines.append(sep)
        lines.append(f"  {rnd}")
        lines.append(sep)
        lines.append("")
        header = (
            f"  {'Model':<20} {'Accuracy':>10} {'Camp F1':>10} {'FP F1':>10}"
            f" {'Camp Recall':>12} {'Camp Prec':>11} {'FP Recall':>10}"
        )
        lines.append(header)
        lines.append("  " + "─" * (len(header.strip())))
        for _, row in grp.iterrows():
            model = str(row["model"])
            lines.append(
                f"  {model:<20}"
                f" {_pct(row['label_acc']):>10}"
                f" {_pct(row['camp_f1']):>10}"
                f" {_pct(row['fp_f1']):>10}"
                f" {_pct(row['camp_recall']):>12}"
                f" {_pct(row['camp_precision']):>11}"
                f" {_pct(row.get('fp_recall', float('nan'))):>10}"
            )
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(description="Compare model eval runs side-by-side")
    p.add_argument(
        "--csv",
        type=Path,
        default=_REPO / "data" / "eval_runs.csv",
        help="Path to eval_runs.csv",
    )
    p.add_argument("--round", default=None, help="Filter to a specific round")
    args = p.parse_args()

    if not args.csv.exists():
        print(f"File not found: {args.csv}", file=sys.stderr)
        sys.exit(1)

    output = print_comparison(args.csv, args.round)
    print(output)


if __name__ == "__main__":
    main()
