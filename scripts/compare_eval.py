#!/usr/bin/env python3
"""
Compare SQLite alert predictions to ground_truth.csv (same metrics as experiment notebook).

Usage:
  python scripts/compare_eval.py
  python scripts/compare_eval.py --db data/alerts.db --gt input/round1/ground_truth.csv
  python scripts/compare_eval.py --json-out output/round1/metrics.json
  python scripts/compare_eval.py --write-metrics-json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from security_agent.app.config import (  # noqa: E402
    GROUND_TRUTH_PATH,
    ROUND_OUTPUT_DIR,
    SQLITE_DB,
)
from security_agent.app.experiments.eval import (  # noqa: E402
    evaluate_against_ground_truth,
    format_eval_report,
)


def _resolve_gt(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    gt = GROUND_TRUTH_PATH
    if gt.is_file():
        return gt.resolve()
    raise FileNotFoundError(f"ground_truth.csv not found at {gt}")


def main() -> None:
    p = argparse.ArgumentParser(description="Evaluate agent DB vs ground truth CSV")
    p.add_argument("--db", type=Path, default=SQLITE_DB, help="Path to alerts.db")
    p.add_argument("--gt", type=Path, default=None, help="Path to ground_truth.csv")
    p.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Write metrics dict to this JSON file",
    )
    p.add_argument(
        "--write-metrics-json",
        action="store_true",
        help=f"Also write metrics to {ROUND_OUTPUT_DIR / 'metrics.json'}",
    )
    p.add_argument("--quiet", action="store_true", help="Only print JSON to stdout")
    args = p.parse_args()

    gt_path = _resolve_gt(args.gt)
    db_path = args.db.resolve()
    metrics = evaluate_against_ground_truth(gt_path, db_path)

    json_out = args.json_out
    if args.write_metrics_json and json_out is None:
        ROUND_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        json_out = ROUND_OUTPUT_DIR / "metrics.json"

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        with json_out.open("w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        if not args.quiet:
            print(f"Wrote {json_out}", file=sys.stderr)

    if not args.quiet:
        print(format_eval_report(metrics))
    else:
        print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
