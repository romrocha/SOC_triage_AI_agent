#!/usr/bin/env python3
"""
Write ground_truth.csv for a given input round directory (TheHive mockup layout).

Usage:
  python scripts/generate_ground_truth.py --round round1
  python scripts/generate_ground_truth.py --input /path/to/dataset
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from security_agent.app.config import INPUT_ROOT, RESEARCH_ROUND  # noqa: E402
from security_agent.app.experiments.ground_truth import write_ground_truth_csv  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description="Generate ground_truth.csv from noise/ + campaing-* JSON.")
    p.add_argument(
        "--round",
        default=None,
        help=f"Round name (folder under input/). Default: env RESEARCH_ROUND or {RESEARCH_ROUND!r}",
    )
    p.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Explicit dataset root (overrides --round)",
    )
    args = p.parse_args()
    if args.input is not None:
        root = args.input.resolve()
    else:
        r = args.round or RESEARCH_ROUND
        root = (INPUT_ROOT / r).resolve()
    if not root.is_dir():
        raise SystemExit(f"Dataset directory does not exist: {root}")
    out = write_ground_truth_csv(root)
    rows = sum(1 for _ in out.open("r", encoding="utf-8")) - 1
    print(f"Wrote {rows} data rows to {out}")


if __name__ == "__main__":
    main()
