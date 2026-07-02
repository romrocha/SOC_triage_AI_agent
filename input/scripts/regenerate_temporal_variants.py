#!/usr/bin/env python3
"""Generate temporal variants of the canonical round1 dataset.

This script takes the round1 dataset as the single source of truth and
produces round2 (90 days) and round3 (180 days) variants that are
identical in every respect EXCEPT the temporal distribution.

Design rules (so the only variable across rounds is time):

* Same alert_ids (sourceRef), titles, descriptions, severities, sources,
  tags, TLP/PAP, status, flag, observables (dataType + data + message).
* Same internal ordering of events per file (campaign-a, campaign-b,
  noise) — i.e. the i-th alert in round1's noise file corresponds to
  the i-th alert in round2's noise file.
* Linear rescaling of `date` (epoch ms): the anchor (earliest date)
  stays at round1's anchor; each event's offset from the anchor is
  multiplied by ``new_span / round1_span`` so the relative *shape* of
  the temporal distribution is preserved across rounds.

Usage::

    python scripts/regenerate_temporal_variants.py

Pre-requisite: ``input/round1/`` exists and was produced by
``regenerate_round1_dataset.py`` (the canonical generator). The script
overwrites ``input/round2/`` and ``input/round3/`` and regenerates
their ``ground_truth.csv`` via :mod:`scripts.generate_ground_truth`.

Why a separate script and not just edit r2/r3 generators? Two reasons:

1. **Single source of truth.** The campaign specs (~50KB of dataclass
   literals) live exactly once, in round1's generator. Round2 and
   round3 derive from it — keeps the three rounds in sync forever.
2. **Defensible methodology.** "Only the temporal axis varies" becomes
   a verifiable mechanical property: this script's output has the
   property by construction. The legacy
   ``regenerate_round{2,3}_dataset.py`` generated content
   independently, which silently broke parity.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
INPUT_DIR = REPO_ROOT / "input"
ROUND1_DIR = INPUT_DIR / "round1_no_ioc"
GROUND_TRUTH_SCRIPT = REPO_ROOT / "scripts" / "generate_ground_truth.py"


# Each round = (output dir name, target span in days).
# round1 is the reference (~30 days); not regenerated here.
TARGET_ROUNDS: List[Tuple[str, int]] = [
    ("round2_no_ioc", 90),
    ("round3_no_ioc", 180),
]


# Files inside each round directory.
ROUND_FILES = [
    ("campaing-a", "finance-ransomware-alerts.json"),
    ("campaing-b", "hr-insider-threat-alerts.json"),
    ("noise", "noise-alerts.json"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_round(round_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Read all 3 alert files for a round, keyed by sub-folder name."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for sub, fname in ROUND_FILES:
        path = round_dir / sub / fname
        if not path.exists():
            raise SystemExit(f"missing source file: {path}")
        with path.open("r", encoding="utf-8") as f:
            out[sub] = json.load(f)
    return out


def _round_span_ms(alerts: Dict[str, List[Dict[str, Any]]]) -> Tuple[int, int]:
    """Return (min_date, max_date) in epoch ms across ALL files of a round."""
    dates: List[int] = []
    for items in alerts.values():
        for alert in items:
            d = alert.get("date")
            if isinstance(d, (int, float)):
                dates.append(int(d))
    if not dates:
        raise SystemExit("no `date` field found in source — corrupt input")
    return min(dates), max(dates)


def _rescale_date(date_ms: int, anchor_ms: int, scale: float) -> int:
    """Linearly rescale a date keeping the anchor fixed.

    new_date = anchor + (old_date - anchor) * scale

    For scale = 3 (90d from 30d source), an event at +5d becomes +15d.
    For scale = 6 (180d from 30d), the same event becomes +30d.
    Anchor itself is preserved so the round still "starts" on the same
    moment as round1.
    """
    offset = date_ms - anchor_ms
    return anchor_ms + int(round(offset * scale))


def _emit_round(
    target_dir: Path,
    source: Dict[str, List[Dict[str, Any]]],
    anchor_ms: int,
    src_span_ms: int,
    target_span_days: int,
) -> Tuple[int, int]:
    """Write a temporal-variant round. Returns (out_min_ms, out_max_ms)."""
    target_span_ms = target_span_days * 86_400 * 1000
    if src_span_ms <= 0:
        raise SystemExit("source span is zero — cannot rescale")
    scale = target_span_ms / src_span_ms

    out_min = float("inf")
    out_max = float("-inf")

    for sub, fname in ROUND_FILES:
        out_path = target_dir / sub / fname
        out_path.parent.mkdir(parents=True, exist_ok=True)

        rescaled = []
        for alert in source[sub]:
            # Deep copy via JSON round-trip to keep the script obviously
            # side-effect free; perf doesn't matter for ~100 alerts.
            new_alert = json.loads(json.dumps(alert))
            old_date = int(new_alert.get("date", anchor_ms))
            new_date = _rescale_date(old_date, anchor_ms, scale)
            new_alert["date"] = new_date
            out_min = min(out_min, new_date)
            out_max = max(out_max, new_date)
            rescaled.append(new_alert)

        with out_path.open("w", encoding="utf-8") as f:
            json.dump(rescaled, f, indent=2, ensure_ascii=False)

    return int(out_min), int(out_max)


def _regen_ground_truth(round_dir: Path) -> None:
    """Re-run the existing ground_truth.csv generator for this round.

    ``generate_ground_truth.py`` accepts ``--input <round_dir>`` and writes
    ``ground_truth.csv`` inside that directory.
    """
    if not GROUND_TRUTH_SCRIPT.exists():
        print(f"warning: {GROUND_TRUTH_SCRIPT} not found — skipping ground_truth")
        return
    rel = round_dir.relative_to(REPO_ROOT)
    try:
        subprocess.run(
            [sys.executable, str(GROUND_TRUTH_SCRIPT), "--input", str(rel)],
            check=True,
            cwd=str(REPO_ROOT),
        )
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"generate_ground_truth.py failed for {rel}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print(f"reading canonical round: {ROUND1_DIR.relative_to(REPO_ROOT)}")
    source = _load_round(ROUND1_DIR)
    anchor_ms, max_ms = _round_span_ms(source)
    src_span_ms = max_ms - anchor_ms
    src_span_days = src_span_ms / (86_400 * 1000)

    print(
        f"  anchor (min date): {anchor_ms}  "
        f"max date: {max_ms}  span: {src_span_days:.2f} days"
    )

    for out_name, days in TARGET_ROUNDS:
        target_dir = INPUT_DIR / out_name
        print(f"\ngenerating {out_name} (target span = {days} days)")
        out_min, out_max = _emit_round(target_dir, source, anchor_ms, src_span_ms, days)
        actual_days = (out_max - out_min) / (86_400 * 1000)
        print(
            f"  wrote files to {target_dir.relative_to(REPO_ROOT)}/  "
            f"actual span: {actual_days:.2f} days"
        )
        _regen_ground_truth(target_dir)

    print("\ndone — temporal variants generated from round1.")


if __name__ == "__main__":
    main()
