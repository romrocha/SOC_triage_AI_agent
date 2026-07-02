"""
Build ground_truth.csv from a TheHive-mockup directory layout.

The default `DATASET_FOLDER_SPECS` covers noise + campaing-a + campaing-b (round 1).
For rounds with **additional campaign folders**, extend `DATASET_FOLDER_SPECS` with
`(folder_name, "in_campaign", expected_campaign_id)` rows so new folders are scanned.
See `input/README.md`.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# (subfolder, expected_label, expected_campaign_id when in_campaign)
DATASET_FOLDER_SPECS: Tuple[Tuple[str, str, str], ...] = (
    ("noise", "false_positive", ""),
    ("campaing-a", "in_campaign", "campaing-a"),
    ("campaing-b", "in_campaign", "campaing-b"),
)


def _alert_id_from_item(item: Dict[str, Any]) -> str:
    aid = item.get("sourceRef") or item.get("id") or item.get("alert_id")
    if not aid:
        raise ValueError("Missing sourceRef/id/alert_id in alert record")
    return str(aid)


def build_ground_truth_rows(root: Path) -> List[Dict[str, str]]:
    """
    Scan `root` for each folder listed in `DATASET_FOLDER_SPECS` and build row dicts.
    """
    rows: List[Dict[str, str]] = []
    for folder, label, camp_id in DATASET_FOLDER_SPECS:
        dir_path = root / folder
        if not dir_path.is_dir():
            continue
        for fp in sorted(dir_path.glob("*.json")):
            with fp.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                rows.append(
                    {
                        "alert_id": _alert_id_from_item(item),
                        "expected_label": label,
                        "expected_campaign_id": camp_id if label == "in_campaign" else "",
                    }
                )
    return rows


def write_ground_truth_csv(
    root: Path,
    out_path: Optional[Path] = None,
) -> Path:
    """
    Write ground_truth.csv under `root` (default) or to `out_path`.
    """
    out = out_path or (root / "ground_truth.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = build_ground_truth_rows(root)
    fieldnames = ["alert_id", "expected_label", "expected_campaign_id"]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    return out
