import json
from pathlib import Path

from security_agent.app.experiments.ground_truth import (
    build_ground_truth_rows,
    write_ground_truth_csv,
)


def _write_alert(path: Path, source_ref: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [{"sourceRef": source_ref, "title": "t"}]
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_build_ground_truth_rows(tmp_path: Path) -> None:
    _write_alert(tmp_path / "noise" / "n.json", "noise-1")
    _write_alert(tmp_path / "campaing-a" / "a.json", "ca-1")
    _write_alert(tmp_path / "campaing-b" / "b.json", "cb-1")
    rows = build_ground_truth_rows(tmp_path)
    by_id = {r["alert_id"]: r for r in rows}
    assert by_id["noise-1"]["expected_label"] == "false_positive"
    assert by_id["ca-1"]["expected_label"] == "in_campaign"
    assert by_id["ca-1"]["expected_campaign_id"] == "campaing-a"
    assert by_id["cb-1"]["expected_campaign_id"] == "campaing-b"


def test_write_ground_truth_csv_roundtrip(tmp_path: Path) -> None:
    _write_alert(tmp_path / "noise" / "n.json", "x-1")
    out = write_ground_truth_csv(tmp_path)
    assert out.name == "ground_truth.csv"
    text = out.read_text(encoding="utf-8")
    assert "x-1" in text
    assert "false_positive" in text
