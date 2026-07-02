from pathlib import Path

import pandas as pd

from security_agent.app.experiments.eval import (
    append_eval_run_csv,
    confusion_dataframes,
    evaluate_against_ground_truth,
    evaluate_and_log,
    format_eval_report,
)
from security_agent.app.ingestion.sqlite_store import SQLiteStore


def _tiny_gt_and_db(tmp_path: Path) -> tuple[Path, Path]:
    gt = pd.DataFrame(
        [
            {"alert_id": "a1", "expected_label": "false_positive", "expected_campaign_id": ""},
            {"alert_id": "a2", "expected_label": "in_campaign", "expected_campaign_id": "c1"},
        ]
    )
    gt_path = tmp_path / "ground_truth.csv"
    gt.to_csv(gt_path, index=False)

    db_path = tmp_path / "alerts.db"
    store = SQLiteStore(db_path=db_path)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, status, campaign_id) VALUES (?, ?, ?)",
        ("a1", "false_positive", None),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, status, campaign_id) VALUES (?, ?, ?)",
        ("a2", "in_campaign", "c1"),
    )
    store.conn.execute(
        "INSERT INTO campaigns (campaign_id, alerts, confidence, rationale, summary) "
        "VALUES (?,?,?,?,?)",
        ("c1", '["a2"]', 0.9, "reason", "summary"),
    )
    store.conn.commit()
    store.conn.close()
    return gt_path, db_path


def test_evaluate_perfect_match(tmp_path: Path) -> None:
    gt_path, db_path = _tiny_gt_and_db(tmp_path)

    m = evaluate_against_ground_truth(gt_path, db_path)
    assert m["input_round"] == tmp_path.name
    assert m["label_acc"] == 1.0
    assert m["fp_tp"] + m["fp_fp"] + m["fp_fn"] + m["fp_tn"] == 2
    assert m["missed_threats_count"] == 0
    assert m["missed_threats_ids"] == []
    assert m["campaigns_expected"] == 1
    assert m["campaigns_detected"] == 1
    assert m["campaign_completeness"] == 1.0
    assert m["campaign_purity"] == 1.0
    assert m["campaign_splits"] == 0
    assert m["campaign_merges"] == 0
    report = format_eval_report(m)
    assert "EVALUATION (vs Ground Truth)" in report
    assert "Overall Label Accuracy: 100.00%" in report
    assert "NOISE FILTERING" in report
    assert "CAMPAIGN DETECTION" in report
    assert "MISSED THREATS: 0" in report
    assert "CAMPAIGN QUALITY" in report


def test_evaluate_missed_threats(tmp_path: Path) -> None:
    """Campaign alert marked as false_positive should appear as a missed threat."""
    gt = pd.DataFrame(
        [
            {"alert_id": "a1", "expected_label": "false_positive", "expected_campaign_id": ""},
            {"alert_id": "a2", "expected_label": "in_campaign", "expected_campaign_id": "c1"},
            {"alert_id": "a3", "expected_label": "in_campaign", "expected_campaign_id": "c1"},
        ]
    )
    gt_path = tmp_path / "ground_truth.csv"
    gt.to_csv(gt_path, index=False)

    db_path = tmp_path / "alerts.db"
    store = SQLiteStore(db_path=db_path)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, status, campaign_id) VALUES (?, ?, ?)",
        ("a1", "false_positive", None),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, status, campaign_id) VALUES (?, ?, ?)",
        ("a2", "in_campaign", "c1"),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, status, campaign_id) VALUES (?, ?, ?)",
        ("a3", "false_positive", None),
    )
    store.conn.commit()
    store.conn.close()

    m = evaluate_against_ground_truth(gt_path, db_path)
    assert m["missed_threats_count"] == 1
    assert m["missed_threats_ids"] == ["a3"]

    report = format_eval_report(m)
    assert "MISSED THREATS: 1" in report
    assert "a3" in report
    assert "dismissed as false positive" in report.lower() or "dismissed as noise" in report.lower()


def test_confusion_dataframes(tmp_path: Path) -> None:
    gt_path, db_path = _tiny_gt_and_db(tmp_path)
    m = evaluate_against_ground_truth(gt_path, db_path)
    fp_c, camp_c = confusion_dataframes(m)
    assert fp_c.shape == (2, 2)
    assert camp_c.shape == (2, 2)


def test_evaluate_and_log_appends_csv(tmp_path: Path) -> None:
    gt_path, db_path = _tiny_gt_and_db(tmp_path)
    log = tmp_path / "eval_runs.csv"
    m = evaluate_and_log(gt_path, db_path, log)
    assert "timestamp" in m
    assert log.is_file()
    df = pd.read_csv(log)
    assert len(df) == 1
    assert df["label_acc"].iloc[0] == 1.0

    evaluate_and_log(gt_path, db_path, log)
    df2 = pd.read_csv(log)
    assert len(df2) == 2


def test_append_eval_run_csv_union_columns(tmp_path: Path) -> None:
    log = tmp_path / "e.csv"
    append_eval_run_csv(log, {"a": 1, "b": 2})
    append_eval_run_csv(log, {"a": 3, "c": 4})
    df = pd.read_csv(log)
    assert len(df) == 2
    assert pd.isna(df["c"].iloc[0]) or str(df["c"].iloc[0]) == "nan"
