"""report_export: human-readable report from SQLite."""

from pathlib import Path

import pandas as pd

from security_agent.app.experiments.report_export import build_campaign_report_body
from security_agent.app.ingestion.sqlite_store import SQLiteStore


def test_build_campaign_report_body_empty_campaigns(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    store = SQLiteStore(db_path=db)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status) "
        "VALUES (?,?,?,?,?,?,?)",
        ("x1", "t", "d", "1", "0", "{}", "unprocessed"),
    )
    store.conn.commit()
    text = build_campaign_report_body(store, generated_at="2026-04-05T18:00:00.000Z")
    assert "Report generated at (UTC): 2026-04-05T18:00:00.000Z" in text
    assert "CAMPAIGN ANALYSIS REPORT" in text
    assert "Total Campaigns Detected: 0" in text
    assert "Unprocessed: 1" in text
    assert "ALERT STATUS SUMMARY" in text


def test_build_full_report_with_eval(tmp_path: Path) -> None:
    from security_agent.app.experiments.report_export import build_full_report_with_eval

    gt = pd.DataFrame(
        [
            {"alert_id": "a1", "expected_label": "false_positive", "expected_campaign_id": ""},
        ]
    )
    gt_path = tmp_path / "ground_truth.csv"
    gt.to_csv(gt_path, index=False)

    db_path = tmp_path / "b.db"
    store = SQLiteStore(db_path=db_path)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status) "
        "VALUES (?,?,?,?,?,?,?)",
        ("a1", "t", "d", "1", "0", "{}", "false_positive"),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("c1", "campaign alert", "campaign desc", "2", "1", "{}", "in_campaign", "Cortex XDR"),
    )
    store.conn.execute(
        "INSERT INTO campaigns (campaign_id, alerts, confidence, rationale, summary, run_id, created_at) "
        "VALUES (?,?,?,?,?,?,datetime('now'))",
        ("camp-1", '["c1"]', 0.8, "same case", "campaign summary", "run-1"),
    )
    store.conn.commit()

    text = build_full_report_with_eval(
        store,
        gt_path,
        db_path,
        generated_at="2026-04-05T18:00:00.000Z",
    )
    assert "Report generated at (UTC): 2026-04-05T18:00:00.000Z" in text
    assert "Alerts In This Case (chronological):" in text
    assert "c1 | campaign alert | source=Cortex XDR" in text
    assert "status=in_campaign" in text
    assert "APPENDIX: FALSE POSITIVE DETAILS" in text
    assert "a1 | t | source=(no source)" in text
    assert "EVALUATION (vs Ground Truth)" in text
    assert "Overall Label Accuracy" in text
    assert "MISSED THREATS: 0" in text
    assert "CAMPAIGN QUALITY" in text


def test_build_full_report_missed_threats_detail(tmp_path: Path) -> None:
    """When a campaign alert is dismissed as FP, the report should show enriched details."""
    from security_agent.app.experiments.report_export import build_full_report_with_eval

    gt = pd.DataFrame(
        [
            {"alert_id": "a1", "expected_label": "in_campaign", "expected_campaign_id": "c1"},
        ]
    )
    gt_path = tmp_path / "ground_truth.csv"
    gt.to_csv(gt_path, index=False)

    db_path = tmp_path / "c.db"
    store = SQLiteStore(db_path=db_path)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status, source, false_positive_reason) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ("a1", "Lateral movement via SMB", "desc", "3", "0", "{}", "false_positive", "CrowdStrike Falcon", "Seed alert, not correlated"),
    )
    store.conn.commit()

    text = build_full_report_with_eval(
        store, gt_path, db_path, generated_at="2026-04-05T18:00:00.000Z",
    )
    assert "MISSED THREATS: 1" in text
    assert "MISSED THREAT DETAILS" in text
    assert "a1" in text
    assert "Lateral movement via SMB" in text
    assert "CrowdStrike Falcon" in text
    assert "Seed alert, not correlated" in text


def test_epoch_ms_to_iso_in_alert_line(tmp_path: Path) -> None:
    """Alert dates should render as ISO 8601 in the report."""
    from security_agent.app.experiments.report_export import build_full_report_with_eval

    gt = pd.DataFrame(
        [{"alert_id": "a1", "expected_label": "in_campaign", "expected_campaign_id": "c1"}]
    )
    gt_path = tmp_path / "ground_truth.csv"
    gt.to_csv(gt_path, index=False)

    db_path = tmp_path / "d.db"
    store = SQLiteStore(db_path=db_path)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("a1", "Test alert", "desc", "2", "1732715520000", "{}", "in_campaign", "Splunk"),
    )
    store.conn.execute(
        "INSERT INTO campaigns (campaign_id, alerts, confidence, rationale, summary, run_id, created_at) "
        "VALUES (?,?,?,?,?,?,datetime('now'))",
        ("camp-1", '["a1"]', 0.9, "reason", "summary", "run-1"),
    )
    store.conn.commit()

    text = build_full_report_with_eval(store, gt_path, db_path, generated_at="2026-04-05T18:00:00.000Z")
    assert "2024-11-27T" in text
    assert "1732715520000" not in text


def test_timeline_ordering(tmp_path: Path) -> None:
    """Campaign alerts should be ordered chronologically, not by UUID."""
    db = tmp_path / "e.db"
    store = SQLiteStore(db_path=db)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status) "
        "VALUES (?,?,?,?,?,?,?)",
        ("zzz-late", "Late alert", "d", "1", "2000000000000", "{}", "in_campaign"),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status) "
        "VALUES (?,?,?,?,?,?,?)",
        ("aaa-early", "Early alert", "d", "1", "1000000000000", "{}", "in_campaign"),
    )
    store.conn.execute(
        "INSERT INTO campaigns (campaign_id, alerts, confidence, rationale, summary, run_id, created_at) "
        "VALUES (?,?,?,?,?,?,datetime('now'))",
        ("camp-1", '["zzz-late","aaa-early"]', 0.9, "r", "s", "run-1"),
    )
    store.conn.commit()

    text = build_campaign_report_body(store, generated_at="2026-04-05T18:00:00.000Z")
    early_pos = text.index("Early alert")
    late_pos = text.index("Late alert")
    assert early_pos < late_pos


def test_status_warning_tag(tmp_path: Path) -> None:
    """Alerts in a campaign listing with status != in_campaign get a [!] tag."""
    db = tmp_path / "f.db"
    store = SQLiteStore(db_path=db)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status) "
        "VALUES (?,?,?,?,?,?,?)",
        ("a1", "Good alert", "d", "1", "0", "{}", "in_campaign"),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status) "
        "VALUES (?,?,?,?,?,?,?)",
        ("a2", "Misclassified", "d", "1", "1", "{}", "false_positive"),
    )
    store.conn.execute(
        "INSERT INTO campaigns (campaign_id, alerts, confidence, rationale, summary, run_id, created_at) "
        "VALUES (?,?,?,?,?,?,datetime('now'))",
        ("camp-1", '["a1","a2"]', 0.9, "r", "s", "run-1"),
    )
    store.conn.commit()

    text = build_campaign_report_body(store, generated_at="2026-04-05T18:00:00.000Z")
    assert "[! status=false_positive]" in text
    assert "Good alert" in text
    lines = text.split("\n")
    good_line = [l for l in lines if "Good alert" in l][0]
    assert "[!" not in good_line


def test_auto_finalized_count(tmp_path: Path) -> None:
    """Auto-finalized FPs should be counted in ALERT STATUS SUMMARY."""
    db = tmp_path / "g.db"
    store = SQLiteStore(db_path=db)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status, false_positive_reason) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("a1", "t", "d", "1", "0", "{}", "false_positive", "Seed not explicitly processed by LLM — auto-finalized"),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status, false_positive_reason) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("a2", "t", "d", "1", "0", "{}", "false_positive", "Investigated and found benign"),
    )
    store.conn.commit()

    text = build_campaign_report_body(store, generated_at="2026-04-05T18:00:00.000Z")
    assert "Auto-finalized (not reviewed by LLM): 1 of 2 FPs" in text


def test_campaign_quality_metrics(tmp_path: Path) -> None:
    """Campaign-level quality metrics should appear in the eval report."""
    gt = pd.DataFrame(
        [
            {"alert_id": "a1", "expected_label": "in_campaign", "expected_campaign_id": "camp-gt-1"},
            {"alert_id": "a2", "expected_label": "in_campaign", "expected_campaign_id": "camp-gt-1"},
            {"alert_id": "a3", "expected_label": "false_positive", "expected_campaign_id": ""},
        ]
    )
    gt_path = tmp_path / "ground_truth.csv"
    gt.to_csv(gt_path, index=False)

    db_path = tmp_path / "h.db"
    store = SQLiteStore(db_path=db_path)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, status, campaign_id) VALUES (?, ?, ?)",
        ("a1", "in_campaign", "camp-pred-1"),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, status, campaign_id) VALUES (?, ?, ?)",
        ("a2", "in_campaign", "camp-pred-1"),
    )
    store.conn.execute(
        "INSERT INTO alerts (alert_id, status) VALUES (?, ?)",
        ("a3", "false_positive"),
    )
    store.conn.execute(
        "INSERT INTO campaigns (campaign_id, alerts, confidence, rationale, summary) "
        "VALUES (?,?,?,?,?)",
        ("camp-pred-1", '["a1","a2"]', 0.9, "reason", "summary"),
    )
    store.conn.commit()

    from security_agent.app.experiments.eval import evaluate_against_ground_truth, format_eval_report

    m = evaluate_against_ground_truth(gt_path, db_path)
    assert m["campaigns_expected"] == 1
    assert m["campaigns_detected"] == 1
    assert m["campaign_completeness"] == 1.0
    assert m["campaign_purity"] == 1.0
    assert m["campaign_splits"] == 0
    assert m["campaign_merges"] == 0

    report = format_eval_report(m)
    assert "CAMPAIGN QUALITY" in report
    assert "Expected Campaigns : 1" in report
    assert "Detected Campaigns : 1" in report
    assert "Completeness : 100.00%" in report
    assert "Purity       : 100.00%" in report
