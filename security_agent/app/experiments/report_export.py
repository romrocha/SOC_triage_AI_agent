"""
Human-readable campaign report (SQLite) + optional evaluation block (ground truth).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from ..ingestion.sqlite_store import SQLiteStore
from .eval import evaluate_against_ground_truth, format_eval_report


def _parse_alert_ids(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    try:
        p = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(p, list):
            return [str(x) for x in p]
    except Exception:
        pass
    return [str(raw)]


def _report_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _epoch_ms_to_iso(value: Any) -> str:
    """Convert epoch-millisecond values to ISO 8601 UTC strings."""
    try:
        ts = int(value)
        if ts > 1_000_000_000_000:
            ts_sec = ts / 1000.0
        elif ts > 1_000_000_000:
            ts_sec = float(ts)
        else:
            return str(value)
        return datetime.fromtimestamp(ts_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(value)


def _format_alert_line(alert: dict[str, Any]) -> str:
    aid = alert.get("alert_id") or "unknown-alert"
    title = alert.get("title") or "(no title)"
    source = alert.get("source") or "(no source)"
    raw_date = alert.get("date") or "(no date)"
    date = _epoch_ms_to_iso(raw_date)
    status = alert.get("status") or "(no status)"
    return f"  • {aid} | {title} | source={source} | date={date} | status={status}"


def _sort_key_date(alert: dict[str, Any]) -> int:
    """Return a numeric sort key from the alert date field."""
    try:
        return int(alert.get("date", 0))
    except (ValueError, TypeError):
        return 0


def _append_campaign_alert_details(lines: list[str], store: SQLiteStore, alert_ids: list[str]) -> None:
    alerts: list[dict[str, Any]] = []
    missing: list[str] = []
    for aid in alert_ids:
        alert = store.fetch_alert(aid)
        if alert:
            alerts.append(alert)
        else:
            missing.append(aid)

    alerts.sort(key=_sort_key_date)

    lines.append("🚨 Alerts In This Case (chronological):")
    for alert in alerts:
        line = _format_alert_line(alert)
        status = alert.get("status") or ""
        if status != "in_campaign":
            line += f"  [! status={status}]"
        lines.append(line)
    for aid in missing:
        lines.append(f"  • {aid} | missing_from_alerts_table")
    lines.append("")


def _count_auto_finalized(store: SQLiteStore) -> int:
    cur = store.conn.cursor()
    cur.execute(
        """
        SELECT COUNT(*) FROM alerts
        WHERE status = 'false_positive'
          AND (false_positive_reason LIKE '%auto-finalized%'
               OR false_positive_reason LIKE '%Seed not explicitly processed%')
        """
    )
    return cur.fetchone()[0]


def _append_false_positive_details(lines: list[str], store: SQLiteStore) -> None:
    cur = store.conn.cursor()
    cur.execute(
        """
        SELECT alert_id
        FROM alerts
        WHERE status = 'false_positive'
        ORDER BY date, alert_id
        """
    )
    rows = cur.fetchall()
    lines.append("=" * 80)
    lines.append("APPENDIX: FALSE POSITIVE DETAILS")
    lines.append("=" * 80)
    lines.append(f"Total False Positives: {len(rows)}")
    lines.append("")
    for row in rows:
        alert = store.fetch_alert(row["alert_id"])
        if not alert:
            lines.append(f"  • {row['alert_id']} | missing_from_alerts_table")
            continue
        base = _format_alert_line(alert)
        reason = alert.get("false_positive_reason") or "(no reason recorded)"
        lines.append(f"{base} | reason={reason}")
    lines.append("")


def build_campaign_report_body(store: SQLiteStore, generated_at: Optional[str] = None) -> str:
    """Main report body: campaigns + alert status summary (FP details moved to appendix)."""
    cur = store.conn.cursor()
    cur.execute(
        """
        SELECT campaign_id, confidence, summary, rationale, alerts, run_id, created_at
        FROM campaigns
        ORDER BY created_at DESC
        """
    )
    rows = cur.fetchall()
    lines: list[str] = []
    generated_at = generated_at or _report_timestamp()
    lines.append(f"Report generated at (UTC): {generated_at}")
    lines.append("=" * 80)
    lines.append("CAMPAIGN ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Total Campaigns Detected: {len(rows)}")
    lines.append("")

    sep = "─" * 80
    for idx, row in enumerate(rows, 1):
        cid = row["campaign_id"]
        conf = float(row["confidence"] or 0.0)
        summary = row["summary"] or ""
        rationale = row["rationale"] or ""
        alert_ids = _parse_alert_ids(row["alerts"])
        run_id = row["run_id"] if "run_id" in row.keys() else None
        created = row["created_at"] if "created_at" in row.keys() else None

        lines.append(sep)
        lines.append(f"CAMPAIGN #{idx}: {cid}")
        lines.append(sep)
        lines.append("")
        lines.append("📊 Overview:")
        lines.append(f"  • Alerts: {len(alert_ids)}")
        lines.append(f"  • Confidence: {conf:.2%}")
        lines.append(f"  • Summary: {summary}")
        if run_id:
            lines.append(f"  • Run ID: {run_id}")
        if created:
            lines.append(f"  • Created at: {created}")
        lines.append("")
        _append_campaign_alert_details(lines, store, alert_ids)
        lines.append("📝 Rationale:")
        for para in (rationale or "").splitlines() or [""]:
            lines.append(f"  {para}" if para else "  ")
        lines.append("")

    lines.append("=" * 80)
    lines.append("ALERT STATUS SUMMARY")
    lines.append("=" * 80)
    stats = store.get_alert_stats()
    labels = {
        "unprocessed": "Unprocessed",
        "in_campaign": "In Campaign",
        "false_positive": "False Positive",
        "reviewed": "Reviewed",
    }
    for key, label in labels.items():
        lines.append(f"  {label}: {stats.get(key, 0)}")

    auto_fin = _count_auto_finalized(store)
    fp_total = stats.get("false_positive", 0)
    if auto_fin > 0:
        lines.append(f"  Auto-finalized (not reviewed by LLM): {auto_fin} of {fp_total} FPs")

    lines.append("=" * 80)
    return "\n".join(lines)


def _build_missed_threats_detail(store: SQLiteStore, alert_ids: list[str]) -> str:
    """Enrich missed-threat alert IDs with title, source, and the FP reason from the DB."""
    if not alert_ids:
        return ""
    lines = [
        "─" * 80,
        "MISSED THREAT DETAILS  —  Why were these campaign alerts dismissed?",
        "─" * 80,
        "",
    ]
    for aid in alert_ids:
        alert = store.fetch_alert(aid)
        if not alert:
            lines.append(f"  • {aid}  (not found in alerts table)")
            continue
        title = alert.get("title") or "(no title)"
        source = alert.get("source") or "(no source)"
        reason = alert.get("false_positive_reason") or "(no reason recorded)"
        lines.append(f"  • {aid}")
        lines.append(f"    Title  : {title}")
        lines.append(f"    Source : {source}")
        lines.append(f"    Reason : {reason}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _build_comparison_summary(eval_log_path: Path, current_round: str) -> str:
    """Compact table of other eval runs on the same round, if any exist."""
    if not eval_log_path.exists():
        return ""
    try:
        df = pd.read_csv(eval_log_path, dtype=str)
    except Exception:
        return ""

    if "input_round" not in df.columns or "model" not in df.columns:
        return ""

    same_round = df[df["input_round"] == current_round].copy()
    if len(same_round) < 2:
        return ""

    float_cols = ["label_acc", "camp_f1", "fp_f1", "camp_recall", "camp_precision"]
    for c in float_cols:
        if c in same_round.columns:
            same_round[c] = pd.to_numeric(same_round[c], errors="coerce")

    last_per_model = same_round.groupby("model").last().reset_index()
    if len(last_per_model) < 2:
        return ""

    lines = [
        "─" * 80,
        "OTHER RUNS ON THIS ROUND",
        "─" * 80,
        "",
    ]

    header = f"  {'Model':<20} {'Accuracy':>10} {'Camp F1':>10} {'FP F1':>10} {'Camp Recall':>12} {'Camp Prec':>11}"
    lines.append(header)
    lines.append("  " + "─" * len(header.strip()))
    for _, row in last_per_model.iterrows():
        model = str(row.get("model", "?"))
        acc = _safe_pct(row.get("label_acc"))
        cf1 = _safe_pct(row.get("camp_f1"))
        ff1 = _safe_pct(row.get("fp_f1"))
        cr = _safe_pct(row.get("camp_recall"))
        cp = _safe_pct(row.get("camp_precision"))
        lines.append(f"  {model:<20} {acc:>10} {cf1:>10} {ff1:>10} {cr:>12} {cp:>11}")
    lines.append("")
    return "\n".join(lines) + "\n"


def _safe_pct(val: Any) -> str:
    try:
        return f"{float(val):.2%}"
    except (ValueError, TypeError):
        return "—"


def build_full_report_with_eval(
    store: SQLiteStore,
    gt_path: Path,
    db_path: Path,
    generated_at: Optional[str] = None,
    eval_log_path: Optional[Path] = None,
) -> str:
    """Report body + evaluation + missed threats + comparison + FP appendix."""
    body = build_campaign_report_body(store, generated_at=generated_at)
    m = evaluate_against_ground_truth(gt_path, db_path)
    eval_block = "\n" + format_eval_report(m)
    missed_detail = _build_missed_threats_detail(
        store, m.get("missed_threats_ids", [])
    )

    comparison = ""
    if eval_log_path is not None:
        comparison = _build_comparison_summary(eval_log_path, m.get("input_round", ""))

    fp_lines: list[str] = [""]
    _append_false_positive_details(fp_lines, store)
    fp_appendix = "\n".join(fp_lines)

    return body + eval_block + missed_detail + comparison + fp_appendix
