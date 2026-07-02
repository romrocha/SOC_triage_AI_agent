"""
Evaluate SQLite alert predictions against ground_truth.csv (same logic as experiment notebook).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd


def _compute_campaign_quality(
    gt: pd.DataFrame, conn: sqlite3.Connection,
) -> Dict[str, Any]:
    """Compute campaign-level quality metrics (split/merge, purity, completeness).

    Compares ground-truth campaign groups with the agent's predicted campaign
    groupings stored in the ``campaigns`` table.
    """
    gt_col = "expected_campaign_id"
    if gt_col not in gt.columns:
        return {}

    gt_camp = gt[gt[gt_col].notna() & (gt[gt_col] != "")]
    gt_groups: Dict[str, set[str]] = {}
    for cid, grp in gt_camp.groupby(gt_col):
        gt_groups[str(cid)] = set(grp["alert_id"].tolist())

    try:
        rows = conn.execute(
            "SELECT campaign_id, alerts FROM campaigns"
        ).fetchall()
    except Exception:
        return {}

    pred_groups: Dict[str, set[str]] = {}
    for row in rows:
        cid = row[0]
        raw = row[1]
        try:
            aids = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            aids = []
        if isinstance(aids, list):
            pred_groups[cid] = {str(a) for a in aids}

    campaigns_expected = len(gt_groups)
    campaigns_detected = len(pred_groups)

    if not gt_groups or not pred_groups:
        return {
            "campaigns_expected": campaigns_expected,
            "campaigns_detected": campaigns_detected,
            "campaign_completeness": 0.0,
            "campaign_purity": 0.0,
            "campaign_splits": 0,
            "campaign_merges": 0,
        }

    # Completeness: for each GT campaign, what fraction of its alerts ended up
    # in *any* predicted campaign?
    completeness_scores: list[float] = []
    splits = 0
    for gt_cid, gt_aids in gt_groups.items():
        matched_preds: set[str] = set()
        found = 0
        for p_cid, p_aids in pred_groups.items():
            overlap = gt_aids & p_aids
            if overlap:
                matched_preds.add(p_cid)
                found += len(overlap)
        found = min(found, len(gt_aids))
        completeness_scores.append(found / len(gt_aids) if gt_aids else 0.0)
        if len(matched_preds) > 1:
            splits += 1

    # Purity: for each predicted campaign, what fraction of its alerts actually
    # belong to *any* GT campaign (vs being noise)?
    all_gt_aids = set()
    for aids in gt_groups.values():
        all_gt_aids |= aids

    purity_scores: list[float] = []
    merges = 0
    for p_cid, p_aids in pred_groups.items():
        if not p_aids:
            continue
        true_positives = p_aids & all_gt_aids
        purity_scores.append(len(true_positives) / len(p_aids))
        gt_sources: set[str] = set()
        for gt_cid, gt_aids in gt_groups.items():
            if p_aids & gt_aids:
                gt_sources.add(gt_cid)
        if len(gt_sources) > 1:
            merges += 1

    return {
        "campaigns_expected": campaigns_expected,
        "campaigns_detected": campaigns_detected,
        "campaign_completeness": (
            sum(completeness_scores) / len(completeness_scores)
            if completeness_scores else 0.0
        ),
        "campaign_purity": (
            sum(purity_scores) / len(purity_scores)
            if purity_scores else 0.0
        ),
        "campaign_splits": splits,
        "campaign_merges": merges,
    }


def evaluate_against_ground_truth(
    gt_path: Path,
    db_path: Path,
) -> Dict[str, Any]:
    """
    Merge ground truth with alerts table and compute FP / campaign metrics.

    Returns a dict suitable for JSON export and for format_eval_report().
    """
    gt = pd.read_csv(gt_path, dtype=str)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    alerts = pd.read_sql_query(
        "SELECT alert_id, status, campaign_id FROM alerts", conn, dtype=str
    )

    merged = gt.merge(alerts, on="alert_id", how="left", suffixes=("_gt", "_pred"))
    merged["status"] = merged["status"].fillna("unprocessed")
    merged["expected_label"] = merged["expected_label"].fillna("unprocessed")

    is_fp_gt = merged["expected_label"] == "false_positive"
    is_fp_pred = merged["status"] == "false_positive"
    fp_tp = int(((is_fp_gt) & (is_fp_pred)).sum())
    fp_fp = int(((~is_fp_gt) & (is_fp_pred)).sum())
    fp_fn = int(((is_fp_gt) & (~is_fp_pred)).sum())
    fp_tn = int(((~is_fp_gt) & (~is_fp_pred)).sum())
    fp_precision = fp_tp / (fp_tp + fp_fp) if (fp_tp + fp_fp) else 0.0
    fp_recall = fp_tp / (fp_tp + fp_fn) if (fp_tp + fp_fn) else 0.0
    fp_f1 = (
        2 * fp_precision * fp_recall / (fp_precision + fp_recall)
        if (fp_precision + fp_recall)
        else 0.0
    )

    is_camp_gt = merged["expected_label"] == "in_campaign"
    is_camp_pred = merged["status"] == "in_campaign"
    camp_tp = int(((is_camp_gt) & (is_camp_pred)).sum())
    camp_fp = int(((~is_camp_gt) & (is_camp_pred)).sum())
    camp_fn = int(((is_camp_gt) & (~is_camp_pred)).sum())
    camp_tn = int(((~is_camp_gt) & (~is_camp_pred)).sum())
    camp_precision = camp_tp / (camp_tp + camp_fp) if (camp_tp + camp_fp) else 0.0
    camp_recall = camp_tp / (camp_tp + camp_fn) if (camp_tp + camp_fn) else 0.0
    camp_f1 = (
        2 * camp_precision * camp_recall / (camp_precision + camp_recall)
        if (camp_precision + camp_recall)
        else 0.0
    )

    # Missed threats: actual campaign alerts the agent actively dismissed as FP.
    missed_mask = is_camp_gt & is_fp_pred
    missed_threats_count = int(missed_mask.sum())
    missed_threats_ids: list[str] = merged.loc[missed_mask, "alert_id"].tolist()

    label_acc = float((merged["expected_label"] == merged["status"]).mean())
    alerts_por_achado_fp = (1.0 / fp_precision) if fp_precision > 0 else float("inf")
    fp_rate = float(is_fp_pred.mean())

    # Campaign-level quality (split/merge, purity, completeness).
    cq = _compute_campaign_quality(gt, conn)
    conn.close()

    input_round = gt_path.resolve().parent.name

    result: Dict[str, Any] = {
        "input_round": input_round,
        "ground_truth_rows": int(len(gt)),
        "evaluated_alerts": int(len(merged)),
        "label_acc": label_acc,
        "fp_tp": fp_tp,
        "fp_fp": fp_fp,
        "fp_fn": fp_fn,
        "fp_tn": fp_tn,
        "fp_precision": fp_precision,
        "fp_recall": fp_recall,
        "fp_f1": fp_f1,
        "fp_rate": fp_rate,
        "alerts_por_achado_fp": alerts_por_achado_fp,
        "camp_tp": camp_tp,
        "camp_fp": camp_fp,
        "camp_fn": camp_fn,
        "camp_tn": camp_tn,
        "camp_precision": camp_precision,
        "camp_recall": camp_recall,
        "camp_f1": camp_f1,
        "missed_threats_count": missed_threats_count,
        "missed_threats_ids": missed_threats_ids,
    }
    result.update(cq)
    return result


def _fmt_confusion_matrix(
    tp: int, fp: int, fn: int, tn: int,
    pos_label: str, neg_label: str,
) -> list[str]:
    """Render a 2x2 confusion matrix as aligned text lines."""
    pred_pos = f"Pred: {pos_label}"
    pred_neg = f"Pred: {neg_label}"
    col_w = max(len(pred_pos), len(pred_neg), len(str(tp)), len(str(fp)), len(str(fn)), len(str(tn))) + 2
    gt_pos = f"  Actual {pos_label}"
    gt_neg = f"  Actual {neg_label}"
    row_w = max(len(gt_pos), len(gt_neg)) + 2
    header = " " * row_w + pred_pos.center(col_w) + pred_neg.center(col_w)
    row1 = gt_pos.ljust(row_w) + str(tp).center(col_w) + str(fn).center(col_w)
    row2 = gt_neg.ljust(row_w) + str(fp).center(col_w) + str(tn).center(col_w)
    return [header, row1, row2]


def format_eval_report(metrics: Dict[str, Any]) -> str:
    """Plain-text evaluation block appended to campaign reports."""
    sep = "=" * 80
    thin = "─" * 80

    missed_count = metrics.get("missed_threats_count", 0)
    missed_ids: list[str] = metrics.get("missed_threats_ids", [])
    total_camp = metrics["camp_tp"] + metrics["camp_fn"]

    lines = [
        sep,
        "EVALUATION (vs Ground Truth)",
        sep,
        f"  Ground Truth Alerts  : {metrics['ground_truth_rows']}",
        f"  Agent-Evaluated      : {metrics['evaluated_alerts']}",
        f"  Overall Label Accuracy: {metrics['label_acc']:.2%}",
        "",
    ]

    # --- Missed Threats (most critical signal) ---
    lines.append(thin)
    if missed_count > 0:
        lines.append(
            f"⚠  MISSED THREATS: {missed_count}  —  "
            "Real campaign alerts the agent dismissed as false positive"
        )
    else:
        lines.append(
            "✓  MISSED THREATS: 0  —  "
            "No campaign alerts were incorrectly dismissed as false positive"
        )
    lines.append(thin)
    lines.append("")

    if missed_count > 0 and total_camp > 0:
        pct = missed_count / total_camp
        lines.append(
            f"  {missed_count} of {total_camp} campaign alerts ({pct:.1%}) were actively closed as noise."
        )
        lines.append(
            "  These represent threats the agent would have let through in production."
        )
        lines.append("")
        for aid in missed_ids:
            lines.append(f"  • {aid}")
        lines.append("")
    elif missed_count == 0:
        lines.append(
            "  The agent did not dismiss any real campaign alerts as false positives."
        )
        if metrics["camp_fn"] > 0:
            lines.append(
                f"  Note: {metrics['camp_fn']} campaign alert(s) were missed but not actively"
                " dismissed (left as unprocessed/reviewed)."
            )
        lines.append("")

    # --- Noise Filtering ---
    lines.extend([
        thin,
        "NOISE FILTERING  —  Can the agent correctly identify false positives?",
        thin,
        "",
    ])

    lines.extend(_fmt_confusion_matrix(
        metrics["fp_tp"], metrics["fp_fp"], metrics["fp_fn"], metrics["fp_tn"],
        pos_label="FP", neg_label="Not-FP",
    ))
    lines.append("")

    eff = metrics["alerts_por_achado_fp"]
    eff_str = f"{eff:.2f}" if eff != float("inf") else "inf"
    lines.extend([
        f"  Precision : {metrics['fp_precision']:.2%}  (of alerts marked FP, how many are truly noise)",
        f"  Recall    : {metrics['fp_recall']:.2%}  (of all actual noise, how much was caught)",
        f"  F1 Score  : {metrics['fp_f1']:.2%}",
        "",
        f"  FP Rate           : {metrics['fp_rate']:.2%}  (fraction of all alerts marked as false positive)",
        f"  Review Efficiency : {eff_str} alerts reviewed per true FP found",
        "",
    ])

    # --- Campaign Detection ---
    lines.extend([
        thin,
        "CAMPAIGN DETECTION  —  Can the agent correctly assign alerts to campaigns?",
        thin,
        "",
    ])

    lines.extend(_fmt_confusion_matrix(
        metrics["camp_tp"], metrics["camp_fp"], metrics["camp_fn"], metrics["camp_tn"],
        pos_label="Campaign", neg_label="Not-Campaign",
    ))
    lines.append("")

    lines.extend([
        f"  Precision : {metrics['camp_precision']:.2%}  (of alerts placed in a campaign, how many truly belong)",
        f"  Recall    : {metrics['camp_recall']:.2%}  (of all actual campaign alerts, how many were found)",
        f"  F1 Score  : {metrics['camp_f1']:.2%}",
        "",
    ])

    # --- Campaign Quality (grouping accuracy) ---
    if "campaigns_expected" in metrics:
        c_exp = metrics["campaigns_expected"]
        c_det = metrics["campaigns_detected"]
        c_comp = metrics.get("campaign_completeness", 0.0)
        c_pur = metrics.get("campaign_purity", 0.0)
        c_splits = metrics.get("campaign_splits", 0)
        c_merges = metrics.get("campaign_merges", 0)

        lines.extend([
            thin,
            "CAMPAIGN QUALITY  —  Did the agent reconstruct the right incident groups?",
            thin,
            "",
            f"  Expected Campaigns : {c_exp}",
            f"  Detected Campaigns : {c_det}",
            "",
            f"  Completeness : {c_comp:.2%}  (of each real campaign's alerts, how many were grouped)",
            f"  Purity       : {c_pur:.2%}  (of each predicted campaign's alerts, how many are real)",
            "",
        ])
        if c_splits > 0:
            lines.append(
                f"  Splits : {c_splits}  (real campaign fragmented across multiple predicted campaigns)"
            )
        if c_merges > 0:
            lines.append(
                f"  Merges : {c_merges}  (predicted campaign mixes alerts from different real campaigns)"
            )
        if c_splits == 0 and c_merges == 0:
            lines.append("  Splits : 0  |  Merges : 0  (campaigns mapped 1:1)")
        lines.append("")

    lines.append(sep)
    return "\n".join(lines) + "\n"


def confusion_dataframes(metrics: Dict[str, Any]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Matrizes 2x2 (FP e campanha) a partir do dict devolvido por ``evaluate_against_ground_truth``."""
    fp_tp = metrics["fp_tp"]
    fp_fp = metrics["fp_fp"]
    fp_fn = metrics["fp_fn"]
    fp_tn = metrics["fp_tn"]
    fp_conf = pd.DataFrame(
        [[fp_tp, fp_fn], [fp_fp, fp_tn]],
        index=["GT: FP", "GT: não-FP"],
        columns=["Pred: FP", "Pred: não-FP"],
    )
    camp_tp = metrics["camp_tp"]
    camp_fp = metrics["camp_fp"]
    camp_fn = metrics["camp_fn"]
    camp_tn = metrics["camp_tn"]
    camp_conf = pd.DataFrame(
        [[camp_tp, camp_fn], [camp_fp, camp_tn]],
        index=["GT: in_campaign", "GT: não"],
        columns=["Pred: in_campaign", "Pred: não"],
    )
    return fp_conf, camp_conf


def append_eval_run_csv(eval_log_path: Path, metrics: Dict[str, Any]) -> None:
    """Acrescenta uma linha a ``eval_runs.csv`` (união de colunas com ficheiro existente)."""
    eval_log_path.parent.mkdir(parents=True, exist_ok=True)
    new_row = pd.DataFrame([metrics])
    if eval_log_path.exists():
        old = pd.read_csv(eval_log_path)
        combined = pd.concat([old, new_row], ignore_index=True, sort=False)
    else:
        combined = new_row
    combined.to_csv(eval_log_path, index=False)


def evaluate_and_log(
    gt_path: Path,
    db_path: Path,
    eval_log_path: Path,
    model: str | None = None,
    experiment_version: str | None = None,
) -> Dict[str, Any]:
    """
    Calcula métricas, acrescenta ``timestamp`` UTC e grava em ``eval_log_path``.
    Devolve o mesmo dict (incluindo timestamp, model e experiment_version).

    Parameters
    ----------
    experiment_version
        Rótulo livre que identifica a versão/fase do experimento (ex.
        ``"v1_baseline"``, ``"v2_post_hint_fix"``). Útil para diferenciar
        runs feitas com datasets diferentes mantendo um único ``eval_runs.csv``.
        Quando informado, vira coluna ``experiment_version`` no histórico.
    """
    metrics = evaluate_against_ground_truth(gt_path, db_path)
    metrics["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if model is not None:
        metrics["model"] = model
    if experiment_version is not None:
        metrics["experiment_version"] = experiment_version
    append_eval_run_csv(eval_log_path, metrics)
    return metrics
