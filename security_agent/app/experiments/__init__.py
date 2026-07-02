"""Experiment helpers: ground truth generation, evaluation vs SQLite predictions."""

from .ground_truth import (
    DATASET_FOLDER_SPECS,
    build_ground_truth_rows,
    write_ground_truth_csv,
)
from .eval import (
    append_eval_run_csv,
    confusion_dataframes,
    evaluate_against_ground_truth,
    evaluate_and_log,
    format_eval_report,
)
from .report_export import build_campaign_report_body, build_full_report_with_eval

__all__ = [
    "DATASET_FOLDER_SPECS",
    "build_ground_truth_rows",
    "write_ground_truth_csv",
    "evaluate_against_ground_truth",
    "evaluate_and_log",
    "append_eval_run_csv",
    "confusion_dataframes",
    "format_eval_report",
    "build_campaign_report_body",
    "build_full_report_with_eval",
]
