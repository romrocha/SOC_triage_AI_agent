# Output artifacts (per round)

Results are scoped per round. As you add **more campaigns in the inputs** (beyond the baseline A/B), the agent may detect **more named campaigns** in SQLite and in text reports for that round; filenames below stay the same pattern.

Use one folder per research round, aligned with `RESEARCH_ROUND`:

- `output/round1/`, `output/round2/`, …

Suggested contents per round:

| File | Purpose |
|------|---------|
| `roundN_results_<model>.txt` | Relatório legível: `python scripts/export_campaign_report.py --round roundN --label <modelo>` |
| `metrics.json` | Optional: structured metrics from `scripts/compare_eval.py` |

The active output directory is `output/<RESEARCH_ROUND>/` (`ROUND_OUTPUT_DIR` in `security_agent.app.config`).
