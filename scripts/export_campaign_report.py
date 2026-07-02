#!/usr/bin/env python3
"""
Exporta relatório de campanhas (SQLite) para output/<round>/round<round>_results_<label>.txt

Exemplo (round2, modelo usado no run = gpt5mini):
  RESEARCH_ROUND=round2 python scripts/export_campaign_report.py --label gpt5mini

Por omissão anexa métricas vs ``ground_truth.csv`` do round (se existir).
Só campanhas + resumo de status:

  python scripts/export_campaign_report.py --round round2 --label gpt5mini --no-eval
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


def main() -> None:
    p = argparse.ArgumentParser(description="Export campaign report from alerts.db to output/<round>/")
    p.add_argument(
        "--round",
        default=os.getenv("RESEARCH_ROUND", "round1"),
        help="Pasta do round (input/<round>/ e output/<round>/)",
    )
    p.add_argument(
        "--label",
        default="export",
        help="Sufixo do ficheiro: roundN_results_<label>.txt (ex.: gpt5mini, gpt4o)",
    )
    p.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Caminho para alerts.db (default: data/alerts.db após carregar config)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Ficheiro de saída (default: output/<round>/round<round>_results_<label>.txt)",
    )
    p.add_argument(
        "--no-eval",
        action="store_true",
        help="Não anexar bloco de avaliação (só campanhas + ALERT STATUS SUMMARY)",
    )
    args = p.parse_args()

    os.environ["RESEARCH_ROUND"] = args.round
    import security_agent.app.config as cfg

    importlib.reload(cfg)

    from security_agent.app.config import DATA_ROOT, GROUND_TRUTH_PATH, ROUND_OUTPUT_DIR, SQLITE_DB
    from security_agent.app.experiments.report_export import (
        build_campaign_report_body,
        build_full_report_with_eval,
    )
    from security_agent.app.ingestion.sqlite_store import SQLiteStore

    db_path = args.db.resolve() if args.db else Path(SQLITE_DB).resolve()
    eval_log = DATA_ROOT / "eval_runs.csv"
    store = SQLiteStore(db_path=db_path)
    store.init_db()

    with_eval = not args.no_eval
    if with_eval and GROUND_TRUTH_PATH.exists():
        text = build_full_report_with_eval(
            store, GROUND_TRUTH_PATH, db_path, eval_log_path=eval_log,
        )
    else:
        if with_eval:
            print(
                f"Aviso: ground_truth.csv não encontrado em {GROUND_TRUTH_PATH}; "
                "export só com campanhas.",
                file=sys.stderr,
            )
        text = build_campaign_report_body(store)

    out = args.out
    if out is None:
        ROUND_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")
        out = ROUND_OUTPUT_DIR / f"{args.round}_results_{args.label}_{ts}.txt"
    else:
        out = out.resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

    out.write_text(text, encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
