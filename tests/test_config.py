import importlib
from pathlib import Path


def test_research_round_paths(monkeypatch) -> None:
    import security_agent.app.config as cfg

    monkeypatch.setenv("RESEARCH_ROUND", "round2")
    importlib.reload(cfg)
    assert cfg.RESEARCH_ROUND == "round2"
    assert cfg.ROUND_INPUT_DIR.name == "round2"
    assert cfg.ROUND_OUTPUT_DIR.name == "round2"
    assert cfg.GROUND_TRUTH_PATH == cfg.ROUND_INPUT_DIR / "ground_truth.csv"
    monkeypatch.delenv("RESEARCH_ROUND", raising=False)
    importlib.reload(cfg)
