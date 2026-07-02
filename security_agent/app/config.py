import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

RESEARCH_ROUND = os.getenv("RESEARCH_ROUND", "round1")
INPUT_ROOT = ROOT / "input"
OUTPUT_ROOT = ROOT / "output"
ROUND_INPUT_DIR = INPUT_ROOT / RESEARCH_ROUND
ROUND_OUTPUT_DIR = OUTPUT_ROOT / RESEARCH_ROUND

DATA_ROOT = ROOT / "data"
SQLITE_DB = DATA_ROOT / "alerts.db"
CHROMA_DIR = DATA_ROOT / "chroma_db"

GROUND_TRUTH_PATH = ROUND_INPUT_DIR / "ground_truth.csv"

EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4.1-mini")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

LANGCHAIN_API_KEY = os.getenv("LANGCHAIN_API_KEY")
LANGCHAIN_TRACING_V2 = os.getenv("LANGCHAIN_TRACING_V2", "false").lower() == "true"
LANGCHAIN_PROJECT = os.getenv("LANGCHAIN_PROJECT", "default")

CHROMA_PERSIST = True
