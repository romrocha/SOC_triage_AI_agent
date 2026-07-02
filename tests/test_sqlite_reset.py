"""SQLiteStore.reset_investigation_state"""

from pathlib import Path

from security_agent.app.ingestion.sqlite_store import SQLiteStore


def test_reset_investigation_state(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db_path=db)
    store.init_db()
    store.conn.execute(
        "INSERT INTO alerts (alert_id, title, description, severity, date, raw, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("x1", "t", "d", "1", "0", "{}", "false_positive"),
    )
    store.conn.execute(
        "INSERT INTO campaigns (campaign_id, alerts, confidence, rationale, summary) VALUES (?,?,?,?,?)",
        ("c1", '["x1"]', 0.9, "r", "s"),
    )
    store.conn.commit()

    na, nc = store.reset_investigation_state()
    assert na >= 1
    assert nc >= 1

    cur = store.conn.cursor()
    cur.execute("SELECT status FROM alerts WHERE alert_id = ?", ("x1",))
    assert cur.fetchone()[0] == "unprocessed"
    cur.execute("SELECT COUNT(*) FROM campaigns")
    assert cur.fetchone()[0] == 0
