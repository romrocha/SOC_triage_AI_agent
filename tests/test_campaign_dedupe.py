from pathlib import Path

from security_agent.app.ingestion.sqlite_store import SQLiteStore


def _insert_alert(
    store: SQLiteStore,
    alert_id: str,
    *,
    title: str,
    description: str,
    date: str,
    username: str,
    hostname: str,
) -> None:
    store.upsert_alert(
        alert_id=alert_id,
        title=title,
        description=description,
        severity="3",
        date=date,
        alert_type="Endpoint",
        source="Cortex XDR",
        status="unprocessed",
        tags=["Cortex XDR"],
        observables=[
            {"type": "username", "value": username, "message": "user", "ioc": True},
            {"type": "hostname", "value": hostname, "message": "host", "ioc": True},
        ],
        raw={"alert_id": alert_id},
    )


def test_create_campaign_merges_overlapping_campaigns(tmp_path: Path) -> None:
    store = SQLiteStore(db_path=tmp_path / "alerts.db")
    store.init_db()
    _insert_alert(
        store,
        "a1",
        title="Phishing click on finance laptop",
        description="b.smith clicked a phishing lure from FIN-LT-204",
        date="1704067200000",
        username="b.smith",
        hostname="FIN-LT-204",
    )
    _insert_alert(
        store,
        "a2",
        title="Encoded PowerShell on finance laptop",
        description="PowerShell executed under b.smith on FIN-LT-204",
        date="1704153600000",
        username="b.smith",
        hostname="FIN-LT-204",
    )
    _insert_alert(
        store,
        "a3",
        title="Mass file rename on finance share",
        description="FIN-WS-118 renamed finance files after lateral movement",
        date="1704240000000",
        username="b.smith",
        hostname="FIN-WS-118",
    )

    store.create_campaign(
        campaign_id="free-form-1",
        alert_ids=["a1", "a2"],
        confidence=0.9,
        rationale="Finance ransomware centered on b.smith",
        summary="Finance ransomware campaign for b.smith",
        run_id="run-1",
    )
    store.create_campaign(
        campaign_id="free-form-2",
        alert_ids=["a2", "a3"],
        confidence=0.95,
        rationale="Same ransomware sequence expanding in finance",
        summary="Finance ransomware campaign for b.smith with encryption behavior",
        run_id="run-1",
    )

    cur = store.conn.cursor()
    cur.execute("SELECT campaign_id, alerts, confidence FROM campaigns")
    rows = cur.fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["campaign_id"] == "campaign-ransomware-finance-b-smith-2024-01"
    assert set(store._parse_alert_ids_json(row["alerts"])) == {"a1", "a2", "a3"}
    assert float(row["confidence"]) == 0.95

    cur.execute("SELECT DISTINCT campaign_id FROM alerts WHERE status = 'in_campaign'")
    campaign_ids = {r[0] for r in cur.fetchall()}
    assert campaign_ids == {"campaign-ransomware-finance-b-smith-2024-01"}


def test_create_campaign_returns_persisted_canonical(tmp_path: Path) -> None:
    """Bug 1 regression: store.create_campaign returns the canonical id and merged alerts.

    The LLM-supplied campaign_id is ignored by the store (replaced with a
    canonical slug). The return value must reflect what was persisted, not
    what the caller passed.
    """
    store = SQLiteStore(db_path=tmp_path / "alerts.db")
    store.init_db()
    _insert_alert(
        store,
        "a1",
        title="Phishing click on finance laptop",
        description="b.smith clicked a phishing lure from FIN-LT-204",
        date="1704067200000",
        username="b.smith",
        hostname="FIN-LT-204",
    )
    _insert_alert(
        store,
        "a2",
        title="Encoded PowerShell on finance laptop",
        description="PowerShell executed under b.smith on FIN-LT-204",
        date="1704153600000",
        username="b.smith",
        hostname="FIN-LT-204",
    )

    canonical_id, alerts = store.create_campaign(
        campaign_id="llm-chose-this-name",
        alert_ids=["a1", "a2"],
        confidence=0.9,
        rationale="Finance ransomware centered on b.smith",
        summary="Finance ransomware campaign for b.smith",
        run_id="run-1",
    )
    # Canonical recomputed from theme + entity + month — not the LLM string.
    assert canonical_id != "llm-chose-this-name"
    assert canonical_id.startswith("campaign-ransomware-finance-b-smith")
    assert sorted(alerts) == ["a1", "a2"]


def test_create_campaign_cleans_stale_fk_in_other_campaigns(tmp_path: Path) -> None:
    """Bug 3 regression: when an alert is reassigned to a new campaign with
    sub-threshold overlap, it must be removed from the JSON of the prior
    campaign so ``campaigns.alerts`` stays consistent with ``alerts.campaign_id``.
    """
    store = SQLiteStore(db_path=tmp_path / "alerts.db")
    store.init_db()
    # Two unrelated alert clusters, only sharing one alert.
    _insert_alert(
        store, "a1", title="Phishing click", description="b.smith click",
        date="1704067200000", username="b.smith", hostname="FIN-LT-204",
    )
    _insert_alert(
        store, "a2", title="Encoded PS", description="b.smith ps",
        date="1704153600000", username="b.smith", hostname="FIN-LT-204",
    )
    _insert_alert(
        store, "a3", title="HR doc download", description="h.potter download",
        date="1704240000000", username="h.potter", hostname="HR-LT-118",
    )
    _insert_alert(
        store, "a4", title="HR upload", description="h.potter upload",
        date="1704326400000", username="h.potter", hostname="HR-LT-118",
    )
    _insert_alert(
        store, "a5", title="HR external share", description="h.potter share",
        date="1704412800000", username="h.potter", hostname="HR-LT-118",
    )
    # 1st campaign: a1, a2, a3 (3 alerts — a3 will be the bridge)
    cid_a, _ = store.create_campaign(
        campaign_id="c1", alert_ids=["a1", "a2", "a3"], confidence=0.8,
        rationale="finance ransomware", summary="finance",
        run_id="run-1",
    )
    # 2nd campaign: a3, a4, a5 — only 1 alert in common (a3) with c1.
    # ratio = 1 / min(3, 3) = 0.33 (< 0.5), inter = 1 (< 5) → no automatic merge.
    # a3 will be reassigned to the new campaign and must be removed from c1's
    # JSON to avoid "alert in two campaigns" inconsistency.
    cid_b, _ = store.create_campaign(
        campaign_id="c2", alert_ids=["a3", "a4", "a5"], confidence=0.85,
        rationale="hr exfil insider", summary="insider",
        run_id="run-2",
    )

    cur = store.conn.cursor()
    cur.execute("SELECT campaign_id, alerts FROM campaigns ORDER BY campaign_id")
    rows = cur.fetchall()
    assert len(rows) == 2, f"expected 2 campaigns, got {len(rows)}: {[r['campaign_id'] for r in rows]}"
    by_id = {r["campaign_id"]: set(store._parse_alert_ids_json(r["alerts"])) for r in rows}
    # a3 lives in cid_b only — not in both.
    assert by_id[cid_a] == {"a1", "a2"}, f"cid_a should not contain a3 anymore, got {by_id[cid_a]}"
    assert by_id[cid_b] == {"a3", "a4", "a5"}
    # alerts.campaign_id agrees with whoever holds the alert in JSON.
    cur.execute("SELECT alert_id, campaign_id FROM alerts WHERE alert_id = 'a3'")
    a3_row = cur.fetchone()
    assert a3_row["campaign_id"] == cid_b


def test_create_campaign_clamps_confidence(tmp_path: Path) -> None:
    """Confidence inputs must be clamped to [0, 1].

    Observed in production: the LLM sometimes passes ``95`` (meaning 95%)
    or even ``9e9`` after a few merge rounds when a corrupted historical
    value got max()ed. Both layers (``tools.create_campaign`` and the
    store) clamp to keep ``campaigns.confidence`` honest for downstream
    metrics. This test exercises the store layer directly.
    """
    store = SQLiteStore(db_path=tmp_path / "alerts.db")
    store.init_db()
    _insert_alert(
        store,
        "x1",
        title="t",
        description="d",
        date="1704067200000",
        username="u",
        hostname="h",
    )

    # 95 (percent style) → 0.95
    cid_a, _ = store.create_campaign(
        campaign_id="raw-95", alert_ids=["x1"], confidence=95.0,
        rationale="r", summary="s", run_id="run",
    )
    cur = store.conn.cursor()
    cur.execute("SELECT confidence FROM campaigns WHERE campaign_id = ?", (cid_a,))
    assert cur.fetchone()["confidence"] == 0.95

    # absurd value (9e9) → clamped to 1.0
    store.reset_investigation_state()
    cid_b, _ = store.create_campaign(
        campaign_id="raw-9e9", alert_ids=["x1"], confidence=9e9,
        rationale="r", summary="s", run_id="run",
    )
    cur.execute("SELECT confidence FROM campaigns WHERE campaign_id = ?", (cid_b,))
    assert cur.fetchone()["confidence"] == 1.0

    # negative → 0
    store.reset_investigation_state()
    cid_c, _ = store.create_campaign(
        campaign_id="raw-neg", alert_ids=["x1"], confidence=-0.5,
        rationale="r", summary="s", run_id="run",
    )
    cur.execute("SELECT confidence FROM campaigns WHERE campaign_id = ?", (cid_c,))
    assert cur.fetchone()["confidence"] == 0.0


def test_get_unprocessed_alerts_can_exclude_ids(tmp_path: Path) -> None:
    store = SQLiteStore(db_path=tmp_path / "alerts.db")
    store.init_db()
    _insert_alert(
        store,
        "n1",
        title="Noise one",
        description="Benign event one",
        date="1704067200000",
        username="u.one",
        hostname="HOST-1",
    )
    _insert_alert(
        store,
        "n2",
        title="Noise two",
        description="Benign event two",
        date="1704153600000",
        username="u.two",
        hostname="HOST-2",
    )

    rows = store.get_unprocessed_alerts(limit=10, exclude_alert_ids=["n1"])
    ids = [row["alert_id"] for row in rows]
    assert ids == ["n2"]
