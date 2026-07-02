from pathlib import Path
from types import MethodType

from security_agent.app.agent.langgraph_workflow import (
    CampaignInvestigationWorkflow,
    InvestigationState,
    _get_processed_ids,
)
from security_agent.app.ingestion.sqlite_store import SQLiteStore


def _insert_alert(store: SQLiteStore, alert_id: str) -> None:
    store.upsert_alert(
        alert_id=alert_id,
        title=f"Alert {alert_id}",
        description="Synthetic alert for workflow testing",
        severity="3",
        date="1704067200000",
        alert_type="Endpoint",
        source="Cortex XDR",
        status="unprocessed",
        tags=["Cortex XDR"],
        observables=[{"type": "hostname", "value": f"HOST-{alert_id}", "message": "host", "ioc": True}],
        raw={"alert_id": alert_id},
    )


def _setup_workflow(tmp_path, monkeypatch, alert_ids):
    """Helper: cria store, insere alertas e retorna (store, workflow)."""
    db = tmp_path / "alerts.db"
    store = SQLiteStore(db_path=db)
    store.init_db()
    for aid in alert_ids:
        _insert_alert(store, aid)

    monkeypatch.setattr(
        "security_agent.app.agent.langgraph_workflow.configure_tooling",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "security_agent.app.agent.langgraph_workflow.get_unprocessed_alerts",
        lambda limit, exclude_alert_ids=None: store.get_unprocessed_alerts(limit, exclude_alert_ids=exclude_alert_ids),
    )
    monkeypatch.setattr(
        "security_agent.app.agent.langgraph_workflow.list_campaigns_summary",
        lambda: store.list_campaigns_summary(),
    )
    monkeypatch.setattr(CampaignInvestigationWorkflow, "_build_investigation_graph", lambda self: None)

    workflow = CampaignInvestigationWorkflow(sqlite_path=str(db), chroma_path=str(tmp_path / "chroma"))
    return store, workflow


def test_process_queue_marks_unhandled_seeds_not_evaluated(tmp_path: Path, monkeypatch) -> None:
    """Alertas avaliados pelo LLM sem ação devem ser marcados como not_evaluated."""
    store, workflow = _setup_workflow(tmp_path, monkeypatch, ["a1", "a2"])

    def fake_run_investigation(self, seed_alert_ids, **kwargs):
        return {"related_alert_ids": list(seed_alert_ids), "campaign_result": {"action": "llm_finish"}}

    workflow.run_investigation = MethodType(fake_run_investigation, workflow)

    results = workflow.process_queue(batch_size=1, run_id="test-run", use_llm_seed_selection=False)

    assert len(results) == 2
    cur = store.conn.cursor()
    cur.execute("SELECT status, false_positive_reason FROM alerts ORDER BY alert_id")
    rows = cur.fetchall()
    assert [row["status"] for row in rows] == ["not_evaluated", "not_evaluated"]
    assert all("re-evaluation" in row["false_positive_reason"].lower() for row in rows)


def test_queue_drain_marks_not_evaluated(tmp_path: Path, monkeypatch) -> None:
    """Alertas que nunca passaram pelo LLM (queue drain) devem ser not_evaluated, não false_positive."""
    store, workflow = _setup_workflow(tmp_path, monkeypatch, ["a1", "a2", "a3"])

    def fake_run_investigation(self, seed_alert_ids, **kwargs):
        return {"related_alert_ids": list(seed_alert_ids), "campaign_result": {"action": "llm_finish"}}

    workflow.run_investigation = MethodType(fake_run_investigation, workflow)

    # max_seeds=1 — processa apenas 1 alerta, restante vira leftover
    results = workflow.process_queue(batch_size=1, max_seeds=1, run_id="test-run", use_llm_seed_selection=False)

    cur = store.conn.cursor()
    cur.execute("SELECT alert_id, status, false_positive_reason FROM alerts ORDER BY alert_id")
    rows = cur.fetchall()

    # a1 foi avaliado pelo LLM sem tool calls → not_evaluated (seed não processado)
    assert rows[0]["status"] == "not_evaluated"
    assert "re-evaluation" in rows[0]["false_positive_reason"].lower()

    # a2 e a3 nunca passaram pelo LLM → not_evaluated (queue drain)
    assert rows[1]["status"] == "not_evaluated"
    assert rows[2]["status"] == "not_evaluated"
    assert all("never evaluated by the LLM" in rows[i]["false_positive_reason"] for i in (1, 2))

    # Verifica que o resultado inclui a ação mark_not_evaluated
    drain_results = [r for r in results if r.get("campaign_result", {}).get("action") == "mark_not_evaluated"]
    assert len(drain_results) == 1
    assert set(drain_results[0]["campaign_result"]["alert_ids"]) == {"a2", "a3"}


def test_related_but_not_persisted_alerts_become_seeds(tmp_path: Path, monkeypatch) -> None:
    """
    Alertas que aparecem em related_alert_ids mas NÃO foram persistidos pelo LLM
    (via create_campaign ou mark_false_positive) devem virar seeds em iterações futuras.

    Cenário: investigação do seed a1 descobre a1,a2,a3 como related, mas o LLM só
    persiste a1 (mark_false_positive). a2 e a3 devem ser processados em rodadas seguintes.
    """
    store, workflow = _setup_workflow(tmp_path, monkeypatch, ["a1", "a2", "a3"])

    call_count = 0

    def fake_run_investigation(self, seed_alert_ids, **kwargs):
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            store.mark_false_positive("a1", "LLM: noise alert")
            return {
                "related_alert_ids": ["a1", "a2", "a3"],
                "campaign_result": {
                    "action": "llm_finish",
                    "tool_outputs": [
                        {"tool": "mark_false_positive", "output": {"status": "success", "alert_id": "a1"}},
                    ],
                },
            }
        else:
            for aid in seed_alert_ids:
                store.mark_false_positive(aid, "LLM: noise alert")
            return {
                "related_alert_ids": list(seed_alert_ids),
                "campaign_result": {
                    "action": "llm_finish",
                    "tool_outputs": [
                        {"tool": "mark_false_positive", "output": {"status": "success", "alert_id": aid}}
                        for aid in seed_alert_ids
                    ],
                },
            }

    workflow.run_investigation = MethodType(fake_run_investigation, workflow)

    results = workflow.process_queue(batch_size=1, run_id="test-run", use_llm_seed_selection=False)

    assert call_count == 3, f"Esperava 3 investigações, mas houve {call_count}"

    cur = store.conn.cursor()
    cur.execute("SELECT alert_id, status FROM alerts ORDER BY alert_id")
    rows = cur.fetchall()

    assert all(row["status"] == "false_positive" for row in rows)

    statuses = {row["status"] for row in rows}
    assert "not_evaluated" not in statuses
    assert "unprocessed" not in statuses


def test_related_alerts_in_campaign_not_reprocessed(tmp_path: Path, monkeypatch) -> None:
    """
    Alertas que foram efetivamente incluídos numa campanha pelo LLM não devem
    virar seeds novamente.
    """
    store, workflow = _setup_workflow(tmp_path, monkeypatch, ["a1", "a2", "a3", "a4"])

    call_count = 0

    def fake_run_investigation(self, seed_alert_ids, **kwargs):
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            run_id = kwargs.get("run_id")
            store.create_campaign("camp-1", ["a1", "a2", "a3"], 0.9, "test", "test campaign", run_id)
            store.mark_false_positive("a4", "LLM: noise")
            return {
                "related_alert_ids": ["a1", "a2", "a3", "a4"],
                "campaign_result": {
                    "action": "llm_finish",
                    "tool_outputs": [
                        {"tool": "create_campaign", "output": {"status": "success", "alert_ids": ["a1", "a2", "a3"]}},
                        {"tool": "mark_false_positive", "output": {"status": "success", "alert_id": "a4"}},
                    ],
                },
            }
        else:
            return {
                "related_alert_ids": list(seed_alert_ids),
                "campaign_result": {"action": "llm_finish"},
            }

    workflow.run_investigation = MethodType(fake_run_investigation, workflow)

    workflow.process_queue(batch_size=1, run_id="test-run", use_llm_seed_selection=False)

    assert call_count == 1, f"Esperava 1 investigação, mas houve {call_count}"

    cur = store.conn.cursor()
    cur.execute("SELECT alert_id, status FROM alerts ORDER BY alert_id")
    rows = cur.fetchall()
    statuses = {row["alert_id"]: row["status"] for row in rows}
    assert statuses == {"a1": "in_campaign", "a2": "in_campaign", "a3": "in_campaign", "a4": "false_positive"}


# ---------------------------------------------------------------------------
# Testes da estrutura do grafo (3 nós: investigate → correlate → decide)
# ---------------------------------------------------------------------------


def test_investigation_state_has_required_fields() -> None:
    """InvestigationState deve ter os campos necessários para o grafo de 3 nós."""
    state = InvestigationState(
        seed_alert_ids=["a1"],
        investigation_result=None,
        correlation_result=None,
        loop_count=0,
        campaign_result=None,
        run_id="test",
        model_name="gpt-4o",
        temperature=0.0,
    )
    assert state["seed_alert_ids"] == ["a1"]
    assert state["loop_count"] == 0
    assert state["model_name"] == "gpt-4o"


def test_get_processed_ids_ignores_non_decision_tools() -> None:
    """_get_processed_ids deve ignorar tools de investigação e correlação."""
    campaign_result = {
        "action": "llm_finish",
        "tool_outputs": [
            {"tool": "search_similar_alerts", "output": {"alert_ids": ["a1", "a2"]}},
            {"tool": "fetch_alert_by_id", "output": {"alert": {"alert_id": "a1"}}},
            {"tool": "validate_shared_entities", "output": {"shared_entities": []}},
            {"tool": "compute_time_delta", "output": {"span_days": 5}},
            {"tool": "ready_to_decide", "output": {"status": "ready", "summary": "test"}},
            {"tool": "create_campaign", "output": {"status": "success", "alert_ids": ["a1", "a2"]}},
            {"tool": "mark_false_positive", "output": {"status": "success", "alert_id": "a3"}},
        ],
    }
    processed = _get_processed_ids(campaign_result)
    assert processed == {"a1", "a2", "a3"}


def test_graph_has_three_nodes(tmp_path: Path, monkeypatch) -> None:
    """O grafo compilado deve ter 3 nós: investigate, correlate e decide."""
    monkeypatch.setattr(
        "security_agent.app.agent.langgraph_workflow.configure_tooling",
        lambda **kwargs: None,
    )
    workflow = CampaignInvestigationWorkflow(
        sqlite_path=str(tmp_path / "alerts.db"),
        chroma_path=str(tmp_path / "chroma"),
    )
    graph = workflow._graph
    node_names = set(graph.nodes.keys()) - {"__start__", "__end__"}
    assert node_names == {"investigate", "correlate", "decide"}


def test_route_after_correlate_ready() -> None:
    """Quando ready_to_decide foi chamada, routing deve ir para decide."""
    from security_agent.app.agent.nodes import route_after_correlate

    state = {
        "loop_count": 1,
        "correlation_result": {
            "tool_outputs": [
                {"tool": "validate_shared_entities", "output": {"shared_entities": ["ip::1.2.3.4"]}},
                {"tool": "ready_to_decide", "output": {"status": "ready", "summary": "Strong correlation found"}},
            ],
        },
    }
    assert route_after_correlate(state) == "decide"


def test_route_after_correlate_needs_more() -> None:
    """Quando ready_to_decide NÃO foi chamada, routing deve voltar para investigate."""
    from security_agent.app.agent.nodes import route_after_correlate

    state = {
        "loop_count": 1,
        "correlation_result": {
            "content": "Need more data about the IP range.",
            "tool_outputs": [
                {"tool": "validate_shared_entities", "output": {"shared_entities": []}},
            ],
        },
    }
    assert route_after_correlate(state) == "investigate"


def test_route_after_correlate_safety_net() -> None:
    """Quando safety net (3 loops) é atingido, routing deve forçar decide."""
    from security_agent.app.agent.nodes import route_after_correlate

    state = {
        "loop_count": 3,
        "correlation_result": {
            "tool_outputs": [
                {"tool": "validate_shared_entities", "output": {"shared_entities": []}},
            ],
        },
    }
    assert route_after_correlate(state) == "decide"


# ---------------------------------------------------------------------------
# Tests for seed-selection tools
# ---------------------------------------------------------------------------


def test_submit_selected_seeds_truncates_to_max() -> None:
    """submit_selected_seeds must cap at the configured per-batch limit (3).

    The cap was 1 originally; raised to 3 when ``select_seeds`` got the
    peek/find_similar tools so the agent can group clearly-related alerts
    in a single batch when the queue scan already shows a cluster.
    """
    from security_agent.app.agent.tools import submit_selected_seeds

    # Within cap — passes through.
    result = submit_selected_seeds(["a1", "a2", "a3"])
    assert result["status"] == "ready"
    assert result["count"] == 3
    assert result["selected_seeds"] == ["a1", "a2", "a3"]

    # Over cap — truncated to first 3.
    result = submit_selected_seeds(["a1", "a2", "a3", "a4", "a5"])
    assert result["count"] == 3
    assert result["selected_seeds"] == ["a1", "a2", "a3"]


def test_submit_selected_seeds_deduplicates() -> None:
    """submit_selected_seeds must remove duplicate IDs (preserve first-seen order)."""
    from security_agent.app.agent.tools import submit_selected_seeds

    result = submit_selected_seeds(["a1", "a1", "a2"])
    assert result["count"] == 2
    assert result["selected_seeds"] == ["a1", "a2"]


def test_list_unprocessed_summary_returns_compact(tmp_path: Path) -> None:
    """list_unprocessed_summary returns id/title/source/severity, no full JSON."""
    from security_agent.app.agent import tools as tools_mod

    db = tmp_path / "alerts.db"
    store = SQLiteStore(db_path=db)
    store.init_db()
    for aid in ["x1", "x2"]:
        _insert_alert(store, aid)

    orig = tools_mod._DEFAULT_SQLITE_PATH
    tools_mod._DEFAULT_SQLITE_PATH = str(db)
    try:
        result = tools_mod.list_unprocessed_summary()
        assert result["count"] == 2
        for a in result["alerts"]:
            assert set(a.keys()) == {"alert_id", "title", "source", "severity"}
    finally:
        tools_mod._DEFAULT_SQLITE_PATH = orig


def test_process_queue_with_llm_seed_selection(tmp_path: Path, monkeypatch) -> None:
    """When use_llm_seed_selection=True, the outer graph's select_seeds node fires.

    After the canonical refactor ``select_seeds`` lives inside the workflow as
    ``_node_select_seeds`` (no standalone wrapper). Tests stub the bound
    method via ``MethodType`` — same pattern used for ``run_investigation``.
    """
    store, workflow = _setup_workflow(tmp_path, monkeypatch, ["a1", "a2", "a3"])

    select_calls = []

    def fake_node_select_seeds(self, state):
        already = state.get("already_associated") or set()
        select_calls.append(sorted(already))
        remaining = [aid for aid in ["a1", "a2", "a3"] if aid not in already]
        seeds = remaining[:1] if remaining else []
        return {"current_seeds": seeds, "prior_decisions": None}

    workflow._node_select_seeds = MethodType(fake_node_select_seeds, workflow)

    def fake_run_investigation(self, seed_alert_ids, **kwargs):
        for aid in seed_alert_ids:
            store.mark_false_positive(aid, "LLM: noise")
        return {
            "campaign_result": {
                "action": "llm_finish",
                "tool_outputs": [
                    {"tool": "mark_false_positive", "output": {"status": "success", "alert_id": aid}}
                    for aid in seed_alert_ids
                ],
            },
        }

    workflow.run_investigation = MethodType(fake_run_investigation, workflow)

    results = workflow.process_queue(run_id="test-run", use_llm_seed_selection=True)

    assert len(select_calls) >= 2
    assert len(results) >= 2

    cur = store.conn.cursor()
    cur.execute("SELECT alert_id, status FROM alerts ORDER BY alert_id")
    rows = cur.fetchall()
    assert all(row["status"] == "false_positive" for row in rows)


def test_llm_seed_selection_fallback_when_llm_returns_empty(tmp_path: Path, monkeypatch) -> None:
    """When the agent yields no selected seeds, the chronological fallback kicks in.

    After the canonical refactor the fallback lives inside ``_node_select_seeds``.
    To exercise the *real* fallback path we stub ``_invoke_agent`` (the
    primitive that talks to ``create_react_agent``) to return an empty
    message stream — the node then falls through to ``get_unprocessed_alerts``.
    """
    store, workflow = _setup_workflow(tmp_path, monkeypatch, ["a1", "a2", "a3"])

    from security_agent.app.agent import nodes as _nodes_mod

    def fake_invoke_agent(*, node_name, state, initial, recursion_limit):
        # Empty messages → no submit_selected_seeds tool call → fallback path.
        return {"messages": []}

    monkeypatch.setattr(_nodes_mod, "_invoke_agent", fake_invoke_agent)
    monkeypatch.setattr(
        "security_agent.app.agent.langgraph_workflow._invoke_agent",
        fake_invoke_agent,
    )

    def fake_run_investigation(self, seed_alert_ids, **kwargs):
        for aid in seed_alert_ids:
            store.mark_false_positive(aid, "LLM: noise")
        return {
            "campaign_result": {
                "action": "llm_finish",
                "tool_outputs": [
                    {"tool": "mark_false_positive", "output": {"status": "success", "alert_id": aid}}
                    for aid in seed_alert_ids
                ],
            },
        }

    workflow.run_investigation = MethodType(fake_run_investigation, workflow)

    results = workflow.process_queue(run_id="test-run", use_llm_seed_selection=True)

    cur = store.conn.cursor()
    cur.execute("SELECT alert_id, status FROM alerts ORDER BY alert_id")
    rows = cur.fetchall()

    assert all(row["status"] == "false_positive" for row in rows), (
        f"Expected all false_positive, got: {[(r['alert_id'], r['status']) for r in rows]}"
    )
    assert len(results) >= 2


def test_seed_selection_tools_list_is_canonical() -> None:
    """SEED_SELECTION_TOOLS exposes the LLM-facing seed-selection toolset.

    Beyond ``list_unprocessed_summary`` and ``submit_selected_seeds``, the
    selector also gets ``fetch_alert_by_id`` (peek a candidate before
    committing) and ``find_similar_cluster`` (semantic neighbourhood via
    embeddings) — analyst-style triage actions added when ``select_seeds``
    became a real graph node.
    """
    from security_agent.app.agent.tools import SEED_SELECTION_TOOLS

    names = {t.name for t in SEED_SELECTION_TOOLS}
    assert names == {
        "list_unprocessed_summary",
        "fetch_alert_by_id",
        "find_similar_cluster",
        "submit_selected_seeds",
    }


def test_mark_false_positive_guard_skips_in_campaign(tmp_path, monkeypatch) -> None:
    """mark_false_positive must NOT overwrite an alert that is already in_campaign."""
    from security_agent.app.agent import tools as tools_mod
    from security_agent.app.agent.tools import mark_false_positive

    db = tmp_path / "alerts.db"
    monkeypatch.setattr(tools_mod, "_DEFAULT_SQLITE_PATH", str(db))

    store = SQLiteStore(str(db))
    store.init_db()
    _insert_alert(store, "alert-guarded")

    store.conn.execute(
        "UPDATE alerts SET status = 'in_campaign' WHERE alert_id = 'alert-guarded'"
    )
    store.conn.commit()

    result = mark_false_positive("alert-guarded", "should be blocked")
    assert result["status"] == "skipped"

    refreshed = store.fetch_alert("alert-guarded")
    assert refreshed["status"] == "in_campaign"


def test_mark_false_positive_allows_unprocessed(tmp_path, monkeypatch) -> None:
    """mark_false_positive must work normally for alerts NOT in a campaign."""
    from security_agent.app.agent import tools as tools_mod
    from security_agent.app.agent.tools import mark_false_positive

    db = tmp_path / "alerts.db"
    monkeypatch.setattr(tools_mod, "_DEFAULT_SQLITE_PATH", str(db))

    store = SQLiteStore(str(db))
    store.init_db()
    _insert_alert(store, "alert-free")

    result = mark_false_positive("alert-free", "noise")
    assert result["status"] == "success"
    assert result["marked_as"] == "false_positive"

    refreshed = store.fetch_alert("alert-free")
    assert refreshed["status"] == "false_positive"
