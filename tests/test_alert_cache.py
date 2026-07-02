"""Cache compartilhado de alertas elimina re-fetches entre nós.

Antes desta mudança, ``node_decide`` re-fazia ``fetch_alert_by_id`` para
cada seed (mesmo que ``node_investigate`` já tivesse buscado segundos
antes), e re-parseava ``investigation.tool_outputs`` para encontrar os
demais alertas. Custo: 2N idas ao SQLite + parsing frágil.

Agora ``InvestigationState.alert_cache`` mantém os payloads via
``Command(update=...)`` emitidos pelas tools, e ``node_decide`` consulta o
cache primeiro, com fallback transparente para SQL apenas em cache miss.

Os mocks fingem o retorno do agente prebuilt (``_invoke_agent``) — o agente
real devolve um dict ``{"messages": [...], "discovered_alert_ids": ...,
"alert_cache": ...}`` que o nó destila em outer state delta.
"""

from langchain_core.messages import AIMessage

from security_agent.app.agent import nodes as nodes_module


def _stub_invoke_no_op(*, node_name, state, initial, recursion_limit):
    """Agent finalizou sem produzir mais discoveries / cache."""
    return {"messages": [AIMessage(content="decided")]}


def test_decide_uses_cache_and_skips_fetch(monkeypatch):
    """Se o seed está em alert_cache, node_decide não chama fetch_alert_by_id."""
    fetch_calls: list = []

    def counting_fetch(alert_id):
        fetch_calls.append(alert_id)
        return {"alert_id": alert_id, "title": "from-sql"}

    monkeypatch.setattr(nodes_module, "fetch_alert_by_id", counting_fetch)
    monkeypatch.setattr(nodes_module, "_invoke_agent", _stub_invoke_no_op)

    cached_seed = {"alert_id": "seed1", "title": "from-cache"}
    state = {
        "seed_alert_ids": ["seed1"],
        "alert_cache": {"seed1": cached_seed},
        "discovered_alert_ids": {"seed1"},
        "investigation_result": {"content": "", "tool_outputs": []},
        "correlation_result": {"content": "", "tool_outputs": []},
        "run_id": "test",
    }

    result = nodes_module.node_decide(state)

    assert fetch_calls == [], "node_decide must not refetch when seed is in cache"
    # No new fetches happened — alert_cache delta should be empty.
    assert result["alert_cache"] == {}


def test_decide_falls_back_to_sql_on_cache_miss(monkeypatch):
    """Se o seed não está no cache, node_decide cai para SQLite e devolve o
    payload como delta — assim a próxima iteração já encontra cache hit.
    """
    fetch_calls: list = []
    sql_payload = {"alert_id": "seed_uncached", "title": "from-sql"}

    def counting_fetch(alert_id):
        fetch_calls.append(alert_id)
        return sql_payload if alert_id == "seed_uncached" else None

    monkeypatch.setattr(nodes_module, "fetch_alert_by_id", counting_fetch)
    monkeypatch.setattr(nodes_module, "_invoke_agent", _stub_invoke_no_op)

    state = {
        "seed_alert_ids": ["seed_uncached"],
        "alert_cache": {},
        "discovered_alert_ids": set(),
        "investigation_result": {"content": "", "tool_outputs": []},
        "correlation_result": {"content": "", "tool_outputs": []},
        "run_id": "test",
    }

    result = nodes_module.node_decide(state)

    assert fetch_calls == ["seed_uncached"], "Cache miss should fall back to SQL fetch"
    assert result["alert_cache"] == {"seed_uncached": sql_payload}
    assert "seed_uncached" in result["discovered_alert_ids"]


def test_investigate_seeds_populate_cache(monkeypatch):
    """node_investigate planta o cache com os seeds buscados na primeira
    iteração (fora do agent) e funde com o que o agent descobriu via
    Command(update=...).
    """
    seed_payload = {"alert_id": "s1", "title": "seed"}
    loop_payload = {"alert_id": "loop_id", "title": "found-via-fetch-tool"}

    monkeypatch.setattr(
        nodes_module,
        "fetch_alert_by_id",
        lambda aid: seed_payload if aid == "s1" else None,
    )

    def fake_invoke(*, node_name, state, initial, recursion_limit):
        # Agent simula que rodou as tools e atualizou state via Command:
        # discovered_alert_ids ganhou loop_id + search_only,
        # alert_cache ganhou loop_payload.
        return {
            "messages": [AIMessage(content="done")],
            "discovered_alert_ids": {"s1", "loop_id", "search_only"},
            "alert_cache": {"s1": seed_payload, "loop_id": loop_payload},
        }

    monkeypatch.setattr(nodes_module, "_invoke_agent", fake_invoke)

    state = {
        "seed_alert_ids": ["s1"],
        "loop_count": 0,
        "run_id": "test",
    }
    result = nodes_module.node_investigate(state)

    # Cache final = seed (fetched outside the loop) + loop_payload (Command update).
    assert result["alert_cache"] == {"s1": seed_payload, "loop_id": loop_payload}
    # Discovered final = seed_id + everything the agent saw (incl. search-only).
    assert result["discovered_alert_ids"] == {"s1", "loop_id", "search_only"}


def test_decide_includes_cached_discovered_alerts_in_context(monkeypatch):
    """Discovered alerts já presentes em alert_cache devem entrar no contexto
    do LLM (Discovered Alerts — Summary), sem refetch.
    """
    fetch_calls: list = []
    monkeypatch.setattr(
        nodes_module, "fetch_alert_by_id", lambda aid: fetch_calls.append(aid) or None
    )

    captured: dict = {}

    def capturing_invoke(*, node_name, state, initial, recursion_limit):
        captured["human"] = initial["messages"][0].content
        return {"messages": [AIMessage(content="decided")]}

    monkeypatch.setattr(nodes_module, "_invoke_agent", capturing_invoke)

    seed_alert = {"alert_id": "seed1", "title": "Seed", "observables": []}
    related_alert = {
        "alert_id": "rel1",
        "title": "Related",
        "source": "Cortex XDR",
        "severity": "3",
        "date": "1704067200000",
        "status": "unprocessed",
        "observables": [{"type": "ip", "value": "10.0.0.1"}],
    }
    state = {
        "seed_alert_ids": ["seed1"],
        "alert_cache": {"seed1": seed_alert, "rel1": related_alert},
        "discovered_alert_ids": {"seed1", "rel1"},
        "investigation_result": {"content": "", "tool_outputs": []},
        "correlation_result": {"content": "", "tool_outputs": []},
        "run_id": "test",
    }

    nodes_module.node_decide(state)

    assert fetch_calls == [], "All alerts were cached — no SQL fetches expected"
    human = captured["human"]
    assert "seed1" in human
    assert "rel1" in human
