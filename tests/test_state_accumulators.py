"""State accumulator behaviour after the create_react_agent migration.

Tools that surface alert IDs (``search_*``, ``fetch_alert_by_id``,
``fetch_campaign_alerts``) return ``Command(update={...})`` directly,
mutating the agent state via the ``InvestigationState`` reducers
(``_merge_discovered_ids`` / ``_merge_alert_cache``).

These tests cover:

1. Reducers (``_merge_discovered_ids`` / ``_merge_alert_cache``) — union /
   right-wins / None-tolerant semantics.
2. ``node_correlate`` — read of ``discovered_alert_ids`` from the
   accumulated state (not from re-parsing tool_outputs) so that IDs
   surfaced via ``search_*`` without a follow-up fetch still reach the
   correlation prompt.
"""

from langchain_core.messages import AIMessage

from security_agent.app.agent import nodes as nodes_module
from security_agent.app.agent.langgraph_workflow import (
    _merge_alert_cache,
    _merge_discovered_ids,
)


# -- reducers ----------------------------------------------------------------


def test_merge_discovered_ids_union():
    assert _merge_discovered_ids({"a"}, {"b"}) == {"a", "b"}
    assert _merge_discovered_ids(set(), {"a"}) == {"a"}
    assert _merge_discovered_ids({"a"}, set()) == {"a"}
    assert _merge_discovered_ids(None, {"x"}) == {"x"}
    assert _merge_discovered_ids({"x"}, None) == {"x"}
    assert _merge_discovered_ids(None, None) == set()


def test_merge_discovered_ids_does_not_mutate_inputs():
    left = {"a"}
    right = {"b"}
    merged = _merge_discovered_ids(left, right)
    assert merged == {"a", "b"}
    assert left == {"a"}
    assert right == {"b"}


def test_merge_alert_cache_combines_keys():
    left = {"a1": {"alert_id": "a1"}}
    right = {"a2": {"alert_id": "a2"}}
    merged = _merge_alert_cache(left, right)
    assert set(merged.keys()) == {"a1", "a2"}
    assert "a2" not in left
    assert "a1" not in right


def test_merge_alert_cache_right_wins_for_same_id():
    """Pagamentos mais recentes (right) substituem os antigos (left)."""
    left = {"a1": {"alert_id": "a1", "title": "old"}}
    right = {"a1": {"alert_id": "a1", "title": "new"}}
    merged = _merge_alert_cache(left, right)
    assert merged == {"a1": {"alert_id": "a1", "title": "new"}}


def test_merge_alert_cache_handles_none():
    assert _merge_alert_cache(None, {"a": {"alert_id": "a"}}) == {"a": {"alert_id": "a"}}
    assert _merge_alert_cache({"a": {"alert_id": "a"}}, None) == {"a": {"alert_id": "a"}}
    assert _merge_alert_cache(None, None) == {}


# -- node_correlate reads from accumulated state -----------------------------


def test_node_correlate_includes_search_only_ids_in_human_message(monkeypatch):
    """IDs vistos só via search_* (sem fetch) precisam aparecer em unique_ids
    quando o estado já os trouxe acumulados.

    Antes do refactor, ``node_correlate`` só pegava IDs com payload em
    ``tool_outputs`` (i.e., apenas os que o LLM optou por fetched). IDs
    apenas pesquisados eram silenciosamente perdidos. Agora vêm do state
    populado pelos ``Command(update=...)`` das tools de busca.
    """
    captured: dict = {}

    def fake_invoke(*, node_name, state, initial, recursion_limit):
        captured["human"] = initial["messages"][0].content
        return {"messages": [AIMessage(content="ok")]}

    monkeypatch.setattr(nodes_module, "_invoke_agent", fake_invoke)

    state = {
        "seed_alert_ids": ["seed1"],
        "discovered_alert_ids": {"seed1", "search_only_id", "fetched_id"},
        "alert_cache": {"fetched_id": {"alert_id": "fetched_id"}},
        "investigation_result": {"content": "investigation summary", "tool_outputs": []},
        "loop_count": 0,
        "run_id": "test",
    }

    result = nodes_module.node_correlate(state)

    human = captured["human"]
    assert "seed1" in human
    assert "fetched_id" in human
    # The bug-fix assertion: a search-only ID must reach correlate.
    assert "search_only_id" in human

    assert result["loop_count"] == 1
    assert result["discovered_alert_ids"] == set()
    assert result["alert_cache"] == {}


def test_node_correlate_no_duplicates_when_seed_also_in_discovered(monkeypatch):
    """Seeds já presentes em discovered_alert_ids não devem duplicar."""
    captured: dict = {}

    def fake_invoke(*, node_name, state, initial, recursion_limit):
        captured["human"] = initial["messages"][0].content
        return {"messages": [AIMessage(content="ok")]}

    monkeypatch.setattr(nodes_module, "_invoke_agent", fake_invoke)

    state = {
        "seed_alert_ids": ["seed1"],
        "discovered_alert_ids": {"seed1"},
        "alert_cache": {},
        "investigation_result": {"content": "x", "tool_outputs": []},
        "loop_count": 0,
        "run_id": "test",
    }
    nodes_module.node_correlate(state)

    # "seed1" should appear exactly once (the JSON list has one quoted entry)
    assert captured["human"].count('"seed1"') == 1
