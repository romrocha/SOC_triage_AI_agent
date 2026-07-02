"""LangGraph nodes for the SOC triage workflow.

Three graph nodes (``investigate``, ``correlate``, ``decide``) each wrap a
``langgraph.prebuilt.create_react_agent`` whose state schema is
``InvestigationState``. Tools that surface alert IDs return
``Command(update=...)`` with the matching reducers absorbing the deltas —
no post-hoc parsing of tool outputs.

Routing: ``correlate → [ready_to_decide?] → decide | investigate`` with a
``loop_count >= max_loops`` safety net in :func:`route_after_correlate`.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from ..config import MODEL_NAME
from .prompts import (
    SOC_CORRELATE_PROMPT,
    SOC_DECIDE_PROMPT,
    SOC_INVESTIGATE_PROMPT,
    SOC_SELECT_SEEDS_PROMPT,
)
from .tools import (
    CORRELATION_TOOLS,
    DECISION_TOOLS,
    INVESTIGATION_TOOLS,
    SEED_SELECTION_TOOLS,
    fetch_alert_by_id,
)

logger = logging.getLogger("soc_agent")


# ---------------------------------------------------------------------------
# Per-tool structured logging (BaseCallbackHandler)
# ---------------------------------------------------------------------------


class _PerToolLogger(BaseCallbackHandler):
    """Emit a structured log line for every tool call inside an agent run.

    Replaces the manual ``_log_tool_call`` invocations the old
    ``_react_loop`` made for each dispatch. Discovery / cache plumbing now
    happens via ``Command(update=...)`` from the tools themselves — this
    handler exists *only* for human-readable telemetry.
    """

    def __init__(self, node_name: str):
        super().__init__()
        self.node_name = node_name
        self._pending: Dict[str, Dict[str, Any]] = {}

    def on_tool_start(self, serialized, input_str, *, run_id, **_kwargs):
        name = (serialized or {}).get("name", "") if isinstance(serialized, dict) else ""
        try:
            args = json.loads(input_str) if isinstance(input_str, str) else dict(input_str or {})
        except Exception:
            args = {"raw": input_str}
        if not isinstance(args, dict):
            args = {"raw": args}
        self._pending[str(run_id)] = {"name": name, "args": args}

    def on_tool_end(self, output, *, run_id, **_kwargs):
        pending = self._pending.pop(str(run_id), {"name": "", "args": {}})
        name = pending["name"]
        args = pending["args"]
        # ``output`` may be a Command (when tools update state) or any
        # JSON-serialisable value. Normalise to a dict for log inspection.
        out = _normalise_tool_output(output)
        _format_tool_log(self.node_name, name, args, out)


def _normalise_tool_output(output: Any) -> Dict[str, Any]:
    """Best-effort dict view of a tool result for logging only.

    For Command-returning tools we inspect ``output.update`` (where present)
    to extract a representative payload. For scalar/string returns we fall
    back to JSON parsing. Logging never raises — errors yield ``{}``.
    """
    try:
        # Command from langgraph.types
        update = getattr(output, "update", None)
        if isinstance(update, dict):
            for msg in update.get("messages") or []:
                content = getattr(msg, "content", None)
                if isinstance(content, str):
                    try:
                        parsed = json.loads(content)
                        if isinstance(parsed, dict):
                            return parsed
                    except Exception:
                        return {"raw": content}
            return {k: v for k, v in update.items() if k != "messages"}
        if isinstance(output, dict):
            return output
        if isinstance(output, str):
            try:
                parsed = json.loads(output)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
            return {"raw": output}
    except Exception:
        return {}
    return {}


def _format_tool_log(node: str, tool: str, args: Dict[str, Any], out: Dict[str, Any]) -> None:
    status = out.get("status") or ""
    if tool == "search_alerts_by_entity":
        ids = out.get("alert_ids", [])
        logger.info(
            "[%s] %s(type=%s, value=%s) -> %d results",
            node, tool, args.get("entity_type", "?"), args.get("value", "?"), len(ids),
        )
    elif tool == "search_similar_alerts":
        ids = out.get("alert_ids", [])
        q = (args.get("query_text") or "")[:60]
        logger.info("[%s] %s(q=%r) -> %d results", node, tool, q, len(ids))
    elif tool == "fetch_alert_by_id":
        logger.debug(
            "[%s] %s(%s) -> %s", node, tool, str(args.get("alert_id", ""))[:12], status,
        )
    elif tool == "fetch_campaign_alerts":
        n = out.get("alert_count", 0)
        logger.info(
            "[%s] %s(%s) -> %d alerts",
            node, tool, str(args.get("campaign_id", ""))[:40], n,
        )
    elif tool == "mark_false_positive":
        logger.info(
            "[%s] %s(%s) -> %s", node, tool, str(args.get("alert_id", ""))[:12], status,
        )
    elif tool == "create_campaign":
        aids = args.get("alert_ids") or []
        logger.info("[%s] %s(%d alerts) -> %s", node, tool, len(aids), status)
    elif tool == "add_alerts_to_campaign":
        aids = args.get("alert_ids") or []
        cid = str(args.get("campaign_id") or "")[:40]
        logger.info("[%s] %s(%s, %d alerts) -> %s", node, tool, cid, len(aids), status)
    elif tool == "validate_shared_entities":
        shared = out.get("shared_entities", [])
        logger.info("[%s] %s -> %d shared entities", node, tool, len(shared))
    elif tool == "compute_time_delta":
        span = out.get("span_days", "?")
        logger.info("[%s] %s -> span=%s days", node, tool, span)
    elif tool == "ready_to_decide":
        logger.info("[%s] %s -> %s", node, tool, status)
    else:
        logger.info("[%s] %s -> %s", node, tool, status)


# ---------------------------------------------------------------------------
# Helpers — extract findings from a finished agent run
# ---------------------------------------------------------------------------


def _last_ai_content(messages: List[Any]) -> str:
    """Return the content of the last AIMessage in ``messages`` (or empty)."""
    last = next((m for m in reversed(messages) if isinstance(m, AIMessage)), None)
    content = (last.content if last else "") or ""
    if not isinstance(content, str):
        content = str(content)
    return content[:8000]


def _tool_outputs_from_messages(messages: List[Any]) -> List[Dict[str, Any]]:
    """Walk a message list and reconstruct ``[{tool, output}, ...]`` pairs.

    Used by ``node_decide`` to pick up the ``validate_shared_entities`` /
    ``compute_time_delta`` / ``ready_to_decide`` outputs that ``correlate``
    produced. Tool name is recovered by matching ``ToolMessage.tool_call_id``
    to the ``tool_calls`` of preceding ``AIMessage``s — the canonical way to
    answer "what tool produced this output" on a finished message stream.
    """
    name_by_id: Dict[str, str] = {}
    for msg in messages:
        if isinstance(msg, AIMessage):
            for tc in getattr(msg, "tool_calls", None) or []:
                tcid = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None)
                tcname = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", None)
                if tcid:
                    name_by_id[tcid] = tcname or ""

    outputs: List[Dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        name = name_by_id.get(getattr(msg, "tool_call_id", ""), "")
        content = msg.content
        try:
            parsed = json.loads(content) if isinstance(content, str) else content
        except Exception:
            parsed = {"raw": content}
        if not isinstance(parsed, (dict, list)):
            parsed = {"raw": parsed}
        outputs.append({"tool": name, "output": parsed})
    return outputs


# ---------------------------------------------------------------------------
# Agent factory (cached) + invocation helper
# ---------------------------------------------------------------------------


_AGENT_CACHE: Dict[Tuple[str, str, float], Any] = {}

_NODE_CONFIG: Dict[str, Tuple[str, list]] = {
    "investigate": (SOC_INVESTIGATE_PROMPT, INVESTIGATION_TOOLS),
    "correlate": (SOC_CORRELATE_PROMPT, CORRELATION_TOOLS),
    "decide": (SOC_DECIDE_PROMPT, DECISION_TOOLS),
    "select_seeds": (SOC_SELECT_SEEDS_PROMPT, SEED_SELECTION_TOOLS),
}


def _is_reasoning_model(model_name: str) -> bool:
    """``gpt-5*``, ``o1*``, ``o3*``, ``o4*`` don't accept ``temperature``."""
    name = (model_name or "").lower()
    return name.startswith(("gpt-5", "o1", "o3", "o4"))


_CIRCUIT_BREAKER_THRESHOLD = 3
_CIRCUIT_BREAKER_TAG = "[circuit_breaker]"


def _circuit_breaker_hook(state: Dict[str, Any]) -> Dict[str, Any]:
    """``pre_model_hook`` that warns on N consecutive same-tool errors.

    Operational protection (not a decision nudge) — when the LLM keeps
    calling the same tool with arguments that fail Pydantic validation,
    inject a brief ``SystemMessage`` so it switches strategy on the next
    turn. Stateless: counts the tail of consecutive ``ToolMessage`` errors
    in ``state["messages"]`` and dedups by detecting a previous breaker
    message in the same tail.
    """
    messages = state.get("messages") or []
    consecutive = 0
    last_tool: Optional[str] = None

    for m in reversed(messages):
        if isinstance(m, ToolMessage):
            is_error = (
                getattr(m, "status", None) == "error"
                or "validation error" in (m.content or "").lower()
            )
            if not is_error:
                break
            tname = getattr(m, "name", None) or "?"
            if last_tool is None:
                last_tool = tname
            if tname == last_tool:
                consecutive += 1
            else:
                break
        elif isinstance(m, SystemMessage) and _CIRCUIT_BREAKER_TAG in (m.content or ""):
            # Already warned within this error streak — do not re-warn.
            return {}
        # AIMessages between tool messages are part of the ReAct cadence —
        # skip and keep counting backwards.

    if consecutive >= _CIRCUIT_BREAKER_THRESHOLD and last_tool:
        warning = SystemMessage(content=(
            f"{_CIRCUIT_BREAKER_TAG} Tool '{last_tool}' has failed validation "
            f"{consecutive} consecutive times. Try a different tool or a "
            f"different argument format — repeating the same call will not succeed."
        ))
        return {"messages": [warning]}
    return {}


def _get_agent(node_name: str, model_name: str, temperature: float):
    """Lazily build (and cache) the prebuilt ReAct agent for ``node_name``.

    The agent uses ``InvestigationState`` as its state schema so tools that
    return ``Command(update={...})`` can write to ``discovered_alert_ids`` /
    ``alert_cache`` directly — and the same updates flow up to the outer
    graph through the matching reducers.

    The schema import is deferred to break a circular dependency
    (``langgraph_workflow`` imports the node functions defined below).
    """
    key = (node_name, model_name, float(temperature))
    cached = _AGENT_CACHE.get(key)
    if cached is not None:
        return cached
    if node_name not in _NODE_CONFIG:
        raise ValueError(f"Unknown node: {node_name!r}")
    prompt, tools = _NODE_CONFIG[node_name]
    llm_kwargs: Dict[str, Any] = {
        "model": model_name,
        "api_key": os.getenv("OPENAI_API_KEY"),
    }
    if not _is_reasoning_model(model_name):
        llm_kwargs["temperature"] = float(temperature)
    llm = ChatOpenAI(**llm_kwargs)

    from .langgraph_workflow import InvestigationState  # local to break cycle

    agent = create_react_agent(
        llm,
        tools,
        prompt=prompt,
        state_schema=InvestigationState,
        pre_model_hook=_circuit_breaker_hook,
    )
    _AGENT_CACHE[key] = agent
    return agent


def _langsmith_config(state: Dict[str, Any], node_name: str) -> Dict[str, Any]:
    rid = state.get("run_id") or "langgraph"
    return {
        "run_name": node_name,
        "tags": ["soc-agent", node_name],
        "metadata": {"run_id": rid, "graph_node": node_name},
    }


def _invoke_agent(
    *,
    node_name: str,
    state: Dict[str, Any],
    initial: Dict[str, Any],
    recursion_limit: int,
) -> Dict[str, Any]:
    """Invoke the cached agent for ``node_name`` and return its final state.

    Thin testability seam — tests can monkeypatch this single function
    instead of reaching into the agent cache. Production behaviour is just
    ``agent.invoke(initial, config=cfg)`` with a logging callback attached.
    """
    model_name = state.get("model_name") or MODEL_NAME
    temperature = float(state.get("temperature", 0.0))
    agent = _get_agent(node_name, model_name, temperature)

    cfg = _langsmith_config(state, node_name)
    cfg["callbacks"] = [_PerToolLogger(node_name)]
    cfg["recursion_limit"] = recursion_limit

    try:
        return agent.invoke(initial, config=cfg)
    except Exception as exc:
        if exc.__class__.__name__ == "GraphRecursionError":
            logger.warning(
                "[%s] hit recursion limit (%d) — returning partial state",
                node_name, recursion_limit,
            )
            return {"messages": []}
        raise


# ---------------------------------------------------------------------------
# Node 1: investigate
# ---------------------------------------------------------------------------

_MAX_SEED_CHARS = 80_000


def node_investigate(state: Dict[str, Any]) -> Dict[str, Any]:
    """Discover all alerts related to the seed(s).

    Seeds are fetched outside the agent so ``decide`` always sees them
    cached even if the LLM never calls ``fetch_alert_by_id`` for them. The
    pre-loaded payloads are passed to the agent via the initial state so
    Command-based tool updates from the agent merge cleanly with the seed
    cache via the ``InvestigationState`` reducers.
    """
    seed_ids = state.get("seed_alert_ids") or []
    run_id = state.get("run_id") or "langgraph"
    loop_count = int(state.get("loop_count", 0))

    logger.info(
        "[investigate] Enter | loop=%d | seeds=%s",
        loop_count, ",".join(str(s)[:12] for s in seed_ids[:5]),
    )

    seed_discovered: set = set()
    seed_cache: Dict[str, Dict[str, Any]] = {}

    if loop_count == 0:
        seed_alerts: List[Dict[str, Any]] = []
        for aid in seed_ids:
            alert = fetch_alert_by_id(aid)
            if alert:
                seed_alerts.append(alert)
                aid_str = str(alert.get("alert_id") or aid)
                seed_discovered.add(aid_str)
                seed_cache[aid_str] = alert

        seed_json = json.dumps(seed_alerts, indent=2, ensure_ascii=False, default=str)
        if len(seed_json) > _MAX_SEED_CHARS:
            seed_json = seed_json[:_MAX_SEED_CHARS] + "\n...(truncated)"

        prior = state.get("prior_decisions") or ""
        prior_section = (
            f"\n## PRIOR DECISIONS (from earlier investigations)\n{prior}\n"
            if prior else ""
        )

        human = f"""Investigate the following seed alerts. Use your tools to discover all related alerts.
{prior_section}
SEED ALERTS ({len(seed_alerts)} alerts):
{seed_json}

run_id={run_id!r}
"""
    else:
        prev_correlation = state.get("correlation_result") or {}
        prev_content = prev_correlation.get("content") or "No previous findings."
        human = f"""The correlation phase determined that more investigation is needed.

PREVIOUS CORRELATION FINDINGS (loop {loop_count}):
{prev_content}

Search for additional related alerts based on the gaps identified above.
Focus on observables or patterns not yet explored.

run_id={run_id!r}
"""

    initial: Dict[str, Any] = {
        "messages": [HumanMessage(content=human)],
        # Seed the agent with the alerts we already fetched so its tools
        # don't refetch them — the alert_cache reducer accumulates anything
        # the LLM fetches on top.
        "discovered_alert_ids": seed_discovered,
        "alert_cache": seed_cache,
    }

    result = _invoke_agent(
        node_name="investigate",
        state=state,
        initial=initial,
        recursion_limit=60,  # ~30 ReAct turns
    )

    messages = result.get("messages") or []
    return {
        "investigation_result": {
            "content": _last_ai_content(messages),
            "tool_outputs": _tool_outputs_from_messages(messages),
        },
        # Discoveries flowed through Command(update=...) inside the agent;
        # we pluck them from the agent's final state and propagate to outer.
        "discovered_alert_ids": result.get("discovered_alert_ids") or set(),
        "alert_cache": result.get("alert_cache") or {},
    }


# ---------------------------------------------------------------------------
# Node 2: correlate
# ---------------------------------------------------------------------------


def node_correlate(state: Dict[str, Any]) -> Dict[str, Any]:
    """Validate correlations + decide whether to loop back to investigate."""
    investigation = state.get("investigation_result") or {}
    seed_ids = state.get("seed_alert_ids") or []
    run_id = state.get("run_id") or "langgraph"
    loop_count = int(state.get("loop_count", 0))

    logger.info("[correlate] Enter | loop=%d", loop_count + 1)

    inv_content = investigation.get("content") or "No investigation findings."

    discovered_state = state.get("discovered_alert_ids") or set()

    seen: set = set()
    unique_ids: List[str] = []
    for aid in seed_ids:
        s = str(aid)
        if s not in seen:
            seen.add(s)
            unique_ids.append(s)
    for aid in sorted(discovered_state):
        s = str(aid)
        if s not in seen:
            seen.add(s)
            unique_ids.append(s)

    prior = state.get("prior_decisions") or ""
    prior_section = (
        f"\n## OPEN CASES (campaigns from earlier investigations)\n{prior}\n"
        if prior else ""
    )

    human = f"""Assess the cluster from the investigation below — does the
evidence support a coherent incident, or do the alerts look unrelated?
{prior_section}
## Investigation Summary (loop {loop_count + 1})
{inv_content}

## Alert IDs discovered ({len(unique_ids)} alerts)
{json.dumps(unique_ids)}

Your tools (validate_shared_entities, compute_time_delta,
fetch_campaign_alerts) are available if you need additional evidence.
When you have enough evidence, call ready_to_decide with a summary.
If the evidence is incomplete, explain in text what is missing — the
system will loop back to investigate.

run_id={run_id!r}
"""

    initial = {"messages": [HumanMessage(content=human)]}

    result = _invoke_agent(
        node_name="correlate",
        state=state,
        initial=initial,
        recursion_limit=40,  # ~20 ReAct turns
    )

    messages = result.get("messages") or []
    return {
        "correlation_result": {
            "content": _last_ai_content(messages),
            "tool_outputs": _tool_outputs_from_messages(messages),
        },
        "loop_count": loop_count + 1,
        "discovered_alert_ids": result.get("discovered_alert_ids") or set(),
        "alert_cache": result.get("alert_cache") or {},
    }


def route_after_correlate(state: Dict[str, Any]) -> str:
    """Conditional route after correlate.

    - ``loop_count >= max_loops`` → ``decide`` (safety net).
    - any ``ready_to_decide`` tool output with ``status == 'ready'`` → ``decide``.
    - otherwise → ``investigate`` (loop back).
    """
    max_loops = 3
    loop_count = int(state.get("loop_count", 0))

    if loop_count >= max_loops:
        logger.warning(
            "[route] correlate -> decide (safety net: %d loops)", loop_count
        )
        return "decide"

    correlation = state.get("correlation_result") or {}
    for t in correlation.get("tool_outputs") or []:
        if t.get("tool") == "ready_to_decide":
            out = t.get("output") or {}
            if out.get("status") == "ready":
                logger.info("[route] correlate -> decide (ready_to_decide)")
                return "decide"

    logger.info("[route] correlate -> investigate (needs more data)")
    return "investigate"


# ---------------------------------------------------------------------------
# Node 3: decide
# ---------------------------------------------------------------------------


def node_decide(state: Dict[str, Any]) -> Dict[str, Any]:
    """Persist the final triage decision (campaign / FP / merge)."""
    investigation = state.get("investigation_result") or {}
    correlation = state.get("correlation_result") or {}
    seed_ids = state.get("seed_alert_ids") or []
    run_id = state.get("run_id") or "langgraph"

    logger.info("[decide] Enter")

    inv_content = investigation.get("content") or ""
    corr_content = correlation.get("content") or ""
    corr_tools = correlation.get("tool_outputs") or []

    alert_cache: Dict[str, Dict[str, Any]] = state.get("alert_cache") or {}
    discovered_state: set = state.get("discovered_alert_ids") or set()

    fetched_alerts: List[Dict[str, Any]] = []
    validation_results: List[Dict[str, Any]] = []
    temporal_results: List[Dict[str, Any]] = []
    ready_summary = ""
    new_cache_delta: Dict[str, Dict[str, Any]] = {}

    seen_ids: set = set()
    for aid in seed_ids:
        s = str(aid)
        alert = alert_cache.get(s)
        if alert is None:
            # Fallback transparent to SQL — preserves "decide always sees the
            # seed in full" even when the cache is empty (e.g. tests that
            # skip investigate).
            alert = fetch_alert_by_id(aid)
            if alert:
                new_cache_delta[s] = alert
        if alert:
            fetched_alerts.append(alert)
            seen_ids.add(s)

    for aid in sorted(discovered_state):
        s = str(aid)
        if s in seen_ids:
            continue
        alert = alert_cache.get(s)
        if alert:
            fetched_alerts.append(alert)
            seen_ids.add(s)

    for t in corr_tools:
        tool_name = t.get("tool")
        out = t.get("output") or {}
        if tool_name == "validate_shared_entities":
            validation_results.append(out)
        elif tool_name == "compute_time_delta":
            temporal_results.append(out)
        elif tool_name == "ready_to_decide" and out.get("summary"):
            ready_summary = out["summary"]

    context_parts: List[str] = []
    if ready_summary:
        context_parts.append(f"## Correlation Conclusion\n{ready_summary}")
    if inv_content:
        context_parts.append(f"\n## Investigation Findings\n{inv_content}")
    if corr_content:
        context_parts.append(f"\n## Correlation Analysis\n{corr_content}")

    if fetched_alerts:
        seed_id_set = set(str(s) for s in seed_ids)
        seed_alerts_full = [a for a in fetched_alerts if str(a.get("alert_id")) in seed_id_set]
        other_alerts = [a for a in fetched_alerts if str(a.get("alert_id")) not in seed_id_set]

        if seed_alerts_full:
            seeds_json = json.dumps(seed_alerts_full, indent=2, ensure_ascii=False, default=str)
            context_parts.append(
                f"\n## Seed Alerts — Full Detail ({len(seed_alerts_full)} alerts)\n{seeds_json}"
            )

        if other_alerts:
            compact = []
            for a in other_alerts:
                obs = a.get("observables") or []
                key_obs = [f"{o['type']}:{o['value']}" for o in obs[:8]]
                compact.append(
                    {
                        "alert_id": a.get("alert_id"),
                        "title": a.get("title"),
                        "source": a.get("source"),
                        "date": a.get("date"),
                        "severity": a.get("severity"),
                        "status": a.get("status"),
                        "observables": key_obs,
                    }
                )
            compact_json = json.dumps(compact, indent=2, ensure_ascii=False, default=str)
            if len(compact_json) > 60_000:
                compact_json = compact_json[:60_000] + "\n...(truncated)"
            context_parts.append(
                f"\n## Discovered Alerts — Summary ({len(compact)} alerts)\n{compact_json}"
            )

    if validation_results:
        context_parts.append(
            f"\n## Entity Validation\n{json.dumps(validation_results, indent=2, default=str)}"
        )
    if temporal_results:
        context_parts.append(
            f"\n## Temporal Analysis\n{json.dumps(temporal_results, indent=2, default=str)}"
        )

    prior = state.get("prior_decisions") or ""
    prior_section = (
        f"\n## PRIOR DECISIONS (from earlier investigations)\n{prior}\n"
        if prior else ""
    )

    seed_id_list = ", ".join(str(s) for s in seed_ids) if seed_ids else "(none)"
    human = f"""Based on the investigation and correlation below, persist ALL results using your tools.

## MANDATORY SEED ALERTS ({len(seed_ids)} seeds)
The following alert IDs were the starting point of this investigation.
You MUST call either create_campaign (including the ID), add_alerts_to_campaign,
or mark_false_positive for EACH of them. No seed may be left without an explicit tool call.

Seed IDs: {seed_id_list}
{prior_section}
{"".join(context_parts)}

Use run_id={run_id!r} in create_campaign when applicable.
"""

    initial = {"messages": [HumanMessage(content=human)]}

    result = _invoke_agent(
        node_name="decide",
        state=state,
        initial=initial,
        recursion_limit=50,  # ~25 ReAct turns; production runs use 5-7 turns,
                             # so 50 is a generous safety net without burning
                             # tokens on a runaway loop.
    )
    messages = result.get("messages") or []
    decide_outputs = _tool_outputs_from_messages(messages)

    # Retry guard: if the LLM described actions without calling decision tools,
    # nudge once with an explicit instruction.
    _DECISION_TOOL_NAMES = {"create_campaign", "mark_false_positive", "add_alerts_to_campaign"}
    tools_used = {t["tool"] for t in decide_outputs}
    if not (tools_used & _DECISION_TOOL_NAMES):
        logger.warning(
            "[decide] LLM finished without calling decision tools — retrying"
        )
        retry_human = (
            "CRITICAL: You just described actions in text without actually calling any tools. "
            "Your text response was NOT persisted. You MUST call create_campaign and/or "
            "mark_false_positive tools NOW. Do not describe — call the tools.\n\n" + human
        )
        result = _invoke_agent(
            node_name="decide_retry",
            state=state,
            initial={"messages": [HumanMessage(content=retry_human)]},
            recursion_limit=40,  # retry path: smaller budget, the LLM already
                                 # had its full chance in the first invocation.
        )
        messages = result.get("messages") or []
        decide_outputs = _tool_outputs_from_messages(messages)

    all_tool_outputs = (
        (investigation.get("tool_outputs") or [])
        + corr_tools
        + decide_outputs
    )

    return {
        "campaign_result": {
            "content": _last_ai_content(messages),
            "tool_outputs": all_tool_outputs,
        },
        "discovered_alert_ids": (set(new_cache_delta.keys())
                                 | (result.get("discovered_alert_ids") or set())),
        "alert_cache": {**new_cache_delta, **(result.get("alert_cache") or {})},
    }


# Selector logic now lives in ``CampaignInvestigationWorkflow._node_select_seeds``
# (see ``langgraph_workflow.py``) — a pure outer-graph node that mirrors the
# shape of the other graph nodes. The ``select_seeds`` standalone wrapper was
# removed in the canonical refactor.

MAX_SEEDS_PER_BATCH = 3
