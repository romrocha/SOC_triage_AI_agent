"""
LangGraph workflow: orquestração em duas camadas.

1) Orquestrador (Python): `process_queue` — seleciona seeds (via LLM ou
   cronologicamente), chamando `run_investigation` por ciclo.

2) Grafo interno (uma investigação = `run_investigation`):
   Três nós LLM com loops ReAct independentes e routing condicional:
     investigate → correlate → [ready?] → decide → END
                      ↑           │ não
                      └───────────┘
"""

import logging
import operator
import time
from pathlib import Path
from typing import Annotated, Any, Callable, Dict, List, Literal, Optional, Set, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import MessagesState

from langchain_core.messages import HumanMessage

from ..config import CHROMA_DIR, MODEL_NAME, SQLITE_DB
from ..ingestion.sqlite_store import SQLiteStore
from .nodes import (
    _invoke_agent,
    _tool_outputs_from_messages,
    node_correlate,
    node_decide,
    node_investigate,
    route_after_correlate,
)
from .tools import configure_tooling, get_unprocessed_alerts, list_campaigns_summary

logger = logging.getLogger("soc_agent")


def _merge_alert_cache(
    left: Optional[Dict[str, Dict[str, Any]]],
    right: Optional[Dict[str, Dict[str, Any]]],
) -> Dict[str, Dict[str, Any]]:
    """LangGraph reducer that accumulates alert payloads across nodes.

    Later writes win for the same alert_id (so a refreshed fetch supersedes
    an older snapshot). Tolerant of ``None`` inputs because LangGraph may
    invoke the reducer before the field is initialised in some code paths.
    """
    if not left and not right:
        return {}
    if not left:
        return dict(right or {})
    if not right:
        return dict(left)
    merged = dict(left)
    merged.update(right)
    return merged


def _merge_discovered_ids(
    left: Optional[Set[str]],
    right: Optional[Set[str]],
) -> Set[str]:
    """LangGraph reducer that unions discovered alert IDs across nodes."""
    if not left and not right:
        return set()
    if not left:
        return set(right or ())
    if not right:
        return set(left)
    return set(left) | set(right)


class InvestigationState(MessagesState):
    """Estado compartilhado do grafo de investigação.

    Estende ``langgraph.graph.message.MessagesState`` — herda
    ``messages: Annotated[list[AnyMessage], add_messages]``, que é o que
    ``create_react_agent`` espera por padrão. Esse mesmo schema é passado a
    cada subagente via ``state_schema=InvestigationState``, então as tools
    podem retornar ``Command(update={...})`` e os reducers absorvem
    automaticamente — sem mais parsing post-hoc de ``tool_outputs`` para
    reconstruir descobertas.

    Campos com ``Annotated[..., reducer]`` (``discovered_alert_ids`` e
    ``alert_cache``) são acumuladores: cada update é mesclado com o existente.

    ``remaining_steps`` é exigido por ``create_react_agent`` (cheque por
    NOME de campo no ``state_schema``). Mantemos como ``int`` simples — o
    tipo ``RemainingSteps`` (managed) do langgraph entra em conflito com a
    introspecção repetida que ``add_conditional_edges`` faz no schema.
    O cap real de iterações ReAct vem do ``recursion_limit`` no
    ``RunnableConfig`` que ``_invoke_agent`` passa, não desse campo.
    """

    # Required by create_react_agent — schema check is by field name only.
    remaining_steps: int

    # Input (definido pelo orquestrador)
    seed_alert_ids: List[str]

    # Passado entre nós
    investigation_result: Optional[Dict[str, Any]]
    correlation_result: Optional[Dict[str, Any]]
    loop_count: int

    # Acumuladores populados pelos Command(update=...) das tools de busca/fetch.
    # discovered_alert_ids: união dos IDs vistos em search_*, fetch_alert_by_id, fetch_campaign_alerts.
    # alert_cache: payload completo dos alertas fetched, por alert_id.
    discovered_alert_ids: Annotated[Set[str], _merge_discovered_ids]
    alert_cache: Annotated[Dict[str, Dict[str, Any]], _merge_alert_cache]

    # Output (contrato com o orquestrador)
    campaign_result: Optional[Dict[str, Any]]

    # Cross-investigation memory
    prior_decisions: Optional[str]

    # Configuração
    run_id: str
    model_name: str
    temperature: float


class BatchState(TypedDict, total=False):
    """Outer-graph state for a full triage round (one ``process_queue`` call).

    The previous implementation drove the queue with a Python ``while`` loop
    around ``run_investigation``. That worked but produced N+1 root traces in
    LangSmith (one per investigation + one for select_seeds), no shared
    state between iterations, and no checkpointing.

    Modelling the round as a StateGraph gives us:

    * a single root trace per round (waterfall in LangSmith);
    * a real ``already_associated`` accumulator with reducer (so iterations
      can't lose track of processed alerts);
    * a ``results`` accumulator (concatenated via ``operator.add``) for the
      caller-facing return value;
    * the ability to plug a ``SqliteSaver`` checkpointer later without
      rewriting the orchestration.

    Per-iteration ephemeral fields (``current_seeds``, ``prior_decisions``,
    ``last_inv_result``) carry data between adjacent nodes within one trip
    around the loop.
    """

    # Static configuration (set at run start, immutable through the round)
    run_id: str
    max_seeds: Optional[int]
    auto_finalize_unprocessed: bool
    skip_already_in_campaign: bool
    use_llm_seed_selection: bool
    batch_size: int

    # Per-iteration ephemeral
    current_seeds: List[str]
    prior_decisions: Optional[str]
    last_inv_result: Optional[Dict[str, Any]]

    # Accumulators
    seed_count: int
    already_associated: Annotated[Set[str], _merge_discovered_ids]
    results: Annotated[List[Dict[str, Any]], operator.add]


def _campaign_result_associates_alerts(campaign_result: Dict[str, Any]) -> bool:
    """True se houve create_campaign ou mark_false_positive com sucesso."""
    action = campaign_result.get("action")
    if action in ("campaign", "false_positive"):
        return True
    for item in campaign_result.get("tool_outputs") or []:
        tool = item.get("tool")
        out = item.get("output") or {}
        if tool == "create_campaign" and out.get("status") == "success":
            return True
        if tool == "mark_false_positive" and out.get("status") == "success":
            return True
    return False


def _get_processed_ids(campaign_result: Dict[str, Any]) -> set:
    """Extrai IDs dos alertas que o LLM efetivamente processou via tool calls."""
    processed: set = set()
    for item in campaign_result.get("tool_outputs") or []:
        tool = item.get("tool")
        out = item.get("output") or {}
        if out.get("status") not in ("success", "no_change"):
            continue
        if tool in ("create_campaign", "add_alerts_to_campaign"):
            for aid in out.get("alert_ids") or []:
                processed.add(str(aid))
            for aid in out.get("added") or []:
                processed.add(str(aid))
        elif tool == "mark_false_positive":
            aid = out.get("alert_id")
            if aid:
                processed.add(str(aid))
    return processed


def setup_file_logging(log_path: str | Path, level: int = logging.INFO) -> logging.FileHandler:
    """Configure the ``soc_agent`` logger to write to *log_path* and return the handler."""
    soc_logger = logging.getLogger("soc_agent")
    soc_logger.setLevel(level)

    handler = logging.FileHandler(str(log_path), mode="w", encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", datefmt="%H:%M:%S"))
    soc_logger.addHandler(handler)
    return handler


class CampaignInvestigationWorkflow:
    """
    Workflow LangGraph para investigação de campanhas.

    Grafo: investigate → correlate → [ready?] → decide → END
                                        ↑         │ não
                                        └─────────┘

    - `run_investigation(seed_alert_ids)`: uma investigação (grafo com 3 nós LLM).
    - `process_queue(...)`: loop sobre a fila de não processados.
    """

    def __init__(
        self,
        sqlite_path: Optional[str] = None,
        chroma_path: Optional[str] = None,
        model_name: Optional[str] = None,
        temperature: float = 0.0,
    ):
        self.sqlite_path = str(sqlite_path or SQLITE_DB)
        self.chroma_path = str(chroma_path or CHROMA_DIR)
        self.model_name = model_name or MODEL_NAME
        self.temperature = temperature
        configure_tooling(sqlite_path=self.sqlite_path, chroma_path=self.chroma_path)
        self._graph = self._build_investigation_graph()

    @staticmethod
    def _route_after_correlate(state: InvestigationState) -> Literal["investigate", "decide"]:
        return route_after_correlate(state)

    def _build_investigation_graph(self):
        workflow = StateGraph(InvestigationState)

        workflow.add_node("investigate", node_investigate)
        workflow.add_node("correlate", node_correlate)
        workflow.add_node("decide", node_decide)

        workflow.set_entry_point("investigate")
        workflow.add_edge("investigate", "correlate")
        workflow.add_conditional_edges(
            "correlate",
            self._route_after_correlate,
            {"investigate": "investigate", "decide": "decide"},
        )
        workflow.add_edge("decide", END)

        return workflow.compile()

    def _make_investigation_state(
        self,
        seed_alert_ids: List[str],
        run_id: str = "langgraph",
        prior_decisions: Optional[str] = None,
    ) -> InvestigationState:
        return InvestigationState(
            seed_alert_ids=list(seed_alert_ids),
            investigation_result=None,
            correlation_result=None,
            loop_count=0,
            discovered_alert_ids=set(),
            alert_cache={},
            campaign_result=None,
            prior_decisions=prior_decisions,
            run_id=run_id,
            model_name=self.model_name,
            temperature=self.temperature,
        )

    def run_investigation(
        self,
        seed_alert_ids: List[str],
        run_id: Optional[str] = None,
        prior_decisions: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executa uma investigação para um ou mais alertas seed.
        Retorna o estado final (incluindo campaign_result).
        """
        if not seed_alert_ids:
            return {"campaign_result": {"action": "skip", "reason": "empty_seed"}}
        run_id = run_id or "langgraph"
        initial = self._make_investigation_state(seed_alert_ids, run_id=run_id, prior_decisions=prior_decisions)
        final = self._graph.invoke(initial)
        return final

    @staticmethod
    def _build_prior_decisions(store: SQLiteStore) -> Optional[str]:
        """Build a compact summary of campaigns created so far for cross-investigation memory.

        The header line announces the two cross-investigation tools
        (``fetch_campaign_alerts`` and ``add_alerts_to_campaign``) without
        forcing their use — the LLM decides if/when overlap with prior
        decisions warrants opening a case file or merging. Conditional
        wording avoids the previous "always call X then Y" ritual which we
        observed driving rote tool calls regardless of evidence.
        """
        campaigns = store.list_campaigns_summary()
        if not campaigns:
            return None
        lines = [
            "Previously created campaigns. If you suspect overlap with any of "
            "these, fetch_campaign_alerts(campaign_id) returns the full alerts "
            "inside, and add_alerts_to_campaign lets you merge when overlap is "
            "confirmed:",
        ]
        for c in campaigns:
            ids_preview = ", ".join(c["alert_ids"][:5])
            if len(c["alert_ids"]) > 5:
                ids_preview += f", ... ({c['alert_count']} total)"
            lines.append(
                f"  - {c['campaign_id']} | {c['alert_count']} alerts | "
                f"confidence={c['confidence']:.0%} | {c['summary'][:120]}"
            )
            lines.append(f"    alert_ids: [{ids_preview}]")
        return "\n".join(lines)

    def _mark_not_evaluated(
        self,
        store: SQLiteStore,
        alert_ids: List[str],
        *,
        reason: str,
    ) -> List[str]:
        """Marca alertas como not_evaluated — nunca passaram pelo LLM."""
        marked: List[str] = []
        for aid in list(dict.fromkeys(str(aid) for aid in alert_ids if aid)):
            if not store.fetch_alert(aid):
                continue
            store.mark_not_evaluated(aid, reason)
            marked.append(aid)
        return marked

    # ------------------------------------------------------------------
    # Outer-graph nodes (round-level orchestration)
    # ------------------------------------------------------------------

    def _node_init_batch(self, state: BatchState) -> Dict[str, Any]:
        """Seed the round: load already-processed IDs from SQLite."""
        store = SQLiteStore(self.sqlite_path)
        if state.get("skip_already_in_campaign", True):
            initial = set(store.list_campaign_alert_ids())
        else:
            initial = set()
        logger.info(
            "[batch] Init | run_id=%s | already_associated=%d",
            state.get("run_id"), len(initial),
        )
        return {"already_associated": initial, "seed_count": 0}

    def _node_select_seeds(self, state: BatchState) -> Dict[str, Any]:
        """Pick the next seed list (LLM or chronological) and snapshot prior_decisions.

        Pure outer-graph node: builds the human prompt, invokes the
        ``select_seeds`` ReAct agent via ``_invoke_agent``, parses the
        ``submit_selected_seeds`` tool output from the message stream, and
        falls back to chronological selection when the LLM yields nothing.
        Symmetric with the other outer nodes — no standalone wrapper layer.
        """
        store = SQLiteStore(self.sqlite_path)
        already = state.get("already_associated") or set()
        batch_size = state.get("batch_size") or 1
        prior_decisions = self._build_prior_decisions(store)
        seed_list: List[str] = []

        if state.get("use_llm_seed_selection", True):
            logger.info(
                "[select_seeds] Enter | %d already associated", len(already)
            )

            prior_section = ""
            if prior_decisions:
                prior_section = (
                    "\n## OPEN CASES (campaigns from earlier investigations)\n"
                    f"{prior_decisions}\n"
                )

            human = f"""Select the next seed alert(s) to investigate.

Use your tools to inspect the unprocessed queue, then call
submit_selected_seeds when done.
{prior_section}"""

            agent_state: Dict[str, Any] = {
                "run_id": state.get("run_id") or "langgraph-batch",
                "model_name": self.model_name,
                "temperature": self.temperature,
            }
            result = _invoke_agent(
                node_name="select_seeds",
                state=agent_state,
                initial={"messages": [HumanMessage(content=human)]},
                recursion_limit=30,  # ~15 ReAct turns
            )
            for t in _tool_outputs_from_messages(result.get("messages") or []):
                if t.get("tool") == "submit_selected_seeds":
                    out = t.get("output") or {}
                    if out.get("status") == "ready":
                        seed_list = list(out.get("selected_seeds") or [])
                        logger.info(
                            "[select_seeds] Selected %d seeds: %s",
                            len(seed_list),
                            ",".join(s[:12] for s in seed_list),
                        )
                        break
            else:
                logger.warning(
                    "[select_seeds] LLM did not call submit_selected_seeds"
                )

            if not seed_list:
                fallback = get_unprocessed_alerts(
                    limit=batch_size or 5,
                    exclude_alert_ids=list(already) if already else None,
                )
                for a in fallback:
                    aid = a.get("alert_id") if isinstance(a, dict) else None
                    if aid and aid not in already:
                        seed_list.append(aid)
                        if len(seed_list) >= (batch_size or 5):
                            break
                if seed_list:
                    logger.info(
                        "LLM seed selector returned [] — chronological fallback: %s",
                        ",".join(s[:12] for s in seed_list),
                    )
        else:
            batch = get_unprocessed_alerts(
                limit=batch_size or 100,
                exclude_alert_ids=list(already) if already else None,
            )
            for a in batch:
                aid = a.get("alert_id") if isinstance(a, dict) else None
                if not aid or aid in already:
                    continue
                seed_list.append(aid)
                if len(seed_list) >= (batch_size or 1):
                    break

        return {"current_seeds": seed_list, "prior_decisions": prior_decisions}

    def _node_run_investigation(self, state: BatchState) -> Dict[str, Any]:
        """Invoke the inner investigation subgraph for the current seeds."""
        seed_list = state.get("current_seeds") or []
        seed_count = int(state.get("seed_count") or 0)
        max_seeds = state.get("max_seeds")
        run_id_base = state.get("run_id") or "langgraph-batch"
        rid = f"{run_id_base}-{seed_count}" if max_seeds and max_seeds > 1 else run_id_base

        logger.info("=" * 60)
        logger.info(
            "Investigation %d | seeds: %s | run_id=%s",
            seed_count + 1, ",".join(s[:12] for s in seed_list), rid,
        )

        t_inv = time.time()
        final = self.run_investigation(
            seed_alert_ids=seed_list,
            run_id=rid,
            prior_decisions=state.get("prior_decisions"),
        )
        inv_elapsed = time.time() - t_inv

        campaign_result = final.get("campaign_result") or {}
        fp_count = sum(
            1 for t in (campaign_result.get("tool_outputs") or [])
            if t.get("tool") == "mark_false_positive"
            and (t.get("output") or {}).get("status") == "success"
        )
        camp_count = sum(
            len((t.get("output") or {}).get("alert_ids") or [])
            for t in (campaign_result.get("tool_outputs") or [])
            if t.get("tool") == "create_campaign"
            and (t.get("output") or {}).get("status") == "success"
        )

        logger.info(
            "Investigation %d done | %.1fs | %d FP + %d campaign | action=%s",
            seed_count + 1, inv_elapsed, fp_count, camp_count,
            campaign_result.get("action", "?"),
        )

        # ``on_progress`` flows via instance attribute (set by ``process_queue``).
        # Using LangGraph's ``RunnableConfig`` injection on a bound method
        # didn't pick up the ``config`` parameter on this langgraph version,
        # and callbacks aren't JSON-serialisable so they can't live in state.
        on_progress = getattr(self, "_on_progress", None)
        if on_progress:
            tools_used: Dict[str, int] = {}
            for t in campaign_result.get("tool_outputs") or []:
                name = t.get("tool", "?")
                tools_used[name] = tools_used.get(name, 0) + 1
            on_progress({
                "inv": seed_count + 1,
                "max_seeds": state.get("max_seeds"),
                "seeds": seed_list,
                "elapsed_s": inv_elapsed,
                "fp": fp_count,
                "campaign": camp_count,
                "action": campaign_result.get("action", "?"),
                "tools_used": tools_used,
            })

        return {
            "last_inv_result": final,
            "results": [final],  # operator.add reducer on outer state
        }

    def _node_post_iteration(self, state: BatchState) -> Dict[str, Any]:
        """Update accumulators + auto-finalize unhandled seeds for this iteration."""
        seed_list = state.get("current_seeds") or []
        final = state.get("last_inv_result") or {}
        campaign_result = final.get("campaign_result") or {}
        seed_count = int(state.get("seed_count") or 0)
        run_id_base = state.get("run_id") or "langgraph-batch"
        max_seeds = state.get("max_seeds")
        rid = f"{run_id_base}-{seed_count}" if max_seeds and max_seeds > 1 else run_id_base

        llm_processed = _get_processed_ids(campaign_result)
        delta = set(seed_list) | llm_processed

        if state.get("auto_finalize_unprocessed", True):
            unhandled = set(seed_list) - llm_processed
            if unhandled:
                marked = self._mark_not_evaluated(
                    SQLiteStore(self.sqlite_path),
                    list(unhandled),
                    reason=(
                        "Seed not explicitly processed by LLM — marked for re-evaluation "
                        f"(run_id={rid})."
                    ),
                )
                logger.info(
                    "Marked %d unhandled seeds as not_evaluated: %s",
                    len(marked), ",".join(s[:12] for s in marked),
                )

        return {
            "already_associated": delta,  # _merge_discovered_ids reducer unions
            "seed_count": seed_count + 1,
        }

    def _node_finalize_batch(self, state: BatchState) -> Dict[str, Any]:
        """End-of-round: mark any leftover unprocessed alerts as not_evaluated."""
        if not state.get("auto_finalize_unprocessed", True):
            return {}
        store = SQLiteStore(self.sqlite_path)
        leftovers = store.get_unprocessed_alerts(limit=1_000_000)
        leftover_ids = [
            row.get("alert_id")
            for row in leftovers
            if isinstance(row, dict) and row.get("alert_id")
        ]
        if not leftover_ids:
            return {}
        marked = self._mark_not_evaluated(
            store,
            leftover_ids,
            reason=(
                "Queue drain: alert was never evaluated by the LLM. "
                f"Consider increasing max_seeds or running another batch "
                f"(run_id={state.get('run_id')})."
            ),
        )
        if not marked:
            return {}
        logger.warning("Queue drain: %d alerts not evaluated", len(marked))
        return {
            "results": [
                {
                    "campaign_result": {
                        "action": "mark_not_evaluated",
                        "alert_ids": marked,
                        "reason": "queue_drain_not_evaluated",
                    }
                }
            ],
        }

    @staticmethod
    def _route_max_seeds_or_select(
        state: BatchState,
    ) -> Literal["select_seeds", "finalize"]:
        """Stop when max_seeds is reached; otherwise (re)enter seed selection.

        Used at two points: right after ``init`` (handles ``max_seeds=0``
        edge case the old ``while`` loop short-circuited at the top) and
        right after ``post_iteration`` (the normal "do another lap?" check).
        """
        max_seeds = state.get("max_seeds")
        seed_count = int(state.get("seed_count") or 0)
        if max_seeds is not None and seed_count >= max_seeds:
            return "finalize"
        return "select_seeds"

    @staticmethod
    def _route_after_select_seeds(state: BatchState) -> Literal["investigate", "finalize"]:
        """If select_seeds produced no IDs, the queue is drained — go to finalize."""
        seeds = state.get("current_seeds") or []
        return "investigate" if seeds else "finalize"

    def _build_round_graph(self):
        graph = StateGraph(BatchState)
        graph.add_node("init", self._node_init_batch)
        graph.add_node("select_seeds", self._node_select_seeds)
        graph.add_node("investigate", self._node_run_investigation)
        graph.add_node("post_iteration", self._node_post_iteration)
        graph.add_node("finalize", self._node_finalize_batch)

        graph.add_edge(START, "init")
        graph.add_conditional_edges(
            "init",
            self._route_max_seeds_or_select,
            {"select_seeds": "select_seeds", "finalize": "finalize"},
        )
        graph.add_conditional_edges(
            "select_seeds",
            self._route_after_select_seeds,
            {"investigate": "investigate", "finalize": "finalize"},
        )
        graph.add_edge("investigate", "post_iteration")
        graph.add_conditional_edges(
            "post_iteration",
            self._route_max_seeds_or_select,
            {"select_seeds": "select_seeds", "finalize": "finalize"},
        )
        graph.add_edge("finalize", END)
        return graph.compile()

    def process_queue(
        self,
        batch_size: int = 1,
        max_seeds: Optional[int] = None,
        run_id: Optional[str] = None,
        skip_already_in_campaign: bool = True,
        auto_finalize_unprocessed: bool = True,
        on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
        use_llm_seed_selection: bool = True,
    ) -> List[Dict[str, Any]]:
        """Drive a full triage round through the outer LangGraph round-graph.

        The public API is unchanged from the legacy Python ``while`` loop:
        same arguments, same return type (a list of per-investigation final
        states, plus an optional sentinel entry from the queue-drain
        finalize step).

        ``on_progress`` is forwarded to the investigation node via
        ``RunnableConfig.configurable`` (LangGraph state must remain
        JSON-serialisable; callbacks don't qualify).
        """
        t_total_start = time.time()
        run_id = run_id or "langgraph-batch"

        # We need a recursion budget large enough for one trip per investigation.
        # Each loop iteration walks 3 outer nodes (select_seeds → investigate →
        # post_iteration). With a default queue of ~100 alerts and 1 seed per
        # iteration, ~300 outer steps are plenty; bumping further is cheap.
        recursion_limit = max(150, 8 * (max_seeds or 200))

        graph = self._build_round_graph()
        config = {
            "recursion_limit": recursion_limit,
            # ``run_name`` is the trace title shown in the LangSmith UI.
            # Using ``run_id`` (which carries the timestamp) makes each
            # execution distinguishable inside a project that aggregates
            # multiple runs (e.g. project=round1-gpt-4.1-mini covers many
            # executions, each trace named with the full run_id).
            "run_name": run_id,
            "tags": ["soc-agent", "round", run_id],
            "metadata": {"run_id": run_id},
        }

        initial: BatchState = {
            "run_id": run_id,
            "max_seeds": max_seeds,
            "auto_finalize_unprocessed": auto_finalize_unprocessed,
            "skip_already_in_campaign": skip_already_in_campaign,
            "use_llm_seed_selection": use_llm_seed_selection,
            "batch_size": batch_size,
            "seed_count": 0,
            "already_associated": set(),
            "results": [],
        }

        # ``on_progress`` is a plain Python callback — can't live in graph
        # state (TypedDict + reducers want JSON-serialisable values), and
        # LangGraph config injection didn't pick it up on bound methods.
        # Stash on the instance for the duration of the run; clear afterwards.
        self._on_progress = on_progress
        try:
            final_state = graph.invoke(initial, config=config)
        finally:
            self._on_progress = None

        total_elapsed = time.time() - t_total_start
        minutes, seconds = divmod(total_elapsed, 60)
        logger.info("=" * 60)
        logger.info(
            "Total execution time: %.1fs (%dm %02ds) | %d investigations | run_id=%s",
            total_elapsed, int(minutes), int(seconds),
            int(final_state.get("seed_count") or 0), run_id,
        )

        return list(final_state.get("results") or [])
