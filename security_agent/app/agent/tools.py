"""Tool definitions for the SOC triage agents.

Two layers live here:

1. **Public Python helpers** (``search_similar_alerts``, ``fetch_alert_by_id``,
   ``create_campaign``, …): direct SQLite/Chroma operations, used by nodes,
   tests, and any code that needs to hit the data layer without going through
   the LLM.

2. **LangChain ``@tool``-decorated wrappers** (``_t_*`` functions): what the
   LLM sees. They wrap the public helpers, apply output truncation, and are
   grouped per agent at the bottom of the module
   (``INVESTIGATION_TOOLS``, ``CORRELATION_TOOLS``, ``DECISION_TOOLS``,
   ``SEED_SELECTION_TOOLS``).

The previous OpenAI function-calling spec helpers and ``FUNCTION_REGISTRY``
were removed in the migration to ``langgraph.prebuilt.create_react_agent`` —
the prebuilt agent discovers tools directly from the ``@tool`` decorators.
"""

from typing import List, Dict, Any, Optional, Literal
from pathlib import Path
import json
import re

from typing_extensions import Annotated

from pydantic import BaseModel, Field, field_validator

from langchain.tools import tool
from langchain_core.messages import ToolMessage
from langchain_core.tools import InjectedToolCallId
from langgraph.types import Command

from ..ingestion.embedding import Embedder
from ..ingestion.chroma_store import ChromaStore
from ..ingestion.sqlite_store import SQLiteStore
from ..config import CHROMA_DIR
from ..utils.datetime import parse_alert_datetime  # re-exported for backward compat

__all__ = [
    "configure_tooling",
    # public python helpers
    "search_similar_alerts",
    "search_alerts_by_entity",
    "fetch_alert_by_id",
    "fetch_campaign_alerts",
    "validate_shared_entities",
    "compute_time_delta",
    "get_unprocessed_alerts",
    "create_campaign",
    "mark_false_positive",
    "add_alerts_to_campaign",
    "list_campaigns_summary",
    "ready_to_decide",
    "list_unprocessed_summary",
    "find_similar_cluster",
    "submit_selected_seeds",
    # LLM tool lists (consumed by create_react_agent)
    "INVESTIGATION_TOOLS",
    "CORRELATION_TOOLS",
    "DECISION_TOOLS",
    "SEED_SELECTION_TOOLS",
    # legacy re-export
    "parse_alert_datetime",
]

# ---------------------------------------------------------------------------
# Module-level cached resources
# ---------------------------------------------------------------------------

_embedder: Optional[Embedder] = None
_chroma: Optional[ChromaStore] = None
_DEFAULT_SQLITE_PATH: Optional[str] = None
_DEFAULT_CHROMA_DIR: str = str(CHROMA_DIR)
_store_cache: Dict[str, SQLiteStore] = {}

_TOOL_OUTPUT_CHAR_LIMIT = 16_000


def _get_store(sqlite_path: Optional[str] = None) -> SQLiteStore:
    """Return a cached SQLiteStore for *sqlite_path* (or the configured default)."""
    path = sqlite_path if sqlite_path is not None else _DEFAULT_SQLITE_PATH
    key = "" if path is None else str(Path(path))
    cached = _store_cache.get(key)
    if cached is None:
        cached = SQLiteStore(db_path=path)
        _store_cache[key] = cached
    return cached


def configure_tooling(
    sqlite_path: Optional[str] = None, chroma_path: Optional[str] = None
) -> None:
    """Configure default paths used by tools to align with the agent instance."""
    global _DEFAULT_SQLITE_PATH, _DEFAULT_CHROMA_DIR, _chroma
    if sqlite_path:
        new_path = str(Path(sqlite_path))
        if new_path != _DEFAULT_SQLITE_PATH:
            _store_cache.clear()  # drop stale connections for the previous path
        _DEFAULT_SQLITE_PATH = new_path
    if chroma_path:
        _DEFAULT_CHROMA_DIR = str(Path(chroma_path))
        _chroma = None  # force re-init with new path


def get_embedder() -> Embedder:
    """Return a singleton Embedder instance."""
    global _embedder
    if _embedder is None:
        _embedder = Embedder()
    return _embedder


def get_chroma() -> ChromaStore:
    """Return a singleton ChromaStore bound to the configured directory."""
    global _chroma
    if _chroma is None:
        _chroma = ChromaStore(persist_directory=_DEFAULT_CHROMA_DIR)
    return _chroma


def _capped(payload: Any) -> Any:
    """Cap an LLM-bound tool payload to ``_TOOL_OUTPUT_CHAR_LIMIT`` chars.

    Lives on the tool side so the cap travels with the result regardless of
    who runs the loop. ToolMessage content is built from the capped payload.
    """
    try:
        s = json.dumps(payload, default=str)
    except Exception:
        return payload  # not JSON-serialisable; let LangChain stringify it
    if len(s) <= _TOOL_OUTPUT_CHAR_LIMIT:
        return payload
    return {
        "__truncated__": True,
        "limit_chars": _TOOL_OUTPUT_CHAR_LIMIT,
        "preview": s[:_TOOL_OUTPUT_CHAR_LIMIT] + "...(truncated)",
    }


def _tool_message(payload: Any, tool_call_id: str) -> ToolMessage:
    """Build a ToolMessage with capped, JSON-serialised content.

    Used by tools that return ``Command(update=...)`` — they are responsible
    for emitting the ToolMessage themselves (the prebuilt ``ToolNode`` only
    wraps return values that are not Commands).
    """
    capped = _capped(payload)
    content = capped if isinstance(capped, str) else json.dumps(capped, default=str)
    return ToolMessage(content=content, tool_call_id=tool_call_id)


def _split_decided(alert_ids: List[str]) -> Dict[str, Any]:
    """Split a list of alert_ids into ``unprocessed`` vs ``decided``.

    Returns ``{"unprocessed": [...], "decided": [{alert_id, decision, ...}]}``
    where each ``decided`` entry carries the current decision and, when
    applicable, the ``campaign_id`` so the agent can call
    ``add_alerts_to_campaign`` against the right case instead of
    fabricating a new one. Alerts not found in the store are silently
    dropped — the search tool already returned them but if the JOIN with
    the alerts table is empty (race / orphan) we don't surface a phantom.
    """
    store = _get_store()
    unprocessed: List[str] = []
    decided: List[Dict[str, Any]] = []
    for aid in alert_ids:
        if not aid:
            continue
        alert = store.fetch_alert(str(aid))
        if not alert:
            continue
        status = alert.get("status") or "unprocessed"
        if status == "unprocessed":
            unprocessed.append(str(aid))
            continue
        entry: Dict[str, Any] = {"alert_id": str(aid), "decision": status}
        if status == "in_campaign" and alert.get("campaign_id"):
            entry["campaign_id"] = alert["campaign_id"]
        if status == "false_positive" and alert.get("false_positive_reason"):
            entry["reason"] = alert["false_positive_reason"]
        decided.append(entry)
    return {"unprocessed": unprocessed, "decided": decided}


def _cmd_with_discovery(
    payload: Any,
    tool_call_id: str,
    *,
    discovered: Optional[set] = None,
    cache: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Command:
    """Build a ``Command(update=...)`` for a search/fetch tool.

    Centralises the boilerplate the 4 discovery tools share: emit the
    ``ToolMessage``, optionally union ``discovered_alert_ids`` and merge
    ``alert_cache`` via the ``InvestigationState`` reducers. Empty deltas
    are omitted so the reducer is not invoked with a no-op update.
    """
    update: Dict[str, Any] = {"messages": [_tool_message(payload, tool_call_id)]}
    if discovered:
        update["discovered_alert_ids"] = discovered
    if cache:
        update["alert_cache"] = cache
    return Command(update=update)


# ---------------------------------------------------------------------------
# Public Python helpers
# ---------------------------------------------------------------------------


def search_similar_alerts(query_text: str, n: int = 10) -> List[str]:
    """Vector search by alert text, returning ALL similar alert IDs.

    Returns ids regardless of triage status — the LLM-facing wrapper
    splits unprocessed vs decided so the agent sees the full semantic
    neighbourhood (including alerts already in campaigns / FP) without
    losing the chance to wire a new alert into an existing case.
    """
    emb = get_embedder().encode([query_text])[0]
    res = get_chroma().query_by_embedding(emb, n_results=n)
    ids: List[str] = []
    if res and "ids" in res:
        # ChromaDB returns ids as [[id1, id2, ...]] from query_by_embedding
        if len(res["ids"]) > 0 and isinstance(res["ids"][0], list):
            ids = res["ids"][0]
        else:
            ids = res["ids"]
    return ids


def search_alerts_by_entity(entity_type: str, value: str) -> List[str]:
    """Find ALL alert IDs sharing a given observable.

    Returns ids regardless of status — the LLM-facing wrapper splits
    unprocessed vs decided so the correlation graph stays visible in
    full (an alert in an existing campaign is the bridge to add the
    new alert into that campaign instead of fabricating a new one).
    """
    return _get_store().find_alerts_by_observable(entity_type, value)


def fetch_alert_by_id(alert_id: str) -> Dict[str, Any]:
    """Fetch a full alert record from SQLite by ID."""
    return _get_store().fetch_alert(alert_id)


def fetch_campaign_alerts(campaign_id: str) -> Dict[str, Any]:
    """Open an existing campaign and return the full payloads of every alert inside it.

    Mimics the analyst behaviour of "opening the case file" — useful when the
    investigation suspects overlap with a campaign listed in
    ``prior_decisions``. Returns ``{campaign_id, alert_count, alerts: [...]}``;
    ``alerts`` is empty if the campaign does not exist.
    """
    alerts = _get_store().fetch_campaign_alerts(campaign_id)
    return {"campaign_id": campaign_id, "alert_count": len(alerts), "alerts": alerts}


def validate_shared_entities(alert_ids: List[str]) -> Dict[str, Any]:
    """Count shared observables across alert IDs."""
    store = _get_store()
    entity_counts: Dict[str, int] = {}
    not_found: List[str] = []
    for aid in alert_ids:
        a = store.fetch_alert(aid)
        if not a:
            not_found.append(aid)
            continue
        for o in a.get("observables") or []:
            k = f"{o['type']}::{o['value']}"
            entity_counts[k] = entity_counts.get(k, 0) + 1
    shared = [k for k, v in entity_counts.items() if v > 1]
    result: Dict[str, Any] = {"shared_entities": shared, "counts": entity_counts}
    if not_found:
        result["not_found"] = not_found
    return result


def compute_time_delta(alert_ids: List[str]) -> Dict[str, Any]:
    """Compute temporal span and gaps for the given alert IDs."""
    store = _get_store()
    raw_dates = []
    invalid: List[str] = []
    for aid in alert_ids:
        a = store.fetch_alert(aid)
        if not a:
            continue
        d = a.get("date")
        if not d:
            continue
        parsed = parse_alert_datetime(d)
        if parsed is not None:
            raw_dates.append(parsed)
        else:
            invalid.append(d)

    if not raw_dates:
        return {
            "count": 0, "dates": [],
            "span_days": None, "min_gap_days": None,
            "invalid_dates": invalid,
        }

    raw_dates.sort()
    span_days = (raw_dates[-1] - raw_dates[0]).days
    gaps = [(raw_dates[i] - raw_dates[i - 1]).days for i in range(1, len(raw_dates))]
    min_gap = min(gaps) if gaps else 0

    return {
        "count": len(raw_dates),
        "dates": [d.isoformat() for d in raw_dates],
        "span_days": span_days,
        "min_gap_days": min_gap,
        "invalid_dates": invalid,
    }


def get_unprocessed_alerts(
    limit: int = 10,
    exclude_alert_ids: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Return alerts with status='unprocessed', limited by `limit`."""
    return _get_store().get_unprocessed_alerts(limit, exclude_alert_ids=exclude_alert_ids)


def _clamp_confidence(value: Any) -> float:
    """Coerce LLM-supplied ``confidence`` to a sane float in ``[0.0, 1.0]``.

    The LLM occasionally passes confidence in the wrong scale (e.g. ``95``
    meaning 95%, or even bizarre numbers like ``9e9`` after a few merge
    rounds when the store ``max(...)``s a stale corrupted value). Without
    clamping these flow into ``campaigns.confidence`` and pollute every
    downstream metric. Strategy: ``float`` cast, NaN → 0, > 1 treated as
    a percentage (divide by 100) up to 100, anything beyond clamps to 1.
    """
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    if f != f:  # NaN
        return 0.0
    if f < 0.0:
        return 0.0
    if f <= 1.0:
        return f
    if f <= 100.0:
        return f / 100.0  # LLM passed a percentage
    return 1.0  # silently clamp absurd values (logged at the store layer)


def create_campaign(
    campaign_id: str,
    alert_ids: List[str],
    confidence: float,
    rationale: str,
    summary: str,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a campaign and mark alerts as in_campaign.

    The returned ``campaign_id`` and ``alert_ids`` reflect what was actually
    persisted — which can differ from inputs when the store recomputes the
    canonical id and/or merges with overlapping campaigns. Flags
    ``renamed_from`` and ``merged_with_existing`` are added when there is
    divergence so the LLM sees it on the next ReAct turn (and does not call
    ``add_alerts_to_campaign`` against a stale id).
    """
    store = _get_store()
    requested_ids = list(dict.fromkeys(str(aid) for aid in alert_ids if aid))
    confidence = _clamp_confidence(confidence)
    persisted_id, persisted_alerts = store.create_campaign(
        campaign_id, requested_ids, confidence, rationale, summary, run_id
    )
    response: Dict[str, Any] = {
        "status": "success",
        "campaign_id": persisted_id,
        "alert_ids": persisted_alerts,
        "alerts_grouped": len(persisted_alerts),
    }
    if persisted_id != campaign_id:
        response["renamed_from"] = campaign_id
    if len(persisted_alerts) != len(requested_ids):
        response["merged_with_existing"] = True
    return response


def mark_false_positive(alert_id: str, reason: str) -> Dict[str, Any]:
    """Mark an alert as false_positive (noise) with a reason.

    Idempotent at the store level — guards against:
    - re-decoding ``in_campaign`` to ``false_positive`` (a campaign alert
      cannot be downgraded silently);
    - re-marking an alert that is already ``false_positive`` (no-op,
      saves tokens and prevents the agent from wandering across iterations
      re-deciding the same alert).
    """
    store = _get_store()
    existing = store.fetch_alert(alert_id)
    if existing and existing.get("status") == "in_campaign":
        return {
            "status": "skipped",
            "alert_id": alert_id,
            "reason": "Alert is already in_campaign — cannot downgrade to false_positive.",
        }
    if existing and existing.get("status") == "false_positive":
        return {
            "status": "skipped",
            "alert_id": alert_id,
            "reason": "Alert is already marked as false_positive — no action taken.",
            "previous_reason": existing.get("false_positive_reason"),
        }
    store.mark_false_positive(alert_id, reason)
    return {
        "status": "success",
        "alert_id": alert_id,
        "marked_as": "false_positive",
        "reason": reason,
    }


def add_alerts_to_campaign(campaign_id: str, alert_ids: List[str]) -> Dict[str, Any]:
    """Add alerts to an existing campaign (merge)."""
    deduped = list(dict.fromkeys(str(aid) for aid in alert_ids if aid))
    return _get_store().add_alerts_to_campaign(campaign_id, deduped)


def list_campaigns_summary() -> List[Dict[str, Any]]:
    """Return compact summary of all existing campaigns."""
    return _get_store().list_campaigns_summary()


def ready_to_decide(summary: str) -> Dict[str, Any]:
    """Signal that correlation is complete and the agent is ready to decide."""
    return {"status": "ready", "summary": summary}


_MAX_UNPROCESSED_SUMMARY = 200


def list_unprocessed_summary(
    exclude_alert_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Compact summary of all unprocessed alerts (id, title, source, severity).

    Returns the full queue (capped at 200) so the LLM has global visibility
    of what's in flight when picking a seed. Pagination was attempted
    (limit=20, offset=N) and rejected — token savings of ~55% per call
    cost ~9pp accuracy and 6 missed threats because the LLM lost the
    ability to contextualise "isolated alert vs part of a larger campaign"
    without seeing its peers in the queue. See DECISIONS.md for data.
    """
    alerts = _get_store().get_unprocessed_alerts(
        limit=_MAX_UNPROCESSED_SUMMARY,
        exclude_alert_ids=exclude_alert_ids,
    )
    summary = []
    for a in alerts:
        if not isinstance(a, dict):
            continue
        summary.append(
            {
                "alert_id": a.get("alert_id"),
                "title": a.get("title"),
                "source": a.get("source"),
                "severity": a.get("severity"),
            }
        )
    return {"count": len(summary), "alerts": summary}


def find_similar_cluster(
    alert_id: str,
    n: int = 10,
    exclude_alert_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Given an alert_id, use its embedding to find similar alerts via VectorDB.

    Returns the full semantic neighbourhood split into ``cluster``
    (unprocessed candidates) and ``decided`` (already classified —
    in_campaign / false_positive — with campaign_id when applicable).
    Visibility into ``decided`` is what lets the agent route the anchor
    into an existing campaign instead of fabricating a new one.
    """
    chroma = get_chroma()
    embedding = chroma.get_embedding_by_id(alert_id)
    if embedding is None:
        return {"status": "error", "message": f"No embedding found for {alert_id}"}

    exclude = set(exclude_alert_ids or [])
    exclude.add(alert_id)

    results = chroma.query_similar_excluding(
        embedding=embedding,
        exclude_ids=list(exclude),
        n_results=n,
    )

    store = _get_store()
    cluster: List[Dict[str, Any]] = []
    decided: List[Dict[str, Any]] = []
    for r in results:
        aid = r["id"]
        alert = store.fetch_alert(aid)
        if not alert:
            continue
        status = alert.get("status") or "unprocessed"
        common = {
            "alert_id": aid,
            "title": alert.get("title"),
            "source": alert.get("source"),
            "severity": alert.get("severity"),
            "distance": r.get("distance"),
        }
        if status == "unprocessed":
            cluster.append(common)
        else:
            entry = {**common, "decision": status}
            if status == "in_campaign" and alert.get("campaign_id"):
                entry["campaign_id"] = alert["campaign_id"]
            if status == "false_positive" and alert.get("false_positive_reason"):
                entry["reason"] = alert["false_positive_reason"]
            decided.append(entry)
    return {
        "anchor_alert_id": alert_id,
        "similar_count": len(cluster),
        "cluster": cluster,
        "decided": decided,
    }


_MAX_SEEDS_PER_BATCH = 3


def submit_selected_seeds(alert_ids: List[str]) -> Dict[str, Any]:
    """Finalize seed selection — committed by the LLM.

    Cap raised to 3 (from 1) so the agent can group clearly-related alerts in
    a single batch when the queue scan + similarity peek already shows a
    cluster. Mimics the analyst behaviour of grabbing 2-3 obviously-linked
    tickets together instead of running separate investigations on each.
    """
    ids = list(dict.fromkeys(str(aid) for aid in alert_ids if aid))[:_MAX_SEEDS_PER_BATCH]
    return {"status": "ready", "selected_seeds": ids, "count": len(ids)}


# ---------------------------------------------------------------------------
# Tool contracts — args_schema + structured returns
# ---------------------------------------------------------------------------
# These guard the LLM-facing surface (tools.py is the only place tools are
# defined). Pydantic validation runs *before* the underlying function — when
# the LLM calls a tool with a malformed argument (e.g. passing a hostname
# where an alert_id is expected) the call is rejected and the LLM sees a
# ToolMessage with the validation error, allowing it to self-correct on the
# next ReAct turn instead of fabricating narrative on top of the bad call.

# Canonical alert_id format observed in the dataset (UUID-like, 8-4-4-4-12).
# Lowercase alphanumeric — tight enough to reject hostnames (DB-SQL-04),
# usernames (s.souza, j.silva@trace), emails, and other observables that
# the LLM tends to confuse with identifiers.
ALERT_ID_PATTERN = r"^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$"
_ALERT_ID_RE = re.compile(ALERT_ID_PATTERN)
CAMPAIGN_ID_PATTERN = r"^campaign-[a-zA-Z0-9_-]+$"

# Allowed observable categories — must match the ``dataType`` vocabulary the
# dataset actually uses (TheHive convention: "mail" not "email", "file" not
# "filename"). ``process`` and ``other`` are dataset-specific (round4 / round1
# respectively) and kept here so the agent can reach them when ingested.
# Adding a new type here without updating ingestion (or vice-versa) creates a
# silent miss in correlation.
ObservableType = Literal[
    "ip", "username", "file", "mail", "domain", "url", "hostname", "process", "other"
]


def _validate_alert_id_list(v: List[str]) -> List[str]:
    """Reject any item that does not match the canonical alert_id pattern."""
    if not isinstance(v, list):
        raise ValueError("alert_ids must be a list")
    invalid = [str(x) for x in v if not _ALERT_ID_RE.match(str(x))]
    if invalid:
        raise ValueError(
            f"invalid alert_id format: {invalid}. "
            f"Expected UUID-like (8-4-4-4-12 lowercase hex). "
            f"If these look like observables (hostname/user/etc), use search_alerts_by_entity instead."
        )
    return v


# --- args_schema models (LLM-visible) ---------------------------------------


class _SearchTextArgs(BaseModel):
    query_text: str = Field(min_length=1, description="Free-text query for semantic search.")
    n: int = Field(default=10, ge=1, le=20, description="Maximum number of results.")


class _SearchEntityArgs(BaseModel):
    entity_type: ObservableType = Field(
        description="Observable category. Must be one of the allowed types."
    )
    value: str = Field(min_length=1, description="Observable value to match exactly.")


class _AlertIdArg(BaseModel):
    alert_id: str = Field(
        pattern=ALERT_ID_PATTERN,
        description=(
            "Canonical alert identifier (UUID-like, 8-4-4-4-12 lowercase hex). "
            "Hostnames, usernames, IPs and other observables are NOT alert_ids — "
            "use search_alerts_by_entity for those."
        ),
    )


class _CampaignIdArg(BaseModel):
    campaign_id: str = Field(
        pattern=CAMPAIGN_ID_PATTERN,
        description="Existing campaign identifier (starts with 'campaign-').",
    )


class _ValidateEntitiesArgs(BaseModel):
    """Permissive — list may contain unknown ids; the tool reports them as not_found."""
    alert_ids: List[str] = Field(min_length=1, description="Alert ids to compare.")


class _TimeDeltaArgs(BaseModel):
    """Permissive — like _ValidateEntitiesArgs."""
    alert_ids: List[str] = Field(min_length=1, description="Alert ids for temporal analysis.")


class _ListUnprocessedArgs(BaseModel):
    exclude_alert_ids: Optional[List[str]] = Field(
        default=None, description="Alert ids to skip in the result."
    )


class _FindSimilarArgs(BaseModel):
    alert_id: str = Field(
        pattern=ALERT_ID_PATTERN,
        description="Anchor alert_id (UUID-like) to use as embedding query.",
    )
    n: int = Field(default=10, ge=1, le=20)
    exclude_alert_ids: Optional[List[str]] = None


class _ReadyToDecideArgs(BaseModel):
    summary: str = Field(min_length=1, description="Concise summary of correlation evidence.")


class _CreateCampaignArgs(BaseModel):
    """Strict — campaign creation persists state, format errors must be caught here."""
    campaign_id: str = Field(min_length=1, description="Proposed campaign id (canonicalized by store).")
    alert_ids: List[str] = Field(
        min_length=2,
        description="At least 2 alert_ids — a campaign of one alert is by definition not a campaign.",
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in [0,1] range.")
    rationale: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    run_id: Optional[str] = None

    @field_validator("alert_ids")
    @classmethod
    def _check_ids(cls, v: List[str]) -> List[str]:
        return _validate_alert_id_list(v)


class _MarkFalsePositiveArgs(BaseModel):
    alert_id: str = Field(pattern=ALERT_ID_PATTERN, description="Canonical alert_id (UUID-like).")
    reason: str = Field(min_length=1, description="Why this alert is noise.")


class _AddToCampaignArgs(BaseModel):
    campaign_id: str = Field(pattern=CAMPAIGN_ID_PATTERN)
    alert_ids: List[str] = Field(min_length=1)

    @field_validator("alert_ids")
    @classmethod
    def _check_ids(cls, v: List[str]) -> List[str]:
        return _validate_alert_id_list(v)


class _SubmitSeedsArgs(BaseModel):
    alert_ids: List[str] = Field(
        min_length=1,
        max_length=3,
        description="Selected seed alert_ids (1 to 3, UUID-like format).",
    )

    @field_validator("alert_ids")
    @classmethod
    def _check_ids(cls, v: List[str]) -> List[str]:
        return _validate_alert_id_list(v)


# ---------------------------------------------------------------------------
# LangChain @tool wrappers — what the LLM sees
# ---------------------------------------------------------------------------
# Native typed signatures (Pydantic-style via type hints) replace the legacy
# ``params: Dict[str, Any]`` pattern. ``@tool("name")`` keeps the LLM-facing
# tool name unchanged across the migration. Each wrapper passes
# ``args_schema=`` so Pydantic validates LLM-provided arguments before the
# function runs.


_MAX_SIMILAR = 20


@tool("search_similar_alerts", args_schema=_SearchTextArgs)
def _t_search_similar_alerts(
    query_text: str,
    n: int = 10,
    tool_call_id: Annotated[str, InjectedToolCallId] = "",
) -> Command:
    """Return alert IDs similar to a query text using semantic vector search.

    Result is split into ``alert_ids`` (still unprocessed — candidates to
    investigate) and ``decided`` (already classified — alerts already
    grouped into a campaign or marked false_positive). Use ``decided`` to
    decide whether the new finding belongs to an existing campaign
    (``add_alerts_to_campaign``) instead of creating a new one.
    """
    ids = search_similar_alerts(query_text, n=int(n))
    split = _split_decided(ids)
    payload = {
        "status": "ok",
        "count": len(ids),
        "alert_ids": split["unprocessed"],
        "decided": split["decided"],
    }
    return _cmd_with_discovery(
        payload,
        tool_call_id,
        discovered={str(aid) for aid in ids if aid},
    )


@tool("search_alerts_by_entity", args_schema=_SearchEntityArgs)
def _t_search_alerts_by_entity(
    entity_type: str,
    value: str,
    tool_call_id: Annotated[str, InjectedToolCallId] = "",
) -> Command:
    """Return alert IDs that share an observable entity.

    ``entity_type`` must be one of: ip, username, hash, filename, email,
    domain, url, hostname. Empty result is reported as ``count: 0``, not as
    an error.

    Result is split into ``alert_ids`` (still unprocessed — candidates to
    investigate) and ``decided`` (already classified). When ``decided``
    entries include ``campaign_id``, that's the existing campaign sharing
    this observable — strong signal to use ``add_alerts_to_campaign``
    rather than creating a new one.
    """
    ids = search_alerts_by_entity(entity_type, value)
    split = _split_decided(ids)
    payload = {
        "status": "ok",
        "count": len(ids),
        "alert_ids": split["unprocessed"],
        "decided": split["decided"],
    }
    return _cmd_with_discovery(
        payload,
        tool_call_id,
        discovered={str(aid) for aid in ids if aid},
    )


@tool("fetch_alert_by_id", args_schema=_AlertIdArg)
def _t_fetch_alert_by_id(
    alert_id: str,
    tool_call_id: Annotated[str, InjectedToolCallId] = "",
) -> Command:
    """Fetch full alert details by canonical alert_id (UUID-like format)."""
    alert = fetch_alert_by_id(alert_id)
    if not isinstance(alert, dict) or not alert.get("alert_id"):
        return _cmd_with_discovery(
            {"status": "not_found", "queried": alert_id},
            tool_call_id,
        )
    aid = str(alert["alert_id"])
    return _cmd_with_discovery(
        {"status": "found", "alert": alert},
        tool_call_id,
        discovered={aid},
        cache={aid: alert},
    )


@tool("fetch_campaign_alerts", args_schema=_CampaignIdArg)
def _t_fetch_campaign_alerts(
    campaign_id: str,
    tool_call_id: Annotated[str, InjectedToolCallId] = "",
) -> Command:
    """Open an existing campaign and read the full alerts inside it.

    Use this when prior decisions mention a campaign that may overlap with
    what you are investigating — read the alerts inside before deciding to
    merge, dispute, or ignore.
    """
    payload = fetch_campaign_alerts(campaign_id)
    alerts = payload.get("alerts") or []
    if not alerts:
        return _cmd_with_discovery(
            {"status": "not_found", "queried": campaign_id},
            tool_call_id,
        )
    discovered: set = set()
    cache: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        if isinstance(alert, dict) and alert.get("alert_id"):
            aid = str(alert["alert_id"])
            discovered.add(aid)
            cache[aid] = alert
    return _cmd_with_discovery(
        {"status": "found", **payload},
        tool_call_id,
        discovered=discovered,
        cache=cache,
    )


@tool("validate_shared_entities", args_schema=_ValidateEntitiesArgs)
def _t_validate_shared_entities(alert_ids: List[str]) -> dict:
    """Validate and count shared entities across multiple alert IDs.

    Permissive: alert_ids that are not in the store are reported under
    ``not_found`` rather than rejected — so you can pass a candidate cluster
    and learn which members exist in the same call.
    """
    result = validate_shared_entities(alert_ids)
    return _capped({"status": "ok", **result})


@tool("compute_time_delta", args_schema=_TimeDeltaArgs)
def _t_compute_time_delta(alert_ids: List[str]) -> dict:
    """Get temporal correlation stats (sorted dates, span_days, min_gap_days) for alert IDs."""
    result = compute_time_delta(alert_ids)
    return _capped({"status": "ok", **result})


@tool("ready_to_decide", args_schema=_ReadyToDecideArgs)
def _t_ready_to_decide(summary: str) -> dict:
    """Signal that correlation analysis is complete and you are ready to make the final triage decision.

    Call this when you have enough evidence to decide. Include in ``summary``
    the related alert IDs, shared observables, temporal span, and your
    preliminary assessment.
    """
    return ready_to_decide(summary)


@tool("create_campaign", args_schema=_CreateCampaignArgs)
def _t_create_campaign(
    campaign_id: str,
    alert_ids: List[str],
    confidence: float,
    rationale: str,
    summary: str,
    run_id: Optional[str] = None,
) -> dict:
    """Create a campaign by grouping related alerts as an attack campaign.

    Requires at least 2 alert_ids in canonical UUID-like format. The persisted
    ``campaign_id`` and ``alert_ids`` returned may differ from the inputs (the
    store recomputes a canonical id and merges with existing overlapping
    campaigns). Use the returned values for any follow-up calls.
    """
    return _capped(create_campaign(campaign_id, alert_ids, confidence, rationale, summary, run_id))


@tool("mark_false_positive", args_schema=_MarkFalsePositiveArgs)
def _t_mark_false_positive(alert_id: str, reason: str) -> dict:
    """Mark an alert as false positive (noise, not part of any campaign)."""
    return mark_false_positive(alert_id, reason)


@tool("add_alerts_to_campaign", args_schema=_AddToCampaignArgs)
def _t_add_alerts_to_campaign(campaign_id: str, alert_ids: List[str]) -> dict:
    """Add alert IDs to an EXISTING campaign (merge).

    Use when you discover alerts that belong to a campaign already created in
    a previous investigation.
    """
    return _capped(add_alerts_to_campaign(campaign_id, alert_ids))


@tool("list_unprocessed_summary", args_schema=_ListUnprocessedArgs)
def _t_list_unprocessed_summary(exclude_alert_ids: Optional[List[str]] = None) -> dict:
    """Get a compact summary (id, title, source, severity) of all unprocessed alerts."""
    result = list_unprocessed_summary(exclude_alert_ids=exclude_alert_ids)
    return _capped({"status": "ok", **result})


@tool("find_similar_cluster", args_schema=_FindSimilarArgs)
def _t_find_similar_cluster(
    alert_id: str,
    n: int = 10,
    exclude_alert_ids: Optional[List[str]] = None,
) -> dict:
    """Given an alert_id, find similar alerts via VectorDB embeddings.

    Result is split into ``cluster`` (unprocessed neighbours — candidates
    to investigate) and ``decided`` (already classified neighbours —
    use ``campaign_id`` when present to route the anchor into the
    existing case). ``min_distance`` (lower = more similar) lets you
    judge whether the cluster is tight enough to act on.
    Returns ``status: not_found`` when the anchor has no embedding.
    """
    raw = find_similar_cluster(alert_id, n=int(n), exclude_alert_ids=exclude_alert_ids)
    # Underlying helper returns status:error when embedding is missing — surface
    # that as not_found so the LLM sees the same vocabulary as the other tools.
    if raw.get("status") == "error":
        return {"status": "not_found", "queried": alert_id, "reason": raw.get("message")}
    cluster = raw.get("cluster") or []
    decided = raw.get("decided") or []
    # min_distance is computed across BOTH unprocessed and decided so the agent
    # can see if the closest neighbour is actually inside an existing campaign.
    all_distances = [
        c.get("distance")
        for c in (cluster + decided)
        if isinstance(c.get("distance"), (int, float))
    ]
    min_distance = min(all_distances) if all_distances else None
    return _capped({
        "status": "ok",
        "anchor_alert_id": raw.get("anchor_alert_id"),
        "similar_count": raw.get("similar_count", 0),
        "min_distance": min_distance,
        "cluster": cluster,
        "decided": decided,
    })


@tool("submit_selected_seeds", args_schema=_SubmitSeedsArgs)
def _t_submit_selected_seeds(alert_ids: List[str]) -> dict:
    """Finalize your seed selection. Pass the alert IDs you chose as seeds for the next investigation.

    Accepts 1 to 3 alert_ids in canonical UUID-like format. The cap is
    enforced by the schema; the LLM decides how many to submit based on
    evidence — submit more than one only when alerts converge on the same
    incident.
    """
    return submit_selected_seeds(alert_ids)


# ---------------------------------------------------------------------------
# Per-agent tool lists (consumed by create_react_agent)
# ---------------------------------------------------------------------------

INVESTIGATION_TOOLS = [
    _t_search_similar_alerts,
    _t_search_alerts_by_entity,
    _t_fetch_alert_by_id,
    _t_fetch_campaign_alerts,
]

CORRELATION_TOOLS = [
    _t_validate_shared_entities,
    _t_compute_time_delta,
    _t_ready_to_decide,
    _t_fetch_campaign_alerts,
]

DECISION_TOOLS = [
    _t_create_campaign,
    _t_mark_false_positive,
    _t_add_alerts_to_campaign,
]

SEED_SELECTION_TOOLS = [
    _t_list_unprocessed_summary,
    _t_fetch_alert_by_id,       # A — peek a candidate before committing
    _t_find_similar_cluster,    # B — semantic neighbourhood via embeddings
    _t_submit_selected_seeds,
]
