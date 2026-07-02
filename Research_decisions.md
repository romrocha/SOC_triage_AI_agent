# Engineering Decisions Log

This file records design decisions made during the SOC triage agent research — including **rejected experiments** and the data that led to their reversal. Negative results are kept here on purpose: they are part of the methodology and contribute to the central thesis (*"augmented triage, not autonomous"*).

The active architecture corresponds to run `0233` (`round1-gpt-4.1-mini-20260510T0049`), finalized with: `decided[]` visibility, `min_length=2` on campaigns, idempotency on `mark_false_positive`, Pydantic contracts on all tools, and a circuit breaker on `pre_model_hook`. All engineering changes past that run that worsened metrics were reverted.

---

## Reference Baseline (Active Architecture)

**Run `0233` — `round1-gpt-4.1-mini`**

| Metric | Value |
|--------|-------|
| Overall Label Accuracy | 69.0% |
| Campaign Recall | 93.3% |
| Campaign Precision | 49.1% |
| Purity | 30.1% |
| Completeness | 96.7% |
| Missed threats | 2 |
| Detected campaigns | 8 (vs 2 expected — over-correlation residual) |
| Splits / Merges | 0 / 0 |
| FP F1 | 72.6% |
| Cost | ~$0.88 / run |
| Duration | ~27 min / round |

---

## Rejected Experiment 1 — `route_to_existing_campaign`

**Hypothesis.** Add a second terminal tool to `select_seeds` allowing the agent to skip the full `investigate → correlate → decide` graph when `find_similar_cluster` shows the candidate's nearest decided neighbour is already inside an existing campaign with a strong semantic match. A guardrail at the tool level re-validated proximity and rejected the route if vector distance > 0.20.

**Implementation.**
- New `@tool` `route_to_existing_campaign` in `tools.py`, wired into `SEED_SELECTION_TOOLS`.
- 3-way conditional edge after `select_seeds` (`investigate` / `post_iteration` / `finalize`).
- New ephemeral fields in `BatchState`: `routed_alert_ids`, `routed_campaign_id`.

**Run.** `132e` (`round1-gpt-4.1-mini-20260510T0233`)

**Result.** 11 calls — **0 routed, 11 rejected by guardrail**. Every attempt failed the distance threshold (closest miss `min_distance = 0.382`; all others between 0.4 and 0.96). The guardrail worked as designed, but the cognitive cost of *trying* poisoned surrounding decisions.

| Metric | 0233 baseline | 132e | Δ |
|--------|---------------|------|---|
| Accuracy | 69.0% | 72.0% | +3.0 pp |
| FP F1 | 72.6% | 77.4% | +4.8 pp |
| **Campaign Recall** | **93.3%** | **80.0%** | **−13.3 pp** |
| **Purity** | **30.1%** | **19.1%** | **−11.0 pp** |
| Completeness | 96.7% | 93.3% | −3.4 pp |
| **Missed threats** | **2** | **6** | **+4** |
| Detected campaigns | 8 | 9 | +1 |

**Diagnosis.** The LLM lacked reliable judgement of *when* routing was appropriate. Even with the guardrail blocking false routes, each rejected attempt consumed a turn and contaminated the iteration's context. Subsequent investigation became less focused, and the agent grew more aggressive in marking borderline alerts as FP — including campaign alerts (missed threats tripled).

**Conclusion.** Capability ≠ benefit. Adding a tool the LLM cannot calibrate increases cost and degrades downstream decisions even when the tool itself is bullet-proofed. **Reverted.**

**Files reverted.**
- `security_agent/app/agent/tools.py` — removed `_t_route_to_existing_campaign`, `_RouteToCampaignArgs`, `_ROUTE_DISTANCE_THRESHOLD`.
- `security_agent/app/agent/langgraph_workflow.py` — reverted `_node_select_seeds`, `_route_after_select_seeds` (back to 2-way), `_node_post_iteration`, `BatchState` (removed `routed_alert_ids`/`routed_campaign_id`), conditional edges in `_build_round_graph`.
- `security_agent/app/agent/prompts.py` — restored single-terminal `SOC_SELECT_SEEDS_PROMPT`.
- `tests/test_langgraph_workflow.py` — restored canonical `SEED_SELECTION_TOOLS` set.

---

## Rejected Experiment 2 — `list_unprocessed_summary` Pagination

**Hypothesis.** The seed-selection tool returns up to 200 alerts on every call, costing ~7k tokens per response. Replacing this with a paged interface (default `limit=20`, `offset=0`, max 100) plus a total-count field should reduce LLM context cost by ~55%, freeing ~10–15% of round-level token spend.

**Implementation.**
- `SQLiteStore.get_unprocessed_alerts` gained an `offset` parameter.
- New `SQLiteStore.count_unprocessed_alerts(...)` for total queue size.
- `_ListUnprocessedArgs` schema gained `limit: int [1..100]` and `offset: int >= 0`.
- Response shape changed from `{count, alerts}` to `{total, returned, offset, limit, alerts}`.
- `SOC_SELECT_SEEDS_PROMPT` updated to describe pagination.

**Run.** `138e` (`round1-gpt-4.1-mini-20260510T2023`)

**Result.** Token plumbing worked: avg prompt tokens per `select_seeds` LLM turn dropped from ~3,322 to ~1,491 (**−55%** as predicted). However, the LLM never advanced `offset` — 13/13 calls used `{limit:20, offset:0}`, draining the queue naturally via the `exclude_alert_ids` filter.

Eval regressed sharply:

| Metric | 0233 baseline | 138e | Δ |
|--------|---------------|------|---|
| **Accuracy** | **69.0%** | **60.0%** | **−9.0 pp** |
| **FP F1** | **72.6%** | **65.5%** | **−7.1 pp** |
| FP Recall | 58.6% | 54.3% | −4.3 pp |
| **Campaign Recall** | **93.3%** | **73.3%** | **−20.0 pp** |
| Purity | 30.1% | 34.1% | +4.0 pp |
| Completeness | 96.7% | 90.0% | −6.7 pp |
| **Missed threats** | **2** | **8** | **+6** |
| Detected campaigns | 8 | 10 | +2 |
| Splits + Merges | 0 | 3 | +3 |

**Diagnosis.** The 200→20 cap removed **global queue visibility**. With the full list, the LLM could see "30 alerts mentioning `b.smith` are still in the queue" and infer scale (campaign). With only 20 alerts visible, it saw 3–4 mentions of the same actor and inferred isolation (FP). Symptoms:
- Missed threats 4× (2 → 8) — campaign alerts dismissed for lack of nearby evidence in the visible window.
- Campaign recall fell 20 pp.
- Splits + merges rose from 0 to 3 — fragmentation grew when the agent couldn't see the full context.
- Purity rose slightly as a side-effect of fewer, more conservative campaign assignments — masked by the recall drop.

**Conclusion.** Token economy is not free. For LLM agents, context *is* capability. The queue-wide view enables reasoning about incident scale; trimming it for cost forces the agent to reason locally and miss campaigns. **Reverted.**

`count_unprocessed_alerts` was also removed (introduced only to serve the paginated wrapper). The `offset` parameter on `get_unprocessed_alerts` was reverted as well.

**Files reverted.**
- `security_agent/app/agent/tools.py` — `list_unprocessed_summary` + wrapper + `_ListUnprocessedArgs` back to pre-pagination shape; restored `_MAX_UNPROCESSED_SUMMARY = 200` and `{count, alerts}` response.
- `security_agent/app/ingestion/sqlite_store.py` — removed `count_unprocessed_alerts`; reverted `get_unprocessed_alerts` (no `offset`).
- `security_agent/app/agent/prompts.py` — restored pre-pagination `SOC_SELECT_SEEDS_PROMPT`.
- `tests/test_langgraph_workflow.py` — restored `count`-shaped assertion in `test_list_unprocessed_summary_returns_compact`.

---

## Design Gap — `add_alerts_to_campaign` Has No `reason` Field

Not a rejected experiment — a **finding from trace auditing** of the gpt-5-mini run `019e1912-5c8b-7230-85af-f40b28b7211f` (round 1). Kept here as a documented design gap because the data showed measurable impact, even though the fix was not implemented before YSTS to avoid introducing new variables.

### Observation

The `add_alerts_to_campaign` tool schema requires only `campaign_id` and `alert_ids`:

```python
class _AddToCampaignArgs(BaseModel):
    campaign_id: str = Field(pattern=CAMPAIGN_ID_PATTERN)
    alert_ids: List[str] = Field(min_length=1)
    # NO reason field
```

Both other state-changing decision tools require textual justification:

| Tool | Reason field? |
|------|---------------|
| `create_campaign` | ✅ `rationale` + `summary` (both required, `min_length=1`) |
| `mark_false_positive` | ✅ `reason` (`min_length=1`) |
| **`add_alerts_to_campaign`** | **❌ none** |

### Effect Measured in Run `019e1912`

5 successful `create_campaign` calls and 6 successful `add_alerts_to_campaign` calls. Two campaigns inflated significantly via adds:

| Campaign | Initial alerts (`create`) | After adds | Growth |
|----------|--------------------------|------------|--------|
| `campaign-ransomware-finance-b-smith-2024-11` | 16 | **44** | +28 across 5 adds |
| `campaign-case-p-freitas-2024-11` | 14 | **21** | +7 in 1 add |

Reasoning tokens per `add_alerts_to_campaign` call (b-smith campaign):

| Add # | Alerts added | Reasoning tokens |
|-------|--------------|------------------|
| 1 | 11 | 11,072 (carried from `create_campaign` deliberation) |
| 2 | 9 | 2,432 |
| 3 | 6 | 3,200 |
| 4 | 1 | 2,944 |
| 5 | 1 | 384 |
| 6 | 1 | 384 |

**Reasoning tokens decay 27× across the 5 adds.** Deliberation collapses after the initial campaign is established; subsequent adds are nearly cache-driven with no fresh articulation per decision.

### Cross-Contamination: `b.smith` in Two Campaigns Simultaneously

The `campaign-case-p-freitas-2024-11` rationale listed **6 distinct usernames** as members: `n.teixeira`, `d.araujo`, `k.barbosa`, `p.freitas`, `b.smith`, `h.potter`. Connective tissue: IP cluster `45.182.21.10-13` (Tor exit) + IP `200.150.30.88`.

But `b.smith` is the centerpiece of a separate, larger campaign (`campaign-ransomware-finance-b-smith-2024-11`). Without per-add justification, the LLM bundled `b.smith`-related alerts into two cases simultaneously without being forced to defend which membership prevails.

### Why This Is a Design Gap, Not a Bug

- **Functionally:** the code does what it says — the tool persists the alerts, no execution error.
- **Semantically:** state-changing decisions deserve accountability; the tool surface signals to the LLM that this decision is mechanical.
- **Behaviourally:** when a tool accepts silence, the LLM takes the path of least resistance. As the cache warms, deliberation decays to zero. Over-aggregation becomes invisible to downstream audit because no rationale was written per add.

### Proposed Fix (Not Yet Implemented)

Add a required `reason` field to `_AddToCampaignArgs`:

```python
class _AddToCampaignArgs(BaseModel):
    campaign_id: str = Field(pattern=CAMPAIGN_ID_PATTERN)
    alert_ids: List[str] = Field(min_length=1)
    reason: str = Field(
        min_length=20,
        description="Why these alerts belong to this campaign — cite "
                    "shared observable or temporal/narrative link with "
                    "concrete entity names.",
    )
```

Expected impact (hypothesis, unmeasured):
- Per-add reasoning tokens rise from ~400 to ~3–5k as the LLM articulates rather than just persisting.
- Number of adds drops ~30% — cognitive friction filters weak adds.
- Purity rises ~5–10 pp (less campaign inflation).
- Run cost rises ~10–15% from extra completion tokens.

**Files where the fix would land:**
- `security_agent/app/agent/tools.py` — `_AddToCampaignArgs` schema and `_t_add_alerts_to_campaign` wrapper docstring.
- `security_agent/app/agent/prompts.py` — `SOC_DECIDE_PROMPT` guidance on what to write in `reason`.
- `tests/test_langgraph_workflow.py` — new test confirming rejection without `reason` and acceptance with valid text.

---

## Behavioral Defect — Action-Reason Desync in `mark_false_positive`

Not a rejected experiment — a **finding from step-by-step trace inspection** of the gpt-4.1-mini round 3 run (`019e19e6-5e76-77a0-a4c6-96b75b0b136f`, 180-day temporal dilation, 72% accuracy, 6 missed threats). Documented as a structural defect with two failure modes and five candidate preventions.

### Observation

The agent investigates competently (pivots on observables, runs correlate validators, produces coherent narratives) but the `decide` step exhibits a structural defect: it calls `mark_false_positive` on alerts it has **just** placed into a campaign in the same `decide` turn, writing a `reason` text that directly contradicts the action being taken.

### Two Failure Modes (from the Round 3 Trace)

**Mode A — "FP-as-receipt" (5 of 6 missed threats in round 3):**

The agent treats `mark_false_positive` as "acknowledge / handled" rather than "this is noise":

| Alert | Iter | Action | Reason written by the LLM |
|-------|------|--------|---------------------------|
| `c3f4a0e6` | 1 | mark_false_positive | "already included in the created campaign, no separate action needed" |
| `d0e217b5` | 1 | mark_false_positive | "already included in the created campaign, no separate action needed" |
| `f2a3d9b5` | 2 | mark_false_positive | "Already part of existing ransomware campaign campaign-ransomware-finance-b-smith-2024-11" |
| `1a2b3c4d` | 6 | mark_false_positive | "This alert is part of the data exfiltration campaign with h.potter, not a false positive" |
| `4b5c6d7e` | 6 | mark_false_positive | "This alert is part of the data exfiltration campaign with h.potter, not a false positive" |

In iterations 1 and 6, `create_campaign` was called in the same decide turn with the same `alert_ids`. The store's idempotency guard (`mark_false_positive` returns `skipped` when `status == "in_campaign"`) absorbs some cases — but failures occur when `mark_false_positive` executes before `create_campaign` due to parallel tool execution in `ToolNode` (no guaranteed ordering).

**Mode B — "isolated == noise" (1 of 6 missed threats):**

The agent treats *"no exact observable overlap"* as proof of FP, even when entity-name semantics suggest otherwise:

- `9c0d1e2f` (iter 8): "Salary workbook to personal mailbox `harry.personal@proton.me`" — agent searched by exact file and email observable, both returned only the seed. Marked FP with reason *"Isolated alert with no related alerts or shared observables; unrelated to ongoing insider exfiltration campaign."* The correlate node had explicitly noted *"username h.potter is common in the campaign alerts"* — the agent saw the semantic bridge (harry → h.potter) and dismissed it because the literal observables didn't join.

### Why This Is a Structural Defect, Not a Bug

- The LLM **writes the negation of the action it takes**. The rationale text is correct; the action is the contradiction. No human L1 analyst would write *"this is part of the campaign"* in a false-positive field.
- The contradiction passes Pydantic validation — there is no cross-tool consistency check.
- The `mark_false_positive` idempotency guard only absorbs failures when campaign membership is written *before* the FP attempt. Parallel tool execution makes the order non-deterministic.
- Once the state lands in SQLite, the auditor sees an alert with `status=false_positive` and a reason text claiming it belongs to a campaign — internally inconsistent state.

### Five Candidate Preventions

Ordered by bang-for-buck:

**1. Rename + prompt clarification — cheap, high impact.**
Rename `mark_false_positive` to something with unambiguous semantics (`classify_as_noise`, `discard_as_unrelated`). Add an explicit instruction in the decide prompt:

> *"`classify_as_noise` is for alerts that are NOT part of any campaign and NOT related to any incident. Do NOT call it on alerts you have just included in a campaign — those are already correctly classified by the campaign action."*

Estimated coverage: ~50% of Mode A.

**2. Cross-tool consistency check — medium effort, high impact.**
Add a `post_model_hook` or wrapper around the decide LLM call that examines the proposed `tool_calls` and rejects any `mark_false_positive(alert_id)` that conflicts with a `create_campaign` / `add_alerts_to_campaign` containing the same `alert_id` in the same turn. Inject a `ToolMessage` forcing the model to re-decide.

Estimated coverage: ~80% of Mode A + some Mode B.

**3. Reason field on `add_alerts_to_campaign` — medium effort, medium impact.**
Already catalogued in the design gap section above. Forces the LLM to articulate per-add justification, reducing the aggregation that fuels Mode A.

**4. Schema-level mutual exclusion via Pydantic validator with state context — low effort, medium impact.**
LangGraph supports passing context via `RunnableConfig`. The Pydantic validator on `create_campaign.alert_ids` can check that no id in the batch is in the `already_marked_fp` set populated during the current decide turn.

**5. Review pass node (LLM-as-judge) — high effort, complete coverage.**
Add a 5th outer node `review` after `decide`. It reads the decisions and challenges contradictions:

> *"alert_id X was placed in campaign Y and marked false_positive in the same batch. Identify the correct action and revert the wrong one."*

Catches arbitrary action-reason desyncs beyond FP-in-campaign.

**Target:** Phase 1 (rename + prompt clarify + consistency check) — estimated ~6h of implementation + 2 runs to measure. Expected outcome: Mode A reduced to near-zero in a gpt-4.1-mini round 3 reproduction.

---

## Methodological Takeaways

The two rejected experiments share the same lesson: **an isolated optimisation can degrade the system because the LLM's behaviour depends on the full surface it sees**. The design-gap and behavioral-defect findings add two more axes. Four corollaries from the data:

1. **Capability ≠ benefit.** Adding `route_to_existing_campaign` gave the agent a faster path, but the agent could not judge when to use it; the attempt itself disrupted decisions even when mechanically blocked.

2. **Context is capability.** Cutting the queue summary from 200 to 20 alerts saved tokens but eliminated the global view the agent used to reason about incident scale.

3. **Tool surface is policy.** When a state-changing tool accepts silence (`add_alerts_to_campaign` has no `reason` field), the LLM takes the path of least resistance. Deliberation collapses 27× across consecutive adds, campaigns inflate invisibly, and audits surface no per-add rationale to interrogate. The schema of a tool tells the model what it owes — and what it can get away with not saying.

4. **Action-reason desync is a class of defect humans never produce.** The LLM writes the negation of the action it takes and neither Pydantic validation nor the idempotency guard catches it reliably. The system needs explicit consistency enforcement that the model will not provide on its own.

These findings reinforce the core thesis: **system-level constraints (contracts, idempotency, visibility, mandatory accountability) are net positive; system-level reductions of context or options are net negative.** The agent does L1-style triage work competently within a system designed around what the LLM cannot do on its own — including what it doesn't naturally choose to do without being asked.

---

## Limitations

This dataset supports **comparative methodology research**, not **production performance prediction**.

### 1. Inverted Base Rate

~70% false positives here vs ~99% in many real SOCs. Accuracy and F1 on this set are an **upper bound**, not a typical operating point.

### 2. Author-Designed Signal and Noise

Campaigns and noise share the same author. Campaigns include deliberate entity coherence; noise is plausible but not adversarially deceptive.

### 3. Limited Scale

100 alerts per round; each missed threat moves binary metrics by ~1 percentage point. Use bootstrap or larger sets for strong significance claims.

### 4. Single Platform Schema

TheHive JSON only. Does not test normalization across Splunk, Sentinel, Elastic, Chronicle, etc.

### 5. Binary Ground Truth

Labels are `in_campaign` vs `false_positive` only. Real triage includes benign positives, rule vs data FPs, and uncertainty buckets.

### 6. Temporal-Only Variation Between Rounds

Rounds differ only in time span (30 / 90 / 180 days). No concept drift, new vendors, or evolving TTPs.

### Appropriate Uses

- Compare agents on the same open, deterministic corpus.
- Ablate temporal dispersion (round 1 vs round 2 vs round 3).
- Critique methodology and metrics (e.g. CWTS with cost-sensitive `k`).

### Inappropriate Uses

- Quoting absolute detection rates as production expectations.
- Claiming adversarial robustness without additional red-team data.
