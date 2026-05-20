# SOC Alert Triage — Synthetic Research Dataset

> **Repository status (May 2026)**  
> This repository is the public home for my AI research on **agentic SOC alert triage** — evaluating whether LLM-based agents can perform Tier-1 triage through recursive entity pivoting and correlation across multi-vendor alert streams.  
> **For now, only the synthetic dataset is published here.** Full research artifacts — additional data, experimental results, and agent code — will be added **after July 2026**.  
> Preliminary findings will be presented at:
> - **[YSTS Security Conference](https://ysts.org/)** — São Paulo, Brazil (May 2026)
> - **[38th Annual FIRST Conference](https://www.first.org/conference/2026/program)** — Denver, USA (June 2026)

A reproducible, synthetic dataset for evaluating LLM-based agents on Tier-1 SOC alert triage. Built for the YSTS research talk *"Agentes de IA no SOC — isso funciona?"* (Rômulo Rocha, 2026).

This dataset companions the agent code (released separately after July 2026) and is intended to support **independent reproduction** of the talk's results, **comparative benchmarking** of other agents, and **methodology critique** by the community.

---

## What this is

— 100 alerts per round, 3 rounds × 1 reference + variants (30 / 90 / 180 days).
— 2 multi-stage campaigns (financial ransomware + HR insider data exfiltration), each spanning 15 alerts across 6–8 vendor sources.
— 70 noise alerts per round, drawn from 12 distinct vendors with realistic severity, observable, and MITRE ATT&CK distributions.
— Schema: **TheHive** JSON (canonical SOC ingestion format).
— Ground truth: CSV with per-alert labels (`in_campaign` / `false_positive`) and expected `campaign_id`.

## What this is NOT

— **Not production data.** Zero PII, zero real attack telemetry. All identifiers are pseudonymized synthetic strings.
— **Not a benchmark of absolute performance.** Class balance (30% true positives) is deliberately inverted versus real SOC base rates (~0.1–1%). Numbers reported on this dataset do *not* transfer to production without recalibration. See [Limitations](#limitations) below.
— **Not a substitute for adversarial testing.** Synthetic campaigns lack attacker tradecraft (active blending, novel TTPs, deception). Real adversaries will perform worse against detection than this dataset implies — use synthetic results as an upper bound, not a guarantee.

---

## Quick reproduction

```bash
# 1. Regenerate the canonical round (round 1, ~30-day span)
python scripts/regenerate_round1_dataset.py

# 2. Generate the temporal variants (rounds 2 and 3, 90d and 180d)
python scripts/regenerate_temporal_variants.py

# 3. Generate ground_truth.csv for each round
python scripts/generate_ground_truth.py --round round1
python scripts/generate_ground_truth.py --round round2
python scripts/generate_ground_truth.py --round round3
```

Output layout after generation:

```
input/
├── round1/
│   ├── campaing-a/finance-ransomware-alerts.json   (15 alerts)
│   ├── campaing-b/hr-insider-threat-alerts.json    (15 alerts)
│   ├── noise/noise-alerts.json                     (70 alerts)
│   └── ground_truth.csv                            (100 rows)
├── round2/   (90-day span — same alerts, rescaled timestamps)
└── round3/   (180-day span — same alerts, rescaled timestamps)
```

Reproduction is **fully deterministic** — no random seeds, no API calls, no external dependencies beyond Python 3.11+. Anyone who clones this repo will produce byte-identical files.

---

## Design philosophy

### 1. Synthetic over anonymized real data

Real SOC data is encumbered by PII, legal constraints, and customer-specific bias. We accept the trade-off of losing adversarial realism in exchange for: full ground truth, zero compliance friction, perfect reproducibility, and zero data sensitivity for researchers receiving the dataset.

### 2. TheHive as canonical schema

Alerts conform to the [TheHive](https://github.com/TheHive-Project/TheHive) JSON ingestion format because it (a) is open-source and free to use, (b) sees actual production adoption in mid-sized SOCs, and (c) preserves the field shape an L1 analyst encounters in real triage. Every alert carries `sourceRef`, `severity`, `tlp`, `pap`, `flag`, `status`, and a list of `observables` with explicit `dataType` and `ioc` flags.

### 3. Time as the only variable across rounds

Round 1 is the **single source of truth**. Rounds 2 and 3 are produced by `regenerate_temporal_variants.py` via linear rescaling of timestamps (`new_date = anchor + (old_date - anchor) × scale`) where `scale = target_span / reference_span`. **Every other field is identical** across rounds — same alert ids, titles, descriptions, severities, sources, tags, observables, ground truth assignments. The only thing that changes is how stretched the temporal distribution is (30 → 90 → 180 days).

This is a deliberate methodological choice: it isolates the effect of temporal dispersion on the agent's cognitive performance, eliminating dataset-shape confounds.

### 4. Deterministic generation, no randomness

Campaigns and noise are specified as Python `dataclass` literals inside `regenerate_round1_dataset.py`. There is no `random.seed()` because there is no random number generation. Anyone who runs the generator twice gets the same bytes. This eliminates a class of "what version of the dataset did you use?" reproducibility headaches.

### 5. Schema preserved across all 100 alerts

Every alert — campaign or noise — carries the same 13 top-level fields. No conditional schemas, no special cases for "campaign alerts get extra fields". An agent treating all alerts equally cannot use schema as an inadvertent label leakage signal.

---

## Approximation to real SOC

The synthetic nature of the dataset is honest, but several design choices specifically push toward representativeness of real SOC operations:

### Heterogeneous vendor mix

Alerts are sourced from **12 distinct vendor products**, mirroring the vendor-multi caos of real corporate SOCs:

| Category | Vendors represented |
|---|---|
| Endpoint detection | Microsoft Defender for Endpoint, Jamf Protect |
| Cloud identity | Microsoft Entra ID Protection, Okta |
| Cloud apps / CASB | Microsoft Defender for Cloud Apps, Netskope |
| Email security | Proofpoint TAP, Google Workspace Security |
| Network / firewall | Cisco Secure Firewall, Cisco Umbrella |
| Secure web gateway | Zscaler Internet Access |
| Data protection | Microsoft Purview |
| Vulnerability mgmt | Qualys VMDR, Rapid7 InsightVM |
| Backup | Veeam Backup & Replication, Rubrik Security Cloud |
| Network anomaly | Darktrace |

This mix forces the agent to handle vendor-specific phrasing, severity scales, and observable shapes — not a monoculture.

### MITRE ATT&CK tagging across all alerts

Every alert carries a tag list that includes its source vendor *and* one or more MITRE ATT&CK technique IDs. The round-1 dataset references **47 distinct techniques** spanning Initial Access (`T1566.*`, `T1190`), Execution (`T1059.001`, `T1204.001`), Persistence/Lateral (`T1078`, `T1021.002`, `T1569.002`), Discovery (`T1046`), Credential Access (`T1003.001`, `T1110`), Collection (`T1005`, `T1530`), Exfiltration (`T1041`, `T1048.*`, `T1567.002`), and Impact (`T1486`, `T1490`).

This reflects modern SOC practice in which detection content carries kill-chain provenance — and gives the agent a structured signal to reason over.

### Realistic severity distribution

Noise alerts skew toward Sev 1–3 (low to medium); campaign alerts concentrate in Sev 3–4 (medium to high). The distribution is not flat ("everything is critical") nor inverted ("only the campaign is severe"), which would bias detection trivially. Roughly:

- Noise severity: Sev 1: ~14% · Sev 2: ~40% · Sev 3: ~41% · Sev 4: ~4%
- Campaign severity: Sev 3: ~50% · Sev 4: ~50%

### Deliberate entity overlap

Campaigns have **internal entity coherence** — the same user, host, and IP appear across multiple alerts in the same campaign, creating a correlation signature an agent can find. But noise also carries **partial entity overlap** between unrelated alerts (e.g., several "Impossible travel" alerts referencing similar IP ranges or usernames), which forces the agent to discriminate genuine campaign from coincidental noise clustering.

This is the structural pattern responsible for the hardest false-positive mode in real SOC triage: noise that *looks* correlated.

### Observable types and IOC flags

The dataset carries **215 observables** across 100 alerts, distributed across 8 standard TheHive observable types: `mail`, `domain`, `url`, `username`, `hostname`, `ip`, `file`, `other`. **76 of them carry the explicit `ioc: true` flag** — meaning the agent (or analyst) should treat them as indicators of compromise eligible for pivoting, while the remaining 139 are context-only. This matches real TheHive deployment patterns.

### Compliance metadata preserved

Every alert carries `tlp` (Traffic Light Protocol) and `pap` (Permissible Actions Protocol) values, defaulted to `2` (AMBER) but explicitly set. Real SOC operations enforce these for downstream sharing decisions — preserving them in the synthetic dataset means agents trained or evaluated here learn to respect compliance metadata.

---

## Public sources used for alert content validation

Synthetic ≠ invented. Alert titles, descriptions, observable shapes, MITRE technique tagging, and kill-chain cadence were modeled against eleven publicly available references. Each synthetic alert resembles, by construction, what a real production detector emits — and any researcher can audit the resemblance against the same sources.

1. **Sigma Rules** — [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
   Vendor-neutral detection rule catalog. Used to model titles and detection logic for endpoint, identity, network, and email alerts.

2. **Microsoft Sentinel Detections** — [github.com/Azure/Azure-Sentinel/tree/master/Detections](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)
   Official analytic rules from Microsoft. Reference format for Defender for Endpoint, Entra ID Protection, Defender for Cloud Apps, and Purview alerts.

3. **Microsoft Defender alert classification** — [learn.microsoft.com/en-us/microsoft-365/security/defender/alert-classification](https://learn.microsoft.com/en-us/microsoft-365/security/defender/alert-classification)
   Microsoft's documentation of MDE alert categories, severity scoring, and detection rule families.

4. **Microsoft Entra ID Protection risk events** — [learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
   Canonical list of identity risk events: anonymous IP, impossible travel, token replay, leaked credentials, password spray.

5. **Microsoft Defender ASR rules reference** — [learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
   Attack Surface Reduction rule IDs (e.g., the GUID `c1db55a8-c869-4445-a3e4-7b4ac4e1dac5` for ransomware behavior block) — reproduced verbatim in synthetic alerts that reference ASR.

6. **Microsoft Purview DLP** — [learn.microsoft.com/en-us/purview/dlp-overview](https://learn.microsoft.com/en-us/purview/dlp-overview)
   DLP policy match alerts, Insider Risk Management taxonomy, and sensitivity-label based file access auditing.

7. **Okta System Log events** — [developer.okta.com/docs/reference/api/event-types](https://developer.okta.com/docs/reference/api/event-types/)
   Canonical event taxonomy for Okta sign-in flows, MFA, OAuth, SSPR, adaptive policy outcomes, and admin actions.

8. **DFIR Report incident reports** — [thedfirreport.com](https://thedfirreport.com/)
   Public ransomware and insider incident reports with screenshots of real alert sequences from CrowdStrike, MDE, and Splunk ES consoles. Reference for kill-chain dwell times, alert ordering, and operational phrasing.

9. **MITRE ATT&CK** — [attack.mitre.org](https://attack.mitre.org/)
   Source of every `T-id` technique reference in alert tags. Each Campaign A alert maps to a specific MITRE technique within its corresponding tactic.

10. **Splunk Security Content** — [github.com/splunk/security_content](https://github.com/splunk/security_content)
    Splunk ES analytic rules in YAML with explicit MITRE mappings. Used to validate phrasing for alerts that would plausibly originate from a SIEM.

11. **Atomic Red Team** — [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
    TTP-level test catalog mapped to MITRE. Used to confirm detection coverage and alert plausibility for each technique that appears in the dataset.

---

## Schema reference

Each alert JSON object has the following structure:

```json
{
  "type": "external",
  "source": "Microsoft Defender for Endpoint",
  "sourceRef": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "title": "Suspicious PowerShell network beacon from finance laptop",
  "description": "Encoded PowerShell on FIN-LT-204 initiated outbound HTTPS to 185.225.17.81 ...",
  "severity": 4,
  "date": 1732826880000,
  "tags": ["Microsoft Defender for Endpoint", "T1071.001"],
  "tlp": 2,
  "pap": 2,
  "flag": false,
  "status": "New",
  "observables": [
    {
      "dataType": "hostname",
      "data": ["FIN-LT-204"],
      "message": "Compromised finance endpoint",
      "tlp": 2,
      "ioc": true,
      "sighted": false
    }
  ]
}
```

### Field semantics

| Field | Type | Notes |
|---|---|---|
| `sourceRef` | string (UUID) | Unique per-alert identifier — stable across rounds |
| `source` | string | Originating vendor product (12 distinct values) |
| `severity` | int 1–4 | TheHive convention: 1 = low, 4 = critical |
| `date` | int (epoch ms) | UTC; **only field that varies between rounds** |
| `tags` | list[string] | First element = source vendor; remaining = MITRE technique IDs |
| `tlp` / `pap` | int 0–3 | 2 = AMBER (default) |
| `flag` | bool | Always `false` at ingest (analyst can set later) |
| `status` | string | Always `"New"` at ingest |
| `observables` | list[obj] | One observable per pivot-eligible entity |

### Observable types

- `mail` — email address
- `domain` — DNS domain name
- `url` — full URL
- `username` — internal account identifier (pseudonymized)
- `hostname` — endpoint or server hostname (pseudonymized)
- `ip` — IPv4 address (synthetic, in non-routable or reserved ranges)
- `file` — file name or hash
- `other` — catch-all for non-standard observables

---

## Ground truth methodology

`ground_truth.csv` is generated by `scripts/generate_ground_truth.py` and has three columns:

```csv
alert_id,expected_label,expected_campaign_id
1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d,in_campaign,finance-ransomware
n7c8d9e0-f1a2-b3c4-d5e6-f7a8b9c0d1e2,false_positive,
```

- `alert_id` matches the `sourceRef` field of the corresponding alert.
- `expected_label` ∈ {`in_campaign`, `false_positive`}.
- `expected_campaign_id` is populated only for `in_campaign` alerts and identifies which of the two campaigns (`finance-ransomware` or `hr-insider-threat`) the alert belongs to.

Generation logic: alerts are assigned to campaigns based on the folder they sit in (`campaing-a/*` → `finance-ransomware`, `campaing-b/*` → `hr-insider-threat`), and noise (`noise/*`) is labeled `false_positive`. This is mechanical and 100% reproducible — no manual annotation.

The single source of truth for **what alert belongs to what campaign** is **file location**, not metadata inside the alert itself. This prevents an agent from cheating by reading a hidden "campaign_id" field — there isn't one.

---

## Limitations

The dataset is appropriate for **comparative methodology research** and inappropriate for **production performance prediction**. Honest accounting:

### 1. Inverted base rate

Real SOC alert streams have ~99% false positives. This dataset has 70% (still favorable to detection). Accuracy and F1 metrics on this dataset will be substantially higher than on production. Reported numbers represent a **ceiling**, not a typical operating point.

### 2. Author-designed signal *and* noise

Both campaigns and noise were authored by the same researcher. This embeds an unconscious "solvability guarantee" — campaigns have entity coherence intentionally placed to be findable, and noise has been crafted to look like plausible noise rather than adversarial deception. Real attackers actively design TTPs to evade detection; this dataset does not test that.

### 3. Limited scale

100 alerts per round, with 30 campaign alerts as ground-truth positives, means each missed-threat move shifts metrics by ~3 percentage points. Statistical significance of comparative claims requires either bootstrap analysis or replication with substantially larger datasets.

### 4. Single platform schema

TheHive's JSON format is one of several SOC schemas. Real production SIEMs (Splunk, Sentinel, Elastic, Chronicle) emit differently shaped events with vendor-specific quirks. The dataset does not test schema normalization or cross-platform reasoning.

### 5. Binary ground truth

The dataset labels are binary (`in_campaign` / `false_positive`). Real triage involves a 4–5-way classification including benign positive, false positive by rule, false positive by data, and uncertain. The agent's capacity to express triage uncertainty is not measured here.

### 6. Temporal-only variation between rounds

Rounds differ only in temporal span (30/90/180 days). Vocabulary, vendor mix, TTP composition, and entity universe are constant. The dataset does not test concept drift, novel vendor onboarding, or adversarial evolution.

---

## How to use this dataset

### For evaluating a new triage agent

1. Configure your agent to ingest TheHive JSON.
2. Run it against `input/round1/` alerts.
3. Persist its output (whatever you define as "decision") to a comparable label schema.
4. Compare against `input/round1/ground_truth.csv`.
5. Report accuracy, F1 (binary in_campaign vs false_positive), missed threat count, and median/P95 latency.
6. Optionally: also report the **CWTS** (Cost-Weighted Triage Score) — the cost-sensitive metric proposed in the companion paper, parameterized over a range of `k` values to expose where rankings invert.

### For ablation studies (effect of temporal dispersion)

Run the same agent against `round1`, `round2`, and `round3`. Holding every other variable constant, you observe pure temporal-stress sensitivity.

### For replication and reporting

This dataset is offered under [LICENSE TBD] for academic and operational research use. We ask that publications cite the companion paper and link this repository. Anonymous community reports are welcome — see [CONTRIBUTING.md] for the proposed reporting template.

---

## Related work and positioning

This dataset addresses a structural gap: SOC alert triage research has been dominated by either proprietary corporate data (not reproducible) or repurposed network IDS datasets like UNSW-NB15 or CICIDS (not at the analyst-decision granularity).

Closest related work:

— **CORTEX (Wei et al., 2025)** — multi-agent triage with a production SOC dataset. Released their dataset in principle; in practice, public access is unclear.
— **Simbian AI SOC Benchmark** — 100 kill-chain scenarios behind a commercial service.
— **AACT (Turcotte et al., 2025)** — uses 6 months of real SOC data (proprietary) plus a synthetic public dataset.

What this dataset adds: a **fully open, reproducible, deterministic** alternative — methodologically defensible for comparative research even where it falls short for absolute performance benchmarking.

---

## Repository layout

```
.
├── README.md                                          # this file
├── LICENSE                                            # [TBD]
├── CONTRIBUTING.md                                    # reporting template
├── input/
│   ├── round1/                                        # canonical, 30-day span
│   │   ├── campaing-a/finance-ransomware-alerts.json
│   │   ├── campaing-b/hr-insider-threat-alerts.json
│   │   ├── noise/noise-alerts.json
│   │   └── ground_truth.csv
│   ├── round2/                                        # 90-day variant
│   └── round3/                                        # 180-day variant
├── scripts/
│   ├── regenerate_round1_dataset.py                   # canonical generator
│   ├── regenerate_temporal_variants.py                # rounds 2 + 3 from round 1
│   └── generate_ground_truth.py                       # ground_truth.csv writer
├── docs/
│   ├── SCHEMA.md                                      # detailed field reference
│   ├── METHODOLOGY.md                                 # design rationale and trade-offs
│   └── LIMITATIONS.md                                 # extended honest accounting
└── tests/
    └── test_dataset_invariants.py                     # property tests (counts, schemas, IDs)
```

---

## Citation

If you use this dataset in published work, please cite:

```bibtex
@misc{rocha2026socllm,
  title  = {Agentes de IA no SOC — Synthetic Research Dataset for L1 Triage Agent Evaluation},
  author = {Rocha, R{\^o}mulo},
  year   = {2026},
  howpublished = {YSTS Brazil 2026 — Companion dataset to talk and CWTS methodology paper},
  url    = {https://github.com/romrocha/SOC_AI_agent-research}
}
```

---

## Contact

Questions, methodology critique, or interest in collaborative extension: @romrocha
