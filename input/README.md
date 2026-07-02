# Schema reference

Each alert is a JSON object in a file-level array (`finance-ransomware-alerts.json`, etc.).

## Top-level fields

| Field | Type | Notes |
|-------|------|-------|
| `type` | string | Alert category (e.g. `Email`, `external`) |
| `source` | string | Originating vendor product (12 distinct values) |
| `sourceRef` | string (UUID) | Unique per-alert identifier — stable across rounds |
| `title` | string | Short detection title |
| `description` | string | Analyst-facing narrative |
| `severity` | int 1–4 | TheHive convention: 1 = low, 4 = critical |
| `date` | int (epoch ms) | UTC; **only field that varies between rounds** |
| `tags` | list[string] | Vendor name + MITRE ATT&CK technique ID(s) |
| `tlp` / `pap` | int 0–3 | Default `2` (AMBER) |
| `flag` | bool | Always `false` at ingest |
| `status` | string | Always `"New"` at ingest |
| `observables` | list[object] | Pivot-eligible entities |

## Observable object

| Field | Type | Notes |
|-------|------|-------|
| `dataType` | string | `mail`, `domain`, `url`, `username`, `hostname`, `ip`, `file`, `other` |
| `data` | list[string] | One or more values |
| `message` | string | Analyst context |
| `tlp` | int | Usually `2` |
| `ioc` | bool | `true` = treat as IOC for pivoting |
| `sighted` | bool | Always `false` at ingest |

## Layout

```
input/roundN/
├── campaing-a/finance-ransomware-alerts.json   (15 alerts)
├── campaing-b/hr-insider-threat-alerts.json    (15 alerts)
├── noise/noise-alerts.json                     (70 alerts)
└── ground_truth.csv                            (100 rows)
```

See `README.md` for a full JSON example and vendor list.



# Input datasets (per round)

Each subdirectory `round1` … `round4` holds alert JSON in a **TheHive-style layout**: one folder per **label group** (noise vs campaigns), with `*.json` files inside.

## Reference layout (round 1 / `thehive_mockup_alerts`)

The baseline dataset uses exactly three groups:

- `noise/` — false-positive noise alerts (`*.json`)
- `campaing-a/` — campaign A (`*.json`)
- `campaing-b/` — campaign B (`*.json`)

## Extra campaigns in other rounds

**Rounds are not limited to campaigns A and B.** For `round2` … `round4` (or new experiments), you may add **additional campaign folders** alongside the same `noise/` pattern, for example:

- `campaing-c/`, `campaign-insider-2024/`, `phishing-wave-02/`, etc.

Conventions:

- **One folder per distinct ground-truth campaign** you want to evaluate (all alerts in that folder share the same `expected_campaign_id` in `ground_truth.csv`).
- **`noise/`** remains the usual bucket for false-positive labels.
- **Naming** is up to you; keep it stable per round so metrics and comparisons stay clear.

The generator that builds `ground_truth.csv` uses an explicit list of folder → label mappings (`DATASET_FOLDER_SPECS` in `security_agent/app/experiments/ground_truth.py`). When you introduce new campaign directories for a round, **extend that list** (or add an equivalent mapping for that round) so those JSON files are included in the CSV with the correct `expected_campaign_id`.

## Ground truth

Generate `ground_truth.csv` in that round folder with:

```bash
python scripts/generate_ground_truth.py --round round1
```

Ou com caminho explícito:

```bash
python scripts/generate_ground_truth.py --input input/round1
```

## Active round

Set the environment variable before ingestion or agent runs (defaults to `round1`):

```bash
export RESEARCH_ROUND=round2
```

`security_agent.app.config` resolves `DATA_DIR` to `input/<RESEARCH_ROUND>/`.

## Round 1

`input/round1/` ships as **JSON files in the repo** (same schema as `round2`): `campaing-a/finance-ransomware-alerts.json`, `campaing-b/hr-insider-threat-alerts.json`, `noise/noise-alerts.json`. The dataset keeps the **15 + 15 + 70** split, but was refreshed to follow the same SOC-style modeling used in `round2`, while preserving the original **1-day** time window:

- `source` uses **real product names** such as `Cortex XDR`, `CrowdStrike Falcon`, `Google Workspace Security`, `Microsoft Entra ID Protection`, `Netskope`, and `Splunk Enterprise Security`
- `tags` now contain **only the source product name**
- alert `description` values include more operational context (mailboxes, hosts, shares, cloud apps, transfer size, sign-in context, etc.)
- all **100 alerts** are distributed across **one UTC day**, **2024-11-27**, with **noise and both campaigns intentionally mixed in time** (see `manifest.json`)

The existing `sourceRef` values were preserved so historical references remain stable. `ground_truth.csv` is included for evaluation.

To regenerate the round 1 dataset:

```bash
python scripts/regenerate_round1_dataset.py
python scripts/generate_ground_truth.py --round round1
```

## Round 2 (4-month SOC-style timeline)

`input/round2/` ships as **JSON files in the repo** (same schema as `round1`): `campaing-a/finance-ransomware-alerts.json`, `campaing-b/hr-insider-threat-alerts.json`, `noise/noise-alerts.json`. The dataset keeps the **15 + 15 + 70** split, but the alert content was rewritten to look closer to real SOC telemetry:

- `source` uses **real product names** such as `Cortex XDR`, `CrowdStrike Falcon`, `Google Workspace Security`, `Microsoft Entra ID Protection`, `Netskope`, and `Splunk Enterprise Security`
- `tags` now contain **only the source product name**
- alert `description` values include more operational context (mailboxes, hosts, shares, cloud apps, transfer size, sign-in context, etc.)
- the **100 alerts** are distributed across **4 months** from **2024-01-01** UTC through **2024-04-30**, with **noise and both campaigns intentionally mixed in time** (see `manifest.json`)

The existing `sourceRef` values were preserved so historical references remain stable. `ground_truth.csv` is included for evaluation.

To regenerate labels only:

```bash
python scripts/generate_ground_truth.py --round round2
```
