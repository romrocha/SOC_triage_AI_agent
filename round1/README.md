# Round 1

Synthetic SOC dataset for evaluating LLM-based alert triage agents. **100 alerts**
distributed across a **30-day window** (2024-11-27 → 2024-12-26 UTC), reflecting
realistic mid-large enterprise SOC telemetry.

## Layout

```
campaing-a/finance-ransomware-alerts.json   15 alerts  (in_campaign A)
campaing-b/hr-insider-threat-alerts.json    15 alerts  (in_campaign B)
noise/noise-alerts.json                     70 alerts  (false_positive)
ground_truth.csv                            labels derived from folder layout
manifest.json                               round metadata + patch history
```

Total: **100 alerts**, ratio 30/70 signal/noise.

## Modeling principles

Two design rules govern this dataset:

1. **Realism over agent performance.** The dataset reflects what a real enterprise
   SOC sees — including ambiguity, repetition within products, hint leakage when
   genuinely emitted, and structural over-correlation patterns. We never tune
   the dataset to make the agent perform better. Performance metrics are what
   they are; the dataset is the truth.

2. **Stable `sourceRef` across regenerations and patches.** Each alert's UUID
   anchors it to the ground-truth CSV, the agent's SQLite state, and historical
   eval logs. Patches modify titles, descriptions, sources, observables, and
   timestamps — but never the `sourceRef`.

## Source products & defensive categories

Round 1 uses **17 distinct security products**, distributed across 15 defensive
categories that mirror a typical mid-large enterprise (5k+ employees) stack:

| # | Product | Category | Total alerts | A | B | N |
|---|---|---|---:|---:|---:|---:|
| 1 | Microsoft Defender for Endpoint | EDR (Endpoint Detection & Response) | 29 | 9 | 3 | 17 |
| 2 | Microsoft Entra ID Protection | IdP — Identity Protection | 10 | 1 | 1 | 8 |
| 3 | Okta | IdP — Workforce Identity | 10 | 0 | 0 | 10 |
| 4 | Cisco Secure Firewall | Firewall / NGFW | 7 | 1 | 1 | 5 |
| 5 | Netskope | CASB / SWG | 7 | 0 | 2 | 5 |
| 6 | Google Workspace Security | Email / SaaS Security | 6 | 1 | 0 | 5 |
| 7 | Microsoft Purview | DLP — Data Loss Prevention | 5 | 0 | 5 | 0 |
| 8 | Qualys VMDR | Vulnerability Management | 5 | 0 | 0 | 5 |
| 9 | Rapid7 InsightVM | Vulnerability Management | 5 | 0 | 0 | 5 |
| 10 | Veeam Backup & Replication | Backup / DR | 4 | 0 | 0 | 4 |
| 11 | Darktrace | NDR — Network Detection & Response | 3 | 0 | 0 | 3 |
| 12 | Zscaler Internet Access | SWG — Secure Web Gateway | 2 | 1 | 1 | 0 |
| 13 | Microsoft Defender for Cloud Apps | CASB | 2 | 0 | 2 | 0 |
| 14 | Jamf Protect | EDR (macOS) | 2 | 0 | 0 | 2 |
| 15 | Proofpoint TAP | Email Security — TAP | 1 | 1 | 0 | 0 |
| 16 | Rubrik Security Cloud | Backup / DR | 1 | 1 | 0 | 0 |
| 17 | Cisco Umbrella | DNS Security | 1 | 0 | 0 | 1 |

Distribution by `type` field (TheHive taxonomy): Endpoint (31), Identity (20),
Network (13), Vulnerability (10), DLP (8), Email (7), Backup (5), SIEM (3),
Cloud (2), Credential Access (1).

## Campaign A — Finance Ransomware

Realistic kill-chain spanning **30 days** (2024-11-27 → 2024-12-26), covering
**9 MITRE ATT&CK tactics** in 15 alerts.

| # | Day | Tactic | Technique | Alert |
|---|---:|---|---|---|
| 1 | 1 | Initial Access | T1566.001 | Credential phishing delivered to finance mailbox |
| 2 | 1 | Initial Access | T1204.001 | User click on credential phishing URL |
| 3 | 2 | Identity | T1078 | Risky sign-in flagged for finance user b.smith |
| 4 | 4 | Execution | T1059.001 | Office application launching suspicious child process |
| 5 | 4 | C&C | T1071.001 | Anomalous outbound connection by PowerShell |
| 6 | 6 | Credential Access | T1003.001 | Suspicious access to LSASS by unsigned binary |
| 7 | 8 | **Privilege Escalation** | T1134.001 | Token impersonation by suspicious process |
| 8 | 11 | Lateral Movement | T1021.002 | SMB authentication chain across finance subnet |
| 9 | 13 | Lateral Movement | T1021.002 | Suspicious remote service installation via SMB (PsExec) |
| 10 | 15 | **Persistence** | T1053.005 | Scheduled task creation by uncommon process |
| 11 | 17 | C&C | T1071.001 | Periodic HTTPS beaconing to recently registered domain |
| 12 | 21 | Defense Evasion | T1490 | Volume Shadow Copy deletion via vssadmin.exe |
| 13 | 22 | Impact | T1486 | Possible ransomware activity: mass file rename detected |
| 14 | 28 | Defense Evasion | T1490 | Backup tampering against finance file server |
| 15 | 30 | Impact | T1486 | File creation matches known ransomware note pattern |

**Primary pivots:** user `b.smith`, hosts `FIN-LT-204` / `FIN-WS-118` / `FIN-WS-221`,
file server `FS-FIN-01`, infrastructure `acme-payables.co`, `cdn-helpdesk-portal.com`,
IP `185.225.17.81`.

**Pattern:** `phishing → credential theft → privilege escalation → lateral movement → persistence → C&C → defense evasion → impact`.

## Campaign B — HR Insider Threat

Insider data exfiltration over **30 days**, with cadence ~2-3 days reflecting an
actor returning periodically to stage and exfiltrate.

Phases:
1. **Recon / baseline anomaly** — after-hours sign-in to HR applications
2. **Initial collection** — mass download from HR Compensation site
3. **Local staging** — archive creation on HR-LT-118
4. **Exfil channel #1 (USB)** — removable storage device connected
5. **Exfil channel #2 (cloud)** — outbound TLS upload to dropbox.com
6. **Volume escalation** — large outbound transfer to personal cloud
7. **Second wave (daytime)** — repeated HR compensation file access
8. **DLP first hit** — Microsoft Purview policy match
9. **Exfil channel #3 (mail)** — salary workbook to personal webmail
10. **Repeat collection** — download of compensation exports
11. **Sustained exfil** — connections to content.dropboxapi.com
12. **Final staging** — archive split into password-protected volumes
13. **Final USB exfil** — USB mass-storage write burst (612 MB)
14. **Final cloud exfil** — multi-part TLS to dropbox
15. **Final DLP escalation** — Purview high-confidence salary keyword match

**Primary pivots:** user `h.potter`, host `HR-LT-118`, data scope
`HR/Compensation/2024` and salary adjustment files, exfil channels personal
Dropbox / personal webmail / USB.

**Pattern:** `off-hours access → progressive collection → multi-channel staging → exfiltration`.

## Noise — diversity profile

70 alerts distributed **uniformly random** (seed=42) across the same 30-day
window. Diversity stats:

- **61 distinct titles** out of 70 alerts (87% diversity)
- **Largest cluster:** 3× (down from 9× in earlier versions)
- **15 defensive categories represented** in noise (vuln mgmt, IAM admin, CASB
  UEBA, email security depth, network depth, NDR, backup, etc.)

Within-product variety includes:

- **Identity (Okta + Entra)** — geo anomalies, impossible travel, MFA fatigue,
  password spray, token replay, OAuth grants, SSPR, adaptive policy denials,
  privileged service principal actions, risk-based step-up auth, anonymous IP
  (Tor) sign-ins
- **Vuln management (Qualys + Rapid7)** — CVE detections, EOL software, insecure
  TLS ciphers, CIS benchmark failures, container vulnerabilities, asset
  out-of-scope, insecure default configurations
- **Email (Workspace + Proofpoint)** — DMARC/SPF failures, sandbox attachment
  detection, reply-chain hijack, suspicious sender domains
- **Cloud / CASB (Netskope)** — file uploads, unsanctioned app uploads, risky
  OAuth grants, personal account use blocked
- **Network (Cisco SF + Darktrace + Umbrella)** — port scans, east-west traffic
  anomalies, weak TLS ciphers, DNS tunneling, geo blocks, peer-group deviation
- **Endpoint noise (MDE)** — PowerShell with bypass policy, encoded commands,
  hidden window, download cradles, logon script chains, remote service creation
  via PsExec/WMI/WinRM/DCOM

Some intentional repetition is preserved (3× geo-anomaly Okta, 3× impossible
travel Entra, 3× backup high-volume transfers) because real SOCs do see the
same rule firing multiple times in a 30-day window.

## Public sources used to validate alert structure

Alert titles, descriptions, observables, and MITRE technique tagging follow
patterns from these **publicly available references**, used to ensure each
synthetic alert resembles what real products emit:

1. **Sigma Rules** — https://github.com/SigmaHQ/sigma  
   Vendor-neutral detection rule catalog. Used to model titles and detection
   logic for endpoint, identity, network, and email alerts.

2. **Microsoft Sentinel Detections** — https://github.com/Azure/Azure-Sentinel/tree/master/Detections  
   Official analytic rules from Microsoft. Used as reference for Defender for
   Endpoint, Entra ID Protection, Defender for Cloud Apps, and Purview alert
   formats.

3. **Microsoft Defender alert classification** — https://learn.microsoft.com/en-us/microsoft-365/security/defender/alert-classification  
   Microsoft's documentation of MDE alert categories, severity scoring, and
   detection rule families.

4. **Microsoft Entra ID Protection risk events** — https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks  
   Canonical list of identity risk events: anonymous IP, impossible travel,
   token replay, leaked credentials, password spray, etc.

5. **Microsoft Defender ASR rules reference** — https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference  
   Attack Surface Reduction rule IDs (e.g., the GUID `c1db55a8-c869-4445-a3e4-7b4ac4e1dac5`
   for ransomware behavior block).

6. **Microsoft Purview DLP** — https://learn.microsoft.com/en-us/purview/dlp-overview  
   DLP policy match alerts, Insider Risk Management, and sensitivity-label
   based file access auditing.

7. **Okta System Log events** — https://developer.okta.com/docs/reference/api/event-types/  
   Canonical event taxonomy for Okta sign-in flows, MFA, OAuth, SSPR,
   adaptive policy outcomes, and admin actions.

8. **DFIR Report incident reports** — https://thedfirreport.com/  
   Public ransomware and insider incident reports with screenshots of real
   alert sequences from CrowdStrike, MDE, Splunk ES consoles. Used as
   reference for kill-chain dwell times, alert ordering, and operational
   phrasing.

9. **MITRE ATT&CK** — https://attack.mitre.org/  
   Source of all `T-id` technique references in alert tags. Each Campaign A
   alert maps to a specific MITRE technique within its tactic.

10. **Splunk Security Content** — https://github.com/splunk/security_content  
    Splunk ES analytic rules in YAML format with MITRE mappings. Used to
    validate phrasing for alerts that would originate from a SIEM.

11. **Atomic Red Team** — https://github.com/redcanaryco/atomic-red-team  
    TTP-level test catalog mapped to MITRE. Used to confirm detection
    coverage and alert plausibility for each technique.

## Patch history

The dataset has evolved through five patches. See `manifest.json` for the
authoritative log; summary:

- **v1_baseline** — original 1-day window with hint-leaking titles and brute-force noise cluster.
- **v2_post_hint_fix** — rewrote 9 hint-leaking campaign titles, replaced 6-alert brute-force noise cluster with 6 diverse alerts.
- **v3_30day_window** — expanded window from 1 day to 30 days; campaigns gained realistic phase-based timing; noise re-distributed uniform-random with seed=42.
- **v4_mde_consolidation** — consolidated 5 EDR vendors into Microsoft Defender for Endpoint (+ Jamf Protect for macOS); migrated 2 alerts to Microsoft Purview (DLP territory); rewrote 30 titles using MDE/Purview conventions from public sources.
- **v5_taxonomy** — Campaign A added Privilege Escalation (T1134.001) and Persistence (T1053.005) to cover full kill-chain; noise diversified across 9 repetitive clusters with within-product variety and new categories (vuln mgmt depth, IAM admin, CASB UEBA, email depth, network depth).

Backups for each patch are preserved under `input/round1_backup_<version>/` for
rollback or comparison.

## Ground truth & labels

Labels are derived **automatically** from folder layout via the convention in
`security_agent/app/experiments/ground_truth.py`:

```python
DATASET_FOLDER_SPECS = (
    ("noise",      "false_positive", ""),
    ("campaing-a", "in_campaign",    "campaing-a"),
    ("campaing-b", "in_campaign",    "campaing-b"),
)
```

To regenerate the CSV after any change to the JSON files:

```bash
python scripts/generate_ground_truth.py --round round1
```

The notebook also calls `write_ground_truth_csv()` automatically before each
evaluation cycle, so the CSV stays in sync without manual regeneration.

## Workflow

To run an evaluation cycle on Round 1:

```bash
export RESEARCH_ROUND=round1
# In notebooks/experiment.ipynb, set RESEARCH_ROUND="round1" and EXPERIMENT_VERSION="v5_taxonomy"
# Run cells in order — they handle ground-truth regeneration, agent execution, evaluation, and cost/latency reporting
```

Each notebook run produces:
- `output/round1/round1_results_<model>_<timestamp>.txt` — campaign analysis report
- `output/round1/round1_agent_<model>_<timestamp>.log` — execution log (latency, tool calls)
- A new row in `data/eval_runs.csv` — metrics tagged with `experiment_version`
- A LangSmith project named `round1-<model>-<timestamp>` — full traces with
  per-call token counts and cost (consumed by the cost+latency cell)

## Notes for future work

- **Lacunas conhecidas no stack representado:** falta Cloud Workload Protection
  (Wiz/Prisma Cloud/AWS GuardDuty) e Container Security (Falco/Sysdig/Aqua).
  Plausível em SOCs modernos; pode ser adicionado em iterações futuras se
  ampliarmos o escopo das campanhas.
- **Reconnaissance e Resource Development (TA0043, TA0042)** estão ausentes
  por design — fora do escopo do que o SOC tipicamente vê.
- **The 27/30 noise alerts in `noise/`** include intentional structural
  patterns (clusters of similar alerts) that mirror real SOC telemetry, even
  though they may induce ghost campaigns in the agent. This is by design —
  noise reflects reality, not what makes the agent look good.
