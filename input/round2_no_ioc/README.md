# Round 2

Synthetic SOC-style dataset for evaluation with a 4-month timeline and mixed noise/campaign activity.

## Layout

- `campaing-a/finance-ransomware-alerts.json`: 15 alerts
- `campaing-b/hr-insider-threat-alerts.json`: 15 alerts
- `noise/noise-alerts.json`: 70 alerts
- `ground_truth.csv`: labels derived from folder membership
- `manifest.json`: round metadata

Total: 100 alerts distributed from `2024-01-01` through `2024-04-30`.

## Modeling goals

This round was rewritten to look closer to real SOC telemetry:

- `source` uses real product names such as `Google Workspace Security`, `Proofpoint TAP`, `Microsoft Entra ID Protection`, `Cortex XDR`, `CrowdStrike Falcon`, `Microsoft Defender for Endpoint`, `Netskope`, `Zscaler Internet Access`, `Splunk Enterprise Security`, and `Rubrik Security Cloud`
- `tags` contains exactly one value, always equal to the `source`
- `description` carries operational context such as user names, hosts, file shares, cloud apps, URLs, transfer sizes, and sign-in anomalies
- campaign and noise events are intentionally interleaved in time rather than grouped into isolated windows
- existing `sourceRef` values were preserved so historical references remain stable across regenerations

## Campaign A

`campaing-a` models a finance intrusion that starts with phishing and progresses to ransomware.

Narrative:

1. Phishing email reaches `b.smith`
2. User clicks the lure from `FIN-LT-204`
3. Risky sign-in suggests credential theft
4. Word spawns encoded PowerShell on the finance laptop
5. Post-compromise beaconing appears
6. LSASS access indicates credential harvesting
7. SMB access expands into finance file servers
8. Lateral movement reaches additional finance workstations
9. Remote service creation consistent with `PsExec`
10. Shadow copies are deleted
11. Beaconing to staging infrastructure continues
12. Mass file renames hit finance shares
13. SIEM correlates the precursor sequence
14. Backup tampering attempts target the finance file server
15. Ransom note is dropped on impacted endpoints

Primary pivots used for correlation:

- User: `b.smith`
- Initial host: `FIN-LT-204`
- Spread hosts: `FIN-WS-118`, `FIN-WS-221`
- Server/share context: `FS-FIN-01`, finance shares
- Infrastructure: `acme-payables.co`, `sharepoint-acme-files.com`, `cdn-helpdesk-portal.com`

Expected pattern: `phish -> credential theft -> execution -> lateral movement -> encryption -> backup tampering`.

## Campaign B

`campaing-b` models an insider-style HR data exfiltration scenario.

Narrative:

1. `h.potter` signs in to HR applications outside normal hours
2. Large download occurs from `HR/Compensation/2024`
3. Sensitive files are archived locally on `HR-LT-118`
4. USB media is mounted and used
5. Archive is uploaded to personal Dropbox
6. Firewall confirms large outbound transfer
7. More sensitive HR files are accessed after midnight
8. SIEM correlates access and exfil indicators
9. A salary workbook is attached to a draft sent to personal webmail
10. Additional compensation exports are downloaded
11. Traffic to Dropbox upload endpoints continues
12. Archive is split into password-protected volumes
13. New USB write burst follows archive creation
14. Dropbox upload resumes with the split archive
15. SIEM correlates the full exfiltration sequence

Primary pivots used for correlation:

- User: `h.potter`
- Main endpoint: `HR-LT-118`
- Data scope: `HR/Compensation/2024`, salary adjustment files
- Exfil channels: personal Dropbox, personal webmail, removable media

Expected pattern: `off-hours access -> collection -> staging -> exfiltration`.

## Noise

`noise/` contains 70 realistic false-positive style alerts that should look operationally plausible without forming a coherent campaign.

Examples include:

- VPN and identity anomalies resolved by MFA or VPN egress changes
- scheduled vulnerability scans from approved scanners
- software deployment activity that triggers endpoint detections
- backup and disaster recovery transfers
- sanctioned cloud storage uploads
- approved IT remote administration
- login scripts or updater executions already allow-listed

The noise is intentionally mixed across the same 4-month period so the agent must separate true campaign cohesion from everyday SOC background activity.

## Regeneration

Rebuild the round 2 JSON files:

```bash
python scripts/regenerate_round2_dataset.py
```

Regenerate labels after changing the dataset:

```bash
python scripts/generate_ground_truth.py --round round2
```

## Full workflow

To produce a fresh `round2` end-to-end:

1. Regenerate the synthetic input dataset
2. Regenerate `ground_truth.csv`
3. Run ingestion and the agent workflow against `round2`
4. Export a new text report

Example:

```bash
export RESEARCH_ROUND=round2
python scripts/regenerate_round2_dataset.py
python scripts/generate_ground_truth.py --round round2
python scripts/export_campaign_report.py --round round2 --label gpt5mini
```

Notes:

- `scripts/export_campaign_report.py` writes to `output/round2/round2_results_<label>.txt`
- the exported report now starts with a UTC generation timestamp
- if you want the report to reflect a new run, re-run the notebook or agent flow first so `data/alerts.db` contains fresh campaign results for `round2`
