# Round 3

Synthetic SOC-style dataset for evaluation with a **6-month timeline** and the same campaigns/noise as rounds 1 and 2.

## Purpose

Round 3 isolates the **temporal dilation variable**: same campaigns, same noise, same 100 alerts — only the timeline is stretched from 4 months (round 2) to 6 months. This allows measuring whether increased time span between correlated events degrades agent accuracy.

| Round | Timeline | Span |
|-------|----------|------|
| Round 1 | 2024-11-27 (single day) | 0 days |
| Round 2 | 2024-01-01 → 2024-04-30 | 120 days |
| **Round 3** | **2024-07-01 → 2024-12-31** | **182 days** |

## Layout

- `campaing-a/finance-ransomware-alerts.json`: 15 alerts
- `campaing-b/hr-insider-threat-alerts.json`: 15 alerts
- `noise/noise-alerts.json`: 70 alerts
- `ground_truth.csv`: labels derived from folder membership
- `manifest.json`: round metadata

Total: 100 alerts distributed from `2024-07-01` through `2024-12-31`.

## Modeling goals

This round uses the same structure as round 2:

- `source` uses real product names such as `Google Workspace Security`, `Proofpoint TAP`, `Microsoft Entra ID Protection`, `Cortex XDR`, `CrowdStrike Falcon`, `Microsoft Defender for Endpoint`, `Netskope`, `Zscaler Internet Access`, `Splunk Enterprise Security`, and `Rubrik Security Cloud`
- `tags` contains exactly one value, always equal to the `source`
- `description` carries operational context such as user names, hosts, file shares, cloud apps, URLs, transfer sizes, and sign-in anomalies
- campaign and noise events are intentionally interleaved in time rather than grouped into isolated windows

## Campaign A

`campaing-a` models a finance intrusion that starts with phishing and progresses to ransomware.

Narrative (same as rounds 1/2, spread across Jul–Dec):

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

## Campaign B

`campaing-b` models an insider-style HR data exfiltration scenario.

Narrative (same as rounds 1/2, spread across Jul–Dec):

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

## Noise

`noise/` contains 70 alerts with the same 14 templates as rounds 1/2:

- Sign-in anomalies, impossible travel
- Port scanning and vulnerability assessment
- PowerShell execution
- Backup data transfers
- Suspicious emails
- Remote administration
- Cloud storage uploads
- Authentication failures
- macOS unsigned binary execution
- Script interpreter chains at logon

Severity distribution: sev 1 (11), sev 2 (29), sev 3 (25), sev 4 (5).

## Regeneration

Rebuild the round 3 JSON files:

```bash
python scripts/regenerate_round3_dataset.py
```

Regenerate labels after changing the dataset:

```bash
python scripts/generate_ground_truth.py --round round3
```

## Full workflow

```bash
export RESEARCH_ROUND=round3
python scripts/regenerate_round3_dataset.py
python scripts/export_campaign_report.py --round round3 --label gpt5mini
```
