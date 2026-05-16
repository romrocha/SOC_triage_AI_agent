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
