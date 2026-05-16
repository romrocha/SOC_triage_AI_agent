# Methodology

## Design choices

1. **Synthetic over real data** — Full ground truth, no PII, reproducible generation, safe to share.
2. **TheHive JSON** — Open schema used in production SOCs; preserves L1 triage field shapes.
3. **Time as the only cross-round variable** — Round 1 is canonical; rounds 2–3 rescale `date` linearly from round 1 (`new_date = anchor + (old_date - anchor) × scale`). All other fields are identical across rounds.
4. **Deterministic generation** — Campaign and noise specs are Python dataclass literals in `scripts/regenerate_round1_dataset.py`; no RNG.
5. **Uniform schema** — All 100 alerts share the same top-level fields; no hidden campaign metadata inside alerts.

## Ground truth

`ground_truth.csv` is produced by `scripts/generate_ground_truth.py`:

- Alerts under `noise/` → `false_positive`
- `campaing-a/` → `in_campaign`, `expected_campaign_id=campaing-a`
- `campaing-b/` → `in_campaign`, `expected_campaign_id=campaing-b`

Label assignment is **mechanical from folder path**, not from alert content. `alert_id` equals `sourceRef`.

## Realism levers

- 12 vendor products, MITRE tags on every alert, severity skew (noise lower, campaigns higher).
- Entity coherence within campaigns; partial overlap in noise to simulate false correlation.
- Observable `ioc` flags and TLP/PAP metadata preserved.

## Reproduction

```bash
python scripts/regenerate_round1_dataset.py
python scripts/regenerate_temporal_variants.py
python scripts/generate_ground_truth.py --round round1
python scripts/generate_ground_truth.py --round round2
python scripts/generate_ground_truth.py --round round3
```

Public references used to shape alert content are listed in `README.md` (Sigma, Sentinel, MITRE ATT&CK, DFIR Report, etc.).
