# Limitations

This dataset supports **comparative methodology research**, not **production performance prediction**.

## 1. Inverted base rate

~70% false positives here vs ~99% in many real SOCs. Accuracy and F1 on this set are an **upper bound**, not a typical operating point.

## 2. Author-designed signal and noise

Campaigns and noise share the same author. Campaigns include deliberate entity coherence; noise is plausible but not adversarially deceptive.

## 3. Limited scale

100 alerts per round; each missed threat moves binary metrics by ~1 percentage point. Use bootstrap or larger sets for strong significance claims.

## 4. Single platform schema

TheHive JSON only. Does not test normalization across Splunk, Sentinel, Elastic, Chronicle, etc.

## 5. Binary ground truth

Labels are `in_campaign` vs `false_positive` only. Real triage includes benign positives, rule vs data FPs, and uncertainty buckets.

## 6. Temporal-only variation between rounds

Rounds differ only in span (30 / 90 / 180 days). No concept drift, new vendors, or evolving TTPs.

## Appropriate uses

- Compare agents on the same open, deterministic corpus.
- Ablate temporal dispersion (round1 vs round2 vs round3).
- Critique methodology and metrics (e.g. CWTS with cost-sensitive `k`).

## Inappropriate uses

- Quoting absolute detection rates as production expectations.
- Claiming adversarial robustness without additional red-team data.
