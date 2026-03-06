# Case Diffing

Use cross-case diffing to compare the same host across two investigations. Same-host scope is enforced by default from case metadata.

## Purpose

1. Identify what changed between two case bundles.
2. Detect newly observed login sources, ports, findings, and trust anomalies.
3. Support scene reconstruction without inferring causality beyond evidence.

## Recommended Inputs

1. Base case: older case bundle for the same host.
2. Target case: newer case bundle for the same host.
3. Prefer `evidence.reviewed.auto.json` when present.

## Run Manually

```bash
python scripts/compare_case_bundles.py \
  --base-case reports/<older-case> \
  --target-case reports/<newer-case>
```

Add `--allow-host-mismatch` only when cross-host comparison is intentional or host metadata is incomplete and the analyst explicitly accepts the lower scope confidence.

Default output:

1. `reports/_comparisons/<older-case>__vs__<newer-case>/comparison.json`
2. `reports/_comparisons/<older-case>__vs__<newer-case>/comparison.md`

## What The Diff Compares

1. Findings statements.
2. IP trace entries.
3. Timeline events.
4. Log-integrity states.
5. Authentication source IPs.
6. Listening ports.
7. Command-trust anomalies.
8. Process IOC keyword matches.

## Interpretation Rules

1. `added` means present in target but absent in base.
2. `removed` means present in base but absent in target.
3. Diff output is descriptive only; it does not prove causality.
4. Always go back to evidence IDs in the underlying case before concluding impact.
5. If host metadata does not match or is incomplete, downgrade scope confidence even when the diff is manually forced.
