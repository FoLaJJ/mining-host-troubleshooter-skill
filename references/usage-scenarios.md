# Usage Scenarios

Operator-facing entry examples kept outside the README front page.

All host identifiers, usernames, key paths, and case paths below are placeholders and must be replaced with live case values.

## Scenario 1: Remote Read-Only Triage

```bash
python scripts/run_readonly_workflow.py   --remote <REMOTE_USER>@<HOST_IP>   --host-key-fingerprint "<SHA256_HOST_KEY_FINGERPRINT>"   --identity <SSH_KEY_PATH>   --analyst <ANALYST>   --host-ip <HOST_IP>   --os-hint "<OS_HINT>"   --mining-mode auto   --profile enterprise-self-audit   --strict-report
```

## Scenario 2: Remote Triage With Password Authentication

```bash
python scripts/run_readonly_workflow.py   --remote <REMOTE_USER>@<HOST_IP>   --host-key-fingerprint "<SHA256_HOST_KEY_FINGERPRINT>"   --password-env <SSH_PASSWORD_ENV>   --analyst <ANALYST>   --host-ip <HOST_IP>   --os-hint "<OS_HINT>"   --mining-mode auto   --profile enterprise-self-audit   --strict-report
```

## Scenario 3: Local Host Investigation

```bash
python scripts/run_readonly_workflow.py   --analyst <ANALYST>   --host-name <HOST_NAME>   --host-ip <HOST_IP>   --os-hint "<OS_HINT>"   --mining-mode cpu   --profile enterprise-self-audit   --strict-report
```

## Scenario 4: Build a Same-Host Clean Baseline

```bash
python scripts/generate_host_baseline.py   --reports-root reports   --host-ip <HOST_IP>
```

## Scenario 5: Apply a Baseline During a New Run

```bash
python scripts/run_readonly_workflow.py   --remote <REMOTE_USER>@<HOST_IP>   --identity <SSH_KEY_PATH>   --analyst <ANALYST>   --host-ip <HOST_IP>   --os-hint "<OS_HINT>"   --mining-mode auto   --profile enterprise-self-audit   --baseline reports/_baselines/<HOST_IP>-baseline-<timestamp>/baseline.json   --strict-report
```

## Scenario 6: Same-Host Repeat Incident Comparison

```bash
python scripts/compare_case_bundles.py   --base-case reports/<older-case>   --target-case reports/<newer-case>
```

Add `--allow-host-mismatch` only when cross-host comparison is deliberate or host metadata is incomplete.

## Scenario 7: Staged Manual Workflow

```bash
python scripts/collect_live_evidence.py   --remote <REMOTE_USER>@<HOST_IP>   --host-key-fingerprint "<SHA256_HOST_KEY_FINGERPRINT>"   --identity <SSH_KEY_PATH>   --analyst <ANALYST>   --host-name <HOST_NAME>   --host-ip <HOST_IP>   --os-hint "<OS_HINT>"   --mining-mode auto

python scripts/enrich_case_evidence.py   --input reports/<case>/evidence/evidence.raw.json   --output reports/<case>/evidence/evidence.reviewed.auto.json

python scripts/validate_case_bundle.py   --case-dir reports/<case>   --input reports/<case>/evidence/evidence.reviewed.auto.json   --strict

python scripts/apply_host_baseline.py   --case-dir reports/<case>   --baseline reports/_baselines/<host>-baseline-<timestamp>/baseline.json

python scripts/export_investigation_report.py   --input reports/<case>/evidence/evidence.reviewed.auto.json   --case-dir reports/<case>   --strict
```

## Scenario 8: Refresh After Manual Review

```bash
python scripts/refresh_case_bundle.py   --case-dir reports/<case>   --input reports/<case>/evidence/evidence.reviewed.json   --strict
```

## Scenario 9: External Sharing Copy

```bash
python scripts/export_investigation_report.py   --input reports/<case>/evidence/evidence.reviewed.auto.json   --case-dir reports/<case>   --redact   --strict
```

## Scenario 10: Manual Resume-Friendly Investigation

Use explicit markers during long manual work:

```text
[MODE: SHELL_FALLBACK]
[PRIVILEGE: user]
[CHECKPOINT: scope_confirmed]
[CHECKPOINT: trust_preflight_complete]
[CHECKPOINT: evidence_collection_complete]
```
