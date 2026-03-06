# Live Evidence Collection

Use this workflow to build a case bundle under `reports/<target>-<utc-time>/` with read-only commands.

## Safety

1. The collector executes read-only probes only.
2. It does not restart services, edit configs, or delete files.
3. For remote mode, it uses SSH and records exact commands in artifacts.

## One-Command Workflow (Recommended)

```bash
python scripts/run_readonly_workflow.py \
  --remote <target_user>@<target_host> \
  --identity <private-key-path> \
  --analyst <team> \
  --host-name <host-name> \
  --host-ip <host-ip> \
  --os-hint "<os-version>" \
  --mining-mode auto \
  --strict-report
```

This runs read-only collection, scene reconstruction, case validation, and report export in sequence.
It writes `evidence/evidence.reviewed.auto.json`, `meta/enrichment.local.json`, and `meta/case_validation.json`.

## Local Linux Collection

```bash
python scripts/collect_live_evidence.py \
  --analyst sec-team \
  --host-name <host-name> \
  --host-ip <host-ip> \
  --os-hint "<os-version>" \
  --mining-mode gpu
```

## Remote Collection (SSH Key)

```bash
python scripts/collect_live_evidence.py \
  --remote <target_user>@<target_host> \
  --identity <private-key-path> \
  --analyst sec-team \
  --host-name <host-name> \
  --host-ip <host-ip> \
  --os-hint "<os-version>" \
  --mining-mode gpu
```

## Remote Collection (Jump Host)

```bash
python scripts/collect_live_evidence.py \
  --remote <target_user>@<target_host> \
  --jump <jump_user>@<jump_host> \
  --identity <private-key-path> \
  --case-tag <host-ip>-incident-a
```

## Dry Run

```bash
python scripts/collect_live_evidence.py --remote <target_user>@<target_host> --dry-run
```

## Output

1. `reports/<target>-<utc-time>/evidence/evidence.raw.json`
2. `reports/<target>-<utc-time>/artifacts/E-xxx.txt`
3. `reports/<target>-<utc-time>/meta/case_manifest.json`
4. `reports/<target>-<utc-time>/meta/artifact_hashes.json`
5. `reports/<target>-<utc-time>/meta/case_validation.json`
6. `reports/<target>-<utc-time>/meta/enrichment.local.json`
7. `reports/<target>-<utc-time>/reports/` for final markdown report

Then enrich + validate explicitly (recommended before manual export):

```bash
python scripts/enrich_case_evidence.py --input reports/<case>/evidence/evidence.raw.json --output reports/<case>/evidence/evidence.reviewed.auto.json
python scripts/validate_case_bundle.py --case-dir reports/<case> --input reports/<case>/evidence/evidence.reviewed.auto.json --strict
```

Then export final report:

```bash
python scripts/export_investigation_report.py --input reports/<case>/evidence/evidence.reviewed.auto.json --case-dir reports/<case> --redact --strict
```
