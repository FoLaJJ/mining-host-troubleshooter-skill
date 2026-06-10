# Generate Reports From Bundle Design

## Context

The skill already supports the normal read-only workflow:

`collect -> enrich -> review -> validate -> export`

It also supports degraded failure-bundle reporting when collection fails.

What is missing is an explicit operator-facing way to regenerate reports from an existing case bundle when:

- evidence collection already completed earlier
- reporting/export was interrupted
- only part of the report set exists
- the operator wants to reuse existing evidence without recollecting

This must not weaken the normal workflow. Weak models must not see a partial `artifacts/` or `evidence/` directory and incorrectly assume collection is complete.

## Goals

- Add a direct script for: "generate reports from the current case bundle evidence".
- Keep report regeneration strictly separate from evidence collection.
- Reuse the existing evidence processing and export chain instead of creating a parallel report stack.
- Allow regeneration from:
  - reviewed evidence
  - auto-reviewed evidence
  - raw evidence
  - collection failure bundles
- Rebuild the full required report set, not just one missing file.
- Keep the current leadership-report format unchanged.

## Non-Goals

- No automatic detection inside the normal collection workflow.
- No implicit mode switching based on directory contents.
- No recollection, remote access, SSH login, or host probing.
- No remediation or state-changing actions.
- No partial "best effort" export contract. Regeneration should still verify the expected report outputs.

## Chosen Approach

Add a new explicit script:

`scripts/generate_reports_from_bundle.py`

This script is the only supported regeneration entrypoint. It takes an existing case bundle and rebuilds the report set from the evidence already present in that bundle.

This is preferred over extending `run_readonly_workflow.py` or overloading `refresh_case_bundle.py` because the operator intent is different:

- `run_readonly_workflow.py` means "perform investigation collection"
- `generate_reports_from_bundle.py` means "do not collect again; use what already exists"

The semantic separation is the main safety property.

## Operator Contract

The regeneration path is opt-in only.

It is allowed only when the operator explicitly asks for one of these intents:

- generate reports from existing evidence
- regenerate reports from the current case bundle
- do not recollect; export from existing artifacts/evidence/meta
- resume report generation from an interrupted bundle

It is not allowed for generic intents such as:

- investigate this host
- check whether it was breached
- collect evidence
- log in and inspect
- check mining / malware / persistence / privilege escalation

Even if the current directory already contains a partial case bundle, generic investigation requests must still stay on the normal collection path.

## CLI Design

Primary usage:

```bash
python scripts/generate_reports_from_bundle.py --case-dir .
```

CLI rules:

- `--case-dir` defaults to the current working directory.
- The script requires an existing case bundle with an `evidence/` directory.
- The script rejects collection-oriented options such as remote host, SSH, password, identity, or host IP parameters.
- The script does not accept any argument that could be mistaken for collection mode.

Optional flags:

- `--case-dir <path>`: explicit existing case bundle path
- `--input <path>`: optional override for a specific evidence JSON inside the bundle
- `--strict`: pass strict validation/export behavior through the existing validation/export steps
- `--redact`: export redacted report variants using the existing report behavior

## Evidence Selection Order

When `--input` is not provided, the script chooses the best available evidence file in this order:

1. `evidence/evidence.reviewed.json`
2. `evidence/evidence.reviewed.auto.json`
3. `evidence/evidence.raw.json`
4. `evidence/evidence.collection.failed.json`

If none of the above exists, the script fails clearly and does not guess.

## Processing Flow

### Case A: Reviewed Evidence Exists

Use the reviewed evidence directly and run:

`validate -> operator-brief -> external-evidence-checklist -> export -> verify outputs`

No enrichment or second-pass review rerun is needed because the reviewed artifact is already the best available report source.

### Case B: Only Auto-Reviewed Evidence Exists

Treat it the same as reviewed evidence:

`validate -> operator-brief -> external-evidence-checklist -> export -> verify outputs`

### Case C: Only Raw Evidence Exists

Build the missing derived evidence first:

`enrich -> review -> validate -> operator-brief -> external-evidence-checklist -> export -> verify outputs`

This uses only the raw evidence already stored in the case bundle. It must not recollect from the host.

### Case D: Only Failure Bundle Exists

Use the failure bundle directly and run:

`operator-brief -> external-evidence-checklist -> export -> verify outputs`

Validation is skipped in this one case because the current validator is designed around host-side evidence completeness, while a failure bundle exists specifically to preserve a degraded no-evidence state. The script should record the skipped validation reason in metadata/checkpoints.

The resulting reports must clearly state:

- host-side collection did not complete
- no host-side investigative conclusion can be asserted
- the output is a degraded report set preserving the failed collection context

## Output Contract

The script always rebuilds the full fixed report set instead of patching one file in place.

Required outputs remain:

- `report.md`
- `report.zh-CN.md`
- `leadership-report.md`
- `leadership-report.zh-CN.md`
- `meta/report-manifest.json`
- `reports/index.md`
- `reports/index.zh-CN.md`
- `reports/management-summary.md`
- `reports/management-summary.zh-CN.md`
- `reports/soc-summary.md`
- `reports/soc-summary.zh-CN.md`
- `reports/operator-brief.md`
- `reports/operator-brief.zh-CN.md`
- `reports/operator-brief.json`
- `reports/external-evidence-checklist.md`

`meta/report-manifest.json` is rewritten each regeneration run so the bundle reflects the current required output contract.

## Metadata And Checkpoints

The script should write workflow checkpoints under `meta/workflow_checkpoints.json` so later reviewers can distinguish:

- normal collection workflow output
- report regeneration from existing bundle
- degraded failure-bundle regeneration

Suggested regeneration checkpoints:

- `report_regeneration_started`
- `report_regeneration_enrichment_complete`
- `report_regeneration_second_pass_complete`
- `report_regeneration_validation_complete`
- `report_regeneration_export_complete`
- `report_regeneration_output_contract_verified`
- `report_regeneration_completed`

For failure bundles, the status should be explicit about degraded mode.

## NL Controller Gate

`scripts/nl_control.py` must add an explicit routing gate.

It should invoke `generate_reports_from_bundle.py` only when the natural-language request contains strong regeneration intent such as:

- "根据现有证据生成报告"
- "补生成报告"
- "不要重新采集，直接出报告"
- "根据现有 case bundle 生成报告"
- "generate reports from existing evidence"
- "resume report generation from this case bundle"

For normal investigation wording, it must keep routing to `run_readonly_workflow.py` even if a bundle already exists in the current directory.

This duplicate gate exists on purpose:

- first gate: intent routing in `nl_control.py`
- second gate: collection arguments rejected by `generate_reports_from_bundle.py`

## Error Handling

- Missing `evidence/`: fail clearly
- No recognized evidence JSON: fail clearly
- Missing `meta/`: recreate only the metadata directory as needed
- Missing `artifacts/`: continue if evidence JSON already supports reporting, but let validation/reporting surface any resulting gaps
- Export failure: fail the script after preserving any already-written metadata/checkpoints
- Missing required outputs after export: fail via the existing output-contract verification logic

## Testing Strategy

TDD-first changes will add tests for:

1. reviewed evidence bundle regenerates the full report set without calling collection
2. raw-only bundle runs enrich/review before export
3. failure bundle still generates degraded reports
4. `nl_control.py` routes explicit regeneration requests to the new script
5. `nl_control.py` does not route generic investigation requests to the new script even when evidence-like wording appears
6. regeneration preserves the existing leadership-report structure and Markdown behavior
7. regeneration rejects collection-style arguments

## Risks And Mitigations

### Risk: Weak model silently skips collection

Mitigation:

- separate script
- explicit NL keyword gate
- no implicit auto-detection in the normal workflow

### Risk: Split logic diverges from the normal export path

Mitigation:

- reuse existing enrich/review/validate/export scripts
- reuse existing output verification

### Risk: Existing partial outputs mask a broken regeneration

Mitigation:

- always regenerate the full required output set
- always verify the expected outputs after export
- rewrite the manifest each run

## Implementation Notes

Implementation should favor helper reuse from:

- `scripts/run_readonly_workflow.py`
- `scripts/refresh_case_bundle.py`

But the new script should remain operator-facing and semantically narrow:

- input: existing case bundle
- action: generate reports only
- boundary: no collection
