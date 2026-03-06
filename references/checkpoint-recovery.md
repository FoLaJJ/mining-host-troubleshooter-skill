# Checkpoint And Recovery

Use this file for long investigations that may be interrupted.

## Required Markers

Emit these markers in plain text during manual investigations:

1. `[MODE: AUTOMATED_WORKFLOW]` or `[MODE: SHELL_FALLBACK]`
2. `[PRIVILEGE: restricted|user|sudo|root]`
3. `[CHECKPOINT: <stage>]` after each completed phase

Recommended stage names:

1. `scope_confirmed`
2. `privilege_checked`
3. `trust_preflight_complete`
4. `evidence_collection_complete`
5. `scene_reconstruction_complete`
6. `validation_complete`
7. `baseline_assessment_complete`
8. `report_export_complete`

## Resume Rule

If the user interrupts and later asks to continue, resume from the latest explicit checkpoint rather than restarting the whole analysis.

## Automated Workflow Integration

The bundled automated workflow writes checkpoint history into `meta/workflow_checkpoints.json`. Reports exported from a case bundle should include this history for resume-friendly review.
