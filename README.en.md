# Mining Host Troubleshooter

[中文说明](README.md)

A read-only Linux mining-incident troubleshooting skill focused on scene reconstruction and traceable reporting.

This repository is a **skill package**, not a manual CLI playbook. In normal usage, the model invokes the skill and the skill orchestrates scripts internally.

## Positioning

- Minimum disruption: read-only first.
- Evidence first: collect before concluding.
- Confidence-gated output: observed fact / inference / attribution.
- Approval-gated changes: no state change without explicit approval.

## Typical Use Cases

- Suspicious CPU/GPU load with possible mining activity.
- Suspected disguised miner process/service/startup path.
- Business host triage requiring low-impact and high traceability.
- Missing/deleted logs where fallback evidence is required.

## How To Use (Skill Invocation)

Call the skill in natural language. No need to run workflow scripts manually:

- `$mining-host-troubleshooter Investigate <HOST_IP>, account <REMOTE_USER>, password <PASSWORD>, focus on GPU mining`
- `$mining-host-troubleshooter Run local read-only triage and export Chinese + English reports`
- `$mining-host-troubleshooter Compare this case against previous cases and rate confidence`

You can add control constraints directly in plain language:

- "Read-only only. No changes."
- "If any kill/stop/delete is needed, explain impact/rollback first and wait for approval."
- "Keep traceable IPs visible in internal reports."

## Internal Investigation Flow

1. **Trust Bootstrap**: verify target identity and SSH trust chain.
2. **Readonly Sweep**: low-impact collection with timeout and fallback paths.
3. **Deep Correlation**: correlate process/network/persistence/container/cloud/GPU evidence.
4. **Confidence-Gated Conclusion**: output confirmed vs inconclusive without fabrication.
5. **Approval-Gated Response**: provide response plan only; no automatic mutation.

## Output Layout

By default, case bundles are created under the current working directory:

```text
reports/
`-- <host-or-ip>-<utc-timestamp>/
    |-- artifacts/
    |-- evidence/
    |-- meta/
    |-- report.md
    |-- report.zh-CN.md
    `-- reports/
        |-- index.md
        |-- index.zh-CN.md
        |-- management-summary.md
        |-- management-summary.zh-CN.md
        |-- soc-summary.md
        |-- soc-summary.zh-CN.md
        |-- operator-brief.md
        |-- operator-brief.zh-CN.md
        `-- operator-brief.json
```

Recommended reading order:

1. `reports/index.md`
2. `reports/management-summary.md` or `reports/soc-summary.md`
3. `report.md`

## Project Structure And File Responsibilities

```text
.
|-- SKILL.md
|-- README.md
|-- README.en.md
|-- package.json
|-- agents/
|   `-- openai.yaml
|-- references/
|   |-- diagnostic-playbook.md
|   |-- command-trust-verification.md
|   |-- log-loss-fallbacks.md
|   |-- os-compatibility.md
|   `-- skill-maintenance.md
|-- scripts/
|   |-- run_readonly_workflow.py
|   |-- collect_live_evidence.py
|   |-- enrich_case_evidence.py
|   |-- export_investigation_report.py
|   |-- nl_control.py
|   |-- generate_operator_brief.py
|   |-- compare_case_bundles.py
|   |-- generate_host_baseline.py
|   |-- apply_host_baseline.py
|   |-- validate_case_bundle.py
|   |-- command_guard.py
|   `-- install-skill.mjs
`-- reports/
    `-- .gitkeep
```

Key files:

- `SKILL.md`: runtime contract and hard safety rules.
- `agents/openai.yaml`: skill metadata and runtime binding.
- `scripts/run_readonly_workflow.py`: orchestrates end-to-end workflow.
- `scripts/collect_live_evidence.py`: read-only collection engine with fallback probes.
- `scripts/enrich_case_evidence.py`: evidence correlation and timeline reconstruction.
- `scripts/export_investigation_report.py`: layered EN/ZH report export.
- `scripts/nl_control.py`: natural-language request parser.
- `scripts/generate_operator_brief.py`: novice-friendly operator summary.
- `scripts/command_guard.py`: dangerous-command gating.
- `references/`: playbooks, compatibility notes, fallback rules, maintenance guide.

## Installation

Install into Agents:

```bash
node scripts/install-skill.mjs install --target agents --force
```

Other targets:

```bash
node scripts/install-skill.mjs install --target codex --force
node scripts/install-skill.mjs install --target cc-switch --force
```

Custom path:

```bash
node scripts/install-skill.mjs install --dest /path/to/skills --name mining-host-troubleshooter --force
```

Show target paths:

```bash
node scripts/install-skill.mjs print-targets
```

After publishing to npm/private registry:

```bash
npx mining-host-troubleshooter-skill install --target agents
```

## Safety Boundary

These actions must always be explicitly approved first:

- kill process
- stop service
- delete/move files
- modify startup/config
- reboot or interrupt business workloads

## Maintainer Notes

Release/validation details are documented in `references/skill-maintenance.md`.
