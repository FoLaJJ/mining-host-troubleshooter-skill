# Mining Host Troubleshooter

[中文说明](README.md)

A practical skill for read-only Linux mining-incident triage and evidence-based reconstruction.

This skill is built for production environments where you need useful conclusions without disrupting running business workloads.

## What This Skill Does

- Investigates local or remote Linux hosts.
- Supports CPU, GPU, and mixed mining scenarios.
- Covers process/network/service/startup/persistence/container/cloud signals.
- Handles distro differences and degrades to fallback commands when tools are missing.
- Continues investigation when primary logs are deleted by using surviving evidence.
- Exports a structured case bundle with layered reports and traceable artifacts.
- Builds a hypothesis-to-evidence matrix with confidence levels.
- Produces operator briefs for non-security readers.

## What This Skill Does Not Do

- No automatic kill/stop/delete/modify actions.
- No over-claiming when evidence is incomplete.
- No direct "high CPU/GPU = compromise" assumption.

## Installation

### Install from this repository

```bash
node scripts/install-skill.mjs install --target agents --force
```

Other targets:

```bash
node scripts/install-skill.mjs install --target codex --force
node scripts/install-skill.mjs install --target cc-switch --force
```

Custom destination:

```bash
node scripts/install-skill.mjs install --dest /path/to/skills --name mining-host-troubleshooter --force
```

Print default targets:

```bash
node scripts/install-skill.mjs print-targets
```

### Install via npx

After publishing to npm (or a private registry):

```bash
npx mining-host-troubleshooter-skill install --target agents
```

## Quick Start

All `<...>` values are placeholders.

### 1) Remote host with SSH key

```bash
python scripts/run_readonly_workflow.py \
  --remote <REMOTE_USER>@<HOST_IP> \
  --host-key-fingerprint "<SHA256_HOST_KEY_FINGERPRINT>" \
  --identity <SSH_KEY_PATH> \
  --analyst <ANALYST> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --expected-workload "<EXPECTED_HIGH_COMPUTE_WORKLOAD_OR_EMPTY>" \
  --strict-report
```

### 2) Remote host with password auth

```bash
python scripts/run_readonly_workflow.py \
  --remote <REMOTE_USER>@<HOST_IP> \
  --host-key-fingerprint "<SHA256_HOST_KEY_FINGERPRINT>" \
  --password-env <SSH_PASSWORD_ENV> \
  --analyst <ANALYST> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --expected-workload "<EXPECTED_HIGH_COMPUTE_WORKLOAD_OR_EMPTY>" \
  --strict-report
```

### 3) Remote quick-connect (IP + username + password)

```bash
export SSH_PASSWORD='<PASSWORD>'
python scripts/run_readonly_workflow.py \
  --remote-user <REMOTE_USER> \
  --remote-ip <HOST_IP> \
  --port <SSH_PORT> \
  --password-env SSH_PASSWORD \
  --trust-on-first-use \
  --analyst <ANALYST> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --strict-report
```

Note: `--trust-on-first-use` is for first-seen internal urgent triage. Prefer pinned fingerprint verification for high-risk targets.

### 4) Natural-language control

```bash
python scripts/nl_control.py \
  --request "Investigate <HOST_IP>, username <REMOTE_USER>, password <PASSWORD>, port <SSH_PORT>, focus on gpu mining" \
  --analyst <ANALYST>
```

### 5) Local host

```bash
python scripts/run_readonly_workflow.py \
  --analyst <ANALYST> \
  --host-name <HOST_NAME> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --expected-workload "<EXPECTED_HIGH_COMPUTE_WORKLOAD_OR_EMPTY>" \
  --strict-report
```

## Output Layout

By default, outputs are written to `reports/` under your current working directory:

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

## Investigation Order

1. Confirm host identity and access boundary.
2. Verify SSH trust assumptions.
3. Run low-impact read-only collection.
4. Correlate process/network/persistence/container/cloud evidence.
5. Normalize timeline and preserve uncertainty.
6. Export layered reports.
7. Discuss response actions only after explicit approval.

## When Logs Are Deleted

The workflow can still use read-only surviving evidence:

- `wtmp`, `btmp`, `lastlog`
- system logger/runtime config state
- service/timer/cron/startup metadata
- shell/tool traces
- `/proc/*/exe (deleted)` and runtime socket/process views

## Baseline And Cross-Case Comparison

- Same-host baseline is for same-host history only.
- A small baseline is weak context, not proof of benign state.

Generate same-host baseline:

```bash
python scripts/generate_host_baseline.py \
  --reports-root reports \
  --host-ip <HOST_IP>
```

Compare case bundles:

```bash
python scripts/compare_case_bundles.py \
  --base-case reports/<older-case> \
  --target-case reports/<newer-case>
```

## Safety Boundaries

These actions must always be explicitly approved first:

- kill process
- stop service
- delete/move files
- modify startup/config
- reboot or interrupt production workload

## Project Map

- `SKILL.md`: runtime operating contract
- `references/`: playbooks and fallback guidance
- `scripts/`: executable workflow and helper tools
- `references/skill-maintenance.md`: maintainer release/validation process
