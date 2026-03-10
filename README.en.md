# Mining Host Troubleshooter

[中文说明](README.md)

A production-oriented skill for Linux mining-incident triage, scene reconstruction, and evidence-bound reporting.

This repository is designed for operators who need to investigate suspected mining abuse on Linux hosts without turning the investigation itself into a source of business impact.

It is built around a strict operating model:

- read-only first
- minimum disruption
- explicit approval before any change
- evidence before conclusion
- no fabrication
- traceability preserved in internal reports

## Why Install This Skill

Most "mining detection" playbooks stop at spotting a suspicious process. This skill goes further.

It helps an agent or operator answer the questions that actually matter during an incident:

- Is this host really compromised, or is it a legitimate high-compute workload?
- If mining is present, where is it running: process, service, startup item, container, user session, or disguised path?
- What persistence or re-entry surfaces exist?
- Can source IPs, wallets, pools, or infrastructure be traced from the available evidence?
- Are logs intact, missing, tampered, or only partially visible?
- What can be said with confidence, and what must remain inconclusive?

## What It Can Do Today

This skill currently covers the majority of day-to-day Linux mining incident scenarios, especially for CPU mining, GPU mining, mixed rigs, disguised miner services, and suspicious Linux hosts that need controlled read-only triage.

Key capabilities:

- Remote and local investigation workflows.
- Multiple access modes: local shell, SSH private key, agent-loaded key, password auth, jump host, console access.
- SSH trust bootstrap with known-hosts or pinned fingerprint verification.
- Read-only evidence collection with timeout control and checkpoint recording.
- Distro-aware triage for Ubuntu, Debian, Arch, and similar Linux systems.
- Command-trust checks for missing commands, aliases, wrapped binaries, suspicious path drift, and partially trusted tooling.
- Read-only fallback chains when key commands are missing, such as `ss -> netstat -> lsof -> /proc/net` or `ps -> /proc`.
- Deeper host review for processes, services, startup items, shell history, user persistence, systemd, timers, cron, preload, sudoers, PAM, container and cloud indicators.
- Additional surviving-evidence coverage when primary logs are gone, including `wtmp`, `btmp`, `lastlog`, journald/rsyslog configuration, package-manager history, shell trace files, and `/proc/*/exe (deleted)`.
- False-positive control for legitimate high-compute workloads.
- Timeline normalization with host/report timezone separation.
- Confidence-gated conclusions: observed fact, inference, attribution.
- Case-bundle export with artifacts, evidence, metadata, and layered reports.
- Same-host baseline generation and application.
- Cross-case comparison for repeat incidents on the same host.

## Investigation Outcomes

A successful run produces more than a pass/fail answer.

You get a structured case bundle that helps with:

- scene reconstruction
- traceability review
- reporting to management and SOC
- evidence handoff
- later comparison against another incident on the same host

Default output layout:

```text
reports/
`-- <host-or-ip>-<utc-timestamp>/
    |-- artifacts/
    |-- evidence/
    |   |-- evidence.raw.json
    |   `-- evidence.reviewed.auto.json
    |-- report.md
    |-- report.zh-CN.md
    |-- meta/
    |   |-- artifact_hashes.json
    |   |-- case_manifest.json
    |   |-- case_validation.json
    |   |-- scene_reconstruction.json
    |   `-- workflow_checkpoints.json
    `-- reports/
        |-- index.md
        |-- index.zh-CN.md
        |-- management-summary.md
        |-- management-summary.zh-CN.md
        |-- soc-summary.md
        `-- soc-summary.zh-CN.md
```

The full report includes clickable evidence IDs, evidence detail blocks, artifact links, and layered conclusions instead of a flat text dump.

## Output Preview

The snippets below are adapted from a validated case bundle and normalized for public documentation. Real internal runs keep traceability values such as IPs visible unless you intentionally prepare an external-sharing version.

### 1. Bundle index page

```md
# Mining Host Investigation - Bundle Index

## Status Card
- Incident ID: `INC-20260306-xxxxxx`
- Host: `<HOST_IP>` (`<HOST_IP>`)
- Evidence Items: `65` | Findings: `5` | Timeline: `1`
- Auth Source IPs: `1` | Listening Ports: `3`

## Latest Judgments
- `F-AUTO-001` [observed_fact/confirmed/medium] Authentication evidence includes 1 failed password event across 1 source IP.
- `F-AUTO-002` [observed_fact/confirmed/high] Listening socket evidence includes ports: 22, 3307, 53.
- `F-AUTO-003` [inference/confirmed/low] Initial-access and privileged-access review surfaces returned noteworthy lines for analyst review.
```

### 2. Full report excerpt

```md
## Executive Summary
- Evidence Item Count: `65`
- Finding Status: `5` confirmed, `0` inconclusive
- Log-Integrity Risks: `2`
- Finding Type Distribution: observed fact `2`, inference `3`, attribution `0`
- Confidence Distribution: high `1`, medium `1`, low `3`

### ✅ F-AUTO-002
- Statement: Listening socket evidence includes ports: 22, 3307, 53.
- Finding Type: `observed_fact`
- Confidence: `high`
- Status: `confirmed`
- Evidence Chain: [E-008](./report.md#evidence-e-008) / [artifact](artifacts/E-008.txt)
```

### 3. Evidence index excerpt

```md
## Evidence Index
| Evidence ID | Collected At | Command Preview | Artifact |
| --- | --- | --- | --- |
| [E-001](#evidence-e-001) | 2026-03-06T13:05:43+00:00 | date -Is; timedatectl show ... | [E-001.txt](artifacts/E-001.txt) |
| [E-008](#evidence-e-008) | 2026-03-06T13:05:46+00:00 | ss -tulpen | [E-008.txt](artifacts/E-008.txt) |
| [E-012](#evidence-e-012) | 2026-03-06T13:05:47+00:00 | journalctl -u ssh --since ... | [E-012.txt](artifacts/E-012.txt) |
```

A typical deliverable therefore includes:

- a bundle landing page that tells each audience what to read first
- a management summary for quick risk framing
- a SOC summary for triage teams
- a full report for technical review and evidence tracing
- hashed artifacts plus structured evidence JSON for later validation

## What Still Works When Logs Are Gone

If `auth.log`, `secure`, `syslog`, or journal history has been deleted, the workflow does not stop there.

It keeps collecting read-only evidence from:

- `wtmp`, `btmp`, and `lastlog`
- journald / rsyslog / syslog-ng runtime and configuration state
- service, timer, cron, and startup metadata
- shell traces beyond `.bash_history`, such as `.wget-hsts`, `.lesshst`, `.viminfo`, and other history files
- package-manager history logs
- `/proc/*/exe (deleted)` and current runtime state
- socket visibility through `netstat`, `lsof`, or `/proc/net/*` when `ss` is not available

These sources do not replace complete logs, but they often let you bound the timeline, identify likely access paths, and explain why a conclusion must stay inconclusive.

## Investigation Order

This skill follows a stable incident-triage order so results stay defensible:

1. Confirm case scope.
2. Confirm host identity and access path.
3. Verify SSH trust or local execution trust assumptions.
4. Verify privilege scope and command trust.
5. Run low-impact read-only collection.
6. Reconstruct the scene from collected evidence.
7. Normalize time references and preserve uncertainty.
8. Review persistence, startup surfaces, services, containers, cloud signals, and initial-access clues.
9. Validate the case bundle and evidence chain.
10. Export layered reports.
11. Compare against a prior same-host clean baseline or prior case when available.
12. Only then discuss approval-gated response actions.

## Design Principles

This skill is opinionated in a way that matters for business hosts.

- It does not auto-kill, auto-delete, auto-disable, or auto-remediate.
- It allows unrestricted read-only inspection by default.
- It requires explicit approval before any state-changing command.
- It keeps internal IPs and traceability fields visible by default.
- It still protects secrets such as passwords, tokens, and private keys.
- It does not invent attacker attribution when evidence is incomplete.
- It degrades gracefully when logs are missing or privileges are limited.
- It avoids package changes, service restarts, forced rotation, or other state-changing shortcuts during first-pass triage.

## Supported Access Modes

Use the safest access path available:

- local shell on the target host
- SSH with a private key file
- SSH with an agent-loaded key
- SSH with username and password
- SSH through a jump host
- emergency or cloud console access

For remote cases, the recommended order is:

1. reuse an already trusted `known_hosts` entry if possible
2. otherwise pin the host-key fingerprint out of band
3. prefer key-based auth over password auth
4. if password auth is unavoidable, use `--password-env` or `--prompt-password`

## Installation

### Option 1: Install from this repository

Install into the local Agents runtime:

```bash
node scripts/install-skill.mjs install --target agents --force
```

Other supported targets:

```bash
node scripts/install-skill.mjs install --target codex --force
node scripts/install-skill.mjs install --target cc-switch --force
```

Install into a custom skill directory:

```bash
node scripts/install-skill.mjs install --dest /path/to/skills --name mining-host-troubleshooter --force
```

See available default targets:

```bash
node scripts/install-skill.mjs print-targets
```

### Option 2: Install through `npx`

This repository is packaged for npm-style installation. After publishing the package to npm or an internal registry, users can install with:

```bash
npx mining-host-troubleshooter-skill install --target agents
```

At the moment, `npx` installation is only valid after the package has actually been published.

## Quick Start

### Remote host with SSH key

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

### Remote host with password auth

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

### Local host triage

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

## Recommended Usage Sequence

If you want the most useful investigation output, use the skill in this order:

1. Run `scripts/preflight_environment.py` if you need a quick environment check.
2. Run `scripts/run_readonly_workflow.py` for the standard end-to-end read-only workflow.
3. Review `reports/<case>/reports/index.md` or `index.zh-CN.md` first.
4. Read `management-summary` or `soc-summary` depending on audience.
5. Use the full report for evidence-backed conclusions and artifact drill-down.
6. Apply a same-host baseline only after you have known-clean same-host history.
7. Use cross-case diffing if the same host has repeated suspicious activity.

## Typical Use Cases

- A production Linux server suddenly shows high CPU usage and strange outbound traffic.
- A GPU worker reports hash-rate anomalies, rejected shares, or miner crashes, and you need to rule out compromise.
- A host has suspicious services or cron entries that look like normal business components.
- A cloud VM or container host may be abused through metadata credentials or image-level persistence.
- Logs are missing and you need a fallback-driven read-only reconstruction path.
- An incident repeats on the same host and you need a clean-vs-suspicious comparison.

## What Makes The Reports Useful

This skill exports layered reports instead of a single oversized dump.

- `report.md` / `report.zh-CN.md`: core full reports at the case root
- `reports/index.*`: bundle landing pages and reading order
- `reports/management-summary.*`: concise management-facing view
- `reports/soc-summary.*`: triage-focused SOC view

The full report distinguishes:

- observed fact
- inference
- attribution
- confidence and confidence reason
- normalized timeline
- traceable vs untraceable IPs
- log-integrity caveats
- approval-gated action records

## Baseline And Case Comparison

Baseline types should be kept separate:

- same-host clean baseline: used for suppression and drift comparison only on the same host
- role-reference profile: used for human interpretation across similar hosts, but not valid for automatic same-host matching

A similar cloud controller, honeypot node, or sibling business VM may be useful as reference material, but it must not be merged into a clean baseline unless it is literally the same host across time.

Generate a same-host clean baseline:

Note: a baseline is only same-host historical context. If it is built from a single VM snapshot or too few known-clean cases, treat it as weak and never as proof of benign state. Keep enriching it over time with additional known-clean cases from the same host. Similar hosts can still help you build a role-reference profile for analyst review, but they must not auto-clear findings on a different machine.

```bash
python scripts/generate_host_baseline.py \
  --reports-root reports \
  --host-ip <HOST_IP>
```

Apply a baseline during a new run:

```bash
python scripts/run_readonly_workflow.py \
  --remote <REMOTE_USER>@<HOST_IP> \
  --identity <SSH_KEY_PATH> \
  --analyst <ANALYST> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --baseline reports/_baselines/<HOST_IP>-baseline-<timestamp>/baseline.json \
  --strict-report
```

Compare two case bundles:

```bash
python scripts/compare_case_bundles.py \
  --base-case reports/<older-case> \
  --target-case reports/<newer-case>
```

## Safety Boundaries

Read-only inspection is allowed by default.

The following categories always require explicit approval first:

- killing processes
- stopping services
- deleting, truncating, or moving files
- modifying startup items or configs
- rebooting or interrupting business workloads
- anything that may damage evidence or change host state

## Validation Before Publishing Or Reinstalling

```bash
python C:/Users/admin/.codex/skills/.system/skill-creator/scripts/quick_validate.py D:/skills/mining-host-troubleshooter-skill
python scripts/audit_example_placeholders.py --strict
```

## Repository Notes

- `README.md` is the Chinese landing page and `README.en.md` is the English landing page.
- `SKILL.md` is the runtime operating contract.
- `references/` holds detailed playbooks and fallback guidance.
- `scripts/` holds the executable workflow and helper tooling.

If you want a skill that is usable on real Linux business hosts, keeps the investigation read-only by default, exports defensible case bundles, and avoids overclaiming, this one is already built for that job.


