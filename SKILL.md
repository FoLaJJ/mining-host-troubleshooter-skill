---
name: mining-host-troubleshooter
description: "Diagnose suspected Linux mining compromise or miner-like abuse on local or remote hosts. Use for read-only triage, scene reconstruction, persistence review, command-trust verification, same-host baseline comparison, and evidence-bound reporting. Allow unrestricted read-only inspection, require explicit user confirmation before any state-changing action, keep traceability values visible by default for internal work, and never fabricate findings or attribution."
---

# Mining Host Troubleshooter

## Mission

Use this skill when a Linux host may be affected by CPU mining, GPU mining, disguised miner services, persistence abuse, or related compromise.

Primary goals:

1. Preserve scene and minimize impact.
2. Collect read-only evidence first.
3. Reconstruct what happened from evidence only.
4. Trace source IPs and execution paths when the evidence supports it.
5. Normalize time references before drawing timeline conclusions.
6. Export concise, layered, traceable reports.

## Hard Rules

1. Never fabricate facts, timelines, attribution, or command outputs.
2. If evidence is insufficient, say `inconclusive`.
3. Read-only commands are allowed by default.
4. Any state-changing command requires explicit user approval first.
5. Before requesting approval, explain purpose, impact, risk, rollback, and whether the action is `reversible_change`, `irreversible_change`, or `business_interruption`.
6. Never auto-delete files, kill processes, disable services, edit configs, rotate logs, or reboot.
7. Always protect secrets such as passwords, private keys, tokens, and wallet credentials. Never pass secrets on the command line when a safer path exists.
8. Internal reports keep traceability values such as IPs visible by default, but passwords, tokens, and private-key material must still be redacted.

## Example Anchoring Rules

Treat example values in this skill and its bundled references as placeholders unless the user or live evidence says otherwise.

1. Placeholder examples such as `<HOST_IP>`, `<REMOTE_USER>`, `<SSH_KEY_PATH>`, `<CASE_DIR>`, and `<SERVICE_PATH>` are templates only.
2. Do not infer a host IP, username, service name, path, or container name from README or reference examples.
3. Linux evidence paths inside scripts, such as `/var/log/...`, `/etc/systemd/...`, `/proc/...`, are intentional evidence targets, not case-specific conclusions.
4. Every conclusion must come from the current machine, current case bundle, or user-supplied facts.


## LLM Execution Guardrails

1. If the automated Python workflow cannot run, immediately switch to shell fallback and state `[MODE: SHELL_FALLBACK]`.
2. At the beginning of a manual run, state `[PRIVILEGE: restricted|user|sudo|root]` based on the actual session.
3. After each major phase, emit `[CHECKPOINT: <stage>]` so the investigation can resume after interruption.
4. Use explicit low-confidence markers. Preferred forms:
   - `[CONFIRMED: ...]` for evidence-backed conclusions
   - `[INCONCLUSIVE: ...]` when evidence is partial or insufficient
   - `[OCR-UNCERTAIN: ...]` when screenshot or image interpretation is not fully reliable
5. If the host only allows partial visibility, say so directly and narrow the scope instead of guessing.
6. When user-supplied screenshots, logs, or config snippets are used, label them as user-supplied evidence and do not infer hidden content.
7. Separate every conclusion into `observed_fact`, `inference`, or `attribution`, and attach a confidence label plus confidence reason.
8. If high compute is seen without direct miner evidence, keep the result inconclusive unless the declared legitimate workload is verified by runtime evidence.

## Access Modes

Support the safest available access path:

1. Local shell on the target host.
2. SSH with private key file.
3. SSH with agent-loaded key.
4. SSH with username and password.
5. SSH via jump host.
6. Platform console access.

Before connecting remotely, confirm:

1. Host identity.
2. Trusted host-key source: existing `known_hosts` entry or out-of-band fingerprint.
3. Auth method. Prefer SSH key or agent-loaded key; if password auth is unavoidable, use environment-variable input or a secure prompt instead of command-line plaintext.
4. Whether sudo is allowed.
5. Whether the host is business-critical.
6. Whether change operations are forbidden unless explicitly approved.

Use [references/login-methods.md](references/login-methods.md) only when you need concrete connection examples.

## Workflow

Follow this order unless the user gives a narrower scope:

1. Scope the case.
   - Confirm symptom, time window, host role, blast radius, and mining mode: `cpu`, `gpu`, `mixed`, or `unknown`.
2. Preserve scene.
   - Avoid restarts, config edits, cleanup, and log rotation until read-only capture is complete.
3. Trust bootstrap and verify environment trust.
   - Confirm host-key trust first. Reject unknown host keys by default unless an explicit out-of-band fingerprint is provided. Then check distro family, package manager family, actual privilege level, command path trust, alias/function wrapping, and missing-command fallbacks such as `ss -> netstat -> lsof -> /proc/net` or `ps -> /proc`.
4. Collect read-only evidence.
   - Prefer the bundled workflow scripts and case-bundle layout under `./reports/`.
   - If Python or bundled scripts are unavailable, switch to the manual shell-only fallback flow.
5. Check log survivability.
   - Detect missing logs, null-routing, suspicious links, and fallback to `wtmp`, `btmp`, `lastlog`, journald/rsyslog configuration, service/timer metadata, package-manager history, shell traces such as `.wget-hsts` or `.lesshst`, `/proc/*/exe (deleted)`, and other surviving artifacts.
6. Review execution and persistence.
   - Check processes, deleted-on-disk executables, service `ExecStart`, user startup items, shell histories, suspicious drop paths, network listeners, containers, preload hooks, PAM, sudoers, keys, modules, and eBPF where visible.
7. Review initial access and cloud/container paths.
   - Check weak-credential evidence, SSH key surfaces, metadata-service traces, Docker, Kubernetes, cloud-init, CI/CD clues, and supply-chain indicators when visible.
8. Reconstruct the scene.
   - Build findings, normalized timeline, and IP traceability only from evidence.
9. Compare against history when available.
   - Use same-host case diffing and same-host clean baselines to suppress repeated normal patterns.
10. Export the report.
   - Keep it concise, evidence-bound, and explicit about gaps.

## Preferred Automation Path

For most investigations, prefer the bundled workflow and state `[MODE: AUTOMATED_WORKFLOW]`:

```bash
python scripts/run_readonly_workflow.py ...
```

Behavior:

1. Performs trust bootstrap for remote collection using `known_hosts` or a pinned fingerprint.
2. Writes the case bundle under the current working directory in `./reports/<case>/` by default.
3. Performs low-impact read-only collection with per-probe timeouts.
4. Enriches evidence and reconstructs scene.
5. Validates the case bundle.
6. Optionally applies a same-host clean baseline when `--baseline <BASELINE_JSON>` is provided.
7. Exports `report.md`, `report.zh-CN.md`, `reports/index.md`, `reports/index.zh-CN.md`, `reports/management-summary.md`, `reports/management-summary.zh-CN.md`, `reports/soc-summary.md`, and `reports/soc-summary.zh-CN.md`. The index pages act as case-bundle landing pages with status cards, key-risk summaries, reading order, report inventories, and directory status, and full reports use source-grouped evidence navigation, fixed section anchors, and clickable evidence IDs that jump to detail blocks and link to artifact files.

If the user wants staged control, use these scripts separately:

1. `scripts/collect_live_evidence.py`
2. `scripts/enrich_case_evidence.py`
3. `scripts/validate_case_bundle.py`
4. `scripts/apply_host_baseline.py`
5. `scripts/export_investigation_report.py`
6. `scripts/compare_case_bundles.py`
7. `scripts/refresh_case_bundle.py`

## Same-Host Baseline Rules

Use baselines only as suppression and comparison aids.

1. Build baselines from repeated known-clean cases of the same host.
2. Apply baselines only when same-host scope is supported by host IP, host name, or deliberate analyst choice.
3. A baseline match does not prove the host is clean.
4. A weak or single-case baseline must never be used as the sole reason to clear a host, suppress an incident, or whitelist future behavior.
5. Similar hosts in the same business role, such as another honeypot node or another cloud VM, may be used only as role-reference context and must not be treated as a same-host clean baseline.
6. Keep enriching same-host baselines over time with additional known-clean cases; baseline quality is mutable and should improve with evidence depth.
7. New values, new execution paths, new source IPs, trust anomalies, or persistence drift must still be reviewed.

Use:

1. `scripts/generate_host_baseline.py`
2. `scripts/apply_host_baseline.py`

## Dangerous Command Gate

Ask before any command that can:

1. Delete, overwrite, truncate, or move files.
2. Kill processes or stop services.
3. Edit unit files, crontabs, shell profiles, startup items, firewall rules, routes, or user accounts.
4. Install, remove, or upgrade packages.
5. Flush logs, alter audit state, or modify evidence.
6. Reboot or otherwise disrupt service.

If a user approves such a command, state:

1. Why it is needed.
2. What may break.
3. What evidence may be lost.
4. How to roll back, if rollback exists.

Use [references/risk-command-policy.md](references/risk-command-policy.md) and `scripts/command_guard.py` when needed.

## Evidence Integrity Requirements

1. Preserve or generate artifact hashes whenever the workflow can write a case bundle.
2. If hashes or validation output are unavailable, say so explicitly instead of implying a complete evidence chain.
3. When citing a critical artifact, prefer including its evidence ID and, when available, its artifact path or hash context from the case bundle.
4. Treat user-pasted snippets and screenshots as separate from live shell artifacts.

## Reporting Standard

Every final output should include:

1. Scope and observation window.
2. Evidence-backed findings.
3. Timeline with normalized UTC when available.
4. IP traceability status.
5. Log survivability status.
6. Unknowns and evidence gaps.
7. Approval-gated actions, if any.
8. Clear statement of confirmed vs inconclusive items.
9. Claim type (`observed_fact` / `inference` / `attribution`) and confidence reason for each key conclusion.
10. False-positive control note when high compute might be legitimate.

When exporting files, use the case-bundle layout under `reports/<case>/` and prefer the bundled report exporter.

## When To Load References

Load only what is needed:

1. `references/diagnostic-playbook.md` for detailed incident-triage flow.
2. `references/os-compatibility.md` for distro differences.
3. `references/command-trust-verification.md` for command trust issues.
4. `references/log-loss-fallbacks.md` for deleted or damaged log scenarios.
5. `references/manual-shell-fallback.md` when Python or scripts are unavailable.
6. `references/restricted-permissions.md` when privilege is limited.
7. `references/multimodal-evidence.md` for screenshots, pasted logs, and config fragments.
8. `references/checkpoint-recovery.md` for stage markers and resume behavior.
9. `references/enterprise-self-audit.md` for enterprise-style self-check flow.
10. `references/case-diffing.md` for repeat-case comparison.
11. `references/reporting-and-traceability.md` for report discipline.
12. `references/usage-scenarios.md` for operator examples.
13. `references/legitimate-high-compute-review.md` for false-positive control.
14. `references/external-evidence-interfaces.md` for cloud, K8s, and boundary telemetry pivots.

## Skill Maintenance

If updating this skill itself:

1. Use the `skill-creator` workflow.
2. Keep `SKILL.md`, both README files, and `agents/openai.yaml` aligned.
3. Keep examples placeholder-based; do not bake in real host facts.
4. Keep `reports/` empty except for the placeholder file when packaging.
5. Re-run validation before publishing or reinstalling.
6. Run `python scripts/audit_example_placeholders.py --strict` to catch accidental example anchoring or machine-specific values.
7. Keep `SKILL.md` compact; move detail into `references/` when the core operating contract is already clear.
