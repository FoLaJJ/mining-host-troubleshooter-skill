---
name: mining-host-troubleshooter
description: "Use when a Linux host may be compromised, running a miner, hiding persistence, or showing signs of local privilege escalation. Supports read-only evidence collection, distro-aware triage, deleted-log fallback review, detailed evidence correlation, and evidence-bound reporting. Default to read-only investigation only, keep state-changing actions out of scope unless the user explicitly approves them as a separate step, and never fabricate findings or attribution."
---

# Mining Host Troubleshooter

## Operating Contract

Use this skill for Linux host compromise triage, mining-malware review, intrusion reconstruction, persistence review, and read-only local-privilege-escalation exposure assessment.

This skill is an investigation skill, not a remediation skill.

## Hard Rules

1. Default mode is `read_only_evidence_collection`.
2. Read-only commands are allowed by default.
3. State-changing actions are out of scope unless the user explicitly authorizes a separate change step after evidence collection.
4. Never auto-delete files, kill processes, stop services, edit configs, rotate logs, quarantine hosts, reboot systems, install packages, or clean artifacts.
5. If the user asks for kill/stop/delete/restart/remediation, keep the workflow read-only and record those requests as approval-gated follow-up actions instead of executing them.
6. Never fabricate facts, command output, timelines, attacker behavior, or attribution.
7. If evidence is insufficient, say `inconclusive`.
8. Distinguish every key conclusion as `observed_fact`, `inference`, or `attribution`, and include a confidence reason.
9. Keep primary conclusions conservative. Route weaker clues into explicit `inconclusive` investigative leads instead of promoting them into the main case narrative.
10. Treat dual-use admin or remote-control tools such as Sunlogin, ToDesk, AnyDesk, RustDesk, and TeamViewer as neutral observed software presence by default. Do not convert tool presence or runtime alone into compromise.
11. Keep traceable IPs visible in internal reports unless the user asks for redaction.
12. Protect passwords, tokens, private keys, and wallet secrets. Redact them even in internal notes when full value disclosure is not necessary.

## Scope Control

At the start of the run, bind the investigation to the user's requested focus. Supported focus examples include:

1. `intrusion-review`
2. `mining-review`
3. `malware-review`
4. `persistence-review`
5. `privilege-escalation-review`
6. `log-survivability-review`
7. `container-cloud-review`
8. `lateral-movement-review`

If the user asks for one narrow goal such as "only check whether it was breached", "only check mining malware", or "only assess sudo/CopyFail/DirtyFrag exposure", keep that focus visible in the case bundle and report, but still preserve the same read-only contract.

## Required Run Order

1. Confirm scope, host criticality, and whether change operations are forbidden.
2. Establish trust bootstrap for remote access.
3. Detect distro and version first.
   - First host-side collection priority is distro/kernel identity such as `/etc/os-release`, `uname -a`, `uname -r`, package-manager family, and actual privilege level.
4. Collect read-only evidence.
5. If primary logs are missing, pivot immediately to fallback evidence instead of guessing.
6. Reconstruct attacker activity, persistence, runtime behavior, and traceability from evidence only.
7. Run a second-pass self-review before final reporting.
   - Re-check timeline quality, scope closure, distro-aware log layout, overstatement risk, and required external pivots.
8. Export concise but detailed reports.

## Distro and Platform Rules

1. Detect the actual Linux family before interpreting logs or package state.
2. Use distro-aware log expectations:
   - Ubuntu/Debian commonly use `/var/log/auth.log` and `/var/log/syslog`
   - RHEL/CentOS/Rocky/Alma commonly use `/var/log/secure` and `/var/log/messages`
   - systemd environments may rely heavily on `journalctl`
3. If the expected log path is missing, do not treat that alone as compromise. Check whether the host uses a different logging layout first.
4. If the expected log path should exist for that distro and is missing, null-routed, empty, or suspicious, mark log survivability risk and pivot to fallback artifacts.

Use [references/os-compatibility.md](references/os-compatibility.md) when distro-specific command fallbacks are needed.

## Deleted or Missing Log Rules

If logs are missing, deleted, empty, or suspicious:

1. Check `wtmp`, `btmp`, `lastlog`, journald metadata, rsyslog/journald configuration, service metadata, timer metadata, package-manager history, shell traces, and `/proc/*/exe (deleted)`.
2. Record exactly which primary log artifacts are missing or unreliable.
3. Downgrade confidence when fallback evidence is the only remaining source.
4. Never "repair" logging during the investigation phase.

Use [references/log-loss-fallbacks.md](references/log-loss-fallbacks.md) for the fallback matrix.

## Detailed Evidence Correlation Rules

Correlation must be specific. Pay attention to small differences such as:

1. Different parent PID or `ExecStart` path for otherwise similar processes.
2. Same binary name but different executable path, hash, owner, or startup method.
3. New pool, wallet, proxy, algorithm, CPU-thread count, or GPU process mapping.
4. Slightly different authorized key material, sudoers lines, PAM hooks, preload entries, cron schedules, or service unit fragments.
5. Differences between same-host historical cases and current case data.
6. Differences between what the distro normally exposes and what this host now shows.

Do not summarize too early. Preserve the concrete evidence IDs, runtime profile fields, file paths, hashes, and support/counter-evidence links.

## Local Privilege-Escalation Review

This skill may assess local privilege-escalation exposure only in a read-only way.

Allowed:

1. Read kernel version, distro version, package versions, loaded modules, sysctl exposure, sudo version, and sudoers/PAM-related review surfaces.
2. Compare observed Ubuntu package/kernel versions against bundled detector logic for recent issues such as:
   - `CVE-2025-32462`
   - `CVE-2025-32463`
   - `CVE-2026-31431` (`CopyFail`)
   - `CVE-2026-43284`
   - `CVE-2026-43500` (`DirtyFrag` family review in this skill)
3. State that a local privesc path is plausible only when exposure indicators and surrounding evidence support that hypothesis.

Forbidden:

1. Running exploit code
2. Running crashy proof-of-concept checks
3. Changing kernel parameters
4. Installing diagnostic packages without approval

If vulnerable package/kernel status is observed and the case also shows signs of user-level access followed by root-scope effects, it is reasonable to mark `local privilege escalation plausible`, but not `confirmed` without stronger evidence.

## Automation Path

Prefer:

```bash
python scripts/run_readonly_workflow.py ...
```

Natural-language entry is allowed through:

```bash
python scripts/nl_control.py --request "<user request>"
```

The workflow should:

1. Keep the run read-only.
2. Record requested focus in the case bundle.
3. Detect distro, privilege level, and trust state early.
4. Collect detailed evidence, including vulnerability-exposure review surfaces.
5. Enrich evidence into timeline, runtime profiles, hypothesis matrix, file/hash correlation, and privesc plausibility notes.
6. Run a second-pass review to keep scope gaps, timeline gaps, distro-aware log interpretation, and anti-overstatement notes explicit.
7. Export full and leadership reports.

## Reporting Standard

Every final report should include:

1. Requested investigation focus
2. Scope and observation window
3. Distro/kernel/package identity
4. Evidence-backed findings
5. Timeline normalized to UTC when possible
6. Log survivability status
7. IP traceability status
8. Persistence, runtime, and file/hash correlation
9. Local privesc review result if collected
10. Unknowns, gaps, and explicit confidence limits
11. Approval-gated follow-up actions, if the user requested remediation
12. Clear separation between primary conclusions and weaker investigative leads
13. Dual-use remote-tool presence kept separate from unauthorized-use conclusions unless the evidence chain supports escalation
14. Second-pass review status, open gaps, and required external pivots when host-only evidence cannot close the case

## Dangerous Command Gate

Any command that can delete, modify, stop, restart, isolate, or otherwise change host state remains outside normal scope.

If the user later explicitly authorizes a separate change step, explain:

1. exact command
2. why it is needed
3. expected impact
4. evidence that justifies it
5. rollback plan
6. disruption risk

Use [references/risk-command-policy.md](references/risk-command-policy.md) and `scripts/command_guard.py` when needed.

## When To Load References

Load only what is needed:

1. [references/os-compatibility.md](references/os-compatibility.md) for distro and command fallback mapping
2. [references/log-loss-fallbacks.md](references/log-loss-fallbacks.md) for deleted-log fallback review
3. [references/readonly-boundary.md](references/readonly-boundary.md) when the user mixes investigation and remediation intent
4. [references/manual-shell-fallback.md](references/manual-shell-fallback.md) when Python or write access is unavailable
5. [references/restricted-permissions.md](references/restricted-permissions.md) when privilege is limited
6. [references/diagnostic-playbook.md](references/diagnostic-playbook.md) for broader triage flow
7. [references/reporting-and-traceability.md](references/reporting-and-traceability.md) for report discipline
8. [references/usage-scenarios.md](references/usage-scenarios.md) for operator examples
9. [references/deception-and-contradiction-review.md](references/deception-and-contradiction-review.md) for fake-signal and cross-source contradiction handling
10. [references/harness-discipline.md](references/harness-discipline.md) when evidence-linking discipline must stay strict, especially for weaker-model execution or noisy scenes
11. [references/dual-use-remote-tool-review.md](references/dual-use-remote-tool-review.md) when remote-control software such as Sunlogin, ToDesk, AnyDesk, RustDesk, or TeamViewer appears and authorization is unclear
12. [references/second-pass-review.md](references/second-pass-review.md) when the model needs the mandatory second-pass closure and anti-overstatement gate

## Maintainer Rules

1. Keep this skill read-only by default.
2. Keep `SKILL.md`, `README.md`, `README.en.md`, and `agents/openai.yaml` aligned.
3. Keep implementation detail and branch-heavy handling in `references/` and `scripts/`; keep this file short as the operating contract.
4. Preserve placeholder examples; do not bake real host facts into the package.
