# Diagnostic Playbook

Incident-triage-first playbook for Linux compromise review, mining-malware review, and scene reconstruction.

This document is for scene reconstruction, truth recovery from evidence, and traceability.

It is not the default playbook for hashrate tuning, pool optimization, or generic mining performance work.
It is not a remediation playbook.

## Stage 1) Trust Bootstrap

Before any remote evidence collection:

1. confirm target host identity
2. confirm a trusted host-key source
3. reject unknown host keys by default
4. record whether trust came from `known_hosts` or an explicit fingerprint

## Stage 2) Low-Impact Read-Only Sweep

Collect only read-only evidence first, with strict timeouts.

```bash
python scripts/preflight_environment.py
python scripts/check_log_integrity.py
python scripts/run_readonly_workflow.py ... --strict-report
```

Focus on:

1. distro, kernel, package-manager family, and actual privilege level
2. command-path trust
3. current processes and sockets
4. auth evidence
5. persistence surfaces
6. container and cloud surfaces
7. local-privesc exposure surfaces when the case scope requires it

## Stage 3) Log Survivability and Fallbacks

If logs are missing or suspicious, continue with fallback sources from
[log-loss-fallbacks.md](log-loss-fallbacks.md).

Downgrade confidence if:

1. primary auth logs are missing
2. journal storage is absent or truncated
3. shell history or login databases are destroyed
4. distro-expected log paths are absent and no strong substitute exists

## Stage 4) Deep Evidence and Hypothesis Matrix

Build hypotheses from evidence, not from intuition.

Each key conclusion should carry:

1. `claim_type`: `observed_fact`, `inference`, or `attribution`
2. `confidence`: `high`, `medium`, or `low`
3. `confidence_reason`
4. linked `evidence_ids`
5. known gaps or counter-evidence

Required review surfaces:

1. processes, deleted-on-disk executables, command lines, and parent chains
2. systemd units, cron, rc.local, preload hooks, PAM, sudoers, keys
3. `/tmp`, `/var/tmp`, `/dev/shm`, cache and user startup paths
4. Docker, K8s, cloud-init, metadata-service traces
5. weak-credential and SSH-key access paths
6. sudo version, kernel/package exposure, userns/sysctl/module state, and related local-privesc review surfaces
7. subtle differences across paths, hashes, unit fragments, cron schedules, sudoers/PAM lines, and same-host historical baselines

## Stage 5) Confidence-Gated Conclusions

Rules:

1. keep high-compute activity inconclusive unless runtime evidence matches a declared legitimate workload or miner evidence is direct
2. do not convert IOC keyword matches into attribution by themselves
3. reduce attribution confidence when primary logs are missing or trust bootstrap is weak
4. keep untraceable IPs explicitly marked as untraceable
5. treat vulnerable package or kernel status as exposure evidence, not proof of exploitation
6. only call a local privilege-escalation path plausible when exposure indicators and surrounding evidence support that reconstruction

## Stage 6) Approval-Gated Response Plan

Do not auto-remediate.

Output only:

1. evidence-backed findings
2. normalized timeline
3. traceability status
4. unknowns and gaps
5. optional response plan requiring explicit approval

If the user asks for kill/stop/delete/restart in the same request:

1. keep the current run read-only
2. finish evidence collection first
3. record remediation as a later approval-gated step

## External Evidence Interfaces

When the host alone cannot close the initial-access path, pivot to external evidence when available:

1. cloud audit logs
2. K8s audit logs
3. CI/CD logs and secret-store access logs
4. boundary firewall, NAT, proxy, or flow logs
5. identity-provider or bastion authentication logs

Use [external-evidence-interfaces.md](external-evidence-interfaces.md) for the checklist.
