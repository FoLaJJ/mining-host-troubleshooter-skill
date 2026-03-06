# Enterprise Self-Audit Workflow

Use this workflow when a security team, SOC, SIRT, or incident-response team needs a standardized way to examine a Linux host for mining activity with minimal scene damage.

## Objectives

1. Preserve the host state before cleanup.
2. Verify trust in the investigation toolchain before trusting output.
3. Collect enough evidence to explain persistence, execution, network behavior, and impact.
4. Keep every conclusion tied to observable evidence.

## Standard Linux Investigation Sequence

1. Define scope first.
   - Confirm target host, expected role, suspected mining type (GPU/CPU/mixed), and observation window.
   - Note whether the host is a production business machine or a dedicated compute node.
2. Preserve scene.
   - Do not restart miners, rotate logs, edit services, delete binaries, or clean temporary files before collection.
   - Avoid package changes, firewall changes, or persistence cleanup during first-pass evidence gathering.
3. Verify command trust.
   - Run `python scripts/preflight_environment.py`.
   - Check for alias/function/path tampering before trusting `lsattr`, `systemctl`, `ss`, `journalctl`, `ps`, and related tools.
4. Check log survivability.
   - Run `python scripts/check_log_integrity.py`.
   - If primary logs are missing/tampered, immediately pivot to fallback evidence such as `last`, `lastb`, `lastlog`, systemd metadata, cron metadata, and socket/process state.
5. Collect read-only baseline.
   - Capture time, uptime, load, memory, disk, sockets, routes, process list, and miner-related process lines.
   - Capture GPU telemetry for suspected GPU mining and CPU/NUMA/hugepages signals for suspected CPU mining.
6. Check persistence and startup paths.
   - Review systemd units, cron jobs, shell startup files, rc/local-style paths, container startup, and suspicious downloaded binaries.
7. Check ingress, egress, and lateral movement hints.
   - Review listening ports, SSH auth events, source IPs, outbound pool connectivity, proxy processes, and tunnel tooling.
8. Build the case bundle.
   - Prefer `python scripts/run_readonly_workflow.py ...` or `collect_live_evidence.py`.
   - By default, case bundles are created under `./reports/<case>/` in the directory where the operator launches the workflow, not under the installed skill directory.
9. Reconstruct and validate.
   - Generate `evidence.reviewed.auto.json`.
   - Validate with `validate_case_bundle.py --strict` before concluding root cause or attribution.
10. Produce findings carefully.
   - State what was observed, how it persisted, how it executed, and what network indicators were present.
   - If logs or trust are weak, mark the conclusion `inconclusive` instead of filling gaps with assumptions.
11. Compare with prior same-host incidents when available.
   - Use cross-case diffing to isolate what changed between incidents.
12. Export and hand off.
   - Keep the internal report unredacted by default so IP traceability and host-level evidence are preserved.
   - Use `--redact` only for externally shared copies.
   - Keep raw evidence, artifacts, and hashes together in the case bundle for later review.

## What Enterprise Teams Usually Standardize

1. Tool trust checks before interpretation.
2. A fixed read-only first-pass command set.
3. Evidence collection into a standard directory layout.
4. Separate handling of volatile evidence, persistence evidence, and attribution evidence.
5. Explicit confidence downgrade when logs are missing, tampered, or partially overwritten.
6. Same-host historical comparison before cleanup.

## Recommended Commands

```bash
python scripts/generate_checklist.py --os linux --mode remote --type auto --profile enterprise-self-audit
python scripts/run_readonly_workflow.py --remote <user@host> --identity <key> --analyst <team> --host-name <host> --host-ip <ip> --strict-report
python scripts/validate_case_bundle.py --case-dir reports/<case> --input reports/<case>/evidence/evidence.reviewed.auto.json --strict
```

## Escalation Triggers

Escalate beyond routine self-audit when any of the following are true:

1. Critical commands appear tampered, aliased unexpectedly, or outside trusted paths.
2. Primary logs are missing/tampered and fallback evidence is also weak.
3. Persistence spans multiple mechanisms or appears to involve tunneling/proxy tooling.
4. The host shows signs of lateral movement rather than isolated mining only.
5. Remediation would require disruptive changes on a production-critical system.
