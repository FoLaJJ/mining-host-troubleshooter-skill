#!/usr/bin/env python3
"""Run a standard read-only investigation workflow and export a report."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def sanitize_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", raw.strip())[:80] or "host"


def target_label(args: argparse.Namespace) -> str:
    if args.host_ip:
        return sanitize_name(args.host_ip)
    if args.remote:
        return sanitize_name(args.remote.split("@")[-1])
    if args.host_name:
        return sanitize_name(args.host_name)
    return "local-host"


def default_case_root() -> str:
    return str((Path.cwd() / "reports").resolve())


def run_step(name: str, cmd: list[str]) -> tuple[int, str]:
    print(f"[STEP] {name}")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode, proc.stdout


def parse_collect_output(text: str) -> tuple[str, str]:
    evidence = ""
    case_dir = ""
    for line in text.splitlines():
        if line.startswith("Evidence JSON written:"):
            evidence = line.split(":", 1)[1].strip()
        elif line.startswith("Case dir:"):
            case_dir = line.split(":", 1)[1].strip()
    return evidence, case_dir


def add_arg(cmd: list[str], key: str, value: str | None) -> None:
    if value:
        cmd.extend([key, value])


def build_collect_cmd(args: argparse.Namespace, collect_script: Path) -> list[str]:
    cmd = [sys.executable, str(collect_script)]
    add_arg(cmd, "--output", args.output)
    add_arg(cmd, "--case-root", args.case_root)
    add_arg(cmd, "--case-dir", args.case_dir)
    add_arg(cmd, "--case-tag", args.case_tag)
    add_arg(cmd, "--incident-id", args.incident_id)
    add_arg(cmd, "--title", args.title)
    add_arg(cmd, "--analyst", args.analyst)
    add_arg(cmd, "--host-name", args.host_name)
    add_arg(cmd, "--host-ip", args.host_ip)
    add_arg(cmd, "--os-hint", args.os_hint)
    add_arg(cmd, "--mining-mode", args.mining_mode)
    add_arg(cmd, "--expected-workload", args.expected_workload)
    add_arg(cmd, "--remote", args.remote)
    if args.port:
        cmd.extend(["--port", str(args.port)])
    add_arg(cmd, "--identity", args.identity)
    add_arg(cmd, "--jump", args.jump)
    add_arg(cmd, "--known-hosts", args.known_hosts)
    add_arg(cmd, "--host-key-fingerprint", args.host_key_fingerprint)
    add_arg(cmd, "--password", args.password)
    add_arg(cmd, "--password-env", args.password_env)
    if args.prompt_password:
        cmd.append("--prompt-password")
    if args.allow_insecure_cli_password:
        cmd.append("--allow-insecure-cli-password")
    if args.timeout:
        cmd.extend(["--timeout", str(args.timeout)])
    if args.dry_run:
        cmd.append("--dry-run")
    return cmd


def write_meta_json(case_dir: str, filename: str, payload_text: str) -> None:
    case_path = Path(case_dir)
    meta = case_path / "meta"
    meta.mkdir(parents=True, exist_ok=True)
    out = meta / filename
    try:
        data = json.loads(payload_text)
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except json.JSONDecodeError:
        out.write_text(payload_text, encoding="utf-8")
    print(f"[INFO] Wrote {out}")


def load_json_file(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_checkpoint(case_dir: str, stage: str, status: str = "completed", note: str = "", extra: dict | None = None) -> None:
    meta = Path(case_dir) / "meta"
    meta.mkdir(parents=True, exist_ok=True)
    path = meta / "workflow_checkpoints.json"
    payload = {}
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
    history = payload.get("history", []) if isinstance(payload.get("history"), list) else []
    entry = {
        "time_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "stage": stage,
        "status": status,
        "note": note,
    }
    if extra:
        entry["extra"] = extra
    history.append(entry)
    payload = {
        "latest": entry,
        "history": history,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    label = f"[CHECKPOINT] stage={stage} status={status}"
    if note:
        label += f" note={note}"
    print(label)


def split_artifact_sections(text: str) -> tuple[str, str]:
    marker_stdout = "\n[STDOUT]\n"
    marker_stderr = "\n[STDERR]\n"
    if marker_stdout not in text:
        return text, ""
    _, rest = text.split(marker_stdout, 1)
    if marker_stderr not in rest:
        return rest, ""
    stdout, stderr = rest.split(marker_stderr, 1)
    return stdout, stderr


def host_meta_from_data(data: dict) -> dict:
    host = data.get("host") if isinstance(data.get("host"), dict) else {}
    return {
        "name": str(host.get("name", "unknown")),
        "ip": str(host.get("ip", "unknown")),
        "os": str(host.get("os", "unknown")),
        "mining_mode": str(host.get("mining_mode", "unknown")),
    }


def build_preflight_summary_from_local(payload: dict) -> dict:
    checks = [item for item in payload.get("command_checks", []) if isinstance(item, dict)]
    missing_commands = sorted(str(item.get("command", "unknown")) for item in checks if str(item.get("trust", "")) == "missing")
    suspicious_commands = sorted(str(item.get("command", "unknown")) for item in checks if str(item.get("trust", "")) == "suspicious")
    commands_aliased = sorted(
        str(item.get("command", "unknown"))
        for item in checks
        if str(item.get("alias", "")) not in {"not_aliased", "unknown", "bash_unavailable", ""}
    )
    commands_as_functions = sorted(
        str(item.get("command", "unknown"))
        for item in checks
        if " is a function" in str(item.get("type", ""))
    )
    return {
        "collection_basis": "local_preflight_script",
        "host": {
            "name": str(payload.get("hostname", "unknown")),
            "ip": "unknown",
            "os": str(payload.get("os_family", "unknown")),
            "mining_mode": "unknown",
        },
        "os_family": str(payload.get("os_family", "unknown")),
        "package_manager": str(payload.get("package_manager", "unknown")),
        "fallbacks": payload.get("fallbacks", {}),
        "command_check_count": len(checks),
        "missing_commands": missing_commands,
        "suspicious_commands": suspicious_commands,
        "commands_aliased": commands_aliased,
        "commands_as_functions": commands_as_functions,
    }


def build_preflight_summary_from_evidence(data: dict) -> dict:
    evidence_items = data.get("evidence", []) if isinstance(data.get("evidence"), list) else []
    command_resolution: dict[str, list[str]] = {}
    sha256_samples: list[dict] = []
    missing_commands: set[str] = set()
    aliased_commands: set[str] = set()
    function_commands: set[str] = set()
    path_value = "unknown"
    trust_probe_ids: list[str] = []

    for item in evidence_items:
        if not isinstance(item, dict) or str(item.get("source", "")) != "trust":
            continue
        trust_probe_ids.append(str(item.get("id", "unknown")))
        artifact = Path(str(item.get("artifact", "")))
        if not artifact.exists():
            continue
        stdout, _ = split_artifact_sections(artifact.read_text(encoding="utf-8", errors="replace"))
        current_cmd = ""
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("PATH="):
                path_value = line[5:]
                continue
            if line.startswith("## "):
                current_cmd = line[3:].strip()
                command_resolution.setdefault(current_cmd, [])
                continue
            if " is aliased to " in line:
                cmd = current_cmd or line.split(" is aliased to ", 1)[0].strip()
                aliased_commands.add(cmd)
            if " is a function" in line:
                cmd = current_cmd or line.split(" is a function", 1)[0].strip()
                function_commands.add(cmd)
            if line.endswith(": not_found"):
                missing_commands.add(line.split(":", 1)[0].strip())
            if current_cmd and (f"{current_cmd} is " in line or line.startswith("/")):
                bucket = command_resolution.setdefault(current_cmd, [])
                if line not in bucket and len(bucket) < 4:
                    bucket.append(line)
            match = re.match(r"^([a-fA-F0-9]{64})\s+(.+)$", line)
            if match:
                sha256_samples.append({
                    "command": Path(match.group(2)).name,
                    "path": match.group(2),
                    "sha256": match.group(1),
                })

    suspicious_commands = sorted(set(missing_commands) | set(aliased_commands) | set(function_commands))
    return {
        "collection_basis": "collector_trust_probes",
        "generated_from": str(data.get("generated_at", "unknown")),
        "host": host_meta_from_data(data),
        "trust_probe_ids": trust_probe_ids,
        "path_value": path_value,
        "command_check_count": len(command_resolution),
        "missing_commands": sorted(missing_commands),
        "suspicious_commands": suspicious_commands,
        "commands_aliased": sorted(aliased_commands),
        "commands_as_functions": sorted(function_commands),
        "command_resolution": {key: value for key, value in sorted(command_resolution.items()) if value},
        "sha256_samples": sha256_samples[:32],
    }


def build_log_summary_from_local(payload: dict) -> dict:
    logs = [item for item in payload.get("logs", []) if isinstance(item, dict)]
    primary_log_risk_count = sum(1 for item in logs if str(item.get("status", "ok")) != "ok")
    return {
        "collection_basis": "local_log_integrity_script",
        "overall_status": str(payload.get("overall_status", "unknown")),
        "primary_log_risk_count": primary_log_risk_count,
        "logs": logs,
        "journald": payload.get("journald", {}),
        "fallback_sources": payload.get("fallback_sources", []),
    }


def build_log_summary_from_evidence(data: dict) -> dict:
    logs = [item for item in data.get("log_integrity", []) if isinstance(item, dict)]
    levels = {"ok": 1, "suspicious": 2, "missing": 3, "tampered": 4, "unknown": 3}
    overall = "ok"
    top = 1
    for item in logs:
        level = levels.get(str(item.get("status", "unknown")), 3)
        if level > top:
            top = level
            overall = str(item.get("status", "unknown"))
    fallback_sources: set[str] = set()
    evidence_ids: set[str] = set()
    evidence_items = data.get("evidence", []) if isinstance(data.get("evidence"), list) else []
    for item in evidence_items:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source", ""))
        command = str(item.get("command", ""))
        if source == "log_integrity":
            evidence_ids.add(str(item.get("id", "unknown")))
        if "last -Faiwx" in command:
            fallback_sources.add("last -Faiwx")
        if "lastb -Faiwx" in command:
            fallback_sources.add("lastb -Faiwx")
        if "lastlog" in command:
            fallback_sources.add("lastlog")
        if "journalctl" in command:
            fallback_sources.add("journalctl")
        if "/etc/systemd/system" in command or "systemctl" in command:
            fallback_sources.add("systemd metadata")
        if "/etc/cron" in command or "crontab" in command:
            fallback_sources.add("cron metadata")
    return {
        "collection_basis": "collector_log_integrity_probes",
        "host": host_meta_from_data(data),
        "overall_status": overall,
        "primary_log_risk_count": sum(1 for item in logs if str(item.get("status", "ok")) != "ok"),
        "logs": logs,
        "fallback_required": any(str(item.get("status", "ok")) in {"missing", "tampered", "suspicious"} for item in logs),
        "fallback_sources_detected": sorted(fallback_sources),
        "log_probe_ids": sorted(evidence_ids),
    }


def export_sidecar_summaries(case_dir: str, evidence_path: str, preflight_json: str = "", log_json: str = "") -> None:
    evidence_data = load_json_file(evidence_path)
    if preflight_json:
        preflight_payload = json.loads(preflight_json)
        write_meta_json(case_dir, "preflight.summary.json", json.dumps(build_preflight_summary_from_local(preflight_payload), ensure_ascii=False))
    else:
        write_meta_json(case_dir, "preflight.summary.json", json.dumps(build_preflight_summary_from_evidence(evidence_data), ensure_ascii=False))

    if log_json:
        log_payload = json.loads(log_json)
        write_meta_json(case_dir, "log_integrity.summary.json", json.dumps(build_log_summary_from_local(log_payload), ensure_ascii=False))
    else:
        write_meta_json(case_dir, "log_integrity.summary.json", json.dumps(build_log_summary_from_evidence(evidence_data), ensure_ascii=False))


def export_scene_reconstruction(case_dir: str, evidence_path: str) -> None:
    data = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    reconstruction = data.get("scene_reconstruction")
    if not isinstance(reconstruction, dict):
        return
    write_meta_json(case_dir, "scene_reconstruction.json", json.dumps(reconstruction, ensure_ascii=False))


def default_case_tag(args: argparse.Namespace) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{target_label(args)}-{ts}"


def build_workflow_profile_summary(args: argparse.Namespace) -> dict:
    profile = str(getattr(args, "profile", "standard"))
    warnings: list[str] = []
    if profile == "enterprise-self-audit":
        order = [
            "trust_bootstrap",
            "low_impact_readonly_sweep",
            "deep_evidence_hypothesis_matrix",
            "confidence_gated_conclusions",
            "validation_gate",
            "same_host_baseline_assessment",
            "approval_gated_response_plan",
        ]
        if args.skip_preflight:
            warnings.append("skip_preflight weakens command-trust verification.")
        if args.skip_log_integrity:
            warnings.append("skip_log_integrity weakens log survivability assessment.")
        if args.skip_validate:
            warnings.append("skip_validate weakens enterprise profile quality gate.")
    else:
        order = [
            "trust_bootstrap",
            "low_impact_readonly_sweep",
            "confidence_gated_conclusions",
            "report_export",
        ]
    return {
        "profile": profile,
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "scene_preservation_required": True,
        "same_host_comparison_default": True,
        "remote_trust_required": True,
        "recommended_order": order,
        "baseline_path": str(getattr(args, "baseline", "") or ""),
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run optimized read-only workflow: collect evidence + optional report export."
    )
    parser.add_argument("--output", help="Output evidence JSON path. Usually omit to use case layout.")
    parser.add_argument("--case-root", default=default_case_root(), help="Root directory for case bundles. Defaults to <current working directory>/reports.")
    parser.add_argument("--case-dir", help="Explicit case directory path.")
    parser.add_argument("--case-tag", help="Case folder tag (auto if omitted).")
    parser.add_argument("--incident-id", help="Incident ID override.")
    parser.add_argument("--title", help="Incident title.")
    parser.add_argument("--analyst", default="unknown", help="Analyst/team name.")
    parser.add_argument("--host-name", help="Host display name.")
    parser.add_argument("--host-ip", help="Host IP.")
    parser.add_argument("--os-hint", help="OS hint.")
    parser.add_argument("--mining-mode", choices=["auto", "gpu", "cpu", "mixed"], default="auto")
    parser.add_argument("--expected-workload", help="Declared legitimate high-compute workload for false-positive control.")
    parser.add_argument("--remote", help="Remote target in user@host format.")
    parser.add_argument("--port", type=int, help="SSH port.")
    parser.add_argument("--identity", help="SSH private key path.")
    parser.add_argument("--jump", help="SSH jump host user@host.")
    parser.add_argument("--known-hosts", help="Known-hosts file containing the pinned server key.")
    parser.add_argument("--host-key-fingerprint", help="Pinned remote host key fingerprint in SHA256:<base64> form.")
    parser.add_argument("--password", help="Deprecated insecure SSH password input. Disabled unless --allow-insecure-cli-password is set.")
    parser.add_argument("--password-env", help="Read SSH password from env var name.")
    parser.add_argument("--prompt-password", action="store_true", help="Prompt securely for the SSH password instead of using command-line plaintext.")
    parser.add_argument("--allow-insecure-cli-password", action="store_true", help="Allow deprecated plaintext --password usage. Avoid unless no safer path exists.")
    parser.add_argument("--timeout", type=int, default=30, help="Per-command timeout seconds for all probe execution paths.")
    parser.add_argument("--dry-run", action="store_true", help="Create case structure without running probes.")
    parser.add_argument("--profile", choices=["standard", "enterprise-self-audit"], default="standard", help="Workflow profile written into case metadata.")
    parser.add_argument("--skip-preflight", action="store_true", help="Skip local preflight check.")
    parser.add_argument("--skip-log-integrity", action="store_true", help="Skip local log integrity check.")
    parser.add_argument("--skip-enrich", action="store_true", help="Skip auto evidence enrichment.")
    parser.add_argument("--require-enrich", action="store_true", help="Fail workflow if enrichment step fails.")
    parser.add_argument("--skip-validate", action="store_true", help="Skip case validation gate.")
    parser.add_argument("--skip-export", action="store_true", help="Skip report export step.")
    parser.add_argument("--baseline", help="Optional same-host baseline JSON generated by generate_host_baseline.py.")
    parser.add_argument("--compare-base-case", help="Older/base case directory for cross-case diff after export.")
    parser.add_argument("--allow-host-mismatch", action="store_true", help="Allow cross-case compare when same-host metadata is not confirmed.")
    parser.add_argument("--strict-report", action="store_true", help="Use strict validation when exporting report.")
    parser.add_argument("--redact", action="store_true", help="Redact IPs and other sensitive values for external sharing.")
    parser.add_argument("--no-redact", action="store_true", help="Deprecated compatibility flag. Internal reports are already unredacted by default.")
    args = parser.parse_args()

    if args.redact and args.no_redact:
        raise SystemExit("Use either --redact or --no-redact, not both.")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be greater than 0.")
    if args.password and not args.allow_insecure_cli_password:
        raise SystemExit("Plaintext --password is disabled by default. Use --password-env or --prompt-password instead.")
    if sum(bool(x) for x in [args.password, args.password_env, args.prompt_password]) > 1:
        raise SystemExit("Use only one of --password, --password-env, or --prompt-password.")

    script_dir = Path(__file__).resolve().parent
    preflight_script = script_dir / "preflight_environment.py"
    log_script = script_dir / "check_log_integrity.py"
    collect_script = script_dir / "collect_live_evidence.py"
    enrich_script = script_dir / "enrich_case_evidence.py"
    validate_script = script_dir / "validate_case_bundle.py"
    compare_script = script_dir / "compare_case_bundles.py"
    baseline_script = script_dir / "apply_host_baseline.py"
    export_script = script_dir / "export_investigation_report.py"
    external_evidence_script = script_dir / "export_external_evidence_checklist.py"

    if not args.case_dir and not args.case_tag:
        args.case_tag = default_case_tag(args)

    print("[MODE: AUTOMATED_WORKFLOW]")
    preflight_json = ""
    log_json = ""
    if not args.remote and not args.skip_preflight:
        code, out = run_step("preflight_environment", [sys.executable, str(preflight_script), "--json"])
        if code != 0:
            print("[ERROR] preflight_environment failed", file=sys.stderr)
            return code
        preflight_json = out

    if not args.remote and not args.skip_log_integrity:
        code, out = run_step("check_log_integrity", [sys.executable, str(log_script), "--json"])
        if code != 0:
            print("[ERROR] check_log_integrity failed", file=sys.stderr)
            return code
        log_json = out

    collect_cmd = build_collect_cmd(args, collect_script)
    code, collect_out = run_step("collect_live_evidence", collect_cmd)
    if code != 0:
        print("[ERROR] collect_live_evidence failed", file=sys.stderr)
        return code

    evidence_path, case_dir = parse_collect_output(collect_out)
    if not evidence_path or not case_dir:
        print("[ERROR] Could not parse evidence path/case dir from collector output.", file=sys.stderr)
        return 2
    evidence_for_next = evidence_path
    write_checkpoint(case_dir, "workflow_started", extra={"mode": "AUTOMATED_WORKFLOW", "remote": bool(args.remote), "profile": args.profile, "expected_workload": bool(args.expected_workload)})
    if args.remote:
        write_checkpoint(case_dir, "trust_bootstrap_complete", extra={"evidence_path": evidence_for_next})
    write_checkpoint(case_dir, "low_impact_readonly_sweep_complete", extra={"evidence_path": evidence_for_next})

    if preflight_json:
        write_meta_json(case_dir, "preflight.local.json", preflight_json)
    if log_json:
        write_meta_json(case_dir, "log_integrity.local.json", log_json)
    write_meta_json(case_dir, "workflow_profile.json", json.dumps(build_workflow_profile_summary(args), ensure_ascii=False))
    export_sidecar_summaries(case_dir, evidence_path, preflight_json=preflight_json, log_json=log_json)

    if not args.skip_enrich:
        enriched_path = str(Path(case_dir) / "evidence" / "evidence.reviewed.auto.json")
        enrich_cmd = [
            sys.executable,
            str(enrich_script),
            "--input",
            evidence_path,
            "--output",
            enriched_path,
        ]
        code, enrich_out = run_step("enrich_case_evidence", enrich_cmd)
        if code == 0:
            evidence_for_next = enriched_path
            write_meta_json(case_dir, "enrichment.local.json", json.dumps({"output": enrich_out}, ensure_ascii=False))
            export_scene_reconstruction(case_dir, evidence_for_next)
            write_checkpoint(case_dir, "deep_evidence_hypothesis_matrix_complete", extra={"evidence_path": evidence_for_next})
        else:
            msg = "[ERROR] enrich_case_evidence failed" if args.require_enrich else "[WARN] enrich_case_evidence failed; continuing with raw evidence"
            print(msg, file=sys.stderr)
            if args.require_enrich:
                return code

    if not args.skip_validate:
        validate_cmd = [
            sys.executable,
            str(validate_script),
            "--case-dir",
            case_dir,
            "--input",
            evidence_for_next,
            "--json",
        ]
        if args.strict_report:
            validate_cmd.append("--strict")
        code, validate_out = run_step("validate_case_bundle", validate_cmd)
        write_meta_json(case_dir, "case_validation.json", validate_out)
        if code != 0:
            print("[ERROR] validate_case_bundle failed", file=sys.stderr)
            return code
        write_checkpoint(case_dir, "confidence_gated_conclusions_complete", extra={"validation_path": str(Path(case_dir) / "meta" / "case_validation.json")})

    if args.baseline:
        baseline_cmd = [
            sys.executable,
            str(baseline_script),
            "--case-dir",
            case_dir,
            "--baseline",
            args.baseline,
        ]
        if args.allow_host_mismatch:
            baseline_cmd.append("--allow-host-mismatch")
        code, _ = run_step("apply_host_baseline", baseline_cmd)
        if code != 0:
            print("[ERROR] apply_host_baseline failed", file=sys.stderr)
            return code
        write_checkpoint(case_dir, "baseline_assessment_complete", extra={"baseline_path": args.baseline})

    if not args.skip_export:
        export_cmd = [
            sys.executable,
            str(export_script),
            "--input",
            evidence_for_next,
            "--case-dir",
            case_dir,
        ]
        if args.redact:
            export_cmd.append("--redact")
        if args.strict_report:
            export_cmd.append("--strict")
        code, _ = run_step("export_investigation_report", export_cmd)
        if code != 0:
            print("[ERROR] export_investigation_report failed", file=sys.stderr)
            return code
        write_checkpoint(case_dir, "approval_gated_response_plan_complete", extra={"report_path": str(Path(case_dir) / "reports" / "report.md")})
        checklist_cmd = [
            sys.executable,
            str(external_evidence_script),
            "--input",
            evidence_for_next,
            "--case-dir",
            case_dir,
        ]
        code, _ = run_step("export_external_evidence_checklist", checklist_cmd)
        if code != 0:
            print("[ERROR] export_external_evidence_checklist failed", file=sys.stderr)
            return code
        write_checkpoint(case_dir, "external_evidence_checklist_complete", extra={"checklist_path": str(Path(case_dir) / "reports" / "external-evidence-checklist.md")})

    if args.compare_base_case:
        compare_cmd = [
            sys.executable,
            str(compare_script),
            "--base-case",
            args.compare_base_case,
            "--target-case",
            case_dir,
        ]
        if args.allow_host_mismatch:
            compare_cmd.append("--allow-host-mismatch")
        if args.redact:
            compare_cmd.append("--redact")
        code, _ = run_step("compare_case_bundles", compare_cmd)
        if code != 0:
            print("[ERROR] compare_case_bundles failed", file=sys.stderr)
            return code
        write_checkpoint(case_dir, "case_comparison_complete", extra={"base_case": args.compare_base_case})

    write_checkpoint(case_dir, "workflow_completed")
    print("[DONE] Workflow completed.")
    print(f"[DONE] Case dir: {case_dir}")
    print(f"[DONE] Evidence: {evidence_for_next}")
    if args.baseline:
        print(f"[DONE] Baseline Assessment: {Path(case_dir) / 'reports' / 'baseline_assessment.md'}")
    if not args.skip_export:
        print(f"[DONE] Report: {Path(case_dir) / 'report.md'}")
        print(f"[DONE] Chinese Report: {Path(case_dir) / 'report.zh-CN.md'}")
        print(f"[DONE] Management Summary: {Path(case_dir) / 'reports' / 'management-summary.md'}")
        print(f"[DONE] SOC Summary: {Path(case_dir) / 'reports' / 'soc-summary.md'}")
        print(f"[DONE] External Evidence Checklist: {Path(case_dir) / 'reports' / 'external-evidence-checklist.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
