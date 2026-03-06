#!/usr/bin/env python3
"""Compare two case bundles and export a concise cross-case diff report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

from enrich_case_evidence import (
    AUTH_ACCEPT_RE,
    AUTH_CLOSE_RE,
    AUTH_FAIL_RE,
    AUTH_INVALID_RE,
    LISTEN_PORT_RE,
    as_dict,
    as_list,
    load_json,
    split_artifact_sections,
)


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def mask_ip(ip: str) -> str:
    ip = ip.strip()
    if not re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", ip):
        return ip
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.x.x"


def redact_value(value: Any) -> str:
    text = str(value)
    return re.sub(r"\b(\d{1,3}\.){3}\d{1,3}\b", lambda m: mask_ip(m.group(0)), text)


def redact_any(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: redact_any(val) for key, val in value.items()}
    if isinstance(value, list):
        return [redact_any(item) for item in value]
    if isinstance(value, tuple):
        return [redact_any(item) for item in value]
    if isinstance(value, str):
        return redact_value(value)
    return value


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(md_escape(cell) for cell in row) + " |")
    return "\n".join(lines)


def candidate_evidence_paths(case_dir: Path) -> list[Path]:
    evidence_dir = case_dir / "evidence"
    return [
        evidence_dir / "evidence.reviewed.json",
        evidence_dir / "evidence.reviewed.auto.json",
        evidence_dir / "evidence.raw.v2.json",
        evidence_dir / "evidence.raw.json",
    ]


def resolve_evidence_path(case_dir: Path) -> Path:
    for path in candidate_evidence_paths(case_dir):
        if path.exists():
            return path
    raise SystemExit(f"No supported evidence JSON found under {case_dir / 'evidence'}")


def stable_time(value: str) -> str:
    return value.strip() or "unknown"


UNKNOWN_HOST_VALUES = {"", "unknown", "n/a", "na", "none", "null", "unset"}


def normalize_host_identifier(value: Any) -> str:
    text = str(value).strip().lower()
    return "" if text in UNKNOWN_HOST_VALUES else text


def build_host_scope(base_case: dict[str, Any], target_case: dict[str, Any]) -> dict[str, Any]:
    base_ip = normalize_host_identifier(base_case.get("host_ip", ""))
    target_ip = normalize_host_identifier(target_case.get("host_ip", ""))
    base_name = normalize_host_identifier(base_case.get("host_name", ""))
    target_name = normalize_host_identifier(target_case.get("host_name", ""))

    match_basis: list[str] = []
    if base_ip and target_ip and base_ip == target_ip:
        match_basis.append("host_ip")
    if base_name and target_name and base_name == target_name:
        match_basis.append("host_name")

    partial_mismatch = False
    if base_ip and target_ip and base_ip != target_ip:
        partial_mismatch = True
    if base_name and target_name and base_name != target_name:
        partial_mismatch = True

    return {
        "match": bool(match_basis),
        "match_basis": match_basis,
        "partial_mismatch": partial_mismatch,
        "known_identifiers": {
            "base": {
                "host_ip": bool(base_ip),
                "host_name": bool(base_name),
            },
            "target": {
                "host_ip": bool(target_ip),
                "host_name": bool(target_name),
            },
        },
    }


def host_scope_warnings(scope: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if not scope.get("match"):
        warnings.append(
            "Same-host scope could not be confirmed from case metadata; compare only with deliberate analyst review."
        )
        return warnings
    if scope.get("partial_mismatch"):
        warnings.append(
            "Only part of the host identity matches across cases; review naming/IP drift before drawing same-host conclusions."
        )
    return warnings


def parse_case(case_dir: Path) -> dict[str, Any]:
    evidence_path = resolve_evidence_path(case_dir)
    data = load_json(evidence_path)
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    findings = [as_dict(x) for x in as_list(data.get("findings"))]
    ip_traces = [as_dict(x) for x in as_list(data.get("ip_traces"))]
    timeline = [as_dict(x) for x in as_list(data.get("timeline"))]
    log_integrity = [as_dict(x) for x in as_list(data.get("log_integrity"))]

    findings_set = {
        str(item.get("statement", "")).strip()
        for item in findings
        if str(item.get("statement", "")).strip()
    }
    ip_trace_set = {
        (
            str(item.get("ip", "")).strip(),
            str(item.get("role", "unknown")).strip(),
            str(item.get("trace_status", "unknown")).strip().lower(),
        )
        for item in ip_traces
        if str(item.get("ip", "")).strip()
    }
    timeline_set = {
        (
            stable_time(str(item.get("time", ""))),
            str(item.get("event", "")).strip(),
        )
        for item in timeline
        if str(item.get("event", "")).strip()
    }
    log_set = {
        (
            str(item.get("artifact", "")).strip(),
            str(item.get("status", "unknown")).strip().lower(),
        )
        for item in log_integrity
        if str(item.get("artifact", "")).strip()
    }

    auth_source_ips: set[str] = set()
    listening_ports: set[str] = set()
    trust_anomalies: set[str] = set()
    process_ioc_lines: set[str] = set()
    auth_events = {"accepted": 0, "failed": 0, "invalid": 0, "closed": 0}

    for item in evidence_items:
        source = str(item.get("source", "")).strip()
        command = str(item.get("command", "")).strip()
        artifact = Path(str(item.get("artifact", "")).strip())
        if not artifact.exists():
            continue

        stdout, _ = split_artifact_sections(artifact.read_text(encoding="utf-8", errors="replace"))
        if source == "auth":
            for line in stdout.splitlines():
                if AUTH_ACCEPT_RE.search(line):
                    auth_events["accepted"] += 1
                    auth_source_ips.add(AUTH_ACCEPT_RE.search(line).group("ip"))
                if AUTH_FAIL_RE.search(line):
                    auth_events["failed"] += 1
                    auth_source_ips.add(AUTH_FAIL_RE.search(line).group("ip"))
                if AUTH_INVALID_RE.search(line):
                    auth_events["invalid"] += 1
                    auth_source_ips.add(AUTH_INVALID_RE.search(line).group("ip"))
                if AUTH_CLOSE_RE.search(line):
                    auth_events["closed"] += 1
                    auth_source_ips.add(AUTH_CLOSE_RE.search(line).group("ip"))

        if source == "network" and ("ss -antup" in command or "netstat -antup" in command):
            for line in stdout.splitlines():
                match = LISTEN_PORT_RE.search(line)
                if match:
                    listening_ports.add(match.group(2))

        if source == "trust":
            for line in stdout.splitlines():
                if " is aliased to " in line:
                    trust_anomalies.add("alias")
                if " is a function" in line:
                    trust_anomalies.add("function")
                if line.strip().endswith(": not_found"):
                    trust_anomalies.add("command_missing")

        if source == "process" and "grep -Ei 'miner|xmrig|lolminer|trex|gminer|nbminer|clash|autossh|h32|h64|\\-zsh'" in command:
            for line in stdout.splitlines():
                if line.strip():
                    process_ioc_lines.add(line.strip())

    host = as_dict(data.get("host"))
    incident = as_dict(data.get("incident"))
    return {
        "case_dir": str(case_dir),
        "case_name": case_dir.name,
        "evidence_path": str(evidence_path),
        "incident_id": str(incident.get("id", "unknown")),
        "host_name": str(host.get("name", "unknown")),
        "host_ip": str(host.get("ip", "unknown")),
        "os": str(host.get("os", "unknown")),
        "mining_mode": str(host.get("mining_mode", "unknown")),
        "generated_at": str(data.get("generated_at", "unknown")),
        "evidence_count": len(evidence_items),
        "findings_count": len(findings),
        "timeline_count": len(timeline),
        "ip_trace_count": len(ip_traces),
        "log_integrity_count": len(log_integrity),
        "findings_set": sorted(findings_set),
        "ip_trace_set": sorted(ip_trace_set),
        "timeline_set": sorted(timeline_set),
        "log_set": sorted(log_set),
        "auth_source_ips": sorted(auth_source_ips),
        "listening_ports": sorted(listening_ports),
        "trust_anomalies": sorted(trust_anomalies),
        "process_ioc_lines": sorted(process_ioc_lines),
        "auth_events": auth_events,
    }


def diff_sets(before: set[Any], after: set[Any]) -> dict[str, list[Any]]:
    return {
        "added": sorted(after - before),
        "removed": sorted(before - after),
        "unchanged": sorted(before & after),
    }


def build_diff(base_case: dict[str, Any], target_case: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    stats = {
        "evidence_count": target_case["evidence_count"] - base_case["evidence_count"],
        "findings_count": target_case["findings_count"] - base_case["findings_count"],
        "timeline_count": target_case["timeline_count"] - base_case["timeline_count"],
        "ip_trace_count": target_case["ip_trace_count"] - base_case["ip_trace_count"],
        "log_integrity_count": target_case["log_integrity_count"] - base_case["log_integrity_count"],
        "accepted_auth_delta": target_case["auth_events"]["accepted"] - base_case["auth_events"]["accepted"],
        "failed_auth_delta": target_case["auth_events"]["failed"] - base_case["auth_events"]["failed"],
        "invalid_auth_delta": target_case["auth_events"]["invalid"] - base_case["auth_events"]["invalid"],
    }
    return {
        "generated_at_utc": now_utc(),
        "comparison_scope": scope,
        "warnings": host_scope_warnings(scope),
        "base_case": {
            key: base_case[key]
            for key in [
                "case_name",
                "case_dir",
                "incident_id",
                "host_name",
                "host_ip",
                "os",
                "mining_mode",
                "generated_at",
                "evidence_path",
            ]
        },
        "target_case": {
            key: target_case[key]
            for key in [
                "case_name",
                "case_dir",
                "incident_id",
                "host_name",
                "host_ip",
                "os",
                "mining_mode",
                "generated_at",
                "evidence_path",
            ]
        },
        "stats_delta": stats,
        "findings": diff_sets(set(base_case["findings_set"]), set(target_case["findings_set"])),
        "ip_traces": diff_sets(set(base_case["ip_trace_set"]), set(target_case["ip_trace_set"])),
        "timeline": diff_sets(set(base_case["timeline_set"]), set(target_case["timeline_set"])),
        "log_integrity": diff_sets(set(base_case["log_set"]), set(target_case["log_set"])),
        "auth_source_ips": diff_sets(set(base_case["auth_source_ips"]), set(target_case["auth_source_ips"])),
        "listening_ports": diff_sets(set(base_case["listening_ports"]), set(target_case["listening_ports"])),
        "trust_anomalies": diff_sets(set(base_case["trust_anomalies"]), set(target_case["trust_anomalies"])),
        "process_ioc_lines": diff_sets(set(base_case["process_ioc_lines"]), set(target_case["process_ioc_lines"])),
    }


def short_items(items: list[Any], limit: int = 10) -> list[str]:
    rendered = [str(item) for item in items[:limit]]
    if len(items) > limit:
        rendered.append(f"... (+{len(items) - limit} more)")
    return rendered or ["none"]


def render_diff_markdown(diff: dict[str, Any], redact: bool) -> str:
    base = as_dict(diff.get("base_case"))
    target = as_dict(diff.get("target_case"))
    stats = as_dict(diff.get("stats_delta"))
    warnings = [str(x) for x in as_list(diff.get("warnings"))]
    maybe = redact_value if redact else str
    lines: list[str] = []
    lines.append("# Case Bundle Diff")
    lines.append("")
    lines.append("## Scope")
    lines.append(f"- Generated At (UTC): `{diff.get('generated_at_utc', 'unknown')}`")
    lines.append(f"- Base Case: `{base.get('case_name', 'unknown')}`")
    lines.append(f"- Target Case: `{target.get('case_name', 'unknown')}`")
    scope = as_dict(diff.get("comparison_scope"))
    match_basis = ", ".join(str(x) for x in as_list(scope.get("match_basis"))) or "none"
    lines.append(f"- Host Pair: `{maybe(base.get('host_ip', 'unknown'))}` -> `{maybe(target.get('host_ip', 'unknown'))}`")
    lines.append(f"- Same-host metadata match: `{scope.get('match', False)}` (basis: `{match_basis}`)")
    lines.append("")
    if warnings:
        lines.append("## Scope Warnings")
        for item in warnings:
            lines.append(f"- {item}")
        lines.append("")
    lines.append("## Delta Summary")
    rows = [
        ["Evidence", str(stats.get("evidence_count", 0))],
        ["Findings", str(stats.get("findings_count", 0))],
        ["Timeline", str(stats.get("timeline_count", 0))],
        ["IP Traces", str(stats.get("ip_trace_count", 0))],
        ["Log Integrity", str(stats.get("log_integrity_count", 0))],
        ["Accepted Auth Events", str(stats.get("accepted_auth_delta", 0))],
        ["Failed Auth Events", str(stats.get("failed_auth_delta", 0))],
        ["Invalid User Events", str(stats.get("invalid_auth_delta", 0))],
    ]
    lines.append(render_table(["Metric", "Target-Base"], rows))
    lines.append("")

    sections = [
        ("Findings", as_dict(diff.get("findings"))),
        ("IP Traceability", as_dict(diff.get("ip_traces"))),
        ("Timeline", as_dict(diff.get("timeline"))),
        ("Log Integrity", as_dict(diff.get("log_integrity"))),
        ("Auth Source IPs", as_dict(diff.get("auth_source_ips"))),
        ("Listening Ports", as_dict(diff.get("listening_ports"))),
        ("Trust Anomalies", as_dict(diff.get("trust_anomalies"))),
        ("Process IOC Lines", as_dict(diff.get("process_ioc_lines"))),
    ]
    for title, section in sections:
        lines.append(f"## {title}")
        added_items = [maybe(x) for x in short_items(as_list(section.get('added')))]
        removed_items = [maybe(x) for x in short_items(as_list(section.get('removed')))]
        lines.append(f"- Added: {', '.join(added_items)}")
        lines.append(f"- Removed: {', '.join(removed_items)}")
        lines.append(f"- Unchanged count: `{len(as_list(section.get('unchanged')))}`")
        lines.append("")

    lines.append("## Interpretation Rules")
    lines.append("- Added entries mean present in target case but absent in base case.")
    lines.append("- Removed entries mean present in base case but absent in target case.")
    lines.append("- This diff does not infer causality; use evidence IDs in each case before concluding impact.")
    lines.append("")
    return "\n".join(lines).strip() + "\n"


def build_output_layout(base_dir: Path, target_dir: Path, output_dir: str | None) -> Path:
    if output_dir:
        root = Path(output_dir).resolve()
    else:
        root = (base_dir.parent / "_comparisons" / f"{base_dir.name}__vs__{target_dir.name}").resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare two case bundles and export concise diffs.")
    parser.add_argument("--base-case", required=True, help="Base/older case directory.")
    parser.add_argument("--target-case", required=True, help="Target/newer case directory.")
    parser.add_argument("--output-dir", help="Output directory. Defaults to reports/_comparisons/<base>__vs__<target>.")
    parser.add_argument("--allow-host-mismatch", action="store_true", help="Allow comparison even when host name/IP differ.")
    parser.add_argument("--redact", action="store_true", help="Redact IPs and other sensitive values for external sharing.")
    parser.add_argument("--no-redact", action="store_true", help="Deprecated compatibility flag. Comparison output is unredacted by default.")
    args = parser.parse_args()

    if args.redact and args.no_redact:
        raise SystemExit("Use either --redact or --no-redact, not both.")

    base_dir = Path(args.base_case).resolve()
    target_dir = Path(args.target_case).resolve()
    if not base_dir.exists() or not base_dir.is_dir():
        raise SystemExit(f"Base case directory not found: {base_dir}")
    if not target_dir.exists() or not target_dir.is_dir():
        raise SystemExit(f"Target case directory not found: {target_dir}")

    base_case = parse_case(base_dir)
    target_case = parse_case(target_dir)
    scope = build_host_scope(base_case, target_case)
    if not args.allow_host_mismatch and not scope.get("match"):
        raise SystemExit(
            "Same-host scope is not confirmed between base and target case. Use --allow-host-mismatch only when cross-host or low-confidence comparison is intentional."
        )
    diff = build_diff(base_case, target_case, scope)
    out_dir = build_output_layout(base_dir, target_dir, args.output_dir)
    json_path = out_dir / "comparison.json"
    md_path = out_dir / "comparison.md"
    json_payload = redact_any(diff) if args.redact else diff
    json_path.write_text(json.dumps(json_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_diff_markdown(diff, redact=args.redact), encoding="utf-8")

    print(f"Comparison JSON written: {json_path}")
    print(f"Comparison Markdown written: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
