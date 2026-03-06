#!/usr/bin/env python3
"""Generate a per-case external evidence checklist from collected host evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("Input JSON must be an object.")
    return data


def build_checklist(data: dict[str, Any]) -> str:
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    scene = as_dict(data.get("scene_reconstruction"))
    auth_ips = as_list(scene.get("auth_source_ips"))
    has_container_cloud = int(scene.get("container_cloud_review_hit_count", 0) or 0) > 0
    has_log_risk = any(
        str(item.get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}
        for item in [as_dict(x) for x in as_list(data.get("log_integrity"))]
    )
    lines = [
        f"# External Evidence Checklist - {incident.get('id', 'unknown')}",
        "",
        f"- Host: `{host.get('name', 'unknown')}` ({host.get('ip', 'unknown')})",
        f"- Case ID: `{data.get('case_id', 'unknown')}`",
        f"- Goal: close initial-access, lateral-movement, and upstream attribution gaps using non-host evidence.",
        "",
        "## Priority Pivots",
    ]
    if auth_ips:
        lines.append(f"- Authentication source IPs observed on host: {', '.join(str(x) for x in auth_ips[:10])}")
        lines.append("- Pull bastion, VPN, IdP, or jump-host authentication logs for the same window.")
    else:
        lines.append("- No host auth source IPs were extracted; prioritize identity and boundary logs if access-path uncertainty remains.")
    if has_container_cloud:
        lines.append("- Container/cloud indicators were present; pull Kubernetes audit logs, registry pull history, cloud audit trails, and metadata-access telemetry.")
    if has_log_risk:
        lines.append("- Host log survivability is weakened; prioritize SIEM, boundary firewall, NAT, DNS, and snapshot history.")
    lines.append("")
    lines.extend([
        "## Sources To Request",
        "- Cloud audit trail: `not_collected`",
        "- Kubernetes audit logs: `not_collected`",
        "- Container registry pull history: `not_collected`",
        "- Identity provider / bastion logs: `not_collected`",
        "- CI/CD pipeline and secret-store logs: `not_collected`",
        "- Firewall / NAT / proxy / DNS telemetry: `not_collected`",
        "",
        "## Rules",
        "- Mark unavailable sources explicitly instead of inferring their contents.",
        "- Record exact time windows and timezone basis when requesting external evidence.",
        "- Preserve original export files and hashes if external evidence is later attached to the case.",
        "",
    ])
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an external evidence checklist for a case bundle.")
    parser.add_argument("--input", required=True, help="Input reviewed evidence JSON path.")
    parser.add_argument("--case-dir", help="Case directory. Defaults from input path.")
    parser.add_argument("--output", help="Output markdown path.")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    case_dir = Path(args.case_dir).resolve() if args.case_dir else input_path.parent.parent
    output_path = Path(args.output).resolve() if args.output else (case_dir / "reports" / "external-evidence-checklist.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = load_json(input_path)
    body = build_checklist(data)
    output_path.write_text(body, encoding="utf-8")
    print(f"External evidence checklist written: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
