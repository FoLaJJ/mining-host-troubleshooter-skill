#!/usr/bin/env python3
"""Apply a known-clean host baseline to a case bundle and export a concise assessment."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from compare_case_bundles import build_host_scope, parse_case
from enrich_case_evidence import as_dict, as_list, load_json
from generate_host_baseline import extract_case_extras


METRIC_SPECS = [
    ("listening_ports", "Listening Ports", "high"),
    ("auth_source_ips", "Auth Source IPs", "high"),
    ("trust_anomalies", "Trust Anomalies", "high"),
    ("process_ioc_lines", "Process IOC Lines", "critical"),
    ("running_services", "Running Services", "medium"),
    ("container_names", "Container Names", "medium"),
    ("container_images", "Container Images", "medium"),
]


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(md_escape(cell) for cell in row) + " |")
    return "\n".join(lines)


def shorten(items: list[str], limit: int = 6) -> str:
    if not items:
        return "-"
    sample = items[:limit]
    if len(items) > limit:
        sample.append(f"... (+{len(items) - limit} more)")
    return ", ".join(sample)


def load_case_extras(case: dict[str, Any]) -> dict[str, list[str]]:
    data = load_json(Path(case["evidence_path"]))
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    return extract_case_extras(Path(case["case_dir"]), evidence_items)


def normalize_metric(
    name: str,
    label: str,
    severity: str,
    current: list[str],
    stable: list[str],
    majority: list[str],
    observed_union: list[str],
) -> dict[str, Any]:
    current_set = set(current)
    stable_set = set(stable)
    majority_set = set(majority)
    union_set = set(observed_union)
    unexpected_new = sorted(current_set - union_set)
    missing_stable = sorted(stable_set - current_set)
    missing_majority = sorted(majority_set - current_set)
    known_nonstable = sorted((current_set & union_set) - stable_set)
    if unexpected_new:
        status = "unexpected_deviation"
    elif missing_stable:
        status = "baseline_drift"
    else:
        status = "within_baseline"
    return {
        "metric": name,
        "label": label,
        "severity": severity,
        "status": status,
        "current": sorted(current_set),
        "stable_expected": sorted(stable_set),
        "majority_expected": sorted(majority_set),
        "observed_union": sorted(union_set),
        "unexpected_new": unexpected_new,
        "missing_stable": missing_stable,
        "missing_majority": missing_majority,
        "known_nonstable_present": known_nonstable,
        "current_count": len(current_set),
        "stable_count": len(stable_set),
        "union_count": len(union_set),
    }


def overall_status(metrics: list[dict[str, Any]]) -> str:
    if any(item["status"] == "unexpected_deviation" for item in metrics):
        return "unexpected_deviation"
    if any(item["status"] == "baseline_drift" for item in metrics):
        return "baseline_drift"
    return "within_baseline"


def build_summary(status: str, metrics: list[dict[str, Any]], baseline_quality: dict[str, Any] | None = None) -> str:
    unexpected = [item["label"] for item in metrics if item["unexpected_new"]]
    drift = [item["label"] for item in metrics if item["missing_stable"]]
    quality = as_dict(baseline_quality or {})
    quality_prefix = f"Baseline quality is {quality.get('level', 'unknown')}. " if quality else ""
    if status == "unexpected_deviation":
        return (
            quality_prefix
            + "Current case deviates from the supplied same-host baseline. "
            + f"New values were observed in: {', '.join(unexpected)}."
        )
    if status == "baseline_drift":
        return (
            quality_prefix
            + "Current case does not introduce unseen values, but one or more baseline-stable items are missing. "
            + f"Drift observed in: {', '.join(drift)}."
        )
    return quality_prefix + "Current case stays within the supplied same-host baseline for the assessed read-only signals, but this does not prove benign state."


def render_markdown(assessment: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Baseline Assessment")
    lines.append("")
    lines.append(f"- Generated At (UTC): `{assessment['generated_at_utc']}`")
    lines.append(f"- Assessment Status: `{assessment['assessment_status']}`")
    lines.append(f"- Host: `{assessment['host']['name']}` ({assessment['host']['ip']})")
    lines.append(f"- Baseline File: `{assessment['baseline']['path']}`")
    lines.append(f"- Baseline Generated At (UTC): `{assessment['baseline'].get('generated_at_utc', 'unknown')}`")
    quality = as_dict(assessment['baseline'].get('quality'))
    lines.append(f"- Host Scope Match: `{assessment['scope']['match']}` via `{', '.join(assessment['scope'].get('match_basis', [])) or 'none'}`")
    lines.append(f"- Baseline Quality: `{quality.get('level', 'unknown')}`")
    lines.append(f"- Quality Reason: {quality.get('reason', 'not provided')}")
    lines.append("")
    lines.append("## Summary")
    lines.append(assessment["summary"])
    lines.append("")
    unexpected = [item for item in assessment["metrics"] if item["unexpected_new"]]
    drift = [item for item in assessment["metrics"] if item["missing_stable"]]
    known_nonstable = [item for item in assessment["metrics"] if item["known_nonstable_present"]]

    lines.append("## Decision Points")
    lines.append(f"- Metrics with unexpected new values: `{len(unexpected)}`")
    lines.append(f"- Metrics with stable baseline items now missing: `{len(drift)}`")
    lines.append(f"- Metrics still within known historical range but not stable in all clean cases: `{len(known_nonstable)}`")
    lines.append("")

    rows: list[list[str]] = []
    for item in assessment["metrics"]:
        rows.append([
            item["label"],
            item["status"],
            shorten(item["unexpected_new"]),
            shorten(item["missing_stable"]),
            shorten(item["known_nonstable_present"]),
        ])
    lines.append("## Metric Summary")
    lines.append(render_table(["Metric", "Status", "Unexpected New", "Missing Stable", "Known Non-Stable Present"], rows))
    lines.append("")

    if unexpected or drift:
        lines.append("## Analyst Attention")
        for item in unexpected:
            lines.append(
                f"- `{item['label']}` introduced values not present in the clean baseline: {shorten(item['unexpected_new'], limit=10)}"
            )
        for item in drift:
            lines.append(
                f"- `{item['label']}` is missing baseline-stable values: {shorten(item['missing_stable'], limit=10)}"
            )
        lines.append("")

    if known_nonstable:
        lines.append("## Known but Non-Stable Observations")
        for item in known_nonstable:
            lines.append(
                f"- `{item['label']}` contains historically seen values that were not stable across every clean case: {shorten(item['known_nonstable_present'], limit=10)}"
            )
        lines.append("")

    lines.append("## Interpretation Rules")
    lines.append("- Unexpected new values are deviation signals, not proof of compromise by themselves.")
    lines.append("- Missing baseline-stable values indicate drift and should be checked against change windows or host role updates.")
    lines.append("- Baseline matching does not prove the host is clean; it only suppresses repeated same-host normals.")
    lines.append("- Even a within-baseline result cannot be used as the sole reason to clear a host or suppress an incident.")
    for rule in as_list(quality.get('constraints')):
        lines.append(f"- {rule}")
    lines.append("")
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply a known-clean same-host baseline to a case bundle.")
    parser.add_argument("--case-dir", required=True, help="Case directory to assess.")
    parser.add_argument("--baseline", required=True, help="Baseline JSON path generated by generate_host_baseline.py.")
    parser.add_argument("--output-dir", help="Output directory. Defaults to <case-dir>.")
    parser.add_argument("--allow-host-mismatch", action="store_true", help="Allow assessment even if baseline host metadata does not match the case host.")
    args = parser.parse_args()

    case_dir = Path(args.case_dir).resolve()
    baseline_path = Path(args.baseline).resolve()
    if not case_dir.exists() or not case_dir.is_dir():
        raise SystemExit(f"Case directory not found: {case_dir}")
    if not baseline_path.exists():
        raise SystemExit(f"Baseline JSON not found: {baseline_path}")

    case = parse_case(case_dir)
    extras = load_case_extras(case)
    current = {
        "listening_ports": case.get("listening_ports", []),
        "auth_source_ips": case.get("auth_source_ips", []),
        "trust_anomalies": case.get("trust_anomalies", []),
        "process_ioc_lines": case.get("process_ioc_lines", []),
        "running_services": extras.get("running_services", []),
        "container_names": extras.get("container_names", []),
        "container_images": extras.get("container_images", []),
    }

    baseline = load_json(baseline_path)
    baseline_host = {
        "host_name": str(baseline.get("host_name", "unknown")),
        "host_ip": str(baseline.get("host_ip", "unknown")),
    }
    scope = build_host_scope(baseline_host, case)
    if not args.allow_host_mismatch and not scope.get("match"):
        raise SystemExit(
            "Baseline host metadata does not confirm same-host scope. Use --allow-host-mismatch only when this is deliberate."
        )

    stable = as_dict(baseline.get("stable"))
    majority = as_dict(baseline.get("observed_majority"))
    observed_union = as_dict(baseline.get("observed_union"))
    metrics: list[dict[str, Any]] = []
    for name, label, severity in METRIC_SPECS:
        metrics.append(
            normalize_metric(
                name,
                label,
                severity,
                current=current.get(name, []),
                stable=as_list(stable.get(name)),
                majority=as_list(majority.get(name)),
                observed_union=as_list(observed_union.get(name)),
            )
        )

    status = overall_status(metrics)
    baseline_quality = as_dict(baseline.get("baseline_quality"))

    assessment = {
        "generated_at_utc": now_utc(),
        "assessment_status": status,
        "summary": build_summary(status, metrics, baseline_quality=baseline_quality),
        "host": {
            "name": case.get("host_name", "unknown"),
            "ip": case.get("host_ip", "unknown"),
            "os": case.get("os", "unknown"),
            "mining_mode": case.get("mining_mode", "unknown"),
            "case_dir": case.get("case_dir", str(case_dir)),
            "case_name": case.get("case_name", case_dir.name),
            "evidence_path": case.get("evidence_path", "unknown"),
        },
        "baseline": {
            "path": str(baseline_path),
            "generated_at_utc": str(baseline.get("generated_at_utc", "unknown")),
            "host_name": baseline_host["host_name"],
            "host_ip": baseline_host["host_ip"],
            "cases_used": as_list(baseline.get("cases_used")),
            "quality": baseline_quality,
        },
        "scope": scope,
        "metrics": metrics,
        "current_snapshot": current,
        "notes": [
            "Assessment is read-only and evidence-bound.",
            "Baseline matching suppresses repeated same-host normals but does not prove benign state.",
            "Unexpected new values require analyst review before attribution.",
            "A baseline hit must never be used as the sole reason to clear a host or suppress an incident.",
            "Baseline output is same-host historical context only, not a machine truth model.",
        ] + [str(x) for x in as_list(baseline_quality.get("constraints"))],
    }

    output_root = Path(args.output_dir).resolve() if args.output_dir else case_dir
    meta_dir = output_root / "meta"
    reports_dir = output_root / "reports"
    meta_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    json_path = meta_dir / "baseline_assessment.json"
    md_path = reports_dir / "baseline_assessment.md"
    json_path.write_text(json.dumps(assessment, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(assessment), encoding="utf-8")

    print(f"Baseline Assessment JSON written: {json_path}")
    print(f"Baseline Assessment Markdown written: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
