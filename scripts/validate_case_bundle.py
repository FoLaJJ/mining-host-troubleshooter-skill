#!/usr/bin/env python3
"""Validate case bundle completeness and evidence traceability."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


TRACE_STATUSES = {"traced", "untraceable", "unknown"}
CLAIM_TYPES = {"observed_fact", "inference", "attribution"}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON ({path}): {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"Expected JSON object in {path}")
    return data


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_case(case_dir: Path, evidence_path: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    required_dirs = ["evidence", "artifacts", "reports", "meta"]
    for d in required_dirs:
        p = case_dir / d
        ok = p.exists() and p.is_dir()
        checks.append({"check": f"dir:{d}", "ok": ok, "path": str(p)})
        if not ok:
            errors.append(f"Missing required directory: {p}")

    if not evidence_path.exists():
        errors.append(f"Evidence JSON not found: {evidence_path}")
        return {"ok": False, "errors": errors, "warnings": warnings, "checks": checks}

    data = load_json(evidence_path)
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    findings = [as_dict(x) for x in as_list(data.get("findings"))]
    ip_traces = [as_dict(x) for x in as_list(data.get("ip_traces"))]
    log_integrity = [as_dict(x) for x in as_list(data.get("log_integrity"))]
    timeline = [as_dict(x) for x in as_list(data.get("timeline"))]

    for key in ("case_id", "host_id", "collector_version", "timezone", "report_timezone_basis"):
        if not str(data.get(key, "")).strip():
            warnings.append(f"Top-level field missing or empty: {key}")

    if not evidence_items:
        errors.append("No evidence entries in evidence JSON.")

    evidence_ids: set[str] = set()
    duplicate_ids: set[str] = set()
    for item in evidence_items:
        evid = str(item.get("id", "")).strip()
        if not evid:
            errors.append("Evidence entry missing id.")
            continue
        if evid in evidence_ids:
            duplicate_ids.add(evid)
        evidence_ids.add(evid)

        for key in ("source", "observed_at", "command", "artifact"):
            if not str(item.get(key, "")).strip():
                errors.append(f"Evidence {evid} missing field: {key}")
        for key in ("command_hash", "artifact_hash"):
            if not str(item.get(key, "")).strip():
                warnings.append(f"Evidence {evid} missing field: {key}")

        artifact = Path(str(item.get("artifact", "")))
        if not artifact.exists():
            errors.append(f"Evidence {evid} artifact not found: {artifact}")

    if duplicate_ids:
        errors.append(f"Duplicate evidence IDs: {', '.join(sorted(duplicate_ids))}")

    for finding in findings:
        fid = str(finding.get("id", "unknown"))
        ids = [str(x) for x in as_list(finding.get("evidence_ids"))]
        claim_type = str(finding.get("claim_type", "")).strip().lower()
        if claim_type and claim_type not in CLAIM_TYPES:
            errors.append(f"Finding {fid} has invalid claim_type: {claim_type}")
        if not claim_type:
            warnings.append(f"Finding {fid} missing claim_type.")
        if not str(finding.get("hypothesis_id", "")).strip():
            warnings.append(f"Finding {fid} missing hypothesis_id.")
        if not str(finding.get("confidence_reason", "")).strip():
            warnings.append(f"Finding {fid} missing confidence_reason.")
        if not ids:
            warnings.append(f"Finding {fid} has no evidence_ids (will be inconclusive).")
            continue
        missing = [x for x in ids if x not in evidence_ids]
        if missing:
            errors.append(f"Finding {fid} references missing evidence IDs: {', '.join(missing)}")

    for item in timeline:
        if not str(item.get("normalized_time_utc", "")).strip():
            warnings.append("Timeline entry missing normalized_time_utc.")

    remote_trust = as_dict(data.get("remote_trust"))
    if str(as_dict(data.get("host")).get("ip", "")).strip() not in {"", "127.0.0.1"} and not remote_trust:
        warnings.append("remote_trust metadata missing for non-local collection.")

    for ip_item in ip_traces:
        ip = str(ip_item.get("ip", "unknown"))
        status = str(ip_item.get("trace_status", "")).strip().lower()
        if status not in TRACE_STATUSES:
            errors.append(f"IP trace {ip} has invalid trace_status: {status or 'empty'}")
        if status in {"untraceable", "unknown"} and not str(ip_item.get("reason", "")).strip():
            errors.append(f"IP trace {ip} with status={status} must include reason.")

    for entry in log_integrity:
        artifact = str(entry.get("artifact", "unknown"))
        status = str(entry.get("status", "")).strip().lower()
        ids = [str(x) for x in as_list(entry.get("evidence_ids"))]
        if status in {"missing", "tampered"} and not ids:
            errors.append(f"Log integrity entry {artifact} status={status} requires evidence_ids.")

    hash_manifest = case_dir / "meta" / "artifact_hashes.json"
    if not hash_manifest.exists():
        warnings.append("artifact_hashes.json missing; artifact integrity chain is incomplete.")
    else:
        hm = load_json(hash_manifest)
        hash_items = [as_dict(x) for x in as_list(hm.get("items"))]
        hashed = {str(x.get("artifact", "")) for x in hash_items}
        expected_hash: dict[str, str] = {
            str(x.get("artifact", "")): str(x.get("sha256", "")).strip().lower()
            for x in hash_items
            if str(x.get("artifact", "")).strip()
        }
        for item in evidence_items:
            artifact = str(item.get("artifact", ""))
            if artifact and artifact not in hashed:
                warnings.append(f"Artifact not listed in hash manifest: {artifact}")

        for artifact, exp in expected_hash.items():
            ap = Path(artifact)
            if not ap.exists():
                errors.append(f"Hashed artifact not found on disk: {artifact}")
                continue
            if not exp:
                warnings.append(f"Hashed artifact has empty sha256 in manifest: {artifact}")
                continue
            got = sha256_file(ap).lower()
            if got != exp:
                errors.append(f"Artifact hash mismatch: {artifact}")

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
        "stats": {
            "evidence_count": len(evidence_items),
            "findings_count": len(findings),
            "ip_trace_count": len(ip_traces),
            "log_integrity_count": len(log_integrity),
            "timeline_count": len(timeline),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate case bundle and evidence traceability.")
    parser.add_argument("--case-dir", required=True, help="Case directory path.")
    parser.add_argument(
        "--input",
        help="Evidence JSON path. Defaults to <case-dir>/evidence/evidence.raw.json",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failure.")
    args = parser.parse_args()

    case_dir = Path(args.case_dir).resolve()
    evidence_path = Path(args.input).resolve() if args.input else (case_dir / "evidence" / "evidence.raw.json")
    result = validate_case(case_dir, evidence_path)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"ok: {result['ok']}")
        for c in result["checks"]:
            print(f"- {c['check']}: {'ok' if c['ok'] else 'failed'} ({c['path']})")
        if result["errors"]:
            print("errors:")
            for e in result["errors"]:
                print(f"  - {e}")
        if result["warnings"]:
            print("warnings:")
            for w in result["warnings"]:
                print(f"  - {w}")
        stats = result.get("stats", {})
        if stats:
            print(
                "stats: evidence={evidence_count} findings={findings_count} ip_traces={ip_trace_count} log_integrity={log_integrity_count} timeline={timeline_count}".format(
                    **stats
                )
            )

    if result["errors"]:
        return 2
    if args.strict and result["warnings"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
