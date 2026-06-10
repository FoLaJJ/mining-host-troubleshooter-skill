#!/usr/bin/env python3
"""Generate reports from an existing case bundle without recollecting evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from run_readonly_workflow import (
    collection_failure_summary,
    expected_report_outputs,
    run_step,
    verify_expected_report_outputs,
    write_checkpoint,
    write_meta_json,
)


SUPPORTED_INPUTS: list[tuple[str, str]] = [
    ("reviewed", "evidence.reviewed.json"),
    ("reviewed_auto", "evidence.reviewed.auto.json"),
    ("raw", "evidence.raw.json"),
    ("failure_bundle", "evidence.collection.failed.json"),
]


def default_case_dir() -> str:
    return str(Path.cwd().resolve())


def classify_input(path: Path) -> str:
    for input_kind, filename in SUPPORTED_INPUTS:
        if path.name == filename:
            return input_kind

    failure = collection_failure_summary(str(path))
    if failure.get("status") == "failed":
        return "failure_bundle"

    raise SystemExit(
        "Unsupported evidence JSON for report regeneration: "
        f"{path}. Supported files are: "
        + ", ".join(filename for _, filename in SUPPORTED_INPUTS)
    )


def choose_input(case_dir: Path, override: str | None) -> tuple[Path, str]:
    evidence_dir = case_dir / "evidence"
    if not evidence_dir.exists() or not evidence_dir.is_dir():
        raise SystemExit(f"Evidence directory not found: {evidence_dir}")

    if override:
        path = Path(override).resolve()
        if not path.exists() or not path.is_file():
            raise SystemExit(f"Input evidence file not found: {path}")
        return path, classify_input(path)

    for input_kind, filename in SUPPORTED_INPUTS:
        candidate = evidence_dir / filename
        if candidate.exists() and candidate.is_file():
            return candidate, input_kind

    raise SystemExit(
        "No supported evidence JSON found under "
        f"{evidence_dir}. Checked: "
        + ", ".join(filename for _, filename in SUPPORTED_INPUTS)
    )


def step_failed(name: str, returncode: int) -> SystemExit:
    print(f"[ERROR] {name} failed", file=sys.stderr)
    return SystemExit(returncode)


def run_required_step(name: str, cmd: list[str]) -> str:
    code, out = run_step(name, cmd)
    if code != 0:
        raise step_failed(name, code)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate reports from an existing case bundle only."
    )
    parser.add_argument(
        "--case-dir",
        default=default_case_dir(),
        help="Case bundle directory. Defaults to the current working directory.",
    )
    parser.add_argument("--input", help="Optional supported evidence JSON override.")
    parser.add_argument("--strict", action="store_true", help="Use strict validation and report export.")
    parser.add_argument("--redact", action="store_true", help="Redact exported report content for external sharing.")
    args = parser.parse_args()

    case_dir = Path(args.case_dir).resolve()
    if not case_dir.exists() or not case_dir.is_dir():
        raise SystemExit(f"Case directory not found: {case_dir}")

    (case_dir / "meta").mkdir(parents=True, exist_ok=True)
    (case_dir / "reports").mkdir(parents=True, exist_ok=True)
    evidence_path, input_kind = choose_input(case_dir, args.input)

    script_dir = Path(__file__).resolve().parent
    enrich_script = script_dir / "enrich_case_evidence.py"
    review_script = script_dir / "review_case_evidence.py"
    validate_script = script_dir / "validate_case_bundle.py"
    operator_brief_script = script_dir / "generate_operator_brief.py"
    checklist_script = script_dir / "export_external_evidence_checklist.py"
    export_script = script_dir / "export_investigation_report.py"

    failure = collection_failure_summary(str(evidence_path)) if input_kind == "failure_bundle" else {}
    degraded = input_kind == "failure_bundle"

    print("[MODE: BUNDLE_REPORT_REGENERATION]")
    print(f"[INFO] Case dir: {case_dir}")
    print(f"[INFO] Evidence input: {evidence_path}")

    write_checkpoint(
        str(case_dir),
        "report_regeneration_started",
        status="degraded" if degraded else "completed",
        note=failure.get("reason", "") if degraded else "",
        extra={
            "mode": "BUNDLE_REPORT_REGENERATION",
            "input_kind": input_kind,
            "input_path": str(evidence_path),
        },
    )

    evidence_for_export = evidence_path
    if input_kind == "raw":
        reviewed_auto = case_dir / "evidence" / "evidence.reviewed.auto.json"
        run_required_step(
            "enrich_case_evidence",
            [
                sys.executable,
                str(enrich_script),
                "--input",
                str(evidence_path),
                "--output",
                str(reviewed_auto),
            ],
        )
        write_checkpoint(
            str(case_dir),
            "deep_evidence_hypothesis_matrix_complete",
            extra={"evidence_path": str(reviewed_auto)},
        )

        run_required_step(
            "review_case_evidence",
            [
                sys.executable,
                str(review_script),
                "--input",
                str(reviewed_auto),
                "--output",
                str(reviewed_auto),
                "--case-dir",
                str(case_dir),
            ],
        )
        write_checkpoint(
            str(case_dir),
            "second_pass_case_review_complete",
            extra={"evidence_path": str(reviewed_auto)},
        )
        evidence_for_export = reviewed_auto

    if input_kind == "failure_bundle":
        skip_note = failure.get("reason") or "Collection failed before host-side evidence could be gathered."
        write_checkpoint(
            str(case_dir),
            "report_regeneration_validation_complete",
            status="skipped",
            note=skip_note,
            extra={"input_kind": input_kind, "input_path": str(evidence_for_export)},
        )
    else:
        validate_cmd = [
            sys.executable,
            str(validate_script),
            "--case-dir",
            str(case_dir),
            "--input",
            str(evidence_for_export),
            "--json",
        ]
        if args.strict:
            validate_cmd.append("--strict")
        validate_out = run_required_step("validate_case_bundle", validate_cmd)
        write_meta_json(str(case_dir), "case_validation.json", validate_out)
        write_checkpoint(
            str(case_dir),
            "report_regeneration_validation_complete",
            extra={
                "input_kind": input_kind,
                "input_path": str(evidence_for_export),
                "validation_path": str(case_dir / "meta" / "case_validation.json"),
            },
        )

    run_required_step(
        "generate_operator_brief",
        [
            sys.executable,
            str(operator_brief_script),
            "--input",
            str(evidence_for_export),
            "--case-dir",
            str(case_dir),
        ],
    )
    write_checkpoint(
        str(case_dir),
        "operator_brief_complete",
        extra={"brief_path": str(case_dir / "reports" / "operator-brief.zh-CN.md")},
    )

    run_required_step(
        "export_external_evidence_checklist",
        [
            sys.executable,
            str(checklist_script),
            "--input",
            str(evidence_for_export),
            "--case-dir",
            str(case_dir),
        ],
    )
    write_checkpoint(
        str(case_dir),
        "external_evidence_checklist_complete",
        extra={"checklist_path": str(case_dir / "reports" / "external-evidence-checklist.md")},
    )

    export_cmd = [
        sys.executable,
        str(export_script),
        "--input",
        str(evidence_for_export),
        "--case-dir",
        str(case_dir),
    ]
    if args.strict:
        export_cmd.append("--strict")
    if args.redact:
        export_cmd.append("--redact")
    run_required_step("export_investigation_report", export_cmd)
    verify_expected_report_outputs(str(case_dir))
    write_checkpoint(
        str(case_dir),
        "approval_gated_response_plan_complete",
        status="degraded" if degraded else "completed",
        note=failure.get("reason", "") if degraded else "",
        extra={
            "leadership_report_path": str(case_dir / "leadership-report.zh-CN.md"),
            "report_path": str(case_dir / "report.zh-CN.md"),
        },
    )
    write_checkpoint(
        str(case_dir),
        "report_output_contract_verified",
        extra={"expected_output_count": len(expected_report_outputs(str(case_dir)))},
    )
    write_checkpoint(
        str(case_dir),
        "report_regeneration_completed",
        status="degraded" if degraded else "completed",
        note=failure.get("reason", "") if degraded else "",
        extra={
            "mode": "BUNDLE_REPORT_REGENERATION",
            "input_kind": input_kind,
            "evidence_path": str(evidence_for_export),
        },
    )

    print("[DONE] Report regeneration completed." if not degraded else "[DONE] Report regeneration completed in degraded mode.")
    print(f"[DONE] Case dir: {case_dir}")
    print(f"[DONE] Evidence: {evidence_for_export}")
    print(f"[DONE] Report: {case_dir / 'report.md'}")
    print(f"[DONE] Chinese Report: {case_dir / 'report.zh-CN.md'}")
    print(f"[DONE] Leadership Report: {case_dir / 'leadership-report.md'}")
    print(f"[DONE] Leadership Report (ZH): {case_dir / 'leadership-report.zh-CN.md'}")
    print(f"[DONE] External Evidence Checklist: {case_dir / 'reports' / 'external-evidence-checklist.md'}")
    print(f"[DONE] Operator Brief (ZH): {case_dir / 'reports' / 'operator-brief.zh-CN.md'}")
    print(f"[DONE] Operator Brief (EN): {case_dir / 'reports' / 'operator-brief.md'}")
    print(f"[DONE] Report Manifest: {case_dir / 'meta' / 'report-manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
