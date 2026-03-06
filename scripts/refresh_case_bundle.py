#!/usr/bin/env python3
"""Refresh artifact hashes, revalidate, and re-export a case bundle after analyst updates."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def build_artifact_hashes(artifacts_dir: Path) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for p in sorted(artifacts_dir.glob('E-*.txt')):
        st = p.stat()
        items.append(
            {
                'artifact': str(p),
                'size_bytes': st.st_size,
                'mtime_utc': datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).replace(microsecond=0).isoformat(),
                'sha256': sha256_file(p),
            }
        )
    return {
        'generated_at_utc': now_utc(),
        'algorithm': 'sha256',
        'count': len(items),
        'items': items,
    }


def choose_input(case_dir: Path, override: str | None) -> Path:
    if override:
        path = Path(override).resolve()
        if not path.exists():
            raise SystemExit(f'Input evidence file not found: {path}')
        return path
    candidates = [
        case_dir / 'evidence' / 'evidence.reviewed.json',
        case_dir / 'evidence' / 'evidence.reviewed.auto.json',
        case_dir / 'evidence' / 'evidence.raw.json',
    ]
    for path in candidates:
        if path.exists():
            return path
    raise SystemExit('No evidence JSON found under case_dir/evidence/.')


def run_step(name: str, cmd: list[str]) -> None:
    print(f'[STEP] {name}')
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.stdout:
        print(proc.stdout, end='')
    if proc.stderr:
        print(proc.stderr, end='', file=sys.stderr)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description='Refresh artifact hashes, validate, and export a case bundle after analyst updates.')
    parser.add_argument('--case-dir', required=True, help='Case bundle directory.')
    parser.add_argument('--input', help='Evidence JSON to validate/export. Defaults to reviewed.json, then reviewed.auto.json, then raw.json.')
    parser.add_argument('--skip-validate', action='store_true', help='Skip validate_case_bundle.py.')
    parser.add_argument('--skip-export', action='store_true', help='Skip export_investigation_report.py.')
    parser.add_argument('--strict', action='store_true', help='Use strict validation/report export.')
    parser.add_argument('--redact', action='store_true', help='Redact output for external sharing.')
    args = parser.parse_args()

    case_dir = Path(args.case_dir).resolve()
    if not case_dir.exists() or not case_dir.is_dir():
        raise SystemExit(f'Case directory not found: {case_dir}')

    artifacts_dir = case_dir / 'artifacts'
    meta_dir = case_dir / 'meta'
    meta_dir.mkdir(parents=True, exist_ok=True)
    if not artifacts_dir.exists() or not artifacts_dir.is_dir():
        raise SystemExit(f'Artifacts directory not found: {artifacts_dir}')

    evidence_path = choose_input(case_dir, args.input)
    hash_manifest = build_artifact_hashes(artifacts_dir)
    hash_path = meta_dir / 'artifact_hashes.json'
    hash_path.write_text(json.dumps(hash_manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'[INFO] Artifact hashes refreshed: {hash_path}')
    print(f'[INFO] Evidence input: {evidence_path}')

    script_dir = Path(__file__).resolve().parent
    validate_script = script_dir / 'validate_case_bundle.py'
    export_script = script_dir / 'export_investigation_report.py'

    if not args.skip_validate:
        validate_cmd = [sys.executable, str(validate_script), '--case-dir', str(case_dir), '--input', str(evidence_path), '--json']
        if args.strict:
            validate_cmd.append('--strict')
        run_step('validate_case_bundle', validate_cmd)

    if not args.skip_export:
        export_cmd = [sys.executable, str(export_script), '--input', str(evidence_path), '--case-dir', str(case_dir)]
        if args.strict:
            export_cmd.append('--strict')
        if args.redact:
            export_cmd.append('--redact')
        run_step('export_investigation_report', export_cmd)
        print(f'[DONE] Report: {case_dir / "reports" / "report.md"}')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
