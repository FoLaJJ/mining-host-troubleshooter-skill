#!/usr/bin/env python3
"""Audit skill docs and scripts for example-anchor drift and accidental real-looking values."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

PRIVATE_IP_RE = re.compile(r"\b(?:10(?:\.\d{1,3}){3}|127(?:\.\d{1,3}){3}|169\.254(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b")
TEST_NET_IP_RE = re.compile(r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)(?:\.\d{1,3})\b")
REMOTE_LOGIN_RE = re.compile(r"\b[a-z_][a-z0-9._-]*@(?:\d{1,3}\.){3}\d{1,3}\b", re.IGNORECASE)
SSH_KEY_PATH_RE = re.compile(r"(?:~|/home/[^/\s]+|/root)/\.ssh/(?:id_[a-z0-9_-]+)", re.IGNORECASE)
WINDOWS_ABS_RE = re.compile(r'\b[A-Za-z]:\\[^\s`"\']+')
REPORT_CASE_IP_RE = re.compile(r"reports/[0-9]{1,3}(?:\.[0-9]{1,3}){3}-\d{8}-\d{6}")

TEXT_EXTS = {'.md', '.json', '.yaml', '.yml', '.py', '.mjs'}
DEFAULT_SKIP_PARTS = {'reports', '__pycache__', 'node_modules', '.git'}

RULES = [
    ('private_ip', PRIVATE_IP_RE, 'Replace with <HOST_IP> unless it is live evidence outside the skill package.'),
    ('testnet_ip', TEST_NET_IP_RE, 'Prefer <HOST_IP> placeholders in docs/examples to avoid anchor bias.'),
    ('remote_login_literal', REMOTE_LOGIN_RE, 'Replace with <REMOTE_USER>@<HOST_IP>.'),
    ('ssh_key_path', SSH_KEY_PATH_RE, 'Replace with <SSH_KEY_PATH>.'),
    ('windows_absolute_path', WINDOWS_ABS_RE, 'Avoid machine-specific absolute paths in shipped docs/examples.'),
    ('case_output_ip_path', REPORT_CASE_IP_RE, 'Use reports/<case> in examples, not concrete case names.'),
]

DEFAULT_ALLOW = {
    'scripts/install-skill.mjs': {'windows_absolute_path'},
    'scripts/collect_live_evidence.py': {'private_ip'},
    'references/skill-maintenance.md': {'windows_absolute_path'},
}


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding='utf-8'))
    return data if isinstance(data, dict) else {}


def build_allow_map(config: dict[str, Any]) -> dict[str, set[str]]:
    merged = {key: set(value) for key, value in DEFAULT_ALLOW.items()}
    extra = config.get('allow', {}) if isinstance(config.get('allow'), dict) else {}
    for key, value in extra.items():
        if not isinstance(value, list):
            continue
        merged.setdefault(str(key), set()).update(str(item) for item in value)
    return merged


def build_skip_parts(config: dict[str, Any]) -> set[str]:
    merged = set(DEFAULT_SKIP_PARTS)
    extra = config.get('skip_parts', []) if isinstance(config.get('skip_parts'), list) else []
    merged.update(str(item) for item in extra)
    return merged


def iter_files(root: Path, skip_parts: set[str]) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        if any(part in skip_parts for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTS:
            continue
        out.append(path)
    return sorted(out)


def scan_file(root: Path, path: Path, allow_map: dict[str, set[str]]) -> list[dict[str, object]]:
    rel = path.relative_to(root).as_posix()
    allowed = allow_map.get(rel, set())
    text = path.read_text(encoding='utf-8', errors='replace')
    findings: list[dict[str, object]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule_name, pattern, guidance in RULES:
            if rule_name in allowed:
                continue
            for match in pattern.finditer(line):
                findings.append({
                    'file': rel,
                    'line': line_no,
                    'rule': rule_name,
                    'match': match.group(0),
                    'guidance': guidance,
                })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description='Audit docs/scripts for example-anchor drift and machine-specific values.')
    parser.add_argument('--root', default=str(Path(__file__).resolve().parents[1]), help='Skill root directory.')
    parser.add_argument('--config', help='Optional JSON config path. Defaults to references/example-anchor-audit.json under the skill root.')
    parser.add_argument('--json', action='store_true', help='Emit JSON instead of plain text.')
    parser.add_argument('--strict', action='store_true', help='Return non-zero when findings are present.')
    args = parser.parse_args()

    root = Path(args.root).resolve()
    config_path = Path(args.config).resolve() if args.config else (root / 'references' / 'example-anchor-audit.json')
    config = load_config(config_path)
    allow_map = build_allow_map(config)
    skip_parts = build_skip_parts(config)

    all_findings: list[dict[str, object]] = []
    for path in iter_files(root, skip_parts):
        all_findings.extend(scan_file(root, path, allow_map))

    payload = {
        'ok': len(all_findings) == 0,
        'root': str(root),
        'config_path': str(config_path),
        'strict': bool(args.strict),
        'finding_count': len(all_findings),
        'findings': all_findings,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"root: {root}")
        print(f"config_path: {config_path}")
        print(f"strict: {args.strict}")
        print(f"finding_count: {len(all_findings)}")
        for item in all_findings:
            print(f"- {item['file']}:{item['line']} [{item['rule']}] {item['match']}")
            print(f"  guidance: {item['guidance']}")
    return 1 if args.strict and all_findings else 0


if __name__ == '__main__':
    raise SystemExit(main())
